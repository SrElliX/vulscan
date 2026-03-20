"""
Módulo Risk Scoring
Calcula o nível de risco de cada host com base nos CVEs encontrados,
nos serviços expostos e nas configurações detectadas pelos scripts NSE.

CVSS v3 Severity:
  9.0 - 10.0  → CRITICAL
  7.0 - 8.9   → HIGH
  4.0 - 6.9   → MEDIUM
  0.1 - 3.9   → LOW
  0.0         → NONE / INFO
"""

RESET  = "\033[0m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
GRAY   = "\033[90m"
BOLD   = "\033[1m"

# Portas intrinsecamente de risco alto quando expostas publicamente
HIGH_RISK_PORTS = {
    23:    ("Telnet exposto", "HIGH"),
    3389:  ("RDP exposto", "HIGH"),
    445:   ("SMB exposto (risco EternalBlue)", "CRITICAL"),
    139:   ("NetBIOS exposto", "HIGH"),
    135:   ("MSRPC exposto", "HIGH"),
    5900:  ("VNC exposto", "HIGH"),
    6379:  ("Redis sem auth (padrão)", "HIGH"),
    27017: ("MongoDB sem auth (padrão)", "HIGH"),
    9200:  ("Elasticsearch exposto", "HIGH"),
    2375:  ("Docker API exposta", "CRITICAL"),
    4243:  ("Docker API exposta", "CRITICAL"),
}

# Serviços que indicam risco quando detectados por scripts NSE
NSE_RISK_INDICATORS = {
    "http-methods":      ("Métodos HTTP perigosos habilitados", "MEDIUM"),
    "ftp-anon":          ("FTP anônimo habilitado", "HIGH"),
    "smb-security-mode": ("SMB sem assinatura", "MEDIUM"),
    "http-auth-finder":  ("Autenticação fraca detectada", "MEDIUM"),
}

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0, "INFO": 0}
SEVERITY_COLOR = {
    "CRITICAL": RED,
    "HIGH":     YELLOW,
    "MEDIUM":   "\033[94m",
    "LOW":      GREEN,
    "NONE":     GRAY,
    "INFO":     GRAY,
}


def score_to_severity(score: float | None) -> str:
    if score is None:
        return "NONE"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def calculate_port_risk(port: dict) -> dict:
    """
    Calcula o risco de uma porta individual:
    1. CVEs encontrados (CVSS score mais alto)
    2. Risco intrínseco da porta (ex: Telnet, RDP exposto)
    3. Alertas dos scripts NSE
    """
    findings = []

    # 1. CVEs
    for cve in port.get("cves", []):
        sev = cve.get("severity", "NONE")
        findings.append({
            "type":     "CVE",
            "severity": sev,
            "detail":   f"{cve['id']} — score {cve['score']} — {cve['description'][:120]}",
        })

    # 2. Risco intrínseco da porta
    port_num = port.get("port")
    if port_num in HIGH_RISK_PORTS:
        desc, sev = HIGH_RISK_PORTS[port_num]
        findings.append({
            "type":     "EXPOSURE",
            "severity": sev,
            "detail":   desc,
        })

    # 3. Scripts NSE
    for script_name, script_output in port.get("script_output", {}).items():
        if script_name in NSE_RISK_INDICATORS:
            desc, sev = NSE_RISK_INDICATORS[script_name]
            findings.append({
                "type":     "CONFIG",
                "severity": sev,
                "detail":   f"{desc}: {str(script_output)[:100]}",
            })

    # Severidade máxima dos findings
    if findings:
        max_sev = max(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 0))
        overall = max_sev["severity"]
    else:
        overall = "INFO"

    port["risk"] = {
        "severity": overall,
        "findings": findings,
    }

    return port


def calculate_host_risk(host: dict) -> dict:
    """
    Agrega o risco de todas as portas num score do host.
    """
    severities = [
        p["risk"]["severity"]
        for p in host.get("ports", [])
        if p.get("risk")
    ]

    if not severities:
        host["host_risk"] = "INFO"
        host["risk_score"] = 0
        return host

    # Host risk = severidade máxima encontrada em qualquer porta
    host["host_risk"] = max(severities, key=lambda s: SEVERITY_ORDER.get(s, 0))

    # Score numérico: soma ponderada (útil para ordenar hosts no relatório)
    weights = {"CRITICAL": 100, "HIGH": 30, "MEDIUM": 10, "LOW": 2, "INFO": 0, "NONE": 0}
    host["risk_score"] = sum(weights.get(s, 0) for s in severities)

    return host


def calculate_risk(hosts: list[dict]) -> list[dict]:
    """Calcula risco de todas as portas e hosts."""
    for host in hosts:
        for port in host["ports"]:
            calculate_port_risk(port)
        calculate_host_risk(host)

    # Ordena hosts por risco decrescente (mais críticos primeiro no relatório)
    hosts.sort(key=lambda h: h.get("risk_score", 0), reverse=True)

    # Exibe resumo no terminal
    print(f"\n  {'HOST':<20} {'RISCO':<10} {'PORTAS':<8} {'CVEs'}")
    print(f"  {'─'*55}")
    for host in hosts:
        sev = host.get("host_risk", "INFO")
        col = SEVERITY_COLOR.get(sev, RESET)
        total_cves = sum(len(p.get("cves", [])) for p in host["ports"])
        ip_display = f"{host['ip']}"
        if host.get("hostname"):
            ip_display += f" ({host['hostname'][:20]})"
        print(f"  {ip_display:<32} {col}{sev:<10}{RESET} {len(host['ports']):<8} {total_cves}")

    return hosts
