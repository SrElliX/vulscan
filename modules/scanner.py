"""
Módulo Scanner
Usa python-nmap para orquestrar o Nmap e parsear os resultados
num formato uniforme que os outros módulos consomem.

python-nmap é um wrapper: ele monta o comando nmap, executa como
subprocesso, captura o XML de saída e devolve um dict Python.
"""

import nmap
import socket

RESET  = "\033[0m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
GRAY   = "\033[90m"
BOLD   = "\033[1m"
CYAN   = "\033[96m"

# Mapa de portas conhecidas para exibição amigável
SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC",
    135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 587: "SMTP/TLS", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 3000: "Dev",
    3306: "MySQL", 3389: "RDP", 4443: "Alt-HTTPS",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-alt", 8443: "HTTPS-alt", 8888: "Jupyter",
    9200: "Elasticsearch", 27017: "MongoDB",
}


def build_nmap_args(ports: str, full: bool, timeout: int) -> str:
    """
    Monta os argumentos do Nmap:

    Modo connect (sem root):
      -sT  = TCP connect scan (completa o handshake — não precisa de root)
      -sV  = detecta versão do serviço (banner grabbing)
      -sC  = scripts NSE padrão (detecta configs, HTTPtitle, etc.)
      --open = mostra só portas abertas
      -T4  = timing agressivo (mais rápido)

    Modo full (root necessário):
      -sS  = SYN scan (half-open, mais furtivo e preciso)
      -O   = OS detection
      -sV --version-intensity 7 = detecção de versão mais agressiva
    """
    base = f"--open -T4 --host-timeout {timeout * 10}s"

    if full:
        scan_type = "-sS -sV --version-intensity 7 -sC -O"
    else:
        scan_type = "-sT -sV --version-light -sC"

    if ports == "top100":
        port_spec = "--top-ports 100"
    elif ports == "top1000":
        port_spec = "--top-ports 1000"
    else:
        port_spec = f"-p {ports}"

    return f"{scan_type} {port_spec} {base}"


def parse_host(nm: nmap.PortScanner, host: str) -> dict:
    """
    Extrai do resultado do nmap os dados relevantes de um host:
    - portas abertas com serviço, produto e versão
    - OS detectado (se disponível)
    - hostname reverso
    """
    host_data = {
        "ip":       host,
        "hostname": "",
        "state":    nm[host].state(),
        "os":       None,
        "ports":    [],
    }

    # Resolve hostname reverso
    try:
        host_data["hostname"] = socket.gethostbyaddr(host)[0]
    except Exception:
        pass

    # OS detection (só disponível com -O / modo full)
    if "osmatch" in nm[host] and nm[host]["osmatch"]:
        best = nm[host]["osmatch"][0]
        host_data["os"] = {
            "name":     best.get("name", ""),
            "accuracy": best.get("accuracy", ""),
        }

    # Portas abertas
    for proto in nm[host].all_protocols():
        for port in sorted(nm[host][proto].keys()):
            p = nm[host][proto][port]
            if p["state"] != "open":
                continue

            product = p.get("product", "")
            version = p.get("version", "")
            extra   = p.get("extrainfo", "")

            # Monta a string de versão completa ex: "OpenSSH 8.9p1"
            version_str = " ".join(filter(None, [product, version, extra])).strip()

            port_data = {
                "port":     port,
                "proto":    proto,
                "service":  p.get("name", SERVICE_NAMES.get(port, "unknown")),
                "product":  product,
                "version":  version,
                "version_str": version_str,
                "script_output": {},
                "cves":     [],       # preenchido pelo módulo cve_lookup
                "risk":     None,     # preenchido pelo módulo risk
            }

            # Saída dos scripts NSE (ex: http-title, ssh-hostkey, etc.)
            if "script" in p:
                port_data["script_output"] = dict(p["script"])

            host_data["ports"].append(port_data)
            service_display = SERVICE_NAMES.get(port, p.get("name", "?"))
            print(f"  {GREEN}[+]{RESET} {host}:{port}/{proto:<3}  "
                  f"{CYAN}{service_display:<14}{RESET}  {GRAY}{version_str[:50]}{RESET}")

    return host_data


def run_scan(targets: list[str], ports: str, full: bool, timeout: int) -> list[dict]:
    """
    Executa o scan em todos os alvos e retorna lista de dicts de hosts.
    """
    nm   = nmap.PortScanner()
    args = build_nmap_args(ports, full, timeout)

    results = []
    target_str = " ".join(targets)

    print(f"  {GRAY}nmap {args} -Pn {target_str}{RESET}\n")

    try:
        nm.scan(hosts=target_str, arguments=args + " -Pn")
    except nmap.PortScannerError as e:
        print(f"  {RED}[ERRO] Nmap: {e}{RESET}")
        print(f"  {YELLOW}Certifique-se que o nmap está instalado: sudo apt install nmap{RESET}")
        return []
    except Exception as e:
        print(f"  {RED}[ERRO] {e}{RESET}")
        return []

    for host in nm.all_hosts():
        if nm[host].state() not in ("up", "unknown"):
            continue
        print(f"\n  {BOLD}Host: {CYAN}{host}{RESET}  [{nm[host].state()}]")
        host_data = parse_host(nm, host)
        results.append(host_data)

    # Se nmap achou hosts mas nenhuma porta aberta, inclui mesmo assim
    # para que o relatório mostre o host (com 0 portas)
    if not results:
        for host in nm.all_hosts():
            print(f"\n  {BOLD}Host: {CYAN}{host}{RESET}  [{nm[host].state()}] — sem portas abertas nas top 100")
            results.append({
                "ip": host, "hostname": "", "state": nm[host].state(),
                "os": None, "ports": [], "host_risk": "INFO", "risk_score": 0,
            })

    return results