"""
Módulo CVE Lookup
Consulta a NVD API (National Vulnerability Database — NIST) para buscar
CVEs associados aos serviços e versões detectados pelo scan.

NVD API v2.0: https://nvd.nist.gov/developers/vulnerabilities
- Endpoint: GET https://services.nvd.nist.gov/rest/json/cves/2.0
- Parâmetros: keywordSearch, cvssV3SeverityMin, resultsPerPage
- Rate limit: 5 req/s sem API key, 50 req/s com API key (gratuita)
- Resposta: JSON com lista de CVEs, scores CVSS, descrições
"""

import requests
import time
import re

RESET  = "\033[0m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
GRAY   = "\033[90m"
BOLD   = "\033[1m"
CYAN   = "\033[96m"

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Produtos que não vale buscar na NVD (geram ruído sem resultado útil)
SKIP_PRODUCTS = {"", "tcpwrapped", "unknown", "filtered"}

# Severidade CVSS v3 → cor no terminal
SEVERITY_COLOR = {
    "CRITICAL": "\033[91m",   # vermelho
    "HIGH":     "\033[93m",   # amarelo
    "MEDIUM":   "\033[94m",   # azul
    "LOW":      "\033[92m",   # verde
    "NONE":     "\033[90m",   # cinza
}


def clean_product_name(product: str, version: str) -> str | None:
    """
    Normaliza o nome do produto para busca na NVD.
    Ex: "OpenSSH" → "openssh", "Apache httpd" → "apache http server"
    """
    if not product or product.lower() in SKIP_PRODUCTS:
        return None

    # Remove caracteres especiais, deixa só alfanumérico e espaços
    name = re.sub(r"[^\w\s]", " ", product.lower()).strip()

    # Normaliza nomes conhecidos
    normalizations = {
        "apache httpd":   "apache http server",
        "nginx":          "nginx",
        "openssh":        "openssh",
        "openssl":        "openssl",
        "microsoft iis":  "microsoft iis",
        "vsftpd":         "vsftpd",
        "proftpd":        "proftpd",
        "mysql":          "mysql",
        "mariadb":        "mariadb",
        "postgresql":     "postgresql",
        "redis":          "redis",
        "mongodb":        "mongodb",
        "elasticsearch":  "elasticsearch",
        "dovecot":        "dovecot",
        "postfix":        "postfix",
        "exim":           "exim",
        "samba":          "samba",
        "bind":           "bind",
        "tomcat":         "apache tomcat",
    }

    for key, normalized in normalizations.items():
        if key in name:
            name = normalized
            break

    return name if name else None


def query_nvd(keyword: str, version: str = "", max_results: int = 5) -> list[dict]:
    """
    Consulta a NVD API e retorna os CVEs mais relevantes.

    A API aceita busca por keyword livre — usamos o nome do produto.
    Se tiver versão, filtramos os resultados que mencionam a versão
    na descrição para reduzir falsos positivos.
    """
    params = {
        "keywordSearch":    keyword,
        "resultsPerPage":   max_results * 3,  # busca mais, filtra depois
        "startIndex":       0,
    }

    try:
        resp = requests.get(NVD_API_URL, params=params, timeout=10,
                           headers={"User-Agent": "VulnScan/1.0 (educational)"})
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.Timeout:
        return []
    except requests.exceptions.RequestException:
        return []
    except Exception:
        return []

    cves = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")

        # CVSS v3 score e severidade
        cvss_score    = None
        cvss_severity = "NONE"
        cvss_vector   = ""

        metrics = cve.get("metrics", {})
        # Tenta v3.1 primeiro, depois v3.0, depois v2.0
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metric_key in metrics and metrics[metric_key]:
                m = metrics[metric_key][0]
                if "cvssData" in m:
                    cvss_data     = m["cvssData"]
                    cvss_score    = cvss_data.get("baseScore")
                    cvss_severity = cvss_data.get("baseSeverity",
                                    m.get("baseSeverity", "NONE")).upper()
                    cvss_vector   = cvss_data.get("vectorString", "")
                    break

        # Descrição em inglês
        descriptions = cve.get("descriptions", [])
        description  = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"), ""
        )

        # Filtra por versão se disponível (reduz falsos positivos)
        if version and version not in description and version.split(".")[0] not in description:
            # Versão não mencionada — ainda inclui se score for alto
            if cvss_score is None or cvss_score < 7.0:
                continue

        # Data de publicação
        published = cve.get("published", "")[:10]

        # URLs de referência
        refs = [r.get("url", "") for r in cve.get("references", [])[:3]]

        cves.append({
            "id":          cve_id,
            "score":       cvss_score,
            "severity":    cvss_severity,
            "vector":      cvss_vector,
            "description": description[:300] + ("..." if len(description) > 300 else ""),
            "published":   published,
            "refs":        refs,
        })

        if len(cves) >= max_results:
            break

    # Ordena por score decrescente
    return sorted(cves, key=lambda x: x["score"] or 0, reverse=True)


def run_cve_lookup(hosts: list[dict], rate_limit: float = 0.5) -> list[dict]:
    """
    Para cada porta de cada host, busca CVEs se o produto for identificado.
    Atualiza hosts in-place e retorna a lista modificada.
    """
    queried  = {}   # cache: evita consultas duplicadas
    total    = 0
    skipped  = 0

    for host in hosts:
        for port in host["ports"]:
            product = port.get("product", "")
            version = port.get("version", "")
            keyword = clean_product_name(product, version)

            if not keyword:
                skipped += 1
                continue

            # Cache para não repetir a mesma consulta
            cache_key = f"{keyword}:{version}"
            if cache_key in queried:
                port["cves"] = queried[cache_key]
                continue

            print(f"  {GRAY}Buscando CVEs: {keyword} {version}...{RESET}", end=" ", flush=True)

            cves = query_nvd(keyword, version)
            queried[cache_key] = cves
            port["cves"] = cves
            total += len(cves)

            if cves:
                # Mostra o CVE mais crítico encontrado
                top = cves[0]
                col = SEVERITY_COLOR.get(top["severity"], RESET)
                print(f"{col}{top['id']} ({top['score']} {top['severity']}){RESET}")
            else:
                print(f"{GRAY}nenhum CVE encontrado{RESET}")

            # Respeita rate limit da API (sem API key: 5 req/s)
            time.sleep(rate_limit)

    print(f"\n  Portas sem produto identificado (puladas): {skipped}")
    return hosts
