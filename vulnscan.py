#!/usr/bin/env python3
"""
╦  ╦╦ ╦╦  ╔╗╔╔═╗╔═╗╔═╗╔╗╔
╚╗╔╝║ ║║  ║║║╚═╗║  ╠═╣║║║
 ╚╝ ╚═╝╩═╝╝╚╝╚═╝╚═╝╩ ╩╝╚╝
  Network Vulnerability Scanner
  by SrElliX — uso apenas em alvos autorizados
"""

import argparse
import datetime
import json
import sys
import os

from modules.scanner    import run_scan
from modules.cve_lookup import run_cve_lookup
from modules.risk       import calculate_risk
from modules.report     import generate_html_report, print_summary

RESET  = "\033[0m"
BOLD   = "\033[1m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
GRAY   = "\033[90m"
PURPLE = "\033[95m"


def banner():
    print(f"""{PURPLE}{BOLD}
╦  ╦╦ ╦╦  ╔╗╔╔═╗╔═╗╔═╗╔╗╔
╚╗╔╝║ ║║  ║║║╚═╗║  ╠═╣║║║
 ╚╝ ╚═╝╩═╝╝╚╝╚═╝╚═╝╩ ╩╝╚╝
  Network Vulnerability Scanner
  by SrElliX{RESET}
""")


def parse_targets(target_str: str) -> list[str]:
    """
    Aceita:
      - IP único:        192.168.1.1
      - Range CIDR:      192.168.1.0/24
      - Lista separada:  192.168.1.1,192.168.1.2
      - Hostname:        example.com
    """
    return [t.strip() for t in target_str.split(",") if t.strip()]


def main():
    parser = argparse.ArgumentParser(
        description="VulnScan — Network Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  sudo python3 vulnscan.py -t 192.168.1.1
  sudo python3 vulnscan.py -t 192.168.1.0/24
  sudo python3 vulnscan.py -t 192.168.1.1,192.168.1.5
  sudo python3 vulnscan.py -t 10.0.0.1 --ports 22,80,443,8080
  sudo python3 vulnscan.py -t 192.168.1.1 --full --output report.html
  sudo python3 vulnscan.py -t 192.168.1.1 --no-cve --output report.html
        """,
    )
    parser.add_argument("-t", "--target",  required=True,
                        help="IP, hostname, CIDR ou lista separada por vírgula")
    parser.add_argument("--ports",         default="top100",
                        help="Portas: 'top100', 'top1000', ou lista '22,80,443' (padrão: top100)")
    parser.add_argument("--full",          action="store_true",
                        help="Scan completo: OS detection + scripts NSE + top 1000 portas")
    parser.add_argument("--no-cve",        action="store_true",
                        help="Pular consulta à NVD API (mais rápido, sem internet)")
    parser.add_argument("--output", "-o",  default="vulnscan_report.html",
                        help="Arquivo de saída HTML (padrão: vulnscan_report.html)")
    parser.add_argument("--json",          help="Também salvar dados brutos em JSON")
    parser.add_argument("--timeout",       type=int, default=5,
                        help="Timeout de conexão em segundos (padrão: 5)")
    parser.add_argument("--rate-limit",    type=float, default=0.5,
                        help="Segundos entre chamadas à NVD API (padrão: 0.5)")

    args = parser.parse_args()

    # Root é necessário para SYN scan (modo --full)
    if args.full and os.geteuid() != 0:
        print(f"{RED}[ERRO] --full requer root (SYN scan). Execute com sudo.{RESET}")
        sys.exit(1)

    banner()

    targets   = parse_targets(args.target)
    timestamp = datetime.datetime.now()

    print(f"{BOLD}Alvos:{RESET}    {CYAN}{', '.join(targets)}{RESET}")
    print(f"{BOLD}Modo:{RESET}     {'Full (SYN + OS + NSE)' if args.full else 'Connect scan'}")
    print(f"{BOLD}Portas:{RESET}   {args.ports}")
    print(f"{BOLD}CVE lookup:{RESET} {'desativado' if args.no_cve else 'NVD API (NIST)'}")
    print(f"{BOLD}Output:{RESET}   {args.output}\n")

    # ── ETAPA 1: PORT SCAN ──────────────────────────────
    print(f"{PURPLE}{BOLD}[1/3] Executando scan de rede...{RESET}")
    scan_results = run_scan(targets, args.ports, args.full, args.timeout)

    if scan_results is None or (isinstance(scan_results, list) and len(scan_results) == 0):
        print(f"{RED}[ERRO] Nenhum host encontrado. Verifique conectividade, IP e se o nmap está instalado.{RESET}")
        sys.exit(1)

    total_hosts = len(scan_results)
    total_ports = sum(len(h["ports"]) for h in scan_results)
    print(f"{GREEN}[✓] {total_hosts} host(s) | {total_ports} porta(s) abertas encontradas{RESET}\n")

    # ── ETAPA 2: CVE LOOKUP ─────────────────────────────
    if not args.no_cve:
        print(f"{PURPLE}{BOLD}[2/3] Consultando NVD API para CVEs...{RESET}")
        scan_results = run_cve_lookup(scan_results, rate_limit=args.rate_limit)
        total_cves = sum(
            len(p.get("cves", []))
            for h in scan_results for p in h["ports"]
        )
        print(f"{GREEN}[✓] {total_cves} CVE(s) encontrados{RESET}\n")
    else:
        print(f"{YELLOW}[!] CVE lookup pulado (--no-cve){RESET}\n")

    # ── ETAPA 3: RISK SCORING ───────────────────────────
    scan_results = calculate_risk(scan_results)

    # ── ETAPA 4: RELATÓRIO ──────────────────────────────
    print(f"{PURPLE}{BOLD}[3/3] Gerando relatório HTML...{RESET}")

    report_data = {
        "meta": {
            "targets":   targets,
            "timestamp": timestamp.isoformat(),
            "date":      timestamp.strftime("%d/%m/%Y %H:%M"),
            "mode":      "Full" if args.full else "Connect",
            "ports":     args.ports,
            "cve_lookup": not args.no_cve,
            "tool":      "VulnScan by SrElliX",
        },
        "hosts": scan_results,
    }

    generate_html_report(report_data, args.output)
    print(f"{GREEN}[✓] Relatório salvo: {args.output}{RESET}")

    if args.json:
        with open(args.json, "w") as f:
            json.dump(report_data, f, indent=2, default=str)
        print(f"{GREEN}[✓] JSON salvo: {args.json}{RESET}")

    print()
    print_summary(scan_results)
    print(f"\n{GRAY}Scan concluído às {datetime.datetime.now().strftime('%H:%M:%S')}{RESET}\n")


if __name__ == "__main__":
    main()