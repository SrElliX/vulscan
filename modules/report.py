"""
Módulo Report
Usa Jinja2 para renderizar um template HTML profissional com os resultados.
O template é embutido no código (sem arquivo externo) para facilitar distribuição.
"""

import sys
from jinja2 import Environment, BaseLoader

RESET  = "\033[0m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
GRAY   = "\033[90m"
BOLD   = "\033[1m"

# ──────────────────────────────────────────────────────────────────────────────
# TEMPLATE HTML — Jinja2 inline
# Usa variáveis {{ }} e blocos {% %} do Jinja2
# ──────────────────────────────────────────────────────────────────────────────
HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VulnScan Report — {{ meta.targets | join(', ') }}</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg:       #0d1117;
    --surface:  #161b22;
    --surface2: #21262d;
    --border:   #30363d;
    --text:     #e6edf3;
    --muted:    #8b949e;
    --critical: #ff4444;
    --high:     #ff8c00;
    --medium:   #e3b341;
    --low:      #3fb950;
    --info:     #58a6ff;
    --none:     #8b949e;
    --font:     'Segoe UI', system-ui, -apple-system, sans-serif;
    --mono:     'Cascadia Code', 'Fira Code', 'JetBrains Mono', monospace;
  }
  body { background: var(--bg); color: var(--text); font-family: var(--font); font-size: 14px; line-height: 1.6; }
  a { color: var(--info); text-decoration: none; }
  a:hover { text-decoration: underline; }

  .header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 24px 32px; display: flex; align-items: center; justify-content: space-between; }
  .header-title { font-size: 20px; font-weight: 600; letter-spacing: -.3px; }
  .header-title span { color: var(--info); }
  .header-meta { font-size: 12px; color: var(--muted); text-align: right; }

  .container { max-width: 1200px; margin: 0 auto; padding: 24px 32px; }

  .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 28px; }
  .stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; text-align: center; }
  .stat-value { font-size: 28px; font-weight: 700; line-height: 1; margin-bottom: 4px; }
  .stat-label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .06em; }
  .stat-card.critical .stat-value { color: var(--critical); }
  .stat-card.high     .stat-value { color: var(--high); }
  .stat-card.medium   .stat-value { color: var(--medium); }
  .stat-card.low      .stat-value { color: var(--low); }
  .stat-card.info     .stat-value { color: var(--info); }

  .section-title { font-size: 13px; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: .08em; margin: 0 0 12px; padding-bottom: 8px; border-bottom: 1px solid var(--border); }

  .host-card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; margin-bottom: 20px; overflow: hidden; }
  .host-header { padding: 14px 18px; display: flex; align-items: center; gap: 14px; border-bottom: 1px solid var(--border); cursor: pointer; user-select: none; }
  .host-header:hover { background: var(--surface2); }
  .host-ip { font-family: var(--mono); font-size: 15px; font-weight: 600; }
  .host-hostname { font-size: 12px; color: var(--muted); }
  .host-os { font-size: 12px; color: var(--muted); margin-left: auto; }
  .badge { font-size: 11px; font-weight: 700; padding: 3px 9px; border-radius: 4px; letter-spacing: .04em; text-transform: uppercase; }
  .badge.CRITICAL { background: rgba(255,68,68,.15); color: var(--critical); border: 1px solid rgba(255,68,68,.3); }
  .badge.HIGH     { background: rgba(255,140,0,.15);  color: var(--high);     border: 1px solid rgba(255,140,0,.3); }
  .badge.MEDIUM   { background: rgba(227,179,65,.15); color: var(--medium);   border: 1px solid rgba(227,179,65,.3); }
  .badge.LOW      { background: rgba(63,185,80,.15);  color: var(--low);      border: 1px solid rgba(63,185,80,.3); }
  .badge.INFO, .badge.NONE { background: rgba(139,148,158,.1); color: var(--muted); border: 1px solid rgba(139,148,158,.2); }

  .host-body { padding: 0 18px 14px; }
  .ports-table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }
  .ports-table th { text-align: left; padding: 6px 10px; font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .06em; border-bottom: 1px solid var(--border); }
  .ports-table td { padding: 8px 10px; border-bottom: 1px solid rgba(48,54,61,.5); vertical-align: top; }
  .ports-table tr:last-child td { border-bottom: none; }
  .ports-table tr:hover td { background: var(--surface2); }
  .port-num { font-family: var(--mono); font-weight: 600; color: var(--info); }
  .version-str { font-family: var(--mono); font-size: 12px; color: var(--muted); }

  .cve-list { margin-top: 6px; }
  .cve-item { background: var(--surface2); border-radius: 6px; padding: 8px 10px; margin-bottom: 6px; border-left: 3px solid var(--border); }
  .cve-item.CRITICAL { border-left-color: var(--critical); }
  .cve-item.HIGH     { border-left-color: var(--high); }
  .cve-item.MEDIUM   { border-left-color: var(--medium); }
  .cve-item.LOW      { border-left-color: var(--low); }
  .cve-header { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
  .cve-id { font-family: var(--mono); font-size: 12px; font-weight: 600; }
  .cve-score { font-size: 11px; font-weight: 700; }
  .cve-desc { font-size: 12px; color: var(--muted); line-height: 1.4; }
  .cve-refs { margin-top: 4px; }
  .cve-refs a { font-size: 11px; color: var(--info); margin-right: 8px; }

  .finding-item { font-size: 12px; padding: 4px 0; color: var(--muted); }
  .finding-item.CRITICAL, .finding-item.HIGH { color: var(--high); }
  .finding-item.MEDIUM { color: var(--medium); }

  .nse-output { font-family: var(--mono); font-size: 11px; color: var(--muted); background: var(--bg); padding: 6px 8px; border-radius: 4px; margin-top: 4px; white-space: pre-wrap; word-break: break-all; }

  .footer { text-align: center; padding: 24px; font-size: 12px; color: var(--muted); border-top: 1px solid var(--border); margin-top: 32px; }

  details > summary { list-style: none; }
  details > summary::-webkit-details-marker { display: none; }
</style>
</head>
<body>

<div class="header">
  <div>
    <div class="header-title">Vuln<span>Scan</span> Report</div>
    <div style="font-size:13px;color:var(--muted);margin-top:2px;">{{ meta.targets | join(' · ') }}</div>
  </div>
  <div class="header-meta">
    <div>{{ meta.date }}</div>
    <div>Modo: {{ meta.mode }} | Portas: {{ meta.ports }}</div>
    <div style="margin-top:4px;">{{ meta.tool }}</div>
  </div>
</div>

<div class="container">

  {# ── SUMMARY CARDS ── #}
  {% set ns = namespace(critical=0, high=0, medium=0, low=0, total_cves=0, total_ports=0) %}
  {% for host in hosts %}
    {% for port in host.ports %}
      {% set ns.total_ports = ns.total_ports + 1 %}
      {% for cve in port.cves %}
        {% set ns.total_cves = ns.total_cves + 1 %}
        {% if cve.severity == 'CRITICAL' %}{% set ns.critical = ns.critical + 1 %}
        {% elif cve.severity == 'HIGH' %}{% set ns.high = ns.high + 1 %}
        {% elif cve.severity == 'MEDIUM' %}{% set ns.medium = ns.medium + 1 %}
        {% elif cve.severity == 'LOW' %}{% set ns.low = ns.low + 1 %}
        {% endif %}
      {% endfor %}
    {% endfor %}
  {% endfor %}

  <div class="summary-grid">
    <div class="stat-card info">
      <div class="stat-value">{{ hosts | length }}</div>
      <div class="stat-label">Hosts</div>
    </div>
    <div class="stat-card info">
      <div class="stat-value">{{ ns.total_ports }}</div>
      <div class="stat-label">Portas abertas</div>
    </div>
    <div class="stat-card info">
      <div class="stat-value">{{ ns.total_cves }}</div>
      <div class="stat-label">CVEs</div>
    </div>
    <div class="stat-card critical">
      <div class="stat-value">{{ ns.critical }}</div>
      <div class="stat-label">Critical</div>
    </div>
    <div class="stat-card high">
      <div class="stat-value">{{ ns.high }}</div>
      <div class="stat-label">High</div>
    </div>
    <div class="stat-card medium">
      <div class="stat-value">{{ ns.medium }}</div>
      <div class="stat-label">Medium</div>
    </div>
    <div class="stat-card low">
      <div class="stat-value">{{ ns.low }}</div>
      <div class="stat-label">Low</div>
    </div>
  </div>

  {# ── HOST CARDS ── #}
  <div class="section-title">Hosts analisados</div>

  {% for host in hosts %}
  <div class="host-card">
    <details open>
      <summary>
        <div class="host-header">
          <span class="badge {{ host.host_risk }}">{{ host.host_risk }}</span>
          <div>
            <div class="host-ip">{{ host.ip }}</div>
            {% if host.hostname %}<div class="host-hostname">{{ host.hostname }}</div>{% endif %}
          </div>
          {% if host.os %}
          <div class="host-os">{{ host.os.name }} ({{ host.os.accuracy }}% conf.)</div>
          {% endif %}
          <div style="margin-left:auto;font-size:12px;color:var(--muted);">
            {{ host.ports | length }} portas ·
            {{ host.ports | sum(attribute='cves') | length if false else
               host.ports | map(attribute='cves') | map('length') | sum }} CVEs
          </div>
        </div>
      </summary>

      <div class="host-body">
        <table class="ports-table">
          <thead>
            <tr>
              <th>Porta</th>
              <th>Serviço</th>
              <th>Versão</th>
              <th>Risco</th>
              <th>CVEs / Findings</th>
            </tr>
          </thead>
          <tbody>
            {% set sev_order = {'CRITICAL':4,'HIGH':3,'MEDIUM':2,'LOW':1,'INFO':0,'NONE':0} %}
            {% for port in host.ports | sort(attribute='port') | sort(reverse=True, attribute='cves') %}
            <tr>
              <td><span class="port-num">{{ port.port }}/{{ port.proto }}</span></td>
              <td>{{ port.service }}</td>
              <td><span class="version-str">{{ port.version_str[:60] }}</span></td>
              <td>
                {% if port.risk %}
                <span class="badge {{ port.risk.severity }}">{{ port.risk.severity }}</span>
                {% else %}
                <span class="badge NONE">—</span>
                {% endif %}
              </td>
              <td>
                {# CVEs #}
                {% if port.cves %}
                <div class="cve-list">
                  {% for cve in port.cves[:3] %}
                  <div class="cve-item {{ cve.severity }}">
                    <div class="cve-header">
                      <span class="cve-id">
                        <a href="https://nvd.nist.gov/vuln/detail/{{ cve.id }}" target="_blank">{{ cve.id }}</a>
                      </span>
                      <span class="badge {{ cve.severity }}">{{ cve.score }}</span>
                      <span class="badge {{ cve.severity }}">{{ cve.severity }}</span>
                      <span style="font-size:11px;color:var(--muted);">{{ cve.published }}</span>
                    </div>
                    <div class="cve-desc">{{ cve.description }}</div>
                    {% if cve.refs %}
                    <div class="cve-refs">
                      {% for ref in cve.refs[:2] %}
                      <a href="{{ ref }}" target="_blank">ref {{ loop.index }}</a>
                      {% endfor %}
                    </div>
                    {% endif %}
                  </div>
                  {% endfor %}
                  {% if port.cves | length > 3 %}
                  <div style="font-size:11px;color:var(--muted);padding:4px 0;">
                    + {{ port.cves | length - 3 }} CVEs adicionais (ver JSON)
                  </div>
                  {% endif %}
                </div>
                {% endif %}

                {# Findings de risco (exposição, NSE) #}
                {% if port.risk and port.risk.findings %}
                  {% for f in port.risk.findings %}
                    {% if f.type != 'CVE' %}
                    <div class="finding-item {{ f.severity }}">
                      [{{ f.type }}] {{ f.detail[:120] }}
                    </div>
                    {% endif %}
                  {% endfor %}
                {% endif %}

                {# NSE script output #}
                {% if port.script_output %}
                  {% for script, output in port.script_output.items() %}
                  <details style="margin-top:4px;">
                    <summary style="font-size:11px;color:var(--muted);cursor:pointer;">
                      NSE: {{ script }}
                    </summary>
                    <div class="nse-output">{{ output[:300] }}</div>
                  </details>
                  {% endfor %}
                {% endif %}
              </td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
    </details>
  </div>
  {% endfor %}

</div>

<div class="footer">
  Gerado por <strong>VulnScan by SrElliX</strong> em {{ meta.date }} ·
  Use apenas em alvos com autorização explícita ·
  CVEs via <a href="https://nvd.nist.gov" target="_blank">NVD / NIST</a>
</div>

</body>
</html>
"""


def generate_html_report(data: dict, output_path: str) -> None:
    """Renderiza o template Jinja2 e salva o HTML."""
    env      = Environment(loader=BaseLoader())
    template = env.from_string(HTML_TEMPLATE)
    html     = template.render(**data)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)


def print_summary(hosts: list[dict]) -> None:
    """Sumário final no terminal."""
    sev_color = {
        "CRITICAL": RED, "HIGH": YELLOW,
        "MEDIUM": "\033[94m", "LOW": GREEN, "INFO": GRAY, "NONE": GRAY,
    }

    total_cves   = sum(len(p.get("cves", [])) for h in hosts for p in h["ports"])
    total_ports  = sum(len(h["ports"]) for h in hosts)
    critical_cves = sum(
        1 for h in hosts for p in h["ports"]
        for c in p.get("cves", []) if c.get("severity") == "CRITICAL"
    )
    high_cves = sum(
        1 for h in hosts for p in h["ports"]
        for c in p.get("cves", []) if c.get("severity") == "HIGH"
    )

    print(f"{BOLD}Resumo:{RESET}")
    print(f"  Hosts scaneados:  {len(hosts)}")
    print(f"  Portas abertas:   {total_ports}")
    print(f"  CVEs encontrados: {total_cves}")
    if critical_cves:
        print(f"  {RED}{BOLD}Critical:{RESET}         {critical_cves}")
    if high_cves:
        print(f"  {YELLOW}High:{RESET}             {high_cves}")

    # Top CVEs mais críticos
    all_cves = [
        (c, h["ip"], p["port"], p["service"])
        for h in hosts for p in h["ports"]
        for c in p.get("cves", [])
        if c.get("score") and c["score"] >= 7.0
    ]
    all_cves.sort(key=lambda x: x[0]["score"], reverse=True)

    if all_cves:
        print(f"\n{BOLD}Top CVEs críticos:{RESET}")
        for cve, ip, port, service in all_cves[:5]:
            col = sev_color.get(cve["severity"], RESET)
            print(f"  {col}{cve['id']}{RESET}  score {cve['score']}  "
                  f"{GRAY}{ip}:{port} ({service}){RESET}")