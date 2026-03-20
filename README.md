<div align="center">

```
╦  ╦╦ ╦╦  ╔╗╔╔═╗╔═╗╔═╗╔╗╔
╚╗╔╝║ ║║  ║║║╚═╗║  ╠═╣║║║
 ╚╝ ╚═╝╩═╝╝╚╝╚═╝╚═╝╩ ╩╝╚╝
  Network Vulnerability Scanner
  by SrElliX
```

**VulnScan** — scanner de vulnerabilidades de rede com relatório HTML profissional

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux-orange?style=flat-square&logo=linux)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Educational-purple?style=flat-square)
![Lines](https://img.shields.io/badge/Lines_of_code-1066-informational?style=flat-square)
![NVD](https://img.shields.io/badge/CVEs-NVD%2FNIST-red?style=flat-square)

> *"Encontra vulnerabilidades. Gera relatório. Apresenta para o cliente."*

</div>

---

## Índice

- [Sobre o projeto](#sobre-o-projeto)
- [Como funciona](#como-funciona)
- [Estrutura do projeto](#estrutura-do-projeto)
- [Requisitos](#requisitos)
- [Instalação](#instalação)
- [Como usar](#como-usar)
- [Módulos](#módulos)
  - [Scanner](#scanner)
  - [CVE Lookup](#cve-lookup)
  - [Risk Scoring](#risk-scoring)
  - [Report](#report)
- [Exemplos de saída](#exemplos-de-saída)
- [Arquitetura do código](#arquitetura-do-código)
- [Flags e argumentos](#flags-e-argumentos)
- [Aviso legal](#aviso-legal)
- [Próximos passos](#próximos-passos)
- [Referências técnicas](#referências-técnicas)

---

## Sobre o projeto

**VulnScan** é uma ferramenta de varredura de vulnerabilidades de rede desenvolvida em Python, que combina o poder do **Nmap** com a base de dados oficial de CVEs do governo americano (**NVD/NIST**) para gerar relatórios HTML profissionais — no estilo das ferramentas comerciais como Nessus e OpenVAS.

O projeto foi construído com fins educacionais para demonstrar como ferramentas de pentest profissionais funcionam por dentro: orquestração de ferramentas externas, consumo de APIs REST governamentais, scoring de risco baseado em CVSS e geração de relatórios com template engine.

**O que o VulnScan faz:**

- Escaneia portas TCP com detecção de serviço e versão via Nmap
- Executa scripts NSE para fingerprinting adicional (HTTP title, SSH keys, etc.)
- Consulta a NVD API do NIST para buscar CVEs associados a cada serviço detectado
- Calcula severidade com base no CVSS score (Critical / High / Medium / Low)
- Detecta riscos intrínsecos de exposição (Telnet, RDP, Redis, MongoDB sem auth, etc.)
- Gera relatório HTML com dashboard, tabela de portas, CVEs linkados e output dos scripts NSE
- Exporta dados brutos em JSON para integração com outras ferramentas

---

## Como funciona

```
┌─────────────────────────────────────────────────────────────┐
│                     PIPELINE DO VULNSCAN                    │
│                                                             │
│  Alvo (IP / CIDR / hostname)                                │
│         │                                                   │
│         ▼                                                   │
│  ┌─────────────────────────────────────────┐                │
│  │  MÓDULO 1 — Scanner (python-nmap)       │                │
│  │                                         │                │
│  │  nmap -sT -sV -sC -Pn --top-ports 100  │                │
│  │       │                                 │                │
│  │       ├── portas abertas                │                │
│  │       ├── versão do serviço (banner)    │                │
│  │       ├── OS detection (modo full)      │                │
│  │       └── scripts NSE (http-title...)   │                │
│  └───────────────────┬─────────────────────┘                │
│                      │                                      │
│         ┌────────────┴────────────┐                         │
│         ▼                         ▼                         │
│  ┌─────────────────┐   ┌──────────────────────┐             │
│  │  MÓDULO 2       │   │  MÓDULO 3            │             │
│  │  CVE Lookup     │   │  Risk Scoring        │             │
│  │                 │   │                      │             │
│  │  NVD API/NIST   │   │  CVSS score → sev.   │             │
│  │  keyword search │   │  portas de risco     │             │
│  │  filtra versão  │   │  configs inseguras   │             │
│  └────────┬────────┘   └──────────┬───────────┘             │
│           └────────────┬──────────┘                         │
│                        ▼                                    │
│  ┌─────────────────────────────────────────┐                │
│  │  MÓDULO 4 — Report (Jinja2)             │                │
│  │                                         │                │
│  │  template HTML → dashboard + tabelas    │                │
│  │  exporta também JSON bruto              │                │
│  └─────────────────────────────────────────┘                │
└─────────────────────────────────────────────────────────────┘
```

### Por que python-nmap?

O `python-nmap` é um wrapper Python sobre o Nmap: ele monta o comando, executa como subprocesso, captura o XML de saída e devolve um dicionário Python já estruturado. Isso significa que você tem todo o poder do Nmap (o melhor scanner de rede do mundo) com a ergonomia do Python para processar os resultados.

### Por que a NVD API?

A NVD *(National Vulnerability Database)* do NIST é o banco de dados oficial de vulnerabilidades do governo americano. Todo CVE publicado em qualquer lugar do mundo passa pela NVD. A API é gratuita, pública e retorna dados estruturados com CVSS score, descrição, referências e data de publicação — exatamente o que precisamos para classificar severidade automaticamente.

### O que é CVSS?

O CVSS *(Common Vulnerability Scoring System)* é o padrão global de pontuação de vulnerabilidades, de 0 a 10:

| Score | Severidade | Cor |
|-------|-----------|-----|
| 9.0 – 10.0 | Critical | Vermelho |
| 7.0 – 8.9 | High | Laranja |
| 4.0 – 6.9 | Medium | Amarelo |
| 0.1 – 3.9 | Low | Verde |
| 0.0 | None / Info | Cinza |

---

## Estrutura do projeto

```
vulscan/
│
├── vulnscan.py              ← ponto de entrada, CLI, orquestração
│
└── modules/
    ├── __init__.py
    ├── scanner.py           ← wrapper python-nmap, parsing de resultados
    ├── cve_lookup.py        ← consulta NVD API, filtragem por versão
    ├── risk.py              ← CVSS scoring, risco intrínseco de portas
    └── report.py            ← template Jinja2, geração HTML + JSON
```

**Linhas de código por módulo:**

| Arquivo | Linhas | Responsabilidade |
|---------|--------|-----------------|
| `report.py` | 355 | Template HTML Jinja2 + geração do relatório |
| `cve_lookup.py` | 210 | NVD API, rate limiting, filtragem por versão |
| `risk.py` | 169 | CVSS scoring, risco de exposição, risco NSE |
| `scanner.py` | 174 | python-nmap wrapper, parsing de hosts e portas |
| `vulnscan.py` | 157 | CLI argparse, orquestração do pipeline |

---

## Requisitos

| Requisito | Versão |
|-----------|--------|
| Python | 3.10 ou superior |
| Nmap | 7.0 ou superior |
| Sistema operacional | Linux (qualquer distro) |
| Privilégios | root para `--full` (SYN scan + OS detection) |
| Conexão com internet | necessária para CVE lookup via NVD API |

**Dependências Python:**

| Biblioteca | Versão | Para que serve |
|-----------|--------|---------------|
| `python-nmap` | 0.7.1+ | Wrapper sobre o Nmap |
| `jinja2` | 3.1+ | Template engine para o HTML |
| `requests` | 2.32+ | Requisições HTTP para a NVD API |

---

## Instalação

```bash
# Clone o repositório
git clone https://github.com/SrElliX/vulscan.git
cd vulscan

# Instala o Nmap no sistema
sudo apt install nmap -y

# Cria e ativa o ambiente virtual (recomendado)
python3 -m venv .venv
source .venv/bin/activate

# Instala as dependências Python
pip install python-nmap jinja2 requests

# Confirma que tudo está OK
python3 -c "import nmap, jinja2, requests; print('dependências OK')"
```

> **Importante:** toda vez que abrir um terminal novo, ative o venv antes de rodar:
> ```bash
> source .venv/bin/activate
> ```
> O prompt muda para `(.venv)` quando está ativo.

---

## Como usar

### Uso básico

```bash
# Scan de um host (connect scan, top 100 portas, com CVE lookup)
python3 vulnscan.py -t 192.168.1.1

# Abre o relatório gerado no navegador
firefox vulnscan_report.html &
```

### Com saída personalizada

```bash
# Define nome do arquivo de saída
python3 vulnscan.py -t 192.168.1.1 --output meu_report.html

# Salva também em JSON
python3 vulnscan.py -t 192.168.1.1 --output report.html --json dados.json
```

### Scan completo (requer root)

```bash
# SYN scan + OS detection + scripts NSE + versão intensiva
sudo python3 vulnscan.py -t 192.168.1.1 --full --output report.html
```

### Alvos múltiplos e ranges

```bash
# Range CIDR (varre toda a subrede)
python3 vulnscan.py -t 192.168.1.0/24 --output rede.html

# Múltiplos IPs separados por vírgula
python3 vulnscan.py -t 192.168.1.1,192.168.1.5,192.168.1.10

# Hostname
python3 vulnscan.py -t example.com --output report.html
```

### Portas personalizadas

```bash
# Top 1000 portas (mais lento, mais completo)
python3 vulnscan.py -t 192.168.1.1 --ports top1000

# Portas específicas
python3 vulnscan.py -t 192.168.1.1 --ports 22,80,443,8080,3306
```

### Sem CVE lookup (mais rápido)

```bash
# Útil para redes sem internet ou quando quer só o scan
python3 vulnscan.py -t 192.168.1.1 --no-cve --output report.html
```

---

## Módulos

### Scanner

**Arquivo:** `modules/scanner.py`

Usa `python-nmap` para orquestrar o Nmap e parsear os resultados em um formato uniforme consumido pelos outros módulos.

**Modos de scan:**

| Flag | Tipo | Root? | Quando usar |
|------|------|-------|-------------|
| padrão | TCP Connect (`-sT`) | Não | Scan rápido, redes internas |
| `--full` | SYN Scan (`-sS`) | Sim | Mais preciso e furtivo, pentest real |

**Connect scan vs SYN scan:**

No TCP Connect scan (`-sT`), o scanner completa o handshake TCP inteiro (SYN → SYN-ACK → ACK). É mais lento e deixa rastro nos logs do alvo, mas não requer privilégios de root. O SYN scan (`-sS`) envia só o SYN e analisa a resposta sem completar o handshake — mais rápido, mais furtivo, mas requer root para criar raw sockets.

**O que o scanner coleta por porta:**

```python
{
    "port":          80,
    "proto":         "tcp",
    "service":       "http",
    "product":       "Apache httpd",
    "version":       "2.4.51",
    "version_str":   "Apache httpd 2.4.51",
    "script_output": {"http-title": "Welcome", "http-methods": "GET POST"},
    "cves":          [],   # preenchido pelo cve_lookup
    "risk":          None, # preenchido pelo risk
}
```

---

### CVE Lookup

**Arquivo:** `modules/cve_lookup.py`

Consulta a **NVD API v2.0** do NIST para cada serviço identificado pelo scanner. A API aceita busca por keyword — usamos o nome normalizado do produto (ex: `"Apache httpd"` → `"apache http server"`).

**Endpoint consultado:**

```
GET https://services.nvd.nist.gov/rest/json/cves/2.0
    ?keywordSearch=apache+http+server
    &resultsPerPage=15
```

**Filtragem por versão:**

Depois de receber os CVEs, o módulo filtra os que mencionam a versão detectada na descrição — reduz falsos positivos. CVEs com score ≥ 7.0 passam pelo filtro mesmo sem a versão mencionada, por serem críticos demais para ignorar.

**Rate limiting:**

A NVD API permite 5 requisições/segundo sem API key. O módulo respeita isso com `time.sleep()` configurável via `--rate-limit`. Com uma API key gratuita o limite sobe para 50 req/s.

**Normalização de nomes:**

```python
# Exemplos de normalização automática
"Apache httpd"   → "apache http server"
"OpenSSH"        → "openssh"
"Microsoft IIS"  → "microsoft iis"
"Tomcat"         → "apache tomcat"
```

---

### Risk Scoring

**Arquivo:** `modules/risk.py`

Calcula o nível de risco de cada porta e de cada host a partir de três fontes:

**1. CVEs encontrados**

O CVSS score mais alto entre os CVEs de uma porta define a severidade daquela porta.

**2. Risco intrínseco de exposição**

Algumas portas são perigosas por natureza quando expostas publicamente, independente de CVEs:

| Porta | Serviço | Risco |
|-------|---------|-------|
| 23 | Telnet exposto | HIGH |
| 445 | SMB (risco EternalBlue) | CRITICAL |
| 3389 | RDP exposto | HIGH |
| 5900 | VNC exposto | HIGH |
| 6379 | Redis sem auth | HIGH |
| 27017 | MongoDB sem auth | HIGH |
| 9200 | Elasticsearch exposto | HIGH |
| 2375 | Docker API exposta | CRITICAL |

**3. Scripts NSE**

Scripts que detectam configurações inseguras específicas:

| Script NSE | Indica | Risco |
|-----------|--------|-------|
| `ftp-anon` | FTP anônimo habilitado | HIGH |
| `http-methods` | Métodos HTTP perigosos | MEDIUM |
| `smb-security-mode` | SMB sem assinatura | MEDIUM |

**Risco do host:**

O risco do host é a severidade máxima encontrada em qualquer uma de suas portas. Hosts são ordenados por `risk_score` (soma ponderada das severidades) no relatório — os mais críticos aparecem primeiro.

---

### Report

**Arquivo:** `modules/report.py`

Usa **Jinja2** para renderizar um template HTML embutido no código. O resultado é um relatório dark-themed com visual profissional, similar ao output do Nessus e OpenVAS.

**O que o relatório HTML contém:**

- Header com alvo, data, modo de scan e assinatura
- Cards de sumário: hosts, portas abertas, total de CVEs, contagem por severidade
- Cards por host colapsáveis (clica para expandir/recolher)
- Tabela de portas ordenada por severidade, com badge de risco colorido
- Para cada CVE: ID linkado para NVD, score, badge de severidade, descrição e referências
- Findings de risco intrínseco (exposição, configuração insegura)
- Output dos scripts NSE em seções expansíveis
- Footer com data, assinatura e link para NVD/NIST

**Tecnologias do template:**

```
Jinja2 {{ variáveis }}        → dados do Python injetados no HTML
Jinja2 {% for %} {% if %}     → loops e condicionais no template
CSS variables (--critical)    → tema dark consistente
<details> / <summary>         → seções expansíveis sem JavaScript
```

---

## Exemplos de saída

### Terminal

```
╦  ╦╦ ╦╦  ╔╗╔╔═╗╔═╗╔═╗╔╗╔
╚╗╔╝║ ║║  ║║║╚═╗║  ╠═╣║║║
 ╚╝ ╚═╝╩═╝╝╚╝╚═╝╚═╝╩ ╩╝╚╝
  Network Vulnerability Scanner
  by SrElliX

Alvos:    192.168.1.10
Modo:     Connect scan
Portas:   top100
CVE lookup: NVD API (NIST)
Output:   report.html

[1/3] Executando scan de rede...
  nmap -sT -sV --version-light -sC --top-ports 100 --open -T4 -Pn 192.168.1.10

  Host: 192.168.1.10  [up]
  [+] 192.168.1.10:22/tcp   SSH     OpenSSH 7.9p1
  [+] 192.168.1.10:80/tcp   HTTP    Apache httpd 2.4.38
  [+] 192.168.1.10:3306/tcp MySQL   MySQL 5.7.32
[✓] 1 host(s) | 3 porta(s) abertas encontradas

[2/3] Consultando NVD API para CVEs...
  Buscando CVEs: openssh... CVE-2023-38408 (9.8 CRITICAL)
  Buscando CVEs: apache http server... CVE-2021-41773 (7.5 HIGH)
  Buscando CVEs: mysql... CVE-2021-2307 (6.1 MEDIUM)
[✓] 8 CVE(s) encontrados

  HOST             RISCO      PORTAS   CVEs
  ────────────────────────────────────────────────────
  192.168.1.10     CRITICAL   3        8

[3/3] Gerando relatório HTML...
[✓] Relatório salvo: report.html

Resumo:
  Hosts scaneados:  1
  Portas abertas:   3
  CVEs encontrados: 8

Top CVEs críticos:
  CVE-2023-38408  score 9.8  192.168.1.10:22 (SSH)
  CVE-2021-41773  score 7.5  192.168.1.10:80 (HTTP)
```

### Relatório HTML

O relatório gerado abre no navegador com visual dark profissional:

- Dashboard de cards coloridos por severidade no topo
- Cada host em um card expansível com badge de risco
- Tabela de portas com CVEs linkados diretamente para o NVD
- Scripts NSE em seções `<details>` expansíveis

---

## Arquitetura do código

```
vulnscan.py  (orquestrador)
│
├── parse_targets()      — aceita IP, CIDR, hostname, lista
├── main()
│   ├── [1/3] run_scan()         → lista de hosts com portas
│   ├── [2/3] run_cve_lookup()   → adiciona CVEs em cada porta
│   │         calculate_risk()   → adiciona severidade em cada porta/host
│   └── [3/3] generate_html_report() → salva report.html
│             print_summary()    → sumário no terminal
│
├── modules/scanner.py
│   ├── build_nmap_args()   — monta flags do nmap por modo/portas
│   ├── parse_host()        — extrai portas, versões, scripts NSE
│   └── run_scan()          — executa python-nmap, itera hosts
│
├── modules/cve_lookup.py
│   ├── clean_product_name() — normaliza "Apache httpd" → "apache http server"
│   ├── query_nvd()          — GET na NVD API, filtra por versão
│   └── run_cve_lookup()     — itera portas, aplica cache, rate limit
│
├── modules/risk.py
│   ├── score_to_severity()  — CVSS float → "CRITICAL"/"HIGH"/...
│   ├── calculate_port_risk() — CVEs + exposição + NSE → risco da porta
│   ├── calculate_host_risk() — agrega portas → risco e score do host
│   └── calculate_risk()     — itera todos os hosts, ordena por risco
│
└── modules/report.py
    ├── HTML_TEMPLATE        — template Jinja2 embutido (dark theme)
    ├── generate_html_report() — renderiza template com os dados
    └── print_summary()      — sumário colorido no terminal
```

---

## Flags e argumentos

```
uso: vulnscan.py [-h] -t TARGET [--ports PORTS] [--full] [--no-cve]
                 [--output OUTPUT] [--json JSON]
                 [--timeout TIMEOUT] [--rate-limit RATE_LIMIT]
```

| Argumento | Tipo | Padrão | Descrição |
|-----------|------|--------|-----------|
| `-t`, `--target` | string | **obrigatório** | IP, CIDR, hostname ou lista separada por vírgula |
| `--ports` | string | `top100` | `top100`, `top1000` ou lista `22,80,443` |
| `--full` | flag | — | SYN scan + OS detection + NSE intensivo (requer root) |
| `--no-cve` | flag | — | Pula consulta à NVD API |
| `--output`, `-o` | string | `vulnscan_report.html` | Arquivo HTML de saída |
| `--json` | string | — | Também salva dados brutos em JSON |
| `--timeout` | inteiro | `5` | Timeout de conexão em segundos |
| `--rate-limit` | float | `0.5` | Segundos entre chamadas à NVD API |

---

## Aviso legal

> ⚠️ **Este projeto é estritamente educacional.**
>
> O uso de scanners de vulnerabilidade **sem autorização explícita** é ilegal em muitos países e pode violar legislações como:
> - **Brasil:** Lei nº 12.737/2012 (Lei Carolina Dieckmann) e LGPD
> - **EUA:** Computer Fraud and Abuse Act (CFAA)
> - **Europa:** Computer Misuse Act e regulações similares
>
> Use o VulnScan **somente em:**
> - Sua própria infraestrutura e redes
> - Ambientes de laboratório (VMs isoladas, redes internas de teste)
> - Alvos para os quais você possui **autorização por escrito**
> - Plataformas de prática como HackTheBox, TryHackMe ou VulnHub
>
> O autor não se responsabiliza por qualquer uso indevido desta ferramenta.

---

## Próximos passos

- [ ] API key da NVD para aumentar rate limit de 5 para 50 req/s
- [ ] Exportação em PDF do relatório HTML
- [ ] Suporte a UDP scan (`-sU`)
- [ ] Integração com Exploit-DB para buscar exploits por CVE
- [ ] Modo de comparação entre dois scans (detecta mudanças na rede)
- [ ] Scan agendado com notificação de novos CVEs por e-mail
- [ ] Interface web com Flask para rodar scans via browser
- [ ] Suporte a autenticação SSH para scan interno de servidores
- [ ] Plugin de detecção de versões desatualizadas de CMS (WordPress, Drupal)
- [ ] Integração com Metasploit para verificar exploitability automaticamente

---

## Referências técnicas

- [NVD API v2.0 — NIST](https://nvd.nist.gov/developers/vulnerabilities)
- [CVSS v3.1 Specification](https://www.first.org/cvss/specification-document)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [python-nmap Documentation](https://xael.org/pages/python-nmap-en.html)
- [Jinja2 Documentation](https://jinja.palletsprojects.com/)
- [RFC 793 — Transmission Control Protocol](https://www.rfc-editor.org/rfc/rfc793)
- [OWASP — Network Security Testing](https://owasp.org/www-project-web-security-testing-guide/)
- [CWE — Common Weakness Enumeration](https://cwe.mitre.org/)

---

<div align="center">

Feito por <a href="https://github.com/SrElliX">SrElliX</a> &nbsp;•&nbsp; Projeto educacional de cibersegurança

<sub>Use com responsabilidade. Scans só em alvos autorizados.</sub>

</div>
