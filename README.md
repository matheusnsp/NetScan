# 🔍 NetScan — Network Scanner & Vulnerability Reporter

> Ferramenta de linha de comando (CLI) em Python que automatiza o reconhecimento inicial de um teste de penetração: descoberta de hosts, varredura de portas, **identificação de serviço por protocolo**, cruzamento com CVEs da NVD/NIST **por CPE**, **priorização com CISA KEV + EPSS** e **checagens de má configuração**.

Desenvolvido para fins **educacionais** e de **pentest autorizado**.

---

## 📌 O que o NetScan faz

1. **Descoberta de hosts** — aparelhos ativos via tabela ARP, com identificação de fabricante pelo MAC.
2. **Varredura de portas** — portas TCP abertas, concorrente (ThreadPoolExecutor). Perfis `top100`, `all` ou ranges/listas.
3. **Detecção de serviço** — fingerprinting por protocolo (SSH, FTP, SMTP, MySQL/MariaDB, Redis, MongoDB, HTTP/HTTPS com TLS), não só a linha `Server:` do HTTP.
4. **Checagem de vulnerabilidades** — cruza serviço+versão com a NVD **por CPE** (muito menos falso-positivo que busca por palavra-chave), com timeout, tratamento de rate limit e **cache local**.
5. **Priorização** — enriquece cada CVE com **CISA KEV** (exploração ativa) e **EPSS** (probabilidade de exploração), e calcula um **score de risco** por host.
6. **Má configuração** — Redis/MongoDB sem autenticação, FTP anônimo, Telnet exposto, TLS obsoleto/expirado, cabeçalhos de segurança HTTP ausentes.
7. **Relatórios** — HTML (com resumo executivo e "corrija primeiro"), JSON, **JSON Lines (para SIEM)** e CSV.

> As checagens de má configuração são **de leitura e não-destrutivas**: verificam a *postura* do serviço (exige senha? certificado válido?), sem alterar dados nem explorar nada — o equivalente a conferir se a porta está trancada.

---

## 🚀 Instalação

```bash
git clone https://github.com/matheusnsp/NetScan.git
cd NetScan
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
# (opcional) chave da NVD para limite de requisições maior:
echo "NVD_API_KEY=sua-chave-aqui" > .env
```

---

## 🖥️ Como usar

### Modo CLI (scriptável)

```bash
# Um host, 100 portas mais comuns, relatórios HTML + JSON
python3 main.py 192.168.0.10 --ports top100 --format html,json

# Uma sub-rede inteira, portas 1–1024
python3 main.py 192.168.0.0/24 --ports 1-1024

# Lista de alvos de um arquivo, portas específicas, sem consultar CVE
python3 main.py alvos.txt --ports 22,80,443 --no-vuln

# Saída JSON Lines para ingestão em SIEM (Wazuh/Splunk/Elastic)
python3 main.py 10.0.0.5 --format jsonl -o ./relatorios

# Demonstração (cenário fictício, CVEs reais da NVD)
python3 main.py --demo
```

Principais opções:

| Flag | Descrição | Padrão |
|---|---|---|
| `-p, --ports` | `top100` \| `all` \| `1-1024` \| `80,443,8080` | `top100` |
| `-f, --format` | `html,json,jsonl,csv` (combináveis) | `html,json` |
| `-o, --output` | diretório de saída | `.` |
| `-t, --timeout` | timeout por conexão (s) | `1.5` |
| `--threads` | threads de varredura | `100` |
| `--no-vuln` | só portas/serviços, sem NVD | — |
| `--no-config` | pula checagens de má configuração | — |
| `--log` | arquivo de log | — |
| `-q, --quiet` | menos saída no terminal | — |

### Modo interativo

Sem argumentos, cai no menu de sempre (scan real ou demonstração):

```bash
python3 main.py
```

---

## 🧪 Testes

```bash
pytest
```

A suíte cobre, offline: fingerprinting de serviço, montagem de CPE, priorização (KEV/EPSS), perfis de porta e resolução de alvos (CIDR/arquivo), e o **escape de HTML do relatório** (regressão de XSS).

---

## 🗂️ Estrutura

```
netscan/
├── main.py                  # CLI + menu interativo + orquestração
├── scanner/
│   ├── port_scanner.py      # varredura concorrente de portas
│   ├── service_detect.py    # fingerprinting de serviço por protocolo
│   ├── vuln_checker.py      # NVD por CPE, com cache e rate limit
│   ├── enrich.py            # CISA KEV + EPSS
│   ├── misconfig.py         # checagens de má configuração (não-destrutivas)
│   ├── scoring.py           # priorização e resumo executivo
│   ├── targets.py           # perfis de porta e alvos (CIDR/arquivo)
│   ├── host_discovery.py    # descoberta de hosts (ARP + TCP)
│   └── mac_lookup.py        # fabricante pelo MAC
├── reporter/
│   ├── html_report.py       # relatório HTML (com escape e resumo executivo)
│   ├── json_report.py       # JSON + JSON Lines (SIEM)
│   └── csv_report.py        # CSV (com severidade, KEV, EPSS)
├── tests/
└── requirements.txt
```

---

## 📊 Relatório

O HTML traz, no topo, um **resumo executivo**: score de risco do host, contagem por severidade, total de CVEs em KEV e de achados de configuração, e a tabela **"Corrija primeiro"** (ordenada por KEV → EPSS → CVSS). Cada CVE pode exibir os selos **KEV** e **EPSS**.

Severidade por cor (CVSS): 🔴 crítico (9.0–10) · 🟠 alto (7.0–8.9) · 🟡 médio (4.0–6.9) · 🟢 baixo (<4.0).

---

## 🧰 Tecnologias

`socket`, `ssl`, `concurrent.futures`, `ipaddress`, `argparse`, `logging` (biblioteca padrão) · `requests` (NVD, KEV, EPSS, macvendors) · `rich` (terminal) · `python-dotenv` · `pytest`.

Fontes de dados: **NVD/NIST** (CVE por CPE), **CISA KEV** (exploração ativa), **FIRST EPSS** (probabilidade de exploração).

---

## ⚠️ Aviso legal

> Ferramenta **exclusivamente para fins educacionais e testes em redes próprias ou com autorização explícita do proprietário**. O uso não autorizado em redes de terceiros é **ilegal**. O autor não se responsabiliza por usos indevidos. O score de risco é um auxílio de **triagem**, não um laudo.

---

## 🗺️ Melhorias futuras

- [ ] Diff entre scans (alertar porta/serviço que surgiu desde a última varredura)
- [ ] Exportação para PDF
- [ ] Varredura UDP
- [ ] Interface web (Flask/FastAPI)
- [ ] Dockerfile + GitHub Actions rodando a suíte

---

## 📄 Licença

MIT.
