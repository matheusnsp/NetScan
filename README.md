# 🔍 NetScan — Network Scanner & Vulnerability Reporter

> Ferramenta de linha de comando (CLI) em Python que automatiza o reconhecimento inicial de um teste de penetração: descoberta de hosts, varredura de portas, **identificação de serviço por protocolo**, cruzamento com CVEs da NVD/NIST **por CPE**, **priorização com CISA KEV + EPSS** e **checagens de má configuração**.

> ⚠️ **Use apenas em redes próprias ou com autorização explícita do responsável.** Varredura não autorizada é ilegal. Veja o [aviso legal](#️-aviso-legal).

---

## ✅ Pré-requisitos

| Item | Detalhe |
|---|---|
| Python | **3.9 ou mais novo** (`python3 --version`) |
| Sistema | Linux ou macOS. Windows não é testado |
| Privilégios | **Não precisa de root/sudo.** A varredura usa conexões TCP comuns, sem Scapy nem libpcap |
| Internet | Só na máquina do scanner, e só para CVE/KEV/EPSS (NVD, CISA, FIRST). Com `--no-vuln`, roda 100% offline |
| Chave da NVD | Opcional (ver [Chave da NVD](#-chave-da-nvd-opcional)) |

**macOS:** o `python3` que vem com o sistema (`/usr/bin/python3`, Command Line Tools) é o 3.9 e funciona; testado no macOS 27. Um Python mais novo também serve (`brew install python@3.12` ou o instalador do python.org).

---

## 🚀 Instalação (≈ 3 minutos)

```bash
git clone https://github.com/matheusnsp/NetScan.git
cd NetScan
python3 -m venv venv
source venv/bin/activate          # no Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Para rodar os testes: `pip install -r requirements-dev.txt && python -m pytest -q`.

> Sempre ative o venv (`source venv/bin/activate`) antes de usar. Se aparecer `ModuleNotFoundError: No module named 'rich'`, o venv não está ativo.

---

## ⏱️ Primeiro teste em 2 minutos (sem tocar em nenhuma rede)

```bash
# 1) Demonstração: cenário fictício, só consulta a NVD (precisa de internet)
python3 main.py --demo

# 2) Um alvo local seu: sobe um servidor web na própria máquina e varre só ele
python3 -m http.server 8000 &
python3 main.py 127.0.0.1 -p 8000 --no-vuln
kill %1          # encerra o servidor (no mesmo terminal em que foi iniciado)
```

Os relatórios (`relatorio_*.html` e `.json`) são gravados na pasta atual. Para outra pasta, use `-o`.

---

## 📌 O que o NetScan faz

1. **Descoberta de hosts:** numa faixa (CIDR) ou lista, faz um **ping TCP** (portas 22, 80, 443, 445, 3389) e só varre quem responde. Uma resposta "porta fechada" (RST) já prova que o host existe. No modo interativo, lista os aparelhos que **já estão no cache ARP** do sistema. Isso **não envia pacotes ARP**: mostra só máquinas com quem o seu computador já conversou.
2. **Varredura de portas:** TCP *connect*, concorrente (ThreadPoolExecutor), **só nas portas pedidas**. Perfis `top100` (100 portas), `all`, faixas, listas ou combinações (`top100,2222`).
3. **Detecção de serviço:** fingerprinting por protocolo (SSH, FTP, SMTP, MySQL/MariaDB, Redis, MongoDB, HTTP/HTTPS com TLS), mesmo em portas fora do padrão.
4. **Checagem de vulnerabilidades:** cruza serviço e versão com a NVD **por CPE**, com cache local, ritmo controlado (respeita o limite da NVD) e novas tentativas. **Se a NVD falhar, o relatório avisa** ("checagem de CVE incompleta") em vez de mostrar "0 CVEs".
5. **Priorização:** enriquece cada CVE com **CISA KEV** (exploração ativa) e **EPSS** (probabilidade de exploração) e calcula um **score de risco** por host. A lista por porta mostra os 25 CVEs mais prioritários (KEV → EPSS → CVSS) e informa o total (`--max-cves 0` mostra todos).
6. **Má configuração:** Redis/MongoDB sem autenticação, FTP anônimo, Telnet exposto, TLS 1.0/1.1 aceito, certificado expirado, cabeçalhos de segurança HTTP ausentes.
7. **Diff entre scans:** compara com o scan anterior do mesmo alvo (portas que abriram ou fecharam, serviço/versão alterado, CVEs e KEV novos, nova má configuração).
8. **Relatórios:** HTML (resumo executivo, "corrija primeiro", mudanças), JSON, **JSON Lines (para SIEM)** e CSV.

> As checagens de má configuração são **de leitura e não-destrutivas**: verificam a *postura* do serviço (exige senha? o certificado é válido?) sem alterar dados nem explorar nada. No Redis, os comandos enviados são `INFO server` (metadados) e `PING`.

---

## 🖥️ Como usar

### Modo CLI

```bash
# Um host, 100 portas mais comuns, relatórios HTML + JSON
python3 main.py 172.30.99.2

# Uma faixa de laboratório, restrita ao escopo autorizado, no máximo 50 conexões/s
python3 main.py 172.30.99.0/28 --scope 172.30.99.0/24 --rate 50

# Lista de alvos de um arquivo, portas específicas, sem consultar CVE
python3 main.py alvos.txt -p 22,80,443 --no-vuln

# JSON Lines para ingestão em SIEM (Wazuh/Splunk/Elastic)
python3 main.py 172.30.99.2 -f jsonl -o ./relatorios

# Monitoramento: rode o mesmo alvo de novo; a partir do 2º scan aparece
# "o que mudou desde o último"
python3 main.py 172.30.99.2
```

| Flag | Descrição | Padrão |
|---|---|---|
| `-p, --ports` | `top100` \| `all` \| `1-1024` \| `80,443` \| `top100,2222` | `top100` |
| `-f, --format` | `html,json,jsonl,csv` (combináveis; outros valores dão erro) | `html,json` |
| `-o, --output` | diretório de saída | `.` (pasta atual) |
| `-t, --timeout` | timeout por conexão, em segundos (> 0) | `1.5` |
| `--threads` | conexões simultâneas (1 a 1000) | `100` |
| `--rate` | máximo de conexões novas por segundo | sem limite |
| `--scope` | faixas autorizadas; alvos fora delas são **recusados** | — |
| `--no-discovery` | não faz o ping TCP antes de varrer faixas/listas | — |
| `--max-cves` | CVEs listados por porta (0 = todos) | `25` |
| `-y, --yes` | confirma sem perguntar (alvo em IP público ou mais de 256 endereços) | — |
| `--no-vuln` | só portas/serviços, sem NVD/KEV/EPSS | — |
| `--no-config` | pula as checagens de má configuração | — |
| `--no-diff` | não compara com o scan anterior | — |
| `--state-dir` | onde guardar os snapshots do diff | `~/.local/share/netscan/snapshots` |
| `--log` | arquivo de log | — |
| `-q, --quiet` | menos saída no terminal | — |

Proteções embutidas: aviso de uso autorizado a cada execução; **confirmação obrigatória** para IP público ou faixa grande (sem terminal interativo, exige `--yes`); recusa de alvos fora do `--scope`.

### Modo interativo

```bash
python3 main.py
```

Pede uma **faixa autorizada** (ex.: `172.30.99.0/24`), lista só os aparelhos dessa faixa que estão no cache ARP e pede confirmação antes de varrer as portas 1-1024. A consulta do fabricante pelo MAC (em `api.macvendors.com`, que **envia os MACs para a internet**) só é feita se você aceitar. Usa `arp -a`, `ip neigh` ou `/proc/net/arp`, o que existir no sistema.

---

## 🔑 Chave da NVD (opcional)

Sem chave, a NVD aceita cerca de **5 consultas a cada 30 s**, e o NetScan espera 6 s entre consultas novas. Com chave, o limite é de cerca de 50 a cada 30 s. Consultas repetidas usam o cache local (24 h, em `~/.cache/netscan`).

1. Peça a chave grátis em <https://nvd.nist.gov/developers/request-an-api-key>.
2. Crie o arquivo `.env` na pasta do projeto **com um editor** (para a chave não ficar no histórico do shell), contendo:
   ```
   NVD_API_KEY=sua-chave-aqui
   ```
O `.env` está no `.gitignore`. A chave só é enviada no cabeçalho HTTPS para `services.nvd.nist.gov`; ela não aparece em logs, cache nem relatórios.

---

## 📡 O que a ferramenta gera na rede

Útil para testar detecção (Wazuh, IDS) e para saber o que está fazendo.

| Etapa | Tráfego | Vai para |
|---|---|---|
| Descoberta (faixas/listas) | Até 5 conexões TCP por IP (portas 22, 80, 443, 445, 3389), parando na primeira resposta; host inexistente só gera ARP "who-has". O IP da própria máquina é ignorado | alvos |
| Cache ARP (modo interativo) | Nenhum pacote ARP. DNS reverso (PTR) por aparelho e, se você aceitar, HTTPS para `api.macvendors.com` | seu DNS / internet |
| Varredura de portas | **Handshake TCP completo** (SYN → SYN/ACK → ACK → FIN) por porta aberta; SYN → RST por porta fechada. Cerca de **6 mil conexões/s** com 100 threads na mesma rede; limite com `--rate` | alvos |
| Detecção de serviço e checagens | 1 a 3 conexões extras por porta aberta: leitura do banner, `HEAD / HTTP/1.0` sem User-Agent, `INFO server`/`PING` no Redis, handshakes TLS (incluindo um que oferece só TLS 1.0/1.1) e login `anonymous` no FTP | alvos |
| CVE / KEV / EPSS | HTTPS para `services.nvd.nist.gov`, `www.cisa.gov` (≈1,5 MB, 1×/dia) e `api.first.org` | internet (nunca o alvo) |

**No alvo Linux:** por padrão nada registra portas fechadas. Os serviços abertos registram o contato (o sshd, por exemplo, `kex_exchange_identification: Connection closed by remote host`; o nginx, `"HEAD / HTTP/1.0" 200 ... "-"`). A varredura em si só aparece com log de firewall: uma regra `iptables ... -j LOG` gera uma linha por porta sondada. O `ufw` registra só bloqueios e limita a taxa de log; use `ufw logging medium` para ver mais. Em containers Docker, regras LOG só chegam ao kernel log com `sysctl net.netfilter.nf_log_all_netns=1` no host.

---

## 🧪 Laboratório Docker isolado (sugestão)

No macOS e no Windows, abra o Docker Desktop antes (`open -a Docker` no Mac).

**1. Crie a rede e os alvos.** `--internal` impede que os alvos saiam para a internet.

```bash
docker network create --internal --subnet 172.30.99.0/28 netscan-lab
docker run -d --name lab-nginx --network netscan-lab --ip 172.30.99.2 nginx:1.18.0
docker run -d --name lab-redis --network netscan-lab --ip 172.30.99.4 redis:5.0.0
```

**2a. Linux:** o host alcança os IPs dos containers diretamente.

```bash
python3 main.py 172.30.99.0/28 --scope 172.30.99.0/28
```

**2b. macOS e Windows (Docker Desktop):** os containers rodam numa VM e o host **não** alcança esses IPs. Rode o NetScan num container ligado à rede do lab. O `docker build` instala as dependências usando a rede padrão, que tem internet; a varredura roda depois na rede `--internal`.

```bash
docker build -t netscan .
mkdir -p relatorios
docker run --rm -it --user "$(id -u):$(id -g)" --network netscan-lab \
  -v "$PWD/relatorios":/out netscan \
  172.30.99.0/28 --scope 172.30.99.0/28 --no-vuln -o /out
```

- Dentro da rede `--internal` o container não tem internet, por isso o `--no-vuln`. Para ter CVEs, rode no Linux pelo host (passo 2a).
- O `-it` exige um terminal. Em scripts ou CI, use só `-i`.
- O IP do próprio scanner é ignorado automaticamente na descoberta. O gateway da rede (`.1`) aparece como host: no Linux ele é a própria máquina; no Docker Desktop, é a VM do Docker.

**3. Limpeza:**

```bash
docker rm -f lab-nginx lab-redis && docker network rm netscan-lab
```

---

## 🛠️ Solução de problemas

| Sintoma | Causa e solução |
|---|---|
| `ModuleNotFoundError: No module named 'rich'` | venv não ativado: `source venv/bin/activate` |
| `Cannot connect to the Docker daemon` / `docker.sock: no such file` | Docker Desktop fechado: abra com `open -a Docker` e espere alguns segundos |
| `TypeError: unsupported operand type(s) for \|` | Python antigo (< 3.9): instale um mais novo |
| `⚠ NVD indisponível (HTTP 429/503...)` | Limite de requisições ou NVD fora do ar. Espere e rode de novo (o cache guarda o que deu certo) ou configure a chave |
| "Nenhum host respondeu" numa faixa | Firewall descartando tudo: tente `--no-discovery` |
| Modo interativo não lista ninguém | O cache ARP só tem máquinas já contatadas: use a CLI com a faixa (`python3 main.py 172.30.99.0/28`) |
| Varredura lenta com `--threads` alto, ou o aviso "porta(s) não puderam ser testadas" | O sistema limita os arquivos abertos (no macOS, 256 por padrão). Reduza `--threads` ou rode `ulimit -n 4096`, que vale só para o terminal atual |

---

## 🗂️ Estrutura

```
NetScan/
├── main.py                  # CLI + menu interativo + orquestração
├── scanner/
│   ├── port_scanner.py      # varredura concorrente, limitador de taxa, ping TCP (descoberta)
│   ├── host_discovery.py    # leitura do cache ARP (arp -a / ip neigh / /proc/net/arp)
│   ├── service_detect.py    # fingerprinting de serviço por protocolo
│   ├── vuln_checker.py      # NVD por CPE, com cache, ritmo e status de falha
│   ├── enrich.py            # CISA KEV + EPSS
│   ├── misconfig.py         # checagens de má configuração (não-destrutivas)
│   ├── scoring.py           # priorização e resumo executivo
│   ├── snapshot.py          # diff entre scans (monitoramento)
│   ├── targets.py           # perfis de porta, alvos (CIDR/arquivo), escopo
│   └── mac_lookup.py        # fabricante pelo MAC
├── reporter/                # HTML, JSON/JSONL, CSV
├── Dockerfile               # imagem para rodar dentro de um lab Docker
├── tests/                   # pytest (offline: só 127.0.0.1 e dublês)
├── requirements.txt         # dependências de execução
└── requirements-dev.txt     # + pytest
```

---

## 📊 Relatório

O HTML traz, no topo, um **resumo executivo**: score de risco do host, contagem por severidade, total de CVEs em KEV e de achados de configuração, e a tabela **"Corrija primeiro"** (ordenada por KEV → EPSS → CVSS). Se a consulta à NVD falhar, aparece um aviso de **checagem incompleta** e o risco fica "INDETERMINADO" em vez de "OK". No JSON Lines, essa falha vira um evento `{"tipo": "aviso", "aviso": "checagem_cve_incompleta"}`.

Severidade por cor (CVSS): 🔴 crítico (9.0–10) · 🟠 alto (7.0–8.9) · 🟡 médio (4.0–6.9) · 🟢 baixo (<4.0).

> CVEs são casados por versão anunciada. Distribuições Linux corrigem falhas sem mudar a versão (backport), e alguns CVEs dependem de configuração (ex.: HTTP/2 ligado). Trate a lista como ponto de partida para verificação.

---

## 🧰 Tecnologias

`socket`, `ssl`, `concurrent.futures`, `ipaddress`, `argparse`, `logging` (biblioteca padrão) · `requests` (NVD, KEV, EPSS, macvendors) · `rich` (terminal) · `python-dotenv` · `cryptography` (leitura de certificados) · `pytest`.

Fontes de dados: **NVD/NIST** (CVE por CPE), **CISA KEV** (exploração ativa), **FIRST EPSS** (probabilidade de exploração).

---

## ⚠️ Aviso legal

> Ferramenta **exclusivamente para fins educacionais e testes em redes próprias ou com autorização explícita do proprietário**. O uso não autorizado em redes de terceiros é **ilegal**. O autor não se responsabiliza por usos indevidos. O score de risco é um auxílio de **triagem**, não um laudo.

---

## 🗺️ Melhorias futuras

- [x] Diff entre scans (alertar porta/serviço/CVE que surgiu desde a última varredura)
- [x] GitHub Actions rodando a suíte
- [x] Dockerfile
- [ ] Exportação para PDF
- [ ] Varredura UDP
- [ ] Interface web (Flask/FastAPI)

---

## 📄 Licença

MIT.
