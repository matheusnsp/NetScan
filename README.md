# 🔍 NetScan — Network Scanner & Vulnerability Reporter

> Ferramenta de linha de comando (CLI) em Python que automatiza as etapas iniciais de um teste de penetração: descoberta de hosts, varredura de portas, identificação de serviços e cruzamento com vulnerabilidades conhecidas (CVEs) da base do NIST.

Desenvolvido para fins **educacionais** e de **pentest autorizado**.

---

## 📌 O que o NetScan faz

O NetScan executa o fluxo de reconhecimento de um pentest de ponta a ponta:

1. **Descoberta de hosts** — identifica os aparelhos ativos na rede local (via tabela ARP) e tenta identificar o **fabricante** de cada um pelo endereço MAC.
2. **Varredura de portas** — detecta portas TCP abertas no alvo, de forma **concorrente** (rápida).
3. **Banner grabbing** — coleta informações dos serviços rodando nas portas abertas (incluindo versão, quando exposta).
4. **Checagem de vulnerabilidades** — cruza os serviços detectados com CVEs conhecidos consultando a **API pública da NVD/NIST**, retornando o ID, a severidade (CVSS) e a descrição de cada vulnerabilidade.
5. **Geração de relatórios** — exporta o resultado em **HTML** (visual, com severidade colorida), **JSON** (dados estruturados) e **CSV** (planilha).

---

## ✨ Destaques técnicos

- **Varredura concorrente** com `ThreadPoolExecutor` — escaneia mais de 1000 portas em segundos (tarefa I/O-bound, ideal para threads).
- **Integração real com a NVD** — autenticação por API key, tratamento de *rate limit* (HTTP 429) e navegação entre diferentes versões do CVSS (v3.1 e v2).
- **Identificação de fabricante por OUI** — consulta o MAC na base de fabricantes; lida graciosamente com *MAC randomization* (dispositivos modernos que ocultam o fabricante por privacidade).
- **Saída em múltiplos formatos** a partir de uma única estrutura de dados, com severidade codificada por cores no relatório HTML.
- **Tratamento robusto de falhas** — serviços silenciosos, banners sem versão, alvos sem CVE e erros de rede são tratados sem interromper a execução.
- **Testes automatizados** com `pytest` cobrindo as funções de processamento de dados.

---

## 🗂️ Estrutura do projeto

```
netscan/
├── main.py                  # Ponto de entrada e orquestração do fluxo
├── scanner/
│   ├── port_scanner.py      # Varredura de portas concorrente
│   ├── banner_grabber.py    # Coleta de banners (TCP e HTTP)
│   ├── parser.py            # Extração de serviço/versão dos banners
│   ├── host_discovery.py    # Descoberta de hosts (TCP ping + tabela ARP)
│   ├── vuln_checker.py      # Integração com a API da NVD/NIST
│   └── mac_lookup.py        # Identificação de fabricante pelo MAC
├── reporter/
│   ├── html_report.py       # Relatório HTML (severidade colorida)
│   ├── json_report.py       # Exportação JSON
│   └── csv_report.py        # Exportação CSV
├── tests/
│   ├── test_parser.py       # Testes da extração de serviço
│   └── test_reporter.py     # Testes da coloração por severidade
├── requirements.txt
└── README.md
```

---

## ⚙️ Pré-requisitos

- Python **3.10+**
- Sistema operacional **Linux** ou **macOS** (a leitura da tabela ARP usa o comando `arp` do sistema)
- (Opcional, recomendado) Uma chave de API gratuita da [NIST NVD](https://nvd.nist.gov/developers/request-an-api-key) — sem ela a API funciona, mas com limite de requisições mais baixo.

---

## 🚀 Instalação

```bash
# 1. Clone o repositório
git clone https://github.com/matheusnsp/NetScan.git
cd NetScan

# 2. Crie e ative um ambiente virtual
python3 -m venv venv
source venv/bin/activate        # Linux/macOS

# 3. Instale as dependências
pip install -r requirements.txt

# 4. (Opcional) Configure a chave da API da NVD
# crie um arquivo .env na raiz do projeto com a linha:
# NVD_API_KEY=sua-chave-aqui
```

---

## 🖥️ Como usar

Execute o programa:

```bash
python3 main.py
```

O NetScan vai:

1. Listar os aparelhos encontrados na rede (com IP, MAC e fabricante).
2. Pedir para você escolher um alvo pelo número.
3. Escanear o alvo escolhido, narrando cada etapa no terminal.
4. Gerar os relatórios (`relatorio_<ALVO>.html`, `.json` e `.csv`).

Abra o arquivo `.html` gerado no navegador para ver o relatório visual.

> **Modo demonstração:** digite `0` no menu para rodar um cenário de demonstração com hosts fictícios. As vulnerabilidades exibidas são consultadas de verdade na NVD — apenas o cenário (os hosts) é simulado.

---

## 🧪 Testes

O projeto inclui testes automatizados das funções de processamento:

```bash
pytest
```

---

## 📊 Exemplo de relatório

O relatório HTML apresenta:

- Um resumo executivo (total de portas abertas e de vulnerabilidades).
- Uma tabela com cada porta, o serviço identificado e os CVEs associados.
- CVEs codificados por cor conforme a severidade CVSS:
  - 🔴 **Crítico** (9.0–10.0)
  - 🟠 **Alto** (7.0–8.9)
  - 🟡 **Médio** (4.0–6.9)
  - 🟢 **Baixo** (< 4.0)

---

## 🧰 Tecnologias

| Biblioteca | Uso |
|---|---|
| `socket` | Varredura de portas e banner grabbing (biblioteca padrão) |
| `concurrent.futures` | Varredura concorrente com pool de threads |
| `requests` | Chamadas às APIs da NVD e de fabricantes |
| `python-dotenv` | Carregamento da chave de API a partir do `.env` |
| `subprocess` / `re` | Leitura e parsing da tabela ARP |
| `pytest` | Testes automatizados |

---

## ⚠️ Aviso legal

> Esta ferramenta foi desenvolvida **exclusivamente para fins educacionais e para testes em redes próprias ou com autorização explícita do proprietário**.
>
> O uso não autorizado em redes de terceiros é **ilegal** e pode resultar em penalidades criminais. O autor não se responsabiliza por usos indevidos.

---

## 🗺️ Status e melhorias futuras

**Implementado:**

- [x] Descoberta de hosts (TCP + ARP) com identificação de fabricante
- [x] Varredura de portas TCP concorrente
- [x] Banner grabbing (TCP e HTTP)
- [x] Integração com a API NVD/NIST (com API key e rate limit)
- [x] Relatórios em HTML, JSON e CSV
- [x] Testes automatizados

**Possíveis evoluções:**

- [ ] Exportação para PDF
- [ ] Varredura UDP
- [ ] Interface web (Flask/FastAPI)
- [ ] Sistema de logging em arquivo

---

## 📄 Licença

Distribuído sob a licença MIT.