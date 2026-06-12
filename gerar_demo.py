# gerar_demo.py
# Gera relatórios de DEMONSTRAÇÃO com dados fictícios, pra apresentar o projeto.
# Os dados abaixo são inventados — servem só pra mostrar o formato dos relatórios.

from reporter.html_report import gerar_html
from reporter.json_report import gerar_json
from reporter.csv_report import gerar_csv

# Cenário fictício: um servidor com vários serviços, alguns vulneráveis.
# Escolhi CVEs reais e variados pra exercitar TODAS as cores de severidade.
resultados_demo = [
    {
        "porta": 22,
        "banner": "SSH-2.0-OpenSSH_8.9",
        "servico": "OpenSSH 8.9",
        "cves": []                              # serviço sem vulnerabilidade conhecida
    },
    {
        "porta": 80,
        "banner": "Server: Apache/2.4.49",
        "servico": "Apache 2.4.49",
        "cves": [                               # CRÍTICO (vermelho, >= 9.0)
            {"id": "CVE-2021-41773", "score": 9.8,
             "descricao": "Path traversal no Apache 2.4.49 permitindo leitura de arquivos fora do diretório."},
            {"id": "CVE-2021-42013", "score": 9.8,
             "descricao": "Correção incompleta do CVE-2021-41773, ainda explorável."}
        ]
    },
    {
        "porta": 443,
        "banner": "Server: nginx/1.18.0",
        "servico": "nginx 1.18.0",
        "cves": [                               # ALTO (laranja, >= 7.0)
            {"id": "CVE-2021-23017", "score": 7.7,
             "descricao": "Vulnerabilidade no resolvedor DNS do nginx, possível corrupção de memória."}
        ]
    },
    {
        "porta": 3306,
        "banner": "Server: MySQL 5.5.0",
        "servico": "MySQL 5.5.0",
        "cves": [                               # MÉDIO (amarelo, >= 4.0)
            {"id": "CVE-2012-2122", "score": 5.1,
             "descricao": "Bypass de autenticação no MySQL sob certas condições."}
        ]
    },
    {
        "porta": 21,
        "banner": "220 ProFTPD 1.3.5",
        "servico": "ProFTPD 1.3.5",
        "cves": [                               # BAIXO (verde, < 4.0)
            {"id": "CVE-2017-7418", "score": 3.3,
             "descricao": "Falha de baixo impacto no tratamento de symlinks do ProFTPD."}
        ]
    }
]

alvo = "192.168.0.100 (DEMONSTRAÇÃO)"

# Gera os três formatos
html = gerar_html(alvo, resultados_demo)
with open("demo_relatorio.html", "w", encoding="utf-8") as f:
    f.write(html)

gerar_json(alvo, resultados_demo, "demo_relatorio.json")
gerar_csv(resultados_demo, "demo_relatorio.csv")

print("Relatórios de demonstração gerados:")
print("  demo_relatorio.html")
print("  demo_relatorio.json")
print("  demo_relatorio.csv")