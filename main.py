from scanner.port_scanner import scan_ports_fast
from scanner.banner_grabber import grab_http_banner
from scanner.parser import extrair_servico
from scanner.vuln_checker import buscar_vulnerabilidades
from scanner.host_discovery import read_arp_table
from scanner.mac_lookup import buscar_fabricante
from reporter.html_report import gerar_html
from reporter.json_report import gerar_json
from reporter.csv_report import gerar_csv
import time


def escanear(alvo, porta_inicial, porta_final):
    """Scan REAL: escaneia um alvo de verdade e narra cada etapa."""
    print(f"[*] Iniciando varredura de portas em {alvo} (portas {porta_inicial}-{porta_final})...")
    portas_abertas = scan_ports_fast(alvo, porta_inicial, porta_final)
    print(f"[+] {len(portas_abertas)} porta(s) aberta(s): {portas_abertas}\n")

    resultados = []

    for porta in portas_abertas:
        print(f"[*] Analisando porta {porta}...")
        banner = grab_http_banner(alvo, porta)

        servico = None
        cves = []

        if banner:
            servico = extrair_servico(banner)
            if servico:
                print(f"    [+] Serviço identificado: {servico}")
                print(f"    [*] Consultando NVD por vulnerabilidades...")
                cves = buscar_vulnerabilidades(servico)
                if cves:
                    print(f"    [!] {len(cves)} vulnerabilidade(s) encontrada(s)!")
                else:
                    print(f"    [-] Nenhuma vulnerabilidade conhecida.")
            else:
                print(f"    [-] Serviço não identificado (banner sem versão).")
        else:
            print(f"    [-] Sem resposta de banner.")

        resultados.append({
            "porta": porta,
            "banner": banner,
            "servico": servico,
            "cves": cves
        })

    print(f"\n[*] Varredura concluída.")
    return resultados


# Hosts fictícios pra demonstração. O cenário é simulado, mas as
# vulnerabilidades são buscadas de verdade na NVD.
HOSTS_DEMO = [
    {
        "ip": "192.168.0.100",
        "mac": "00:1a:11:3c:4d:5e",      
        "descricao": "Servidor Web",
        "servicos": [
            {"porta": 22, "servico": "OpenSSH 8.9"},
            {"porta": 80, "servico": "Apache 2.4.49"},
            {"porta": 443, "servico": "nginx 1.18.0"},
        ]
    },
    {
        "ip": "192.168.0.101",
        "mac": "2c:dc:d7:8a:9b:0c",        
        "descricao": "Servidor de Banco de Dados",
        "servicos": [
            {"porta": 3306, "servico": "MySQL 5.5.0"},
            {"porta": 6379, "servico": "Redis 5.0.0"},
        ]
    },
    {
        "ip": "192.168.0.102",
        "mac": "b8:27:eb:1f:2a:3b",
        "descricao": "Servidor FTP",
        "servicos": [
            {"porta": 21, "servico": "ProFTPD 1.3.5"},
            {"porta": 22, "servico": "OpenSSH 7.4"},
        ]
    },
]


def escanear_demo(host):
    """
    Scan de DEMONSTRAÇÃO de um host fictício. O cenário é simulado, mas as
    vulnerabilidades e descrições são buscadas de verdade na NVD.
    """
    resultados = []

    print(f"[*] Iniciando varredura de portas em {host['ip']} ({host['descricao']})...")
    time.sleep(1)
    portas = sorted(s["porta"] for s in host["servicos"])
    print(f"[+] {len(portas)} porta(s) aberta(s): {portas}\n")
    time.sleep(1)

    for s in host["servicos"]:
        porta = s["porta"]
        servico = s["servico"]

        print(f"[*] Analisando porta {porta}...")
        time.sleep(0.6)
        print(f"    [+] Serviço identificado: {servico}")
        time.sleep(0.5)
        print(f"    [*] Consultando NVD por vulnerabilidades...")

        cves = buscar_vulnerabilidades(servico)   # busca REAL na NVD
        time.sleep(0.4)

        if cves:
            print(f"    [!] {len(cves)} vulnerabilidade(s) encontrada(s)!")
            for v in cves:
                print(f"        - [{v['score']}] {v['id']}")
        else:
            print(f"    [-] Nenhuma vulnerabilidade conhecida.")

        resultados.append({
            "porta": porta,
            "banner": f"Server: {servico}",
            "servico": servico,
            "cves": cves
        })
        time.sleep(0.4)

    print(f"\n[*] Varredura concluída.")
    return resultados


def listar_hosts():
    """Mostra os aparelhos da rede (com fabricante) e devolve a lista."""
    aparelhos = read_arp_table()

    print("[*] Descobrindo aparelhos na rede (via ARP)...\n")
    for i, ap in enumerate(aparelhos, start=1):
        fabricante = buscar_fabricante(ap["mac"])
        ap["fabricante"] = fabricante

        print(f"  {i}. {ap['ip']:<16} {ap['mac']:<18} {fabricante}")
        time.sleep(1)   # pausa de 1s pra respeitar o rate limit da API

    return aparelhos


if __name__ == "__main__":
    aparelhos = listar_hosts()

    print("\n  0. [MODO DEMONSTRAÇÃO — cenário fictício, CVEs reais da NVD]")

    while True:
        escolha = input("\nEscolha o número do aparelho (ou 0 para demo): ")
        try:
            numero = int(escolha)

            if numero == 0:
                # MODO DEMO: lista os hosts fictícios e deixa escolher
                print(f"\n{'='*50}")
                print(f"  MODO DEMONSTRAÇÃO — escolha um host:")
                print(f"{'='*50}\n")
                for i, h in enumerate(HOSTS_DEMO, start=1):
                    print(f"  {i}. {h['ip']:<16} {h['mac']:<18} {h['descricao']}")

                while True:
                    escolha_demo = input("\nEscolha o host de demo: ")
                    try:
                        n = int(escolha_demo)
                        if n < 1:
                            print("Número inválido.")
                            continue
                        host_demo = HOSTS_DEMO[n - 1]
                        break
                    except ValueError:
                        print("Digite um número.")
                    except IndexError:
                        print("Não existe host com esse número.")

                alvo = f"{host_demo['ip']} (DEMO - {host_demo['descricao']})"
                print(f"\n{'='*50}")
                print(f"  ALVO: {host_demo['ip']} — {host_demo['descricao']}")
                print(f"{'='*50}\n")
                resultados = escanear_demo(host_demo)
                break

            if numero < 1:
                print("Número inválido.")
                continue

            # MODO REAL
            alvo = aparelhos[numero - 1]["ip"]
            print(f"\n{'='*50}")
            print(f"  ALVO SELECIONADO: {alvo}")
            print(f"{'='*50}\n")
            resultados = escanear(alvo, 1, 1024)
            break

        except ValueError:
            print("Isso não é um número. Digite o número da lista.")
        except IndexError:
            print("Não existe aparelho com esse número.")

    print(f"\n[*] Gerando relatórios...")
    nome_base = f"relatorio_{alvo}".replace(" ", "_").replace("(", "").replace(")", "")
    html = gerar_html(alvo, resultados)
    with open(f"{nome_base}.html", "w", encoding="utf-8") as f:
        f.write(html)
    gerar_json(alvo, resultados, f"{nome_base}.json")
    gerar_csv(resultados, f"{nome_base}.csv")

    print(f"[+] Relatórios salvos:")
    print(f"    - {nome_base}.html  (visual)")
    print(f"    - {nome_base}.json  (dados estruturados)")
    print(f"    - {nome_base}.csv   (planilha)")