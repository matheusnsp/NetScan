from scanner.port_scanner import scan_ports_fast
from scanner.banner_grabber import grab_http_banner
from scanner.parser import extrair_servico
from scanner.vuln_checker import buscar_vulnerabilidades
from scanner.host_discovery import read_arp_table
from reporter.html_report import gerar_html
import time
from scanner.mac_lookup import buscar_fabricante   # também no topo



def escanear(alvo, porta_inicial, porta_final):
    portas_abertas = scan_ports_fast(alvo, porta_inicial, porta_final)

    resultados = []

    for porta in portas_abertas:
        banner = grab_http_banner(alvo, porta)

        servico = None
        cves = []

        if banner:
            servico = extrair_servico(banner)
            if servico:
                cves = buscar_vulnerabilidades(servico)   # guarda em "cves"

        resultados.append({
            "porta": porta,
            "banner": banner,
            "servico": servico,
            "cves": cves
        })

    return resultados        # FORA do for — retorna depois de todas as portas

def listar_hosts():
    """Mostra os aparelhos da rede (com fabricante) e devolve a lista."""
    aparelhos = read_arp_table()

    print("Aparelhos encontrados na rede:\n")
    for i, ap in enumerate(aparelhos, start=1):
        # Busca o fabricante pelo MAC
        fabricante = buscar_fabricante(ap["mac"])
        ap["fabricante"] = fabricante           # guarda no dicionário também

        print(f"  {i}. {ap['ip']:<16} {ap['mac']:<18} {fabricante}")

        time.sleep(1)   # pausa de 1s pra respeitar o rate limit da API

    return aparelhos

# Só roda o scan se o arquivo for executado direto (python3 main.py),
# não se for importado por outro arquivo.
if __name__ == "__main__":
    aparelhos = listar_hosts()

    while True:
        escolha = input("\nEscolha o número do aparelho: ")
        try:
            numero = int(escolha)
            if numero < 1:
                print("Número inválido.")
                continue
            alvo = aparelhos[numero - 1]["ip"]
            break                          # escolha válida, sai do loop
        except ValueError:
            print("Isso não é um número. Digite o número da lista.")
        except IndexError:
            print("Não existe aparelho com esse número.")

    # Só chega aqui depois do break (escolha válida)
    print(f"\nEscaneando {alvo}...\n")
    resultados = escanear(alvo, 1, 1024)

    # Gera e salva o relatório
    html = gerar_html(alvo, resultados)
    nome_arquivo = f"relatorio_{alvo}.html"
    with open(nome_arquivo, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\nRelatório salvo em {nome_arquivo}")