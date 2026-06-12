from scanner.port_scanner import scan_ports_fast
from scanner.banner_grabber import grab_http_banner
from scanner.parser import extrair_servico
from scanner.vuln_checker import buscar_vulnerabilidades
from scanner.host_discovery import read_arp_table


def escanear(alvo, porta_inicial, porta_final):
    portas_abertas = scan_ports_fast(alvo, porta_inicial, porta_final)
    print(f"Portas abertas em {alvo}: {portas_abertas}")

    for porta in portas_abertas:
        banner = grab_http_banner(alvo, porta)

        if banner:
            servico = extrair_servico(banner)
            if servico:
                print(f"Porta {porta}: {servico}")
                vulns = buscar_vulnerabilidades(servico)

                if vulns:
                    for v in vulns:
                        print(f"    [{v['score']}] {v['id']}")
                else:
                    print(" Nenhum CVE encontrado.")

        print(f"\n--- Porta {porta} ---")
        print(banner)


def listar_hosts():
    """Mostra os aparelhos da rede e devolve a lista deles."""
    aparelhos = read_arp_table()

    print("Aparelhos encontrados na rede:\n")
    for i, ap in enumerate(aparelhos, start=1):
        print(f"  {i}. {ap['ip']:<16} {ap['mac']}")

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
    escanear(alvo, 1, 1024)