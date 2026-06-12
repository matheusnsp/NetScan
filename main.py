from scanner.port_scanner import scan_ports_fast
from scanner.banner_grabber import grab_http_banner
from scanner.parser import extrair_servico
from scanner.vuln_checker import buscar_vulnerabilidades


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


# Só roda o scan se o arquivo for executado direto (python3 main.py),
# não se for importado por outro arquivo.
if __name__ == "__main__":
    escanear("127.0.0.1", 1, 8100)