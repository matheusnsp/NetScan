import socket
import subprocess
import re
from concurrent.futures import ThreadPoolExecutor, as_completed


def is_host_alive(host: str, port: int, timeout: float = 1.0) -> bool:
    """
    Testa se um host está vivo tentando conectar numa porta.
    É o mesmo mecanismo do scan_port: se conecta, tem alguém ali.

    Limitação: só detecta hosts com ESSA porta aberta. Um aparelho
    vivo mas "calado" na porta testada passa despercebido.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)                    # sem timeout, trava em host que não responde
        result = s.connect_ex((host, port))      # (host, port) = tupla; connect_ex retorna 0 se conectou
        return result == 0                       # 0 = vivo (True); outro valor = sem resposta (False)


def discover_hosts(base_ip: str, timeout: float = 1.0, max_threads: int = 254) -> list[str]:
    """
    Varre uma rede /24 (ex: base_ip="192.168.0") testando todos os IPs
    de .1 a .254 EM PARALELO. Retorna lista ordenada dos IPs vivos.

    Mesmo padrão de threads do port scanner, mas aqui variamos o IP
    (não a porta): testamos a porta 80 fixa em cada um dos 254 endereços.
    """
    vivos = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        # Pra cada IP de .1 a .254, agenda um teste na porta 80.
        # Dicionário {future: ip} pra saber qual IP era cada resultado
        # (eles voltam fora de ordem).
        futures = {
            executor.submit(is_host_alive, f"{base_ip}.{i}", 80, timeout): f"{base_ip}.{i}"
            for i in range(1, 255)               # 255 pra incluir o .254 (range exclui o último)
        }
        # Colher resultados DENTRO do with (enquanto o pool está ativo).
        for future in as_completed(futures):
            ip = futures[future]                 # recupera o IP deste future pelo dicionário
            if future.result():                  # result() = o True/False do is_host_alive
                vivos.append(ip)
    return sorted(vivos)                         # ordena no fim (as_completed bagunça a ordem)


def read_arp_table() -> list[dict]:
    """
    Lê a tabela ARP do sistema (via 'arp -a') e extrai os aparelhos
    que têm MAC de verdade. Não precisa de root.

    Vantagem sobre discover_hosts: pega TODOS os aparelhos conhecidos,
    mesmo sem porta aberta. Limitação: só vê o que o sistema já tem em
    cache (aparelhos com quem o Mac conversou recentemente).

    Retorna uma lista de dicionários: [{"ip": ..., "mac": ...}, ...]
    """
    # subprocess.run executa o comando do sistema "arp -a".
    # capture_output=True: pega a saída em vez de imprimir na tela.
    # text=True: devolve como string (não bytes).
    resultado = subprocess.run(["arp", "-a"], capture_output=True, text=True)
    saida = resultado.stdout                     # o texto que o comando imprimiu

    # Regex que captura (IP) e (MAC) de cada linha. As linhas "incomplete"
    # não têm MAC válido, então nem casam com o padrão -> são ignoradas sozinhas.
    #   \(...\)        -> os parênteses literais em volta do IP
    #   (\d+\.\d+...)  -> grupo 1: captura o IP
    #   ([0-9a-fA-F:]+)-> grupo 2: captura o MAC
    padrao = r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]+)"
    resultados = re.findall(padrao, saida)       # lista de tuplas (ip, mac)

    # Monta uma lista de dicionários, descartando o que não é aparelho real:
    # broadcast (.255) e multicast (224.x.x.x).
    aparelhos = []
    for ip, mac in resultados:                   # desempacota cada tupla em ip e mac
        if ip.endswith(".255"):                  # broadcast, não é um aparelho
            continue                             # "continue" pula pro próximo item do loop
        if mac == "ff:ff:ff:ff:ff:ff":           # MAC de broadcast
            continue
        if ip.startswith("224."):                # faixa multicast, não é aparelho
            continue
        aparelhos.append({"ip": ip, "mac": mac})

    return aparelhos