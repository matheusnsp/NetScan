import socket
import subprocess
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner.mac_lookup import normalizar_mac


def reverse_dns(ip: str, timeout: float = 1.0) -> str | None:
    """Tenta descobrir o nome do host por DNS reverso. None se não resolver.

    Muitos aparelhos de rede local respondem com um nome útil
    (ex.: 'Galaxy-S23.lan', 'amazon-abc.lan'), dando uma pista do dispositivo.
    """
    antigo = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        nome = socket.gethostbyaddr(ip)[0]
        # Ignora quando o PTR só devolve o próprio IP.
        return None if nome == ip else nome
    except (OSError, socket.herror):
        return None
    finally:
        socket.setdefaulttimeout(antigo)


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

    # Regex por linha. Captura, quando houver: nome do host (antes do IP),
    # o IP, o MAC e a interface (o 'on en0' do macOS/BSD).
    #   ^(\S+)                -> grupo 1: nome do host no arp ('?' quando não há)
    #   \((IP)\) at (MAC)     -> grupos 2 e 3
    #   (?: on (\S+))?        -> grupo 4: interface, opcional
    padrao = re.compile(
        r"^(\S+) \((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]+)(?: on (\S+))?"
    )

    aparelhos = []
    for linha in saida.splitlines():
        m = padrao.match(linha.strip())
        if not m:
            continue
        nome_arp, ip, mac, interface = m.groups()
        mac = normalizar_mac(mac)

        if ip.endswith(".255") or ip.startswith("224."):
            continue                             # broadcast/multicast, não é aparelho
        if mac == "ff:ff:ff:ff:ff:ff":
            continue

        aparelhos.append({
            "ip": ip,
            "mac": mac,
            # Nome vindo do próprio arp (às vezes '?'), tratado no front.
            "hostname_arp": None if nome_arp in ("?", "") else nome_arp,
            "interface": interface,
        })

    return aparelhos