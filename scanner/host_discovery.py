import socket
import subprocess
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

def is_host_alive(host: str, port: int, timeout: float = 1.0) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        return result == 0

def discover_hosts(base_ip: str, timeout: float = 1.0, max_threads: int = 254) -> list[str]:
    vivos = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(is_host_alive, f"{base_ip}.{i}", 80, timeout): f"{base_ip}.{i}"
            for i in range(1, 255)
        }
        for future in as_completed(futures):      # <- DENTRO do with
            ip = futures[future]
            if future.result():
                vivos.append(ip)
    return sorted(vivos)

def read_arp_table() -> list[dict]:
    """
    Lê a tabela ARP do sistema (via 'arp -a') e extrai os aparelhos
    que têm MAC de verdade. Não precisa de root.

    Retorna uma lista de dicionários: [{"ip": ..., "mac": ...}, ...]
    """
    resultado = subprocess.run(["arp", "-a"], capture_output=True, text=True)
    saida = resultado.stdout

    padrao = r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]+)"
    resultados = re.findall(padrao, saida)

    # Monta uma lista de dicionários, descartando endereços que não são
    # aparelhos de verdade: broadcast (.255) e multicast (224.x.x.x).
    aparelhos = []
    for ip, mac in resultados:
        if ip.endswith(".255"):       # broadcast, não é um aparelho
            continue                  # "continue" pula pro próximo item do loop
        if mac == "ff:ff:ff:ff:ff:ff":  # MAC de broadcast
            continue
        if ip.startswith("224."):     # faixa multicast, não é aparelho
            continue
        aparelhos.append({"ip": ip, "mac": mac})

    return aparelhos