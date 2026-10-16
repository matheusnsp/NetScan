"""
Resolução de alvos e perfis de portas para a CLI.

Permite que o alvo seja um IP, um hostname, um range CIDR (192.168.0.0/24) ou um
arquivo com um alvo por linha — como qualquer scanner sério aceita. E traduz
perfis de porta ("top100", "1-1024", "80,443,8080") em listas concretas.
"""
from __future__ import annotations

import ipaddress
from pathlib import Path

# As 100 portas TCP mais comuns (subset do nmap top-ports). Cobre o que aparece
# em 95% das redes sem varrer as 65535.
TOP_100 = [
    7, 20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 179, 199, 389,
    443, 445, 465, 514, 515, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025,
    1026, 1027, 1433, 1521, 1723, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 2181,
    2375, 2376, 3000, 3128, 3306, 3389, 3690, 4444, 4567, 5000, 5060, 5432, 5555,
    5601, 5672, 5900, 5901, 5984, 6379, 6443, 6667, 7001, 7077, 8000, 8008, 8009,
    8080, 8081, 8088, 8089, 8161, 8443, 8500, 8888, 9000, 9042, 9092, 9200, 9300,
    9418, 9999, 10000, 11211, 15672, 27017, 27018, 28017, 50000, 50070, 54321,
    5938, 102,
]


def parse_portas(spec: str) -> list[int]:
    """Converte um spec de portas em lista ordenada e sem repetição.

    Aceita: "top100", "all" (1-65535), "1-1024", "80,443,8080" ou combinações
    como "22,80,8000-8100".
    """
    spec = (spec or "").strip().lower()
    if spec in ("top", "top100"):
        return sorted(set(TOP_100))
    if spec in ("all", "full"):
        return list(range(1, 65536))

    portas: set[int] = set()
    for pedaco in spec.split(","):
        pedaco = pedaco.strip()
        if not pedaco:
            continue
        if "-" in pedaco:
            ini, fim = pedaco.split("-", 1)
            portas.update(range(int(ini), int(fim) + 1))
        else:
            portas.add(int(pedaco))
    portas = {p for p in portas if 1 <= p <= 65535}
    if not portas:
        raise ValueError(f"Spec de portas inválido: {spec!r}")
    return sorted(portas)


def parse_alvos(alvo: str) -> list[str]:
    """Expande o alvo em uma lista de IPs/hosts.

    - CIDR (192.168.0.0/24) -> todos os hosts da faixa
    - caminho de arquivo existente -> um alvo por linha (ignora vazias e #)
    - IP ou hostname -> lista de um elemento
    """
    alvo = alvo.strip()

    p = Path(alvo)
    if p.exists() and p.is_file():
        linhas = []
        for linha in p.read_text().splitlines():
            linha = linha.strip()
            if linha and not linha.startswith("#"):
                linhas.extend(parse_alvos(linha))
        return linhas

    if "/" in alvo:
        try:
            rede = ipaddress.ip_network(alvo, strict=False)
            return [str(ip) for ip in rede.hosts()]
        except ValueError:
            pass

    return [alvo]
