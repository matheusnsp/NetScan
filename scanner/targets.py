"""
Resolução de alvos e perfis de portas para a CLI.

Permite que o alvo seja um IP, um hostname, um range CIDR (192.168.0.0/24) ou um
arquivo com um alvo por linha. E traduz perfis de porta ("top100", "1-1024",
"80,443,8080") em listas concretas.
"""
from __future__ import annotations

import ipaddress
import socket
from pathlib import Path

# As 100 portas TCP mais comuns (baseado no nmap top-ports + serviços de
# infraestrutura/DevOps). Cobre o que aparece na maioria das redes.
TOP_100 = [
    7, 20, 21, 22, 23, 25, 53, 80, 81, 102, 110, 111, 113, 135, 139, 143, 161,
    179, 199, 389, 443, 445, 465, 514, 515, 548, 554, 587, 631, 646, 873, 990,
    993, 995, 1025, 1026, 1027, 1433, 1521, 1723, 2049, 2082, 2083, 2086, 2087,
    2095, 2096, 2181, 2375, 2376, 3000, 3128, 3306, 3389, 3690, 4444, 4567,
    5000, 5060, 5432, 5555, 5601, 5672, 5900, 5901, 5938, 5984, 5985, 6379,
    6443, 6667, 7001, 7077, 8000, 8008, 8009, 8080, 8081, 8088, 8089, 8161,
    8443, 8500, 8888, 9000, 9042, 9092, 9200, 9300, 9418, 9999, 10000, 11211,
    15672, 27017, 27018, 28017, 50000, 50070, 54321,
]


def _porta(texto: str, spec: str) -> int:
    try:
        return int(texto.strip())
    except ValueError:
        raise ValueError(
            f"Spec de portas inválido: {spec!r} ('{texto.strip()}' não é número). "
            "Use top100, all, 1-1024 ou 22,80,443.") from None


def parse_portas(spec: str) -> list[int]:
    """Converte um spec de portas em lista ordenada e sem repetição.

    Aceita: "top100", "all" (1-65535), "1-1024", "80,443,8080" ou combinações
    como "22,80,8000-8100" e "top100,2222".
    """
    spec = (spec or "").strip().lower()
    portas: set[int] = set()
    for pedaco in spec.split(","):
        pedaco = pedaco.strip()
        if not pedaco:
            continue
        if pedaco in ("top", "top100"):
            portas.update(TOP_100)
        elif pedaco in ("all", "full"):
            portas.update(range(1, 65536))
        elif "-" in pedaco:
            ini, fim = pedaco.split("-", 1)
            ini, fim = _porta(ini, spec), _porta(fim, spec)
            if ini > fim:
                raise ValueError(f"Spec de portas inválido: {spec!r} (início maior que o fim).")
            portas.update(range(ini, fim + 1))
        else:
            portas.add(_porta(pedaco, spec))
    portas = {p for p in portas if 1 <= p <= 65535}
    if not portas:
        raise ValueError(f"Spec de portas inválido: {spec!r} (portas válidas: 1 a 65535).")
    return sorted(portas)


def parse_alvos(alvo: str) -> list[str]:
    """Expande o alvo em uma lista de IPs/hosts.

    - CIDR (192.168.0.0/24) -> todos os hosts da faixa
    - caminho de arquivo existente -> um alvo por linha (ignora vazias e #)
    - IP ou hostname -> lista de um elemento
    """
    if not alvo or not alvo.strip():
        raise ValueError("Informe um alvo (IP, hostname, CIDR ou arquivo).")
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
        except ValueError:
            raise ValueError(f"Faixa CIDR inválida: {alvo!r}") from None
        if rede.version != 4:
            raise ValueError("Só IPv4 é suportado por enquanto.")
        hosts = [str(ip) for ip in rede.hosts()]
        return hosts or [str(rede.network_address)]

    return [alvo]


def resolver(alvo: str) -> str:
    """Resolve um IP/hostname para IPv4, UMA vez (evita 1 consulta DNS por porta).

    Lança ValueError com mensagem amigável se não resolver.
    """
    try:
        return socket.gethostbyname(alvo)
    except (OSError, UnicodeError):
        raise ValueError(f"Alvo não resolve: {alvo!r} (IP inválido ou nome inexistente).") from None


def fora_do_escopo(ip: str, escopo: list[ipaddress.IPv4Network] | None) -> bool:
    """True se há escopo definido e o IP não está em nenhuma das faixas."""
    if not escopo:
        return False
    endereco = ipaddress.ip_address(ip)
    return not any(endereco in rede for rede in escopo)


def parse_escopo(texto: str | None) -> list[ipaddress.IPv4Network] | None:
    """'172.30.99.0/24,10.0.0.0/8' -> lista de redes. None se vazio."""
    if not texto:
        return None
    redes = []
    for pedaco in texto.split(","):
        pedaco = pedaco.strip()
        if pedaco:
            try:
                redes.append(ipaddress.ip_network(pedaco, strict=False))
            except ValueError:
                raise ValueError(f"Escopo inválido: {pedaco!r}") from None
    return redes or None


def e_privado(ip: str) -> bool:
    """True para endereços de rede interna (RFC 1918, loopback, link-local)."""
    endereco = ipaddress.ip_address(ip)
    return endereco.is_private or endereco.is_loopback or endereco.is_link_local
