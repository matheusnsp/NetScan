"""
Listagem dos aparelhos que o sistema já conhece (cache/vizinhança ARP).

IMPORTANTE: isto NÃO envia pacotes ARP. Só lê a tabela que o sistema
operacional já montou ao conversar com outras máquinas. Um aparelho com quem
a sua máquina nunca falou não aparece aqui. Para descobrir hosts de verdade
numa faixa, a CLI usa o "ping TCP" de scanner/port_scanner.py (descobrir_hosts).

Fontes, na ordem: `arp -a` (macOS/BSD e Linux com net-tools), `ip neigh`
(Linux moderno) e /proc/net/arp (Linux, sempre presente). Nenhuma exige root.
"""
from __future__ import annotations

import re
import socket
import subprocess
from pathlib import Path

from scanner.mac_lookup import normalizar_mac


def reverse_dns(ip: str, timeout: float = 1.0) -> str | None:
    """Tenta descobrir o nome do host por DNS reverso. None se não resolver."""
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


# Linha do `arp -a`:
#   macOS: "? (192.168.0.1) at 2:10:18:ed:70:60 on en0 ifscope [ethernet]"
#   Linux: "? (172.30.99.2) at 02:42:ac:1e:63:02 [ether] on br-0f4df3c1e1e4"
_RE_ARP = re.compile(
    r"^(\S+) \((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]+)(?: \[\w+\])?(?: on (\S+))?"
)
# Linha do `ip neigh`: "172.30.99.2 dev br-xxx lladdr 02:42:ac:1e:63:02 REACHABLE"
_RE_IP_NEIGH = re.compile(
    r"^(\d+\.\d+\.\d+\.\d+) dev (\S+) lladdr ([0-9a-fA-F:]+)"
)


def _rodar(cmd: list[str]) -> str | None:
    """Executa um comando e devolve a saída; None se o comando não existir."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
    except (FileNotFoundError, PermissionError, subprocess.TimeoutExpired):
        return None


def _parse_arp_a(saida: str) -> list[dict]:
    aparelhos = []
    for linha in saida.splitlines():
        m = _RE_ARP.match(linha.strip())
        if m:
            nome, ip, mac, iface = m.groups()
            aparelhos.append({"ip": ip, "mac": mac, "hostname_arp": nome, "interface": iface})
    return aparelhos


def _parse_ip_neigh(saida: str) -> list[dict]:
    aparelhos = []
    for linha in saida.splitlines():
        m = _RE_IP_NEIGH.match(linha.strip())
        if m:
            ip, iface, mac = m.groups()
            aparelhos.append({"ip": ip, "mac": mac, "hostname_arp": None, "interface": iface})
    return aparelhos


def _parse_proc_net_arp(texto: str) -> list[dict]:
    aparelhos = []
    for linha in texto.splitlines()[1:]:  # 1ª linha é cabeçalho
        partes = linha.split()
        if len(partes) >= 6 and partes[2] != "0x0":  # flags 0x0 = incompleto
            aparelhos.append({"ip": partes[0], "mac": partes[3],
                              "hostname_arp": None, "interface": partes[5]})
    return aparelhos


def read_arp_table() -> list[dict]:
    """
    Lê a tabela ARP do sistema e devolve os aparelhos com MAC conhecido.

    Retorna uma lista de dicionários:
        [{"ip": ..., "mac": ..., "hostname_arp": ..., "interface": ...}, ...]
    Lista vazia se nenhuma fonte estiver disponível.
    """
    brutos: list[dict] = []
    saida = _rodar(["arp", "-a"])
    if saida:
        brutos = _parse_arp_a(saida)
    if not brutos:
        saida = _rodar(["ip", "neigh"])
        if saida:
            brutos = _parse_ip_neigh(saida)
    if not brutos:
        try:
            brutos = _parse_proc_net_arp(Path("/proc/net/arp").read_text())
        except OSError:
            brutos = []

    aparelhos, vistos = [], set()
    for ap in brutos:
        ip, mac = ap["ip"], normalizar_mac(ap["mac"])
        if ip.endswith(".255") or ip.startswith("224.") or mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            continue  # broadcast/multicast/incompleto, não é aparelho
        if ip in vistos:
            continue
        vistos.add(ip)
        nome = ap.get("hostname_arp")
        aparelhos.append({
            "ip": ip,
            "mac": mac,
            "hostname_arp": None if nome in (None, "?", "") else nome,
            "interface": ap.get("interface"),
        })
    return aparelhos
