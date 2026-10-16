"""
Identificação de dispositivo pelo MAC.

Além de consultar o fabricante (OUI) numa API pública, este módulo trata dois
detalhes que faziam TODOS os aparelhos virarem "Desconhecido" na prática:

1. MAC sem zero à esquerda. O `arp` do macOS imprime "2:10:18:ed:70:60" em vez
   de "02:10:18:ed:70:60". A API de fabricante não reconhece o formato curto.
   Aqui a gente normaliza cada octeto para 2 dígitos antes de consultar.

2. MAC aleatório (privacidade). Celulares e notebooks modernos usam MAC
   randomizado por rede — o bit "localmente administrado" fica ligado. Esses
   nunca têm fabricante público, então nem adianta consultar: marcamos como
   "Aleatório (privacidade)" e economizamos a chamada — o que, de quebra, evita
   estourar o limite da API justamente nos poucos MACs reais da lista.

Tudo com cache em memória e tratamento de rate limit (HTTP 429).
"""
from __future__ import annotations

import time

import requests

_cache: dict[str, str] = {}


def normalizar_mac(mac: str) -> str:
    """Zero-padda cada octeto: '2:10:18:ed:70:60' -> '02:10:18:ed:70:60'."""
    partes = mac.split(":")
    if len(partes) != 6:
        return mac.lower()
    return ":".join(p.rjust(2, "0").lower() for p in partes)


def mac_aleatorio(mac: str) -> bool:
    """True se o MAC é localmente administrado (randomizado/privado).

    O 2º bit menos significativo do 1º octeto indica 'localmente administrado'.
    Na prática, o segundo dígito hex do MAC ∈ {2,3,6,7,A,B,E,F}.
    """
    mac = normalizar_mac(mac)
    try:
        primeiro_octeto = int(mac.split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    return bool(primeiro_octeto & 0b10)


def buscar_fabricante(mac: str, timeout: float = 5.0) -> str:
    """Retorna o fabricante do MAC, ou um rótulo explicativo.

    - MAC aleatório -> "Aleatório (privacidade)" sem consultar a API.
    - Caso contrário consulta a macvendors.com, com cache e retry em 429.
    """
    mac_norm = normalizar_mac(mac)

    if mac_aleatorio(mac_norm):
        return "Aleatório (privacidade)"

    if mac_norm in _cache:
        return _cache[mac_norm]

    url = f"https://api.macvendors.com/{mac_norm}"
    for tentativa in range(2):
        try:
            resp = requests.get(url, timeout=timeout)
            if resp.status_code == 200:
                _cache[mac_norm] = resp.text.strip()
                return _cache[mac_norm]
            if resp.status_code == 429:          # rate limit: espera e tenta de novo
                time.sleep(1.5)
                continue
            break
        except requests.RequestException:
            break

    _cache[mac_norm] = "Desconhecido"
    return "Desconhecido"
