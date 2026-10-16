"""
Cruzamento de serviços com CVEs da NVD/NIST.

A versão antiga buscava por palavra-chave (keywordSearch="Apache 2.4.49"). Isso
traz muito ruído: CVEs de QUALQUER versão do produto, e até de produtos com nome
parecido. Aqui a gente busca por CPE (Common Platform Enumeration), o
identificador padrão de produto+versão que a própria NVD usa, e filtra pela
versão detectada. É a diferença entre "tem Apache? toma 300 CVEs" e "a SUA
versão do Apache tem estes CVEs".

Fluxo:
    produto+versao -> monta CPE -> consulta a NVD por cpeName
    -> extrai id, score, severidade, descrição.

Tudo em cima da API pública oficial da NVD, com timeout, tratamento de rate
limit (429) e um cache em disco para não repetir consulta igual (educado com a
API e muito mais rápido em scans repetidos).

Compatibilidade: buscar_vulnerabilidades aceita tanto a forma nova
(produto, versao) quanto a antiga (um único termo string).
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv()

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_DIR = Path(os.getenv("NETSCAN_CACHE", Path.home() / ".cache" / "netscan"))
CACHE_TTL = 60 * 60 * 24  # 24h: CVE novo de um produto antigo é raro no mesmo dia


# Mapa de produto detectado -> (vendor, product) no vocabulário CPE da NVD.
# O CPE tem o formato cpe:2.3:a:<vendor>:<product>:<versao>:*:*:*:*:*:*:*
CPE_MAP = {
    "openssh": ("openbsd", "openssh"),
    "apache httpd": ("apache", "http_server"),
    "nginx": ("f5", "nginx"),
    "microsoft iis": ("microsoft", "internet_information_services"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "proftpd": ("proftpd", "proftpd"),
    "vsftpd": ("beasts", "vsftpd"),
    "exim": ("exim", "exim"),
    "postfix": ("postfix", "postfix"),
    "sendmail": ("proofpoint", "sendmail"),
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "redis": ("redis", "redis"),
    "mongodb": ("mongodb", "mongodb"),
    "dropbear": ("dropbear_ssh_project", "dropbear_ssh"),
}


def _cache_path(chave: str) -> Path:
    h = hashlib.sha256(chave.encode()).hexdigest()[:16]
    return CACHE_DIR / f"{h}.json"


def _cache_get(chave: str):
    p = _cache_path(chave)
    if p.exists() and (time.time() - p.stat().st_mtime) < CACHE_TTL:
        try:
            return json.loads(p.read_text())
        except (OSError, json.JSONDecodeError):
            return None
    return None


def _cache_set(chave: str, valor) -> None:
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        _cache_path(chave).write_text(json.dumps(valor))
    except OSError:
        pass  # cache é otimização; se falhar, segue sem ele


def montar_cpe(produto: str, versao: str | None) -> str | None:
    """Monta a string CPE 2.3 para o produto detectado. None se não mapeado."""
    par = CPE_MAP.get((produto or "").lower())
    if not par:
        return None
    vendor, prod = par
    ver = versao if versao else "*"
    return f"cpe:2.3:a:{vendor}:{prod}:{ver}:*:*:*:*:*:*:*"


def _extrair_cve(item: dict) -> dict:
    """Normaliza um item da NVD para o nosso formato."""
    cve = item["cve"]
    score, severidade, vetor = None, None, None
    metrics = cve.get("metrics", {})
    for chave in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if chave in metrics and metrics[chave]:
            dados = metrics[chave][0]["cvssData"]
            score = dados.get("baseScore")
            severidade = dados.get("baseSeverity") or metrics[chave][0].get("baseSeverity")
            vetor = dados.get("vectorString")
            break
    return {
        "id": cve["id"],
        "descricao": cve["descriptions"][0]["value"],
        "score": score,
        "severidade": severidade,
        "vetor": vetor,
    }


def buscar_vulnerabilidades(
    produto: str,
    versao: str | None = None,
    timeout: float = 15.0,
    max_cves: int = 25,
) -> list[dict]:
    """Retorna os CVEs da NVD para um produto+versão, via CPE.

    Se o produto não estiver no CPE_MAP ou não houver versão, cai para uma busca
    por palavra-chave mais estrita (produto + versão), ainda melhor que a antiga.
    Aceita também a chamada antiga com um único termo (ex: "Apache 2.4.49").
    """
    if versao is None and produto and " " in produto:
        # Compatibilidade retroativa: "Apache 2.4.49" -> ("Apache", "2.4.49")
        partes = produto.rsplit(" ", 1)
        if partes[1][0].isdigit():
            produto, versao = partes[0], partes[1]

    cpe = montar_cpe(produto, versao)
    if cpe and versao:
        chave = f"cpe::{cpe}"
        parametros = {"cpeName": cpe}
    else:
        termo = f"{produto} {versao}".strip() if versao else (produto or "").strip()
        if not termo:
            return []
        chave = f"kw::{termo}"
        parametros = {"keywordSearch": termo}

    cacheado = _cache_get(chave)
    if cacheado is not None:
        return cacheado[:max_cves]

    headers = {}
    nvd_key = os.getenv("NVD_API_KEY")
    if nvd_key:
        headers["apiKey"] = nvd_key

    try:
        resp = requests.get(NVD_URL, params=parametros, headers=headers, timeout=timeout)
        if resp.status_code == 429:  # rate limit
            time.sleep(6)
            resp = requests.get(NVD_URL, params=parametros, headers=headers, timeout=timeout)
        if resp.status_code != 200:
            return []
        dados = resp.json()
    except (requests.RequestException, ValueError):
        return []

    cves = [_extrair_cve(it) for it in dados.get("vulnerabilities", [])]
    # Ordena por score desc (None por último), para o relatório já sair priorizado.
    cves.sort(key=lambda c: (c["score"] is not None, c["score"] or 0), reverse=True)
    _cache_set(chave, cves)
    return cves[:max_cves]
