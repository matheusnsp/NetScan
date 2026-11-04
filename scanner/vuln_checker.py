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
import threading
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


# Limites públicos da NVD: ~5 requisições/30 s sem chave e ~50/30 s com chave.
# Espaçamos as consultas para nunca estourar, em vez de descobrir pelo 429.
INTERVALO_SEM_CHAVE = 6.0
INTERVALO_COM_CHAVE = 0.6
TENTATIVAS = 3
_ultima_consulta = 0.0
_lock_ritmo = threading.Lock()


def _aguardar_vez(com_chave: bool) -> None:
    """Respeita o intervalo mínimo entre consultas à NVD (thread-safe)."""
    global _ultima_consulta
    intervalo = INTERVALO_COM_CHAVE if com_chave else INTERVALO_SEM_CHAVE
    with _lock_ritmo:
        espera = _ultima_consulta + intervalo - time.monotonic()
        if espera > 0:
            time.sleep(espera)
        _ultima_consulta = time.monotonic()


def _espera_retry_after(resp, padrao: float) -> float:
    try:
        return min(float(resp.headers.get("Retry-After", padrao)), 60.0)
    except (TypeError, ValueError):
        return padrao


def _montar_consulta(produto: str, versao: str | None):
    """Devolve (chave_de_cache, parametros) ou (None, None) se não há o que buscar."""
    if versao is None and produto and " " in produto:
        # Compatibilidade retroativa: "Apache 2.4.49" -> ("Apache", "2.4.49")
        partes = produto.rsplit(" ", 1)
        if partes[1][:1].isdigit():
            produto, versao = partes[0], partes[1]

    cpe = montar_cpe(produto, versao)
    if cpe and versao:
        return f"cpe::{cpe}", {"cpeName": cpe}
    termo = f"{produto} {versao}".strip() if versao else (produto or "").strip()
    if not termo:
        return None, None
    return f"kw::{termo}", {"keywordSearch": termo}


def consultar_cves(produto: str, versao: str | None = None,
                   timeout: float = 15.0) -> dict:
    """Consulta a NVD e devolve TODOS os CVEs do produto+versão, com status.

    Retorna:
        {"cves": [...ordenados por CVSS...], "erro": None | "mensagem"}

    Uma falha (rate limit, NVD fora do ar, sem rede) NÃO vira "zero CVEs":
    vem em "erro", para o relatório marcar a checagem como incompleta.
    """
    chave, parametros = _montar_consulta(produto, versao)
    if chave is None:
        return {"cves": [], "erro": None}

    cacheado = _cache_get(chave)
    if cacheado is not None:
        return {"cves": cacheado, "erro": None}

    headers = {}
    nvd_key = os.getenv("NVD_API_KEY")
    if nvd_key:
        headers["apiKey"] = nvd_key

    erro = "falha desconhecida"
    for tentativa in range(TENTATIVAS):
        _aguardar_vez(bool(nvd_key))
        try:
            resp = requests.get(NVD_URL, params=parametros, headers=headers, timeout=timeout)
        except requests.Timeout:
            # NVD pendurada: não insiste (cada tentativa custaria `timeout` s).
            return {"cves": [], "erro": f"NVD não respondeu em {timeout:.0f}s"}
        except requests.RequestException as e:
            erro = f"sem conexão com a NVD ({type(e).__name__})"
            time.sleep(2 ** tentativa)
            continue

        if resp.status_code == 200:
            try:
                dados = resp.json()
                cves = [_extrair_cve(it) for it in dados.get("vulnerabilities", [])]
            except (ValueError, KeyError, IndexError, TypeError):
                return {"cves": [], "erro": "resposta inválida da NVD"}
            # Ordena por score desc (None por último).
            cves.sort(key=lambda c: (c["score"] is not None, c["score"] or 0), reverse=True)
            _cache_set(chave, cves)
            return {"cves": cves, "erro": None}

        if resp.status_code in (403, 429) or resp.status_code >= 500:
            # 403/429 = limite de requisições; 5xx = instabilidade.
            erro = f"NVD respondeu HTTP {resp.status_code}"
            time.sleep(_espera_retry_after(resp, 6.0 * (tentativa + 1)))
            continue

        # 4xx restante: consulta inválida, não adianta repetir.
        return {"cves": [], "erro": f"NVD respondeu HTTP {resp.status_code}"}

    return {"cves": [], "erro": erro}


def buscar_vulnerabilidades(
    produto: str,
    versao: str | None = None,
    timeout: float = 15.0,
    max_cves: int | None = 25,
) -> list[dict]:
    """Forma simples (só a lista), mantida por compatibilidade.

    Prefira consultar_cves(), que também informa se a consulta falhou.
    """
    cves = consultar_cves(produto, versao, timeout)["cves"]
    return cves[:max_cves] if max_cves else cves
