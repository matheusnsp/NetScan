"""
Enriquecimento de CVEs: KEV (CISA) e EPSS (FIRST).

Um scanner que só diz "achei 47 CVEs" não ajuda ninguém: o analista ainda
precisa decidir o que corrigir primeiro. Duas fontes públicas resolvem isso e
são exatamente o que um SOC usa para priorizar:

- CISA KEV (Known Exploited Vulnerabilities): catálogo oficial de CVEs que têm
  exploração ATIVA observada no mundo real. Estar na KEV é o sinal mais forte de
  "corrija agora".
- EPSS (Exploit Prediction Scoring System): probabilidade (0 a 1) de um CVE ser
  explorado nos próximos 30 dias. Complementa o CVSS, que mede impacto mas não
  likelihood.

Ambas as fontes são baixadas uma vez por execução e cacheadas. Se a rede falhar,
o enriquecimento é apenas pulado — nunca derruba o scan.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import requests

from .vuln_checker import CACHE_DIR

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_CACHE = CACHE_DIR / "kev.json"
KEV_TTL = 60 * 60 * 24  # 1 dia


def carregar_kev(timeout: float = 20.0) -> set[str]:
    """Retorna o conjunto de CVE-IDs no catálogo KEV da CISA. Set vazio se falhar."""
    if KEV_CACHE.exists() and (time.time() - KEV_CACHE.stat().st_mtime) < KEV_TTL:
        try:
            return set(json.loads(KEV_CACHE.read_text()))
        except (OSError, json.JSONDecodeError):
            pass
    try:
        resp = requests.get(KEV_URL, timeout=timeout)
        resp.raise_for_status()
        ids = [v["cveID"] for v in resp.json().get("vulnerabilities", [])]
    except (requests.RequestException, ValueError, KeyError):
        return set()
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        KEV_CACHE.write_text(json.dumps(ids))
    except OSError:
        pass
    return set(ids)


def buscar_epss(cve_ids: list[str], timeout: float = 20.0) -> dict[str, float]:
    """Retorna {cve_id: probabilidade_epss} para a lista dada. {} se falhar.

    A API aceita até ~100 CVEs por chamada, separados por vírgula.
    """
    if not cve_ids:
        return {}
    scores: dict[str, float] = {}
    for i in range(0, len(cve_ids), 100):
        lote = cve_ids[i : i + 100]
        try:
            resp = requests.get(
                EPSS_URL, params={"cve": ",".join(lote)}, timeout=timeout
            )
            resp.raise_for_status()
            for item in resp.json().get("data", []):
                scores[item["cve"]] = float(item["epss"])
        except (requests.RequestException, ValueError, KeyError):
            continue  # lote falhou; segue com o que já tem
    return scores


def enriquecer(resultados: list[dict]) -> list[dict]:
    """Anota cada CVE de cada porta com `kev` (bool) e `epss` (float|None).

    Recebe e devolve a mesma estrutura de resultados usada pelo resto do app.
    """
    todos_ids = [
        v["id"] for r in resultados for v in r.get("cves", []) if v.get("id")
    ]
    if not todos_ids:
        return resultados

    kev = carregar_kev()
    epss = buscar_epss(sorted(set(todos_ids)))

    for r in resultados:
        for v in r.get("cves", []):
            cid = v.get("id")
            v["kev"] = cid in kev
            v["epss"] = epss.get(cid)
    return resultados
