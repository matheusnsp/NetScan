"""
Cálculo de risco e resumo executivo.

Transforma a lista crua de CVEs e achados num veredito acionável:
"corrija isto primeiro". A lógica segue a prática de priorização de um SOC:

- Um CVE na KEV (exploração ativa) pesa mais que um CVSS alto sem exploração.
- EPSS alto (probabilidade de exploração) sobe a prioridade.
- Má configuração crítica (Redis aberto) vale tanto quanto um CVE crítico.

O score do host é 0–100, só para ordenar e dar um rótulo. Não é uma métrica
científica — é um semáforo de triagem, e o relatório deixa isso claro.
"""
from __future__ import annotations

PESO_SEVERIDADE = {"CRÍTICA": 40, "ALTA": 25, "MÉDIA": 10, "BAIXA": 3}


def prioridade_cve(cve: dict) -> int:
    """Pontua um CVE para ordenação (maior = mais urgente)."""
    score = cve.get("score") or 0
    base = score * 4  # 0–40
    if cve.get("kev"):
        base += 50     # exploração ativa: topo da fila
    epss = cve.get("epss")
    if epss:
        base += epss * 20  # 0–20
    return round(base)


def rotulo_risco(valor: int) -> str:
    if valor >= 70:
        return "CRÍTICO"
    if valor >= 40:
        return "ALTO"
    if valor >= 15:
        return "MÉDIO"
    if valor > 0:
        return "BAIXO"
    return "OK"


def resumir(resultados: list[dict], achados_config: list[dict] | None = None) -> dict:
    """Gera o bloco de resumo executivo a partir dos resultados do scan.

    Retorna contagens por severidade, destaques (KEV / maior EPSS), o top de CVEs
    a corrigir primeiro e um score de risco do host.
    """
    achados_config = achados_config or []
    cves = [dict(v, porta=r["porta"], servico=r.get("servico"))
            for r in resultados for v in r.get("cves", [])]

    contagem = {"CRÍTICA": 0, "ALTA": 0, "MÉDIA": 0, "BAIXA": 0, "SEM_NOTA": 0}
    for v in cves:
        s = v.get("score")
        if s is None:
            contagem["SEM_NOTA"] += 1
        elif s >= 9.0:
            contagem["CRÍTICA"] += 1
        elif s >= 7.0:
            contagem["ALTA"] += 1
        elif s >= 4.0:
            contagem["MÉDIA"] += 1
        else:
            contagem["BAIXA"] += 1

    for a in achados_config:
        sev = a.get("severidade", "BAIXA")
        contagem[sev] = contagem.get(sev, 0) + 1

    kev = [v for v in cves if v.get("kev")]
    top = sorted(cves, key=prioridade_cve, reverse=True)[:10]

    # Score do host: severidade dos itens, com teto em 100.
    bruto = (
        contagem["CRÍTICA"] * PESO_SEVERIDADE["CRÍTICA"]
        + contagem["ALTA"] * PESO_SEVERIDADE["ALTA"]
        + contagem["MÉDIA"] * PESO_SEVERIDADE["MÉDIA"]
        + contagem["BAIXA"] * PESO_SEVERIDADE["BAIXA"]
        + len(kev) * 30
    )
    score = min(bruto, 100)

    return {
        "total_portas": len(resultados),
        "total_cves": len(cves),
        "total_kev": len(kev),
        "total_config": len(achados_config),
        "contagem": contagem,
        "top_cves": top,
        "achados_config": achados_config,
        "score_risco": score,
        "rotulo_risco": rotulo_risco(score),
    }
