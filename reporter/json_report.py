import json

from scanner.scoring import resumir


def gerar_json(alvo: str, resultados: list[dict], caminho: str,
               achados_config: list[dict] | None = None):
    """Salva os resultados do scan em um arquivo JSON, com resumo e enriquecimento.

    Inclui o bloco de resumo executivo (score de risco, contagens, top CVEs) para
    consumo por outras ferramentas, e os achados de configuração.
    """
    achados_config = achados_config or []
    dados = {
        "alvo": alvo,
        "total_portas": len(resultados),
        "resumo": resumir(resultados, achados_config),
        "achados_config": achados_config,
        "resultados": resultados,
    }
    with open(caminho, "w", encoding="utf-8") as f:
        json.dump(dados, f, indent=2, ensure_ascii=False, default=str)


def gerar_jsonl(alvo: str, resultados: list[dict], caminho: str,
                achados_config: list[dict] | None = None):
    """Exporta em JSON Lines (um evento por linha) para ingestão em SIEM.

    Cada CVE e cada achado de configuração vira uma linha independente — formato
    que Wazuh/Splunk/Elastic consomem direto.
    """
    achados_config = achados_config or []
    with open(caminho, "w", encoding="utf-8") as f:
        for r in resultados:
            for v in r.get("cves", []):
                evento = {
                    "alvo": alvo, "tipo": "cve", "porta": r["porta"],
                    "servico": r.get("servico"), **v,
                }
                f.write(json.dumps(evento, ensure_ascii=False, default=str) + "\n")
        for a in achados_config:
            f.write(json.dumps({"alvo": alvo, "tipo": "config", **a},
                               ensure_ascii=False, default=str) + "\n")
