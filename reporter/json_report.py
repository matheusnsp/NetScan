import json


def gerar_json(alvo: str, resultados: list[dict], caminho: str):
    """Salva os resultados do scan em um arquivo JSON."""

    # Monta uma estrutura com metadados + os resultados
    dados = {
        "alvo": alvo,
        "total_portas": len(resultados),
        "resultados": resultados
    }

    # Abre o arquivo e despeja o JSON nele
    with open(caminho, "w", encoding="utf-8") as f:
        json.dump(dados, f, indent=2, ensure_ascii=False)