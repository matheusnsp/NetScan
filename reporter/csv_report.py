import csv


def gerar_csv(resultados: list[dict], caminho: str):
    """Salva os resultados em CSV, uma linha por CVE (achatado)."""

    # Define as colunas do CSV
    colunas = ["porta", "servico", "cve_id", "score"]

    with open(caminho, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=colunas)
        writer.writeheader()   # escreve a linha de cabeçalho com os nomes das colunas

        # Percorre cada porta
        for r in resultados:
            if r["cves"]:
                # Uma linha por CVE da porta
                for v in r["cves"]:
                    writer.writerow({
                        "porta": r["porta"],
                        "servico": r["servico"],
                        "cve_id": v["id"],
                        "score": v["score"]
                    })
            else:
                # Porta sem CVE: ainda registra uma linha, com CVE vazio
                writer.writerow({
                    "porta": r["porta"],
                    "servico": r["servico"],
                    "cve_id": "",
                    "score": ""
                })