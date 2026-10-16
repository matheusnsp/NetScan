import csv


def gerar_csv(resultados: list[dict], caminho: str):
    """Salva os resultados em CSV, uma linha por CVE (achatado).

    Colunas novas: severidade, kev e epss, para priorização direto na planilha.
    """
    colunas = ["porta", "servico", "cve_id", "score", "severidade", "kev", "epss"]

    with open(caminho, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=colunas)
        writer.writeheader()

        for r in resultados:
            if r.get("cves"):
                for v in r["cves"]:
                    epss = v.get("epss")
                    writer.writerow({
                        "porta": r["porta"],
                        "servico": r.get("servico"),
                        "cve_id": v["id"],
                        "score": v.get("score"),
                        "severidade": v.get("severidade"),
                        "kev": "sim" if v.get("kev") else "",
                        "epss": f"{epss:.4f}" if epss is not None else "",
                    })
            else:
                writer.writerow({
                    "porta": r["porta"],
                    "servico": r.get("servico"),
                    "cve_id": "", "score": "", "severidade": "",
                    "kev": "", "epss": "",
                })
