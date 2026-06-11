import requests
import os
import time
from dotenv import load_dotenv

load_dotenv()

def buscar_vulnerabilidades(termo):

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    parametros = {"keywordSearch": termo}    # <- usa o parâmetro, não um valor fixo


    chave = os.getenv("NVD_API_KEY")
    headers = {"apiKey": chave} if chave else {}



    resposta = requests.get(url, params=parametros, headers=headers)

    if resposta.status_code == 429:

        time.sleep(6)
        resposta = requests.get(url, params=parametros, headers=headers)
    
    if resposta.status_code != 200:
        return []

    dados = resposta.json()

    resultados = []

    for item in dados["vulnerabilities"]:
        cve = item["cve"]
        cve_id = cve["id"]
        descricao = cve["descriptions"][0]["value"]

        score = None
        metrics = cve.get("metrics", {})

        v31 = metrics.get("cvssMetricV31")
        v2 = metrics.get("cvssMetricV2")

        if v31:
            score = v31[0]["cvssData"]["baseScore"]
        elif v2:
            score = v2[0]["cvssData"]["baseScore"]

        resultados.append({
            "id": cve_id,
            "descricao": descricao,
            "score": score
        })
    return resultados