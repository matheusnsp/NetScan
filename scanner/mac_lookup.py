import requests


def buscar_fabricante(mac: str) -> str:
    """
    Consulta o fabricante de um MAC via API pública.
    Devolve "Desconhecido" se não encontrar ou se a consulta falhar.
    """
    url = f"https://api.macvendors.com/{mac}"
    try:
        resposta = requests.get(url, timeout=5)
        if resposta.status_code == 200:
            return resposta.text
        return "Desconhecido"
    except requests.RequestException:
        return "Desconhecido"