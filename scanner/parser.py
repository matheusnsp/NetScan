import re

def extrair_servico(banner: str) -> str | None:
    resultado = re.search(r"Server: (.+)", banner)
    if resultado:
        servico = resultado.group(1).replace("/", " ")
        return servico
    else:
        return None