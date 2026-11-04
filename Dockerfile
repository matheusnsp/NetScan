# Imagem do NetScan para rodar dentro de um laboratório Docker.
#
#   docker build -t netscan .        # precisa de internet (instala as dependências)
#   docker run --rm -it --network <rede-do-lab> netscan <alvo> --scope <faixa> --no-vuln
#
# O build roda na rede padrão (com internet); a varredura pode rodar depois numa
# rede --internal, sem saída para a internet. Veja o README.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py ./
COPY scanner/ scanner/
COPY reporter/ reporter/

# Sem root: a varredura usa conexões TCP comuns e não precisa de privilégio.
USER 65534:65534
ENTRYPOINT ["python", "main.py"]
