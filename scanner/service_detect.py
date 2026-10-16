"""
Detecção de serviço por protocolo.

A versão antiga só mandava um GET HTTP e lia a linha "Server:", então só
identificava servidores web. Aqui a gente usa a estratégia do nmap em
miniatura: para cada porta aberta, tenta primeiro ouvir o banner que o
serviço manda sozinho (SSH, FTP, SMTP, MySQL, Redis anunciam-se ao conectar)
e, se nada vier, manda um probe adequado ao protocolo.

Tudo é leitura/identificação passiva de serviços em redes autorizadas — o
mesmo que um `nmap -sV` faz. Nada aqui explora nada; só descobre o que está
rodando e qual a versão, que é o insumo para o cruzamento com CVEs.

Cada detecção devolve um dicionário normalizado:
    {
        "produto": "apache httpd",   # nome canônico, minúsculo
        "versao": "2.4.49",          # ou None quando não exposta
        "banner": "<texto cru>",     # evidência bruta, p/ o relatório
        "protocolo": "http",         # como foi identificado
    }
"""
from __future__ import annotations

import re
import socket
import ssl


# Palpite de protocolo a partir da porta. Só um atalho: se o palpite falhar,
# os probes genéricos ainda rodam. Serve para mandar o probe certo primeiro.
PORTA_PROTOCOLO = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 110: "pop3",
    143: "imap", 3306: "mysql", 5432: "postgres", 6379: "redis",
    27017: "mongodb", 80: "http", 8080: "http", 8000: "http",
    443: "https", 8443: "https",
}

# Regex que transformam um banner cru em (produto, versão). A ordem importa:
# a primeira que casar vence. Mantidas conservadoras para evitar falso-positivo.
FINGERPRINTS = [
    # SSH: "SSH-2.0-OpenSSH_8.9p1 Ubuntu..."
    (re.compile(r"SSH-[\d.]+-OpenSSH[_-]([\d.]+)", re.I), "openssh", 1),
    (re.compile(r"SSH-[\d.]+-(?:dropbear)[_-]([\d.]+)", re.I), "dropbear", 1),
    # FTP: "220 ProFTPD 1.3.5 Server"
    (re.compile(r"ProFTPD\s+([\d.]+)", re.I), "proftpd", 1),
    (re.compile(r"vsFTPd\s+([\d.]+)", re.I), "vsftpd", 1),
    (re.compile(r"FileZilla Server\s+([\d.]+)", re.I), "filezilla server", 1),
    # SMTP: "220 mail ESMTP Postfix" / Exim / Sendmail
    (re.compile(r"Postfix", re.I), "postfix", None),
    (re.compile(r"Exim\s+([\d.]+)", re.I), "exim", 1),
    (re.compile(r"Sendmail\s+([\d./]+)", re.I), "sendmail", 1),
    # Bancos / cache
    (re.compile(r"([\d.]+)-MariaDB", re.I), "mariadb", 1),
    (re.compile(r"mysql_native_password"), "mysql", None),
    (re.compile(r"redis_version:([\d.]+)", re.I), "redis", 1),
    (re.compile(r"MongoDB", re.I), "mongodb", None),
    # Web (linha Server: do cabeçalho HTTP)
    (re.compile(r"Server:\s*Apache/([\d.]+)", re.I), "apache httpd", 1),
    (re.compile(r"Server:\s*nginx/([\d.]+)", re.I), "nginx", 1),
    (re.compile(r"Server:\s*Microsoft-IIS/([\d.]+)", re.I), "microsoft iis", 1),
    (re.compile(r"Server:\s*lighttpd/([\d.]+)", re.I), "lighttpd", 1),
    # Genérico "Server: Produto/versao" como último recurso
    (re.compile(r"Server:\s*([A-Za-z][\w\-]+)/([\d.]+)"), "_generico_", (1, 2)),
]


def _recv(host: str, port: int, timeout: float, enviar: bytes | None = None) -> str | None:
    """Abre uma conexão TCP, opcionalmente envia `enviar`, lê a resposta.

    Retorna o texto recebido (ignorando bytes inválidos) ou None se a porta
    não responder. Só lê — não interage além do probe mínimo.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            if enviar:
                s.sendall(enviar)
            dados = s.recv(2048)
            return dados.decode("latin-1", errors="ignore").strip() or None
    except OSError:
        return None


def _recv_tls(host: str, port: int, timeout: float) -> str | None:
    """Igual ao _recv, mas sobre TLS, para portas HTTPS. Envia um HEAD."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                s.settimeout(timeout)
                s.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
                return s.recv(2048).decode("latin-1", errors="ignore").strip() or None
    except (OSError, ssl.SSLError):
        return None


def _casar_fingerprint(banner: str) -> tuple[str | None, str | None]:
    """Roda as regex de fingerprint sobre o banner. Devolve (produto, versao)."""
    for regex, produto, grupo in FINGERPRINTS:
        m = regex.search(banner)
        if not m:
            continue
        if grupo is None:
            return produto, None
        if isinstance(grupo, tuple):  # caso genérico Produto/versao
            return m.group(grupo[0]).lower(), m.group(grupo[1])
        return produto, m.group(grupo)
    return None, None


def detectar_servico(host: str, port: int, timeout: float = 2.0) -> dict | None:
    """Identifica o serviço de uma porta aberta.

    1. Tenta o banner passivo (serviços que falam primeiro).
    2. Se o palpite pela porta for HTTP/HTTPS, manda o probe web.
    3. Casa o banner com os fingerprints.

    Retorna o dicionário normalizado ou None se nada responder.
    """
    palpite = PORTA_PROTOCOLO.get(port)
    banner = None

    if palpite == "https":
        banner = _recv_tls(host, port, timeout)
        proto = "https"
    elif palpite == "http":
        banner = _recv(host, port, timeout, b"HEAD / HTTP/1.0\r\n\r\n")
        proto = "http"
    else:
        # Serviços que se anunciam ao conectar (SSH, FTP, SMTP, MySQL, ...).
        banner = _recv(host, port, timeout)
        proto = palpite or "tcp"
        # Se ficou calado, pode ser um HTTP que espera o pedido.
        if not banner:
            banner = _recv(host, port, timeout, b"HEAD / HTTP/1.0\r\n\r\n")
            if banner:
                proto = "http"

    if not banner:
        return None

    produto, versao = _casar_fingerprint(banner)
    return {
        "produto": produto,
        "versao": versao,
        "banner": banner[:500],
        "protocolo": proto,
    }
