"""
Checagens de má configuração (non-CVE findings).

Nem todo risco é um CVE. Os incidentes mais comuns em redes internas vêm de
configuração errada: um Redis sem senha, um FTP que aceita anônimo, TLS velho.
Um scanner de CVE puro não enxerga nada disso — e é justamente o que aparece num
checklist de hardening / auditoria de SOC.

Todas as checagens aqui são de LEITURA e não-destrutivas: elas apenas verificam
a POSTURA do serviço (ele exige autenticação? o certificado está válido?). Nada
é alterado, nenhum dado é lido do serviço, nada é explorado. É o equivalente a
conferir se a porta está trancada — não a invadir.

Cada achado é um dicionário:
    {"id": "REDIS-NOAUTH", "titulo": "...", "severidade": "ALTA",
     "descricao": "...", "porta": 6379}
"""
from __future__ import annotations

import socket
import ssl
import warnings
from datetime import datetime, timezone

# Severidades usadas também no cálculo de risco (scoring.py).
SEV_CRITICA = "CRÍTICA"
SEV_ALTA = "ALTA"
SEV_MEDIA = "MÉDIA"
SEV_BAIXA = "BAIXA"


def _conectar(host, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((host, port))
    return s


def check_redis_sem_auth(host: str, port: int, timeout: float = 3.0) -> dict | None:
    """Verifica se o Redis responde a PING sem autenticação.

    Manda apenas PING. Resposta +PONG => aberto (sem senha). Resposta com NOAUTH
    => protegido. Não lê nem escreve dado nenhum.
    """
    try:
        with _conectar(host, port, timeout) as s:
            s.sendall(b"PING\r\n")
            resp = s.recv(128).decode("latin-1", errors="ignore")
    except OSError:
        return None
    if resp.startswith("+PONG"):
        return {
            "id": "REDIS-NOAUTH", "porta": port, "severidade": SEV_CRITICA,
            "titulo": "Redis acessível sem autenticação",
            "descricao": "O serviço Redis respondeu a PING sem exigir senha. "
                         "Qualquer um na rede pode ler/alterar os dados. "
                         "Defina 'requirepass' e restrinja o bind.",
        }
    return None


def check_mongodb_sem_auth(host: str, port: int, timeout: float = 3.0) -> dict | None:
    """Detecta MongoDB que aceita o comando isMaster sem credenciais.

    Envia um único OP_QUERY mínimo de isMaster (handshake padrão do driver). Se o
    servidor responder normalmente, aceita conexão não autenticada.
    """
    # Pacote wire-protocol mínimo de {isMaster:1} no banco admin.$cmd
    query = (
        b"\x3a\x00\x00\x00"              # messageLength
        b"\x00\x00\x00\x00"              # requestID
        b"\x00\x00\x00\x00"              # responseTo
        b"\xd4\x07\x00\x00"              # opCode OP_QUERY
        b"\x00\x00\x00\x00"              # flags
        b"admin.$cmd\x00"               # fullCollectionName
        b"\x00\x00\x00\x00"              # numberToSkip
        b"\x01\x00\x00\x00"              # numberToReturn
        b"\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00"  # {isMaster:1}
    )
    try:
        with _conectar(host, port, timeout) as s:
            s.sendall(query)
            resp = s.recv(256)
    except OSError:
        return None
    if resp and len(resp) > 4 and b"ismaster" in resp.lower():
        return {
            "id": "MONGO-NOAUTH", "porta": port, "severidade": SEV_CRITICA,
            "titulo": "MongoDB acessível sem autenticação",
            "descricao": "O servidor respondeu ao handshake sem credenciais. "
                         "Ative autorização (--auth) e restrinja o bindIp.",
        }
    return None


def check_ftp_anonimo(host: str, port: int, timeout: float = 4.0) -> dict | None:
    """Verifica se o FTP aceita login anônimo. Apenas tenta o login e desconecta."""
    try:
        with _conectar(host, port, timeout) as s:
            s.recv(256)  # banner
            s.sendall(b"USER anonymous\r\n")
            s.recv(256)
            s.sendall(b"PASS netscan@example.com\r\n")
            resp = s.recv(256).decode("latin-1", errors="ignore")
            s.sendall(b"QUIT\r\n")
    except OSError:
        return None
    if resp.startswith("230"):  # 230 = login bem-sucedido
        return {
            "id": "FTP-ANON", "porta": port, "severidade": SEV_ALTA,
            "titulo": "FTP permite login anônimo",
            "descricao": "O servidor aceitou o usuário 'anonymous'. Desative o "
                         "acesso anônimo a menos que seja intencional (mirror público).",
        }
    return None


def check_telnet_aberto(host: str, port: int, timeout: float = 3.0) -> dict | None:
    """Telnet aberto é risco por si só: credenciais trafegam em texto puro.

    Só marca se o serviço FALAR Telnet: negociação de opções (byte IAC 0xFF)
    ou um prompt de login. Qualquer outro serviço na porta 23 não é Telnet.
    """
    try:
        with _conectar(host, port, timeout) as s:
            dados = s.recv(256)
    except OSError:
        return None
    texto = dados.decode("latin-1", errors="ignore").lower()
    if not (dados.startswith(b"\xff") or "login" in texto or "username" in texto):
        return None
    return {
        "id": "TELNET-OPEN", "porta": port, "severidade": SEV_ALTA,
        "titulo": "Telnet exposto",
        "descricao": "O Telnet transmite login e senha sem criptografia. "
                     "Substitua por SSH e feche a porta 23.",
    }


def _validade_certificado(der: bytes) -> datetime | None:
    """Extrai o fim da validade (UTC) de um certificado em DER. None se falhar."""
    try:
        from cryptography import x509
    except ImportError:
        return None
    try:
        cert = x509.load_der_x509_certificate(der)
    except ValueError:
        return None
    fim = getattr(cert, "not_valid_after_utc", None)
    if fim is None:  # cryptography < 42
        fim = cert.not_valid_after.replace(tzinfo=timezone.utc)
    return fim


def aceita_tls_antigo(host: str, port: int, timeout: float = 5.0) -> str | None:
    """Tenta um handshake limitado a TLS 1.0/1.1. Devolve a versão aceita ou None.

    Se o OpenSSL local nem suportar mais esses protocolos, devolve None
    (não dá para afirmar nada).
    """
    try:
        with warnings.catch_warnings():
            # Usar TLS 1.0/1.1 aqui é de propósito: é exatamente o que testamos.
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1_1
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ValueError, ssl.SSLError, AttributeError):
        return None
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                return s.version()
    except (OSError, ssl.SSLError):
        return None


def check_tls(host: str, port: int, timeout: float = 5.0) -> list[dict]:
    """Inspeciona o certificado e os protocolos TLS. Não-destrutivo.

    Retorna achados para: certificado expirado e suporte a TLS 1.0/1.1 (obsoletos).

    Obs.: com verify_mode=CERT_NONE, getpeercert() devolve {} (o Python só
    decodifica certificados validados). Por isso pegamos o certificado em DER
    (binary_form=True) e o decodificamos com a biblioteca cryptography.
    """
    achados: list[dict] = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    der = None
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                der = s.getpeercert(binary_form=True)
    except ssl.SSLError:
        pass  # pode ser um servidor que SÓ fala TLS antigo: testamos abaixo
    except OSError:
        return achados

    # Protocolo obsoleto: o contexto padrão exige TLS 1.2+, então é preciso um
    # segundo handshake que SÓ ofereça TLS 1.0/1.1 para saber se o servidor aceita.
    antigo = aceita_tls_antigo(host, port, timeout)
    if antigo:
        achados.append({
            "id": "TLS-OLD", "porta": port, "severidade": SEV_MEDIA,
            "titulo": f"Protocolo TLS obsoleto aceito ({antigo})",
            "descricao": "Protocolos anteriores ao TLS 1.2 têm fraquezas conhecidas. "
                         "Desative TLS 1.0/1.1 e exija no mínimo TLS 1.2.",
        })

    expira = _validade_certificado(der) if der else None
    if expira and expira < datetime.now(timezone.utc):
        achados.append({
            "id": "TLS-EXPIRED", "porta": port, "severidade": SEV_ALTA,
            "titulo": "Certificado TLS expirado",
            "descricao": f"O certificado venceu em {expira:%Y-%m-%d %H:%M} UTC. "
                         "Renove para evitar erros e ataques de downgrade.",
        })
    return achados


# Cabeçalhos de segurança HTTP que devem existir numa aplicação web endurecida.
HEADERS_SEGURANCA = {
    "strict-transport-security": "HSTS (força HTTPS)",
    "content-security-policy": "CSP (mitiga XSS/injeção)",
    "x-frame-options": "proteção contra clickjacking",
    "x-content-type-options": "impede MIME sniffing",
}


def check_headers_http(banner: str, port: int) -> list[dict]:
    """A partir do banner HTTP já coletado, aponta cabeçalhos de segurança ausentes.

    Não faz nova conexão — reaproveita o banner da detecção de serviço.
    """
    # Só respostas HTTP de verdade (começam com a linha de status). Um Redis
    # que ecoa "HTTP/1.0" num erro não é servidor web.
    if not banner or not banner.lstrip().upper().startswith("HTTP/"):
        return []
    low = banner.lower()
    faltando = [desc for h, desc in HEADERS_SEGURANCA.items() if h not in low]
    if not faltando:
        return []
    return [{
        "id": "HTTP-HEADERS", "porta": port, "severidade": SEV_BAIXA,
        "titulo": "Cabeçalhos de segurança HTTP ausentes",
        "descricao": "Faltando: " + "; ".join(faltando) + ".",
    }]


def checar_porta(host: str, port: int, servico: dict | None, timeout: float = 4.0) -> list[dict]:
    """Roda as checagens aplicáveis a uma porta, conforme o protocolo detectado."""
    achados: list[dict] = []
    proto = (servico or {}).get("protocolo")
    produto = (servico or {}).get("produto") or ""

    if port == 6379 or produto == "redis" or proto == "redis":
        r = check_redis_sem_auth(host, port, timeout)
        if r:
            achados.append(r)
    if port == 27017 or produto == "mongodb":
        r = check_mongodb_sem_auth(host, port, timeout)
        if r:
            achados.append(r)
    if port == 21 or proto == "ftp":
        r = check_ftp_anonimo(host, port, timeout)
        if r:
            achados.append(r)
    if port == 23 or proto == "telnet":
        r = check_telnet_aberto(host, port, timeout)
        if r:
            achados.append(r)
    if proto == "https" or port in (443, 8443):
        achados.extend(check_tls(host, port, timeout))
    if proto in ("http", "https"):
        achados.extend(check_headers_http((servico or {}).get("banner", ""), port))
    return achados
