import socket


def grab_banner(host: str, port: int, timeout: float = 2.0) -> str | None:
    """
    Pega o banner de serviços que se apresentam sozinhos ao conectar
    (SSH, FTP, SMTP...). Só "ouve" — não envia nada.

    Retorna o texto do banner, ou None se a porta não responder.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.settimeout(timeout)
            # (host, port) é uma TUPLA: o socket trata o endereço de destino
            # como uma unidade fixa de IP+porta. Por isso os parênteses duplos:
            # os de fora são a chamada de connect(); os de dentro criam a tupla.
            s.connect((host, port))
            dados = s.recv(1024)           # recv devolve BYTES, não texto
            texto = dados.decode(errors="ignore").strip()  # bytes -> texto; "ignore" não quebra com byte inválido
            return texto
        except OSError:                    # cobre TimeoutError, ConnectionRefused, etc.
            return None


def grab_http_banner(host: str, port: int, timeout: float = 2.0) -> str | None:
    """
    Pega o banner de serviços WEB (HTTP), que ficam calados até receber
    um pedido. Por isso aqui a gente ENVIA uma requisição antes de ouvir.

    Útil pra extrair a linha 'Server:' (ex: Apache/2.4.49) -> vira busca de CVE.

    Retorna a resposta HTTP como texto, ou None se falhar.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.settimeout(timeout)
            s.connect((host, port))        # (host, port) = tupla com o endereço de destino
            # \r\n\r\n DUPLO no fim é obrigatório: sinaliza "terminei o pedido"
            requisicao = "GET / HTTP/1.0\r\n\r\n"
            s.send(requisicao.encode())    # encode() = texto -> bytes (a rede só transporta bytes)
            dados = s.recv(1024)
            texto = dados.decode(errors="ignore").strip()
            return texto
        except OSError:
            return None