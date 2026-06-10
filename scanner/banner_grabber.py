import socket

def grab_banner(host: str, port: int, timeout: float = 2.0) -> str| None:

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.settimeout(timeout)
            s.connect((host, port))
            dados = s.recv(1024)
            texto = dados.decode(errors="ignore").strip()
            return texto
        except OSError:
            return None
        
def grab_http_banner(host: str, port: int, timeout: float = 2.0) -> str | None:

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.settimeout(timeout)
            s.connect((host, port))
            requisicao = "GET / HTTP/1.0\r\n\r\n"
            s.send(requisicao.encode())
            dados = s.recv(1024)
            texto = dados.decode(errors="ignore").strip()
            return texto
        except OSError:
            return None