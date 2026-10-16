"""Testes da detecção de serviço (parte offline: o casamento de fingerprint)."""
from scanner.service_detect import _casar_fingerprint


def test_ssh_openssh():
    assert _casar_fingerprint("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3") == ("openssh", "8.9")


def test_apache_via_server_header():
    banner = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\n"
    assert _casar_fingerprint(banner) == ("apache httpd", "2.4.49")


def test_nginx_via_server_header():
    assert _casar_fingerprint("Server: nginx/1.18.0") == ("nginx", "1.18.0")


def test_proftpd_banner():
    assert _casar_fingerprint("220 ProFTPD 1.3.5 Server ready") == ("proftpd", "1.3.5")


def test_redis_info():
    assert _casar_fingerprint("redis_version:5.0.0\r\n") == ("redis", "5.0.0")


def test_produto_sem_versao_retorna_none_na_versao():
    produto, versao = _casar_fingerprint("220 mail ESMTP Postfix")
    assert produto == "postfix" and versao is None


def test_banner_desconhecido():
    assert _casar_fingerprint("qualquer coisa sem padrão") == (None, None)


def test_generico_produto_versao():
    produto, versao = _casar_fingerprint("Server: Jetty/9.4.2")
    assert produto == "jetty" and versao == "9.4.2"
