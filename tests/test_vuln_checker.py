"""Testes do vuln_checker: montagem de CPE e compatibilidade retroativa.

Não batem na rede — testam só a lógica pura de montagem de consulta.
"""
from scanner.vuln_checker import montar_cpe


def test_cpe_openssh():
    assert montar_cpe("openssh", "8.9") == "cpe:2.3:a:openbsd:openssh:8.9:*:*:*:*:*:*:*"


def test_cpe_apache():
    assert montar_cpe("apache httpd", "2.4.49") == \
        "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"


def test_cpe_sem_versao_usa_wildcard():
    assert montar_cpe("redis", None) == "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*"


def test_cpe_produto_desconhecido():
    assert montar_cpe("produto_inexistente", "1.0") is None


def test_cpe_case_insensitive():
    assert montar_cpe("OpenSSH", "9.0") == "cpe:2.3:a:openbsd:openssh:9.0:*:*:*:*:*:*:*"
