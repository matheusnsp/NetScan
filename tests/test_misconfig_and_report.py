"""Testes offline de má configuração (parsing) e segurança do relatório HTML."""
from reporter.html_report import gerar_html
from scanner.misconfig import check_headers_http


def test_headers_ausentes_sao_reportados():
    banner = "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\n"
    achados = check_headers_http(banner, 80)
    assert achados and achados[0]["id"] == "HTTP-HEADERS"


def test_headers_presentes_nao_geram_achado():
    banner = (
        "HTTP/1.1 200 OK\r\n"
        "Strict-Transport-Security: max-age=63072000\r\n"
        "Content-Security-Policy: default-src 'self'\r\n"
        "X-Frame-Options: DENY\r\n"
        "X-Content-Type-Options: nosniff\r\n"
    )
    assert check_headers_http(banner, 443) == []


def test_banner_nao_http_e_ignorado():
    assert check_headers_http("SSH-2.0-OpenSSH_8.9", 22) == []


def test_relatorio_html_escapa_xss():
    # Um banner malicioso NÃO pode virar tag ativa no relatório.
    resultados = [{
        "porta": 80,
        "servico": "<script>alert(1)</script>",
        "cves": [{"id": "<img src=x onerror=alert(1)>", "score": 9.9,
                  "severidade": "CRITICAL", "kev": False, "epss": None}],
    }]
    html = gerar_html("alvo<script>", resultados)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "onerror=alert(1)>" not in html


def test_relatorio_html_mostra_badge_kev():
    resultados = [{"porta": 80, "servico": "apache httpd 2.4.49",
                   "cves": [{"id": "CVE-X", "score": 9.8, "severidade": "CRITICAL",
                             "kev": True, "epss": 0.97}]}]
    html = gerar_html("10.0.0.1", resultados)
    assert "KEV" in html and "EPSS" in html
