"""Testes da priorização e do resumo executivo."""
from scanner.scoring import prioridade_cve, resumir, rotulo_risco


def test_kev_prioriza_acima_de_cvss_alto():
    com_kev = {"id": "CVE-1", "score": 7.5, "kev": True, "epss": None}
    sem_kev = {"id": "CVE-2", "score": 9.8, "kev": False, "epss": None}
    assert prioridade_cve(com_kev) > prioridade_cve(sem_kev)


def test_epss_aumenta_prioridade():
    base = {"id": "x", "score": 5.0, "kev": False, "epss": None}
    alto = {"id": "x", "score": 5.0, "kev": False, "epss": 0.9}
    assert prioridade_cve(alto) > prioridade_cve(base)


def test_rotulos():
    assert rotulo_risco(80) == "CRÍTICO"
    assert rotulo_risco(50) == "ALTO"
    assert rotulo_risco(20) == "MÉDIO"
    assert rotulo_risco(5) == "BAIXO"
    assert rotulo_risco(0) == "OK"


def test_resumo_conta_e_ordena():
    resultados = [
        {"porta": 80, "servico": "apache httpd 2.4.49", "cves": [
            {"id": "CVE-A", "score": 9.8, "kev": True, "epss": 0.5},
            {"id": "CVE-B", "score": 4.1, "kev": False, "epss": None},
        ]},
        {"porta": 22, "servico": "openssh 8.9", "cves": []},
    ]
    r = resumir(resultados)
    assert r["total_portas"] == 2
    assert r["total_cves"] == 2
    assert r["total_kev"] == 1
    assert r["contagem"]["CRÍTICA"] == 1
    assert r["contagem"]["MÉDIA"] == 1
    # o KEV crítico deve ser o primeiro do "corrija primeiro"
    assert r["top_cves"][0]["id"] == "CVE-A"
    assert r["rotulo_risco"] in ("CRÍTICO", "ALTO")


def test_resumo_inclui_achados_config():
    r = resumir([], [{"id": "REDIS-NOAUTH", "severidade": "CRÍTICA", "porta": 6379}])
    assert r["total_config"] == 1
    assert r["contagem"]["CRÍTICA"] == 1
