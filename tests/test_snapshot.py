"""Testes do diff entre scans (snapshot.py), todos offline."""
from scanner.snapshot import (carregar_snapshot, comparar, diff_para_jsonl,
                              salvar_snapshot)


def _res(porta, servico=None, cves=None):
    return {"porta": porta, "servico": servico, "cves": cves or []}


def test_primeira_vez_sem_snapshot():
    diff = comparar(None, [_res(80, "nginx 1.18.0")], [])
    assert diff["primeira_vez"] is True
    assert diff["houve_mudanca"] is False


def test_porta_nova_e_fechada(tmp_path):
    antes = [_res(22, "openssh 8.9"), _res(80, "nginx 1.18.0")]
    salvar_snapshot("alvo1", antes, [], state_dir=tmp_path)
    snap = carregar_snapshot("alvo1", state_dir=tmp_path)

    agora = [_res(22, "openssh 8.9"), _res(3389, "rdp")]  # 80 fechou, 3389 abriu
    diff = comparar(snap, agora, [])
    assert diff["portas_novas"] == [3389]
    assert diff["portas_fechadas"] == [80]
    assert diff["houve_mudanca"] is True


def test_servico_alterado(tmp_path):
    salvar_snapshot("a2", [_res(80, "apache httpd 2.4.49")], [], state_dir=tmp_path)
    snap = carregar_snapshot("a2", state_dir=tmp_path)
    diff = comparar(snap, [_res(80, "apache httpd 2.4.58")], [])
    assert diff["servicos_alterados"] == [(80, "apache httpd 2.4.49", "apache httpd 2.4.58")]


def test_cve_novo_e_kev(tmp_path):
    antes = [_res(80, "apache httpd 2.4.49",
                  [{"id": "CVE-2021-1", "score": 7.0, "kev": False}])]
    salvar_snapshot("a3", antes, [], state_dir=tmp_path)
    snap = carregar_snapshot("a3", state_dir=tmp_path)

    agora = [_res(80, "apache httpd 2.4.49", [
        {"id": "CVE-2021-1", "score": 7.0, "kev": False},
        {"id": "CVE-2021-41773", "score": 9.8, "kev": True},  # novo e KEV
    ])]
    diff = comparar(snap, agora, [])
    assert (80, "CVE-2021-41773") in diff["cves_novos"]
    assert (80, "CVE-2021-41773") in diff["kev_novos"]
    assert (80, "CVE-2021-1") not in diff["cves_novos"]  # já existia


def test_config_nova(tmp_path):
    salvar_snapshot("a4", [_res(6379, "redis 5.0.0")], [], state_dir=tmp_path)
    snap = carregar_snapshot("a4", state_dir=tmp_path)
    novo = [{"id": "REDIS-NOAUTH", "porta": 6379, "titulo": "Redis sem auth",
             "severidade": "CRÍTICA"}]
    diff = comparar(snap, [_res(6379, "redis 5.0.0")], novo)
    assert diff["config_novos"] and diff["config_novos"][0]["id"] == "REDIS-NOAUTH"


def test_sem_mudanca(tmp_path):
    res = [_res(80, "nginx 1.18.0", [{"id": "CVE-X", "score": 5.0, "kev": False}])]
    salvar_snapshot("a5", res, [], state_dir=tmp_path)
    snap = carregar_snapshot("a5", state_dir=tmp_path)
    diff = comparar(snap, res, [])
    assert diff["houve_mudanca"] is False


def test_diff_para_jsonl():
    diff = {"portas_novas": [3389], "portas_fechadas": [], "servicos_alterados": [],
            "cves_novos": [(80, "CVE-1")], "kev_novos": [(80, "CVE-1")], "config_novos": []}
    eventos = diff_para_jsonl("10.0.0.1", diff)
    tipos = {e["mudanca"] for e in eventos}
    assert "porta_aberta" in tipos and "cve_novo" in tipos
    cve_ev = [e for e in eventos if e["mudanca"] == "cve_novo"][0]
    assert cve_ev["kev"] is True
