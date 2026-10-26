"""Testes da varredura de portas: só as portas pedidas devem ser tentadas."""
import socket

import main
from scanner import port_scanner
from scanner.port_scanner import scan_port_list, scan_ports_fast


def _registrar_tentativas(monkeypatch, abertas=()):
    """Troca scan_port por um dublê que anota cada porta tentada."""
    tentadas = []

    def falso_scan_port(host, port, timeout=1.0):
        tentadas.append(port)
        return port in abertas

    monkeypatch.setattr(port_scanner, "scan_port", falso_scan_port)
    return tentadas


def test_scan_port_list_tenta_apenas_as_portas_pedidas(monkeypatch):
    tentadas = _registrar_tentativas(monkeypatch, abertas={443})
    abertas = scan_port_list("127.0.0.1", [22, 443, 54321], timeout=0.1, max_threads=4)
    assert sorted(tentadas) == [22, 443, 54321]
    assert abertas == [443]


def test_scan_port_list_devolve_ordenado_sem_repeticao(monkeypatch):
    _registrar_tentativas(monkeypatch, abertas={80, 22})
    assert scan_port_list("127.0.0.1", [80, 22, 80], timeout=0.1, max_threads=2) == [22, 80]


def test_scan_port_list_com_porta_real_aberta():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        porta_aberta = srv.getsockname()[1]
        # Pega uma porta que acabou de ser fechada: não deve estar escutando.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tmp:
            tmp.bind(("127.0.0.1", 0))
            porta_fechada = tmp.getsockname()[1]
        assert scan_port_list("127.0.0.1", [porta_aberta, porta_fechada],
                              timeout=0.5, max_threads=2) == [porta_aberta]


def test_scan_ports_fast_continua_varrendo_o_range(monkeypatch):
    tentadas = _registrar_tentativas(monkeypatch)
    scan_ports_fast("127.0.0.1", 10, 14, timeout=0.1, max_threads=2)
    assert sorted(tentadas) == [10, 11, 12, 13, 14]


def test_escanear_alvo_nao_varre_o_intervalo_entre_as_portas(monkeypatch):
    """Bug: top100 (7..54321) varria 54 mil portas em vez de 100."""
    tentadas = _registrar_tentativas(monkeypatch)
    resultados, achados = main.escanear_alvo(
        "127.0.0.1", [22, 80, 54321], timeout=0.1, threads=4,
        buscar_cve=False, checar_config=False, narrar=False)
    assert sorted(tentadas) == [22, 80, 54321]
    assert resultados == [] and achados == []
