"""Testes das correções da vistoria (tudo offline: só 127.0.0.1 e dublês)."""
from __future__ import annotations

import socket
import ssl
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest
import requests

import main
from reporter.html_report import gerar_html
from scanner import enrich, host_discovery, port_scanner, vuln_checker
from scanner.misconfig import check_headers_http, check_telnet_aberto, check_tls
from scanner.port_scanner import (LimitadorTaxa, descobrir_hosts, host_responde,
                                  scan_port)
from scanner.scoring import resumir
from scanner.service_detect import detectar_servico
from scanner.targets import (TOP_100, e_privado, fora_do_escopo, parse_alvos,
                             parse_escopo, parse_portas, resolver)


# ------------------------------ utilitários ------------------------------

def _porta_fechada() -> int:
    with socket.socket() as tmp:
        tmp.bind(("127.0.0.1", 0))
        return tmp.getsockname()[1]


class _ServidorFalso:
    """Servidor TCP local que responde `responder(dados_recebidos) -> bytes`."""

    def __init__(self, responder, saudacao: bytes = b""):
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(8)
        self.porta = self.srv.getsockname()[1]
        self.responder, self.saudacao = responder, saudacao
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            with conn:
                conn.settimeout(2)
                try:
                    if self.saudacao:
                        conn.sendall(self.saudacao)
                    dados = conn.recv(1024)
                    if dados:
                        conn.sendall(self.responder(dados))
                except OSError:
                    pass

    def fechar(self):
        self.srv.close()


# ------------------------------- portas/alvos -------------------------------

def test_top100_tem_100_portas_unicas():
    assert len(TOP_100) == len(set(TOP_100)) == 100


def test_perfil_combinado_com_porta_extra():
    portas = parse_portas("top100,2222")
    assert 2222 in portas and 80 in portas and len(portas) == 101


@pytest.mark.parametrize("spec", ["abc", "80-", "90-80", "0", "70000"])
def test_spec_de_portas_invalido_tem_mensagem_clara(spec):
    with pytest.raises(ValueError, match="Spec de portas inválido"):
        parse_portas(spec)


def test_alvo_vazio_e_cidr_invalido():
    with pytest.raises(ValueError):
        parse_alvos("")
    with pytest.raises(ValueError, match="CIDR inválida"):
        parse_alvos("172.30.99.0/33")


def test_resolver_alvo_invalido():
    with pytest.raises(ValueError, match="não resolve"):
        resolver("999.1.1.1")


def test_escopo():
    escopo = parse_escopo("172.30.99.0/24,10.0.0.0/8")
    assert not fora_do_escopo("172.30.99.5", escopo)
    assert fora_do_escopo("192.0.2.1", escopo)
    assert not fora_do_escopo("8.8.8.8", None)
    assert e_privado("172.30.99.5") and not e_privado("8.8.8.8")


# ------------------------------ varredura ------------------------------

def test_scan_port_nao_explode_com_host_invalido():
    assert scan_port("999.1.1.1", 80, 0.2) is False


def test_host_responde_com_porta_fechada_conta_como_vivo():
    # Porta recusada (RST) prova que o host existe.
    assert host_responde("127.0.0.1", (_porta_fechada(),), 0.5) is True


def test_descobrir_hosts_filtra_e_mantem_ordem(monkeypatch):
    # Dublê: não depende de quais endereços de loopback o sistema responde
    # (no Linux toda a 127.0.0.0/8 responde; no macOS só 127.0.0.1).
    vivos = {"10.0.0.3", "10.0.0.1"}
    monkeypatch.setattr(port_scanner, "host_responde",
                        lambda ip, *a, **k: ip in vivos)
    ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    assert descobrir_hosts(ips, 0.1) == ["10.0.0.1", "10.0.0.3"]


def test_limitador_de_taxa_espaca_conexoes():
    lim = LimitadorTaxa(20)  # 20/s => 50 ms entre conexões
    t0 = time.monotonic()
    for _ in range(5):
        lim.aguardar()
    assert time.monotonic() - t0 >= 0.18


# --------------------------- cache ARP (sem root) ---------------------------

def test_parse_arp_linux_captura_interface():
    linha = "? (172.30.99.2) at 02:42:ac:1e:63:02 [ether] on br-0f4df3c1e1e4"
    ap = host_discovery._parse_arp_a(linha)[0]
    assert ap["ip"] == "172.30.99.2" and ap["interface"] == "br-0f4df3c1e1e4"


def test_parse_arp_macos():
    linha = "? (192.168.0.1) at 2:0:5e:10:20:30 on en0 ifscope [ethernet]"
    ap = host_discovery._parse_arp_a(linha)[0]
    assert ap["interface"] == "en0"


def test_sem_comando_arp_usa_ip_neigh(monkeypatch):
    saidas = {"arp": None,
              "ip": "172.30.99.3 dev br-x lladdr 02:42:ac:1e:63:03 REACHABLE\n"
                    "172.30.99.9 dev br-x  FAILED\n"}
    monkeypatch.setattr(host_discovery, "_rodar", lambda cmd: saidas[cmd[0]])
    aps = host_discovery.read_arp_table()
    assert [a["ip"] for a in aps] == ["172.30.99.3"]


def test_multicast_e_broadcast_nao_viram_aparelho(monkeypatch):
    saida = ("? (239.255.255.250) at 1:0:5e:7f:ff:fa on en0 ifscope permanent [ethernet]\n"
             "? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]\n"
             "? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]\n"
             "? (10.0.1.255) at 2:0:5e:10:20:31 on en0 ifscope [ethernet]\n"
             "? (10.0.0.7) at 2:0:5e:10:20:32 on en0 ifscope [ethernet]\n")
    monkeypatch.setattr(host_discovery, "_rodar", lambda cmd: saida if cmd[0] == "arp" else None)
    ips = [a["ip"] for a in host_discovery.read_arp_table()]
    # 10.0.1.255 é host válido numa /23; só multicast e broadcast (MAC ff..) saem.
    assert ips == ["10.0.1.255", "10.0.0.7"]


def test_parse_proc_net_arp():
    texto = ("IP address       HW type     Flags       HW address            Mask     Device\n"
             "172.30.99.4      0x1         0x2         02:42:ac:1e:63:04     *        br-x\n"
             "172.30.99.9      0x1         0x0         00:00:00:00:00:00     *        br-x\n")
    aps = host_discovery._parse_proc_net_arp(texto)
    assert [a["ip"] for a in aps] == ["172.30.99.4"]


# --------------------------- detecção de serviço ---------------------------

def _redis_falso(dados: bytes) -> bytes:
    if dados.startswith(b"INFO"):
        corpo = b"# Server\r\nredis_version:5.0.0\r\nredis_mode:standalone\r\n"
        return b"$%d\r\n" % len(corpo) + corpo + b"\r\n"
    if dados.startswith(b"PING"):
        return b"+PONG\r\n"
    return b"-ERR unknown command `HEAD`, with args beginning with: `/`, `HTTP/1.0`, \r\n"


def test_redis_em_porta_nao_padrao_e_identificado_com_versao():
    srv = _ServidorFalso(_redis_falso)
    try:
        info = detectar_servico("127.0.0.1", srv.porta, timeout=0.5)
    finally:
        srv.fechar()
    assert info["produto"] == "redis" and info["versao"] == "5.0.0"
    assert info["protocolo"] == "redis"


def test_eco_de_http_no_redis_nao_gera_achado_de_cabecalho():
    banner = "-ERR unknown command `HEAD`, with args beginning with: `/`, `HTTP/1.0`,"
    assert check_headers_http(banner, 6379) == []


def test_servico_qualquer_na_porta_23_nao_e_telnet():
    srv = _ServidorFalso(lambda d: b"", saudacao=b"220 algum servico\r\n")
    try:
        assert check_telnet_aberto("127.0.0.1", srv.porta, 1.0) is None
    finally:
        srv.fechar()


def test_telnet_de_verdade_e_marcado():
    srv = _ServidorFalso(lambda d: b"", saudacao=b"\xff\xfd\x18\xff\xfd\x20")
    try:
        assert check_telnet_aberto("127.0.0.1", srv.porta, 1.0)["id"] == "TELNET-OPEN"
    finally:
        srv.fechar()


def test_certificado_expirado_e_detectado(tmp_path):
    x509 = pytest.importorskip("cryptography.x509")
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    chave = ec.generate_private_key(ec.SECP256R1())
    nome = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "lab")])
    agora = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(nome).issuer_name(nome)
            .public_key(chave.public_key()).serial_number(1)
            .not_valid_before(agora - timedelta(days=30))
            .not_valid_after(agora - timedelta(days=1))
            .sign(chave, hashes.SHA256()))
    (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "k.pem").write_bytes(chave.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    porta = srv.getsockname()[1]

    def _loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            try:
                with ctx.wrap_socket(conn, server_side=True) as tls:
                    tls.recv(16)
            except (OSError, ssl.SSLError):
                pass

    threading.Thread(target=_loop, daemon=True).start()
    try:
        ids = [a["id"] for a in check_tls("127.0.0.1", porta, 2.0)]
    finally:
        srv.close()
    assert "TLS-EXPIRED" in ids


# ------------------------------- NVD / KEV -------------------------------

class _Resp:
    def __init__(self, status, corpo=None, headers=None):
        self.status_code, self._corpo, self.headers = status, corpo, headers or {}

    def json(self):
        if self._corpo is None:
            raise ValueError("sem json")
        return self._corpo


def _item(cid, score):
    return {"cve": {"id": cid, "descriptions": [{"value": "x"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score,
                                                                 "baseSeverity": "HIGH"}}]}}}


@pytest.fixture
def nvd_isolada(monkeypatch, tmp_path):
    monkeypatch.setattr(vuln_checker, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(vuln_checker, "INTERVALO_SEM_CHAVE", 0)
    monkeypatch.setattr(vuln_checker, "INTERVALO_COM_CHAVE", 0)
    monkeypatch.setattr(vuln_checker.time, "sleep", lambda s: None)
    monkeypatch.delenv("NVD_API_KEY", raising=False)


def test_nvd_429_tenta_de_novo_e_recupera(monkeypatch, nvd_isolada):
    respostas = [_Resp(429, headers={"Retry-After": "1"}),
                 _Resp(200, {"vulnerabilities": [_item("CVE-1", 7.5)]})]
    monkeypatch.setattr(vuln_checker.requests, "get", lambda *a, **k: respostas.pop(0))
    r = vuln_checker.consultar_cves("openssh", "8.4")
    assert r["erro"] is None and [c["id"] for c in r["cves"]] == ["CVE-1"]


@pytest.mark.parametrize("resposta", [_Resp(503), _Resp(429), _Resp(200, None)])
def test_falha_da_nvd_vira_erro_e_nao_zero_cves(monkeypatch, nvd_isolada, resposta):
    monkeypatch.setattr(vuln_checker.requests, "get", lambda *a, **k: resposta)
    r = vuln_checker.consultar_cves("openssh", "8.4")
    assert r["cves"] == [] and r["erro"]


def test_nvd_pendurada_nao_insiste(monkeypatch, nvd_isolada):
    chamadas = []

    def _timeout(*a, **k):
        chamadas.append(1)
        raise requests.Timeout()

    monkeypatch.setattr(vuln_checker.requests, "get", _timeout)
    r = vuln_checker.consultar_cves("openssh", "8.4")
    assert "não respondeu" in r["erro"] and len(chamadas) == 1


def test_kev_fora_do_ar_e_informado(monkeypatch, tmp_path):
    monkeypatch.setattr(enrich, "KEV_CACHE", tmp_path / "kev.json")

    def _falha(*a, **k):
        raise requests.ConnectionError()

    monkeypatch.setattr(enrich.requests, "get", _falha)
    resultados = [{"porta": 22, "cves": [{"id": "CVE-1", "score": 5.0}]}]
    status = enrich.enriquecer(resultados)
    assert status == {"kev_ok": False, "epss_ok": False}
    assert resultados[0]["cves"][0]["kev"] is False


def test_corte_de_cves_preserva_kev_de_cvss_medio():
    cves = [{"id": f"CVE-{i}", "score": 9.0, "kev": False, "epss": None} for i in range(30)]
    cves.append({"id": "CVE-KEV", "score": 5.0, "kev": True, "epss": 0.5})
    resultados = [{"porta": 80, "cves": cves}]
    main._priorizar_e_cortar(resultados, 25)
    ids = [c["id"] for c in resultados[0]["cves"]]
    assert len(ids) == 25 and "CVE-KEV" in ids


def test_checagem_incompleta_nao_vira_ok():
    resultados = [{"porta": 22, "servico": "openssh 8.4", "cves": [],
                   "cves_total": 0, "cve_erro": "NVD respondeu HTTP 503"}]
    r = resumir(resultados, [])
    assert r["rotulo_risco"] == "INDETERMINADO" and r["checagem_cve_incompleta"]
    assert "Checagem de CVE incompleta" in gerar_html("10.0.0.1", resultados)


# --------------------------------- CLI ---------------------------------

@pytest.mark.parametrize("argv", [
    ["-p", "80"],                       # sem alvo
    ["127.0.0.1", "-t", "-1"],
    ["127.0.0.1", "--threads", "0"],
    ["127.0.0.1", "-f", "pdf"],
    ["127.0.0.1", "--rate", "0"],
])
def test_argumentos_invalidos_saem_com_codigo_2(monkeypatch, argv):
    monkeypatch.setattr("sys.argv", ["main.py"] + argv)
    with pytest.raises(SystemExit) as e:
        main.main()
    assert e.value.code == 2


def test_alvo_que_nao_resolve_nao_gera_traceback(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr("sys.argv", ["main.py", "naoexiste.invalid", "-p", "80",
                                     "--no-vuln", "-o", str(tmp_path)])
    assert main.main() == 1
    assert "não resolve" in capsys.readouterr().out


def test_alvo_fora_do_escopo_e_recusado(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr("sys.argv", ["main.py", "127.0.0.1", "--scope", "172.30.99.0/24",
                                     "-p", "80", "--no-vuln", "-o", str(tmp_path)])
    assert main.main() == 1
    assert "fora do escopo" in capsys.readouterr().out


def test_sem_descritores_conta_e_nao_explode(monkeypatch):
    """'Too many open files' persistente: a porta não é dada como aberta,
    mas fica registrada para a CLI avisar (falso negativo possível)."""
    import errno as _errno

    def _sem_fd(*a, **k):
        raise OSError(_errno.EMFILE, "Too many open files")

    monkeypatch.setattr(port_scanner.socket, "socket", _sem_fd)
    monkeypatch.setattr(port_scanner.time, "sleep", lambda s: None)
    port_scanner.zerar_contador_recursos()
    assert scan_port("127.0.0.1", 80, 0.1) is False
    assert port_scanner.portas_sem_recurso == 1


def test_ip_local_para_loopback():
    assert port_scanner.ip_local_para("127.0.0.1") == "127.0.0.1"
