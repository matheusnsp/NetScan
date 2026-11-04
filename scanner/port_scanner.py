"""
Varredura de portas TCP por "connect": para cada porta, o sistema operacional
faz o handshake TCP completo (SYN -> SYN/ACK -> ACK). Não precisa de root.

Também traz o limitador de taxa (--rate), compartilhado por todas as threads,
para quem precisa controlar quantas conexões por segundo saem da máquina.
"""
from __future__ import annotations

import errno
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


class LimitadorTaxa:
    """Garante no máximo `por_segundo` inícios de conexão por segundo.

    Thread-safe: todas as threads do pool pedem uma "vez" aqui antes de
    conectar. Com por_segundo=None (padrão) não limita nada.
    """

    def __init__(self, por_segundo: float | None = None):
        self.intervalo = (1.0 / por_segundo) if por_segundo else 0.0
        self._proximo = 0.0
        self._lock = threading.Lock()

    def aguardar(self) -> None:
        if not self.intervalo:
            return
        with self._lock:
            agora = time.monotonic()
            espera = self._proximo - agora
            self._proximo = max(agora, self._proximo) + self.intervalo
        if espera > 0:
            time.sleep(espera)


def scan_port(host: str, port: int, timeout: float = 1.0) -> bool:
    """
    Tenta se conectar a UMA porta de UM host e diz se ela está aberta.

    Parâmetros:
        host    ->  o IP do alvo (ex: "127.0.0.1"). Resolva nomes ANTES de
                    chamar, para não gerar uma consulta DNS por porta.
        port    ->  o número da porta a testar (ex: 80)
        timeout ->  quanto tempo (em segundos) esperar antes de desistir.
                    Sem isso, uma porta filtrada por firewall deixaria o
                    programa "travado" esperando pra sempre.
    Retorna:
        True    ->  porta aberta (o handshake TCP completou)
        False   ->  porta fechada, filtrada ou qualquer erro de rede
    """
    for _ in range(50):
        try:
            # AF_INET = IPv4; SOCK_STREAM = TCP. O "with" fecha o socket no fim.
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                # connect_ex devolve 0 quando o handshake completa, ou um
                # código de erro (em vez de lançar exceção) quando falha.
                codigo = s.connect_ex((host, port))
        except OSError as e:
            if e.errno in (errno.EMFILE, errno.ENFILE):
                # "Too many open files": muitas threads para o limite do
                # sistema. Espera um socket ser liberado em vez de marcar a
                # porta como fechada (seria um falso negativo).
                time.sleep(0.05)
                continue
            return False  # ex.: nome que não resolve
        if codigo in (errno.EMFILE, errno.ENFILE, errno.EAGAIN):
            time.sleep(0.05)
            continue
        return codigo == 0
    return False


def scan_port_list(host: str, ports, timeout: float = 1.0,
                   max_threads: int = 100,
                   limitador: LimitadorTaxa | None = None) -> list[int]:
    """
    Escaneia APENAS as portas da lista, em paralelo, usando um pool de threads.

    Um perfil como "top100" ou "22,80,443" é esparso: varrer o intervalo
    contíguo entre a menor e a maior porta (7..54321 no top100) custaria
    dezenas de milhares de conexões em vez de ~100.

    Parâmetros:
        host        -> o IP alvo
        ports       -> qualquer iterável de portas (repetições são ignoradas)
        timeout     -> timeout por porta, repassado pra scan_port
        max_threads -> quantas threads no máximo trabalham ao mesmo tempo
        limitador   -> LimitadorTaxa opcional (conexões por segundo)

    Retorna:
        Uma lista ordenada com os números das portas abertas.
    """
    portas = sorted(set(ports))
    if not portas:
        return []

    def _tarefa(port):
        if limitador:
            limitador.aguardar()
        return scan_port(host, port, timeout)

    abertas = []
    with ThreadPoolExecutor(max_workers=min(max_threads, len(portas))) as executor:
        futures = {executor.submit(_tarefa, port): port for port in portas}
        # as_completed devolve os Futures na ordem em que TERMINAM.
        for future in as_completed(futures):
            if future.result():
                abertas.append(futures[future])

    # Ordenamos porque as_completed bagunça a ordem.
    return sorted(abertas)


def scan_ports_fast(host: str, start_port: int, end_port: int,
                    timeout: float = 1.0, max_threads: int = 100) -> list[int]:
    """Atalho para varrer um range contíguo (start_port..end_port, inclusive)."""
    return scan_port_list(host, range(start_port, end_port + 1), timeout, max_threads)


# --------------------------- descoberta de hosts ---------------------------

# Portas usadas para "pingar" por TCP. Não precisam estar abertas: se o host
# responder com RST (conexão recusada), ele existe.
PORTAS_SONDA = (22, 80, 443, 445, 3389)


def host_responde(host: str, portas=PORTAS_SONDA, timeout: float = 1.0,
                  limitador: LimitadorTaxa | None = None) -> bool:
    """True se o host responder em QUALQUER porta de sonda.

    "Responder" inclui recusar a conexão (RST): isso prova que há uma máquina
    ali. Só um host inexistente (ou um firewall que descarta tudo) fica mudo.
    """
    for porta in portas:
        if limitador:
            limitador.aguardar()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                codigo = s.connect_ex((host, porta))
        except OSError:
            continue
        if codigo in (0, errno.ECONNREFUSED):
            return True
    return False


def descobrir_hosts(ips: list[str], timeout: float = 1.0, max_threads: int = 64,
                    limitador: LimitadorTaxa | None = None) -> list[str]:
    """Filtra a lista de IPs, devolvendo só os que respondem (ping TCP).

    Usado antes da varredura de uma faixa (CIDR), para não gastar a varredura
    completa de portas em endereços vazios.
    """
    if not ips:
        return []
    vivos = []
    with ThreadPoolExecutor(max_workers=min(max_threads, len(ips))) as executor:
        futures = {executor.submit(host_responde, ip, PORTAS_SONDA, timeout, limitador): ip
                   for ip in ips}
        for future in as_completed(futures):
            if future.result():
                vivos.append(futures[future])
    ordem = {ip: i for i, ip in enumerate(ips)}
    return sorted(vivos, key=ordem.get)
