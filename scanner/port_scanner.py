import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


def scan_port(host: str, port: int, timeout: float = 1.0) -> bool:
    
    """

    Tenta se conectar a UMA porta de UM host e diz se ela está aberta.

    Parâmetros:
        host    ->  o IP ou nome do alvo (ex: "127.0.0.1")
        port    ->  o número da porta a testar (ex: 80)
        timeout ->  quanto tempo (em segundos) esperar antes de desistir.
                    Importante: sem isso, uma porta filtrada por firewall 
                    deixaria o programa "travado" esperando pra sempre.
    Retorna:
        True    ->  se a porta estiver aberta (ou seja, se a conexão for bem-sucedida)
        False   ->  se a porta estiver fechada ou filtrada (ou seja, se a conexão falhar)

    """
    # Criamos um objeto socket. Pense nele como um "telefone" que vamos
    # usar para ligar pro alvo. Os dois argumentos definem o tipo de ligação:
    #   AF_INET -> vamos usar IPv4 (endereços tipo 192.168.0.1)
    #   SOCK_STREAM -> vamos usar TCP (conexão confiável, com handshake)
    # 
    # O "with" garante que o telefone seja DESLIGADO automaticamente no fim,
    # mesmo se der erro. Sem isso, sobrariam conexões abertas consumindo
    # recursos do sistema.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Define o tempo máximo de espera por uma resposta.
        # Se passar disso sem resposta, a tentativa falha (porta filtrada).
        s.settimeout(timeout)

        # AQUI mora o coração da varredura.
        # conntext_ex() tenta fazer o handshake TCP com (host, porta).

        # Diferença importante:
        #   - connect()     -> LANÇA uma excessão se falhar (dá erro feio)
        #   - connect_ex()  -> RETORNA um número (código de erro) se falhar

        # Usamos connect_ex porque é mais limpo: ele devolve 0 quando a 
        # conexão deu erro, e um número diferente de 0 quando falhou.
        result = s.connect_ex((host, port))

        # Se result == 0, o handshake completou -> a porta está ABERTA.
        # Qualquer outro número significa que não conseguimos conectar.
        # A expressão "result == 0" já é um booleano (True/False),
        # então retornamos ela diretamente.
        return result == 0
    

def scan_port_list(host: str, ports, timeout: float = 1.0,
                   max_threads: int = 100) -> list[int]:
    """
    Escaneia APENAS as portas da lista, em paralelo, usando um pool de threads.

    É o que a CLI usa: um perfil como "top100" ou "22,80,443" é esparso, e
    varrer o intervalo contíguo entre a menor e a maior porta (7..54321 no
    top100) custaria dezenas de milhares de conexões em vez de ~100.

    Parâmetros:
        host        -> o IP/host alvo
        ports       -> qualquer iterável de portas (repetições são ignoradas)
        timeout     -> timeout por porta, repassado pra scan_port
        max_threads -> quantas threads no máximo trabalham ao mesmo tempo

    Retorna:
        Uma lista ordenada com os números das portas abertas.
    """
    portas = sorted(set(ports))
    if not portas:
        return []

    abertas = []
    with ThreadPoolExecutor(max_workers=min(max_threads, len(portas))) as executor:
        # Uma tarefa por porta pedida. Guardamos { future: porta } pra saber
        # qual porta cada resultado representa.
        futures = {executor.submit(scan_port, host, port, timeout): port
                   for port in portas}

        # as_completed devolve os Futures na ordem em que TERMINAM.
        for future in as_completed(futures):
            if future.result():
                abertas.append(futures[future])

    # Ordenamos porque as_completed bagunça a ordem.
    return sorted(abertas)


def scan_ports_fast(host: str, start_port: int, end_port: int,
                    timeout: float = 1.0, max_threads: int = 100) -> list[int]:
    """
    Escaneia um range contíguo de portas (start_port..end_port, inclusive).

    Atalho para scan_port_list(host, range(start_port, end_port + 1), ...).
    """
    return scan_port_list(host, range(start_port, end_port + 1), timeout, max_threads)
