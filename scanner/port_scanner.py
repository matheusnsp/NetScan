import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


def scan_port(host: str, port: int, timeout: float = 1.0) -> bool:
    
    """

    Tenta se conectar a UMA porta de UM host e diz se ela está aberta.

    Parâmetros:
        host    -> o IP ou nome do alvo (ex: "127.0.0.1")
        port    -> o número da porta a testar (ex: 80)
        timeout -> quanto tempo (em segundos) esperar antes de desistir.
                   Importante: sem isso, uma porta filtrada por firewall 
                   deixaria o programa "travado" esperando pra sempre.
    Retorna:
        True    se a porta estiver aberta (ou seja, se a conexão for bem-sucedida)
        False   se a porta estiver fechada ou filtrada (ou seja, se a conexão falhar)

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
    

def scan_ports_fast(host: str, start_port: int, end_port: int,
                    timeout: float = 1.0, max_threads: int = 100) ->[int]:
    """

    Escaneira um range de portas em paralelo usando um pool threads.

    Parâmetros:
        host        -> o IP/host alvo
        start_port  -> primeira porta do range (inclusive)
        end_port    -> última porta do range (inclusive)
        timeout     -> timeout por porta, repassando pra scan_port
        max_threads -> quantas threads no máximo trabalham ao mesmo tempo

    Retorna:
        Uma lista ordenada com os números das portas abertas.
    
    """

    # Lista onde vamos juntar as portas abertas conforme forem descobertas.
    abertas = []

    # Criamos o pool de threads. O "with" garante que o pool seja
    # encerrado corretamente no fim (espera as threads e libera recursos).
    # max_workers = teto de threads rodando simultaneamente.
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        # ---- PASSO 1: agendar uma tarefa por porta ----
        # Para cada porta do range, pedimos ao executor pra rodar
        # scan_port(host, porta, timeout) em ALGUMA thread do pool.

        #  executor.submit NÃO espera o resultado. Ele agenda a tarefa
        # e devolve na hora um objeto "Future" - uma espécie de 
        # "comprovante"que mais tarde conterá o resultado.

        # Guardamos esses Futures num dicionário { future: porta },
        # pra depois sabermos qual porta cada resultado representa.
        futures = {
            executor.submit(scan_port, host, port, timeout,): port
            for port in range(start_port, end_port + 1)
        }

        # ---- PASSO 2: colher os resultados conforme ficam prontos ----
        # as_completed devolve os Futures NA ORDEM em que TERMINAM
        # (não na ordem em que foram criados). Ou seja, o resultado
        # da primeira porta que responder chega primeiro.
        for future in as_completed(futures):
            # Recuperamos qual porta era este Future, usando o dicionário.
            port = futures[future]

            # future.result() devolve o que scan_port retornou (True/False).
            if future.result():
                abertas.append(port)
    
    # Ordenamos antes de retornar, porque as_completed bagunça a ordem
    # (a porta 900 pode ter respondido antes da porta 50).
    return sorted(abertas)