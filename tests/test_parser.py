# Importa a função que vamos testar
from scanner.parser import extrair_servico


def test_extrai_servico_de_banner_com_server():
    # DADO um banner com linha Server:
    banner = "HTTP/1.0 200 OK\nServer: Apache/2.4.49\nDate: hoje"
    # QUANDO extraímos o serviço
    resultado = extrair_servico(banner)
    # ENTÃO esperamos "Apache 2.4.49" (sem o "Server:", com / virando espaço)
    assert resultado == "Apache 2.4.49"

def test_retorna_none_quando_nao_tem_server():
    # Banner SEM linha Server: deve retornar None (não quebrar)
    banner = "HTTP/1.0 200 OK\nDate: hoje"
    assert extrair_servico(banner) is None


def test_troca_barra_por_espaco():
    # A barra do "Servico/Versao" deve virar espaço
    banner = "Server: nginx/1.18.0"
    assert extrair_servico(banner) == "nginx 1.18.0"