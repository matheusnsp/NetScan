"""Testes de normalização e classificação de MAC (offline, sem API)."""
from scanner.mac_lookup import buscar_fabricante, mac_aleatorio, normalizar_mac


def test_normaliza_zero_a_esquerda():
    # Formato curto do arp do macOS -> zero-padded
    assert normalizar_mac("2:00:5e:10:20:30") == "02:00:5e:10:20:30"
    assert normalizar_mac("e:00:5e:aa:bb:c") == "0e:00:5e:aa:bb:0c"


def test_normaliza_ja_completo():
    assert normalizar_mac("00:1A:11:00:00:01") == "00:1a:11:00:00:01"


def test_mac_aleatorio_detecta_localmente_administrado():
    # Segundo bit do 1º octeto ligado => randomizado/privado
    assert mac_aleatorio("fe:00:00:00:00:01") is True
    assert mac_aleatorio("5e:00:00:00:00:02") is True
    assert mac_aleatorio("02:00:5e:10:20:30") is True   # '02' é local
    assert mac_aleatorio("be:00:00:00:00:03") is True


def test_mac_universal_nao_e_aleatorio():
    # OUIs reais (bit local desligado)
    assert mac_aleatorio("00:1a:11:00:00:01") is False
    assert mac_aleatorio("00:1a:11:00:00:02") is False


def test_buscar_fabricante_nao_consulta_api_para_aleatorio():
    # Deve rotular sem rede (se tentasse a API, o teste dependeria de internet)
    assert buscar_fabricante("fe:00:00:00:00:01") == "Aleatório (privacidade)"
