"""Testes de normalização e classificação de MAC (offline, sem API)."""
from scanner.mac_lookup import buscar_fabricante, mac_aleatorio, normalizar_mac


def test_normaliza_zero_a_esquerda():
    # Formato curto do arp do macOS -> zero-padded
    assert normalizar_mac("2:10:18:ed:70:60") == "02:10:18:ed:70:60"
    assert normalizar_mac("e:58:c7:43:54:8") == "0e:58:c7:43:54:08"


def test_normaliza_ja_completo():
    assert normalizar_mac("2C:DC:D7:34:1A:11") == "2c:dc:d7:34:1a:11"


def test_mac_aleatorio_detecta_localmente_administrado():
    # Segundo bit do 1º octeto ligado => randomizado/privado
    assert mac_aleatorio("fe:31:5d:7a:10:d7") is True
    assert mac_aleatorio("5e:34:90:f3:f0:3e") is True
    assert mac_aleatorio("02:10:18:ed:70:60") is True   # '02' é local
    assert mac_aleatorio("be:75:9d:74:bf:90") is True


def test_mac_universal_nao_e_aleatorio():
    # OUIs reais (bit local desligado)
    assert mac_aleatorio("2c:dc:d7:34:1a:11") is False
    assert mac_aleatorio("4c:c9:5e:b1:8a:d7") is False


def test_buscar_fabricante_nao_consulta_api_para_aleatorio():
    # Deve rotular sem rede (se tentasse a API, o teste dependeria de internet)
    assert buscar_fabricante("fe:31:5d:7a:10:d7") == "Aleatório (privacidade)"
