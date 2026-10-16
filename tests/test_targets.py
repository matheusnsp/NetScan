"""Testes da resolução de alvos e perfis de portas."""
import pytest

from scanner.targets import TOP_100, parse_alvos, parse_portas


def test_top100():
    assert parse_portas("top100") == sorted(set(TOP_100))
    assert 80 in parse_portas("top100") and 443 in parse_portas("top100")


def test_range():
    assert parse_portas("1-5") == [1, 2, 3, 4, 5]


def test_lista_e_range_combinados():
    assert parse_portas("22,80,8000-8002") == [22, 80, 8000, 8001, 8002]


def test_remove_duplicatas_e_ordena():
    assert parse_portas("80,22,80") == [22, 80]


def test_spec_invalido():
    with pytest.raises(ValueError):
        parse_portas("")


def test_portas_fora_do_range_sao_descartadas():
    assert parse_portas("0,80,70000") == [80]


def test_cidr_expande():
    alvos = parse_alvos("192.168.0.0/30")
    assert alvos == ["192.168.0.1", "192.168.0.2"]


def test_ip_unico():
    assert parse_alvos("10.0.0.5") == ["10.0.0.5"]


def test_arquivo_de_alvos(tmp_path):
    f = tmp_path / "alvos.txt"
    f.write_text("# comentário\n10.0.0.1\n\n10.0.0.2\n")
    assert parse_alvos(str(f)) == ["10.0.0.1", "10.0.0.2"]
