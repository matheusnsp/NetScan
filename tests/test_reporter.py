from reporter.html_report import cor_por_score


def test_score_critico_e_vermelho():
    # 9.0 ou mais = crítico = vermelho
    assert cor_por_score(9.8) == "#f85149"


def test_score_alto_e_laranja():
    # 7.0 a 8.9 = alto = laranja
    assert cor_por_score(7.7) == "#ff8c42"


def test_score_medio_e_amarelo():
    # 4.0 a 6.9 = médio = amarelo
    assert cor_por_score(5.1) == "#d29922"


def test_score_baixo_e_verde():
    # abaixo de 4.0 = baixo = verde
    assert cor_por_score(3.3) == "#3fb950"


def test_score_none_e_cinza():
    # sem nota = cinza (caso de borda)
    assert cor_por_score(None) == "#8b949e"