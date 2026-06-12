def cor_por_score(score):
    """Retorna uma cor conforme a gravidade do CVSS."""
    if score is None:
        return "#8b949e"        # cinza (sem nota)
    if score >= 9.0:
        return "#f85149"        # vermelho — crítico
    if score >= 7.0:
        return "#ff8c42"        # laranja — alto
    if score >= 4.0:
        return "#d29922"        # amarelo — médio
    return "#3fb950"            # verde — baixo


def gerar_html(alvo: str, resultados: list[dict]) -> str:
    """Monta o relatório HTML a partir dos resultados do scan."""

    total_portas = len(resultados)
    total_cves = sum(len(r["cves"]) for r in resultados)

    # ---- CASCA: cria a variável html com o início da página ----
    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Relatório NetScan - {alvo}</title>
    <style>
        body {{ font-family: -apple-system, Arial, sans-serif; margin: 40px; background: #0d1117; color: #e6edf3; }}
        h1 {{ color: #58a6ff; }}
        .resumo {{ background: #161b22; padding: 16px 20px; border-radius: 8px; margin-bottom: 24px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid #30363d; }}
        th {{ background: #161b22; }}
    </style>
</head>
<body>
    <h1>Relatório de Varredura — {alvo}</h1>
    <div class="resumo">
        <strong>{total_portas}</strong> porta(s) aberta(s) ·
        <strong>{total_cves}</strong> vulnerabilidade(s) encontrada(s)
    </div>
"""

    # ---- MIOLO: adiciona a tabela ao html ----
    html += """
    <table>
        <tr>
            <th>Porta</th>
            <th>Serviço</th>
            <th>Vulnerabilidades</th>
        </tr>
"""

    for r in resultados:
        servico = r["servico"] or "—"

        if r["cves"]:
            cves_html = ""
            for v in r["cves"]:
                cor = cor_por_score(v["score"])
                cves_html += f'<span style="color:{cor}">[{v["score"]}] {v["id"]}</span><br>'
        else:
            cves_html = "—"

        html += f"""
        <tr>
            <td>{r["porta"]}</td>
            <td>{servico}</td>
            <td>{cves_html}</td>
        </tr>
"""

    html += """
    </table>
</body>
</html>
"""
    return html