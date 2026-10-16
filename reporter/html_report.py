"""
Relatório HTML.

Mudanças frente à versão antiga:
- Todo dado dinâmico passa por escape (html.escape). Antes, banners e nomes de
  serviço iam crus para dentro do HTML — uma ferramenta de SEGURANÇA que abria um
  XSS no próprio relatório. Corrigido.
- Resumo executivo no topo: score de risco do host, contagem por severidade e o
  "corrija primeiro" (CVEs KEV / top prioridade).
- Badges de KEV (exploração ativa) e EPSS (probabilidade), quando disponíveis.
- Seção de achados de configuração (não-CVE).
"""
from __future__ import annotations

import html

from scanner.scoring import resumir


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


_COR_ROTULO = {
    "CRÍTICO": "#f85149", "ALTO": "#ff8c42", "MÉDIO": "#d29922",
    "BAIXO": "#3fb950", "OK": "#3fb950",
}


def _esc(valor) -> str:
    """Escapa qualquer valor para inserção segura no HTML."""
    return html.escape(str(valor), quote=True)


def _badges(v: dict) -> str:
    b = ""
    if v.get("kev"):
        b += ' <span class="badge kev">KEV</span>'
    epss = v.get("epss")
    if epss is not None:
        b += f' <span class="badge epss">EPSS {epss:.0%}</span>'
    return b


def gerar_html(alvo: str, resultados: list[dict],
               achados_config: list[dict] | None = None) -> str:
    """Monta o relatório HTML a partir dos resultados do scan."""
    achados_config = achados_config or []
    resumo = resumir(resultados, achados_config)
    c = resumo["contagem"]
    cor_rotulo = _COR_ROTULO.get(resumo["rotulo_risco"], "#8b949e")

    html_doc = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Relatório NetScan - {_esc(alvo)}</title>
    <style>
        body {{ font-family: -apple-system, Segoe UI, Arial, sans-serif; margin: 0; padding: 40px; background: #0d1117; color: #e6edf3; }}
        h1 {{ color: #58a6ff; margin-bottom: 4px; }}
        h2 {{ color: #58a6ff; margin-top: 36px; font-size: 1.2em; }}
        .sub {{ color: #8b949e; margin-top: 0; }}
        .cards {{ display: flex; flex-wrap: wrap; gap: 16px; margin: 24px 0; }}
        .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 16px 20px; min-width: 120px; }}
        .card .n {{ font-size: 1.8em; font-weight: 700; }}
        .card .l {{ color: #8b949e; font-size: .85em; text-transform: uppercase; letter-spacing: .04em; }}
        .risco {{ border-left: 6px solid {cor_rotulo}; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 8px; }}
        th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid #30363d; vertical-align: top; }}
        th {{ background: #161b22; position: sticky; top: 0; }}
        .badge {{ display: inline-block; font-size: .72em; font-weight: 700; padding: 1px 6px; border-radius: 6px; vertical-align: middle; }}
        .badge.kev {{ background: #f85149; color: #fff; }}
        .badge.epss {{ background: #30363d; color: #e6edf3; }}
        .sev {{ font-weight: 700; padding: 2px 8px; border-radius: 6px; font-size: .85em; }}
        .desc {{ color: #8b949e; font-size: .9em; }}
        code {{ background: #161b22; padding: 1px 5px; border-radius: 4px; }}
        footer {{ margin-top: 40px; color: #8b949e; font-size: .8em; }}
    </style>
</head>
<body>
    <h1>Relatório de Varredura</h1>
    <p class="sub">Alvo: <code>{_esc(alvo)}</code></p>

    <div class="cards">
        <div class="card risco">
            <div class="n" style="color:{cor_rotulo}">{_esc(resumo['rotulo_risco'])}</div>
            <div class="l">Risco do host · {resumo['score_risco']}/100</div>
        </div>
        <div class="card"><div class="n">{resumo['total_portas']}</div><div class="l">Portas abertas</div></div>
        <div class="card"><div class="n">{resumo['total_cves']}</div><div class="l">CVEs</div></div>
        <div class="card"><div class="n" style="color:#f85149">{resumo['total_kev']}</div><div class="l">KEV (exploração ativa)</div></div>
        <div class="card"><div class="n">{resumo['total_config']}</div><div class="l">Má configuração</div></div>
    </div>
    <div class="cards">
        <div class="card"><div class="n" style="color:#f85149">{c['CRÍTICA']}</div><div class="l">Críticos</div></div>
        <div class="card"><div class="n" style="color:#ff8c42">{c['ALTA']}</div><div class="l">Altos</div></div>
        <div class="card"><div class="n" style="color:#d29922">{c['MÉDIA']}</div><div class="l">Médios</div></div>
        <div class="card"><div class="n" style="color:#3fb950">{c['BAIXA']}</div><div class="l">Baixos</div></div>
    </div>
"""

    # ---- Corrija primeiro ----
    if resumo["top_cves"]:
        html_doc += "<h2>🎯 Corrija primeiro</h2>\n<table>\n"
        html_doc += "<tr><th>CVE</th><th>CVSS</th><th>Sinais</th><th>Porta / Serviço</th></tr>\n"
        for v in resumo["top_cves"]:
            cor = cor_por_score(v.get("score"))
            html_doc += (
                "<tr>"
                f"<td><code>{_esc(v['id'])}</code></td>"
                f"<td style='color:{cor};font-weight:700'>{_esc(v.get('score'))}</td>"
                f"<td>{_badges(v) or '—'}</td>"
                f"<td>{_esc(v.get('porta'))} / {_esc(v.get('servico') or '—')}</td>"
                "</tr>\n"
            )
        html_doc += "</table>\n"

    # ---- Achados de configuração ----
    if achados_config:
        html_doc += "<h2>⚠️ Má configuração</h2>\n<table>\n"
        html_doc += "<tr><th>Severidade</th><th>Porta</th><th>Achado</th></tr>\n"
        for a in achados_config:
            cor = _COR_ROTULO.get({"CRÍTICA": "CRÍTICO", "ALTA": "ALTO",
                                   "MÉDIA": "MÉDIO", "BAIXA": "BAIXO"}.get(
                                       a.get("severidade"), "OK"), "#8b949e")
            html_doc += (
                "<tr>"
                f"<td><span class='sev' style='background:{cor}22;color:{cor}'>{_esc(a.get('severidade'))}</span></td>"
                f"<td>{_esc(a.get('porta'))}</td>"
                f"<td><strong>{_esc(a.get('titulo'))}</strong><br>"
                f"<span class='desc'>{_esc(a.get('descricao'))}</span></td>"
                "</tr>\n"
            )
        html_doc += "</table>\n"

    # ---- Detalhe por porta ----
    html_doc += "<h2>📋 Portas e serviços</h2>\n<table>\n"
    html_doc += "<tr><th>Porta</th><th>Serviço</th><th>Vulnerabilidades</th></tr>\n"
    for r in resultados:
        servico = _esc(r.get("servico") or "—")
        if r.get("cves"):
            cves_html = ""
            for v in r["cves"]:
                cor = cor_por_score(v.get("score"))
                cves_html += (
                    f'<span style="color:{cor}">[{_esc(v.get("score"))}] '
                    f'{_esc(v["id"])}</span>{_badges(v)}<br>'
                )
        else:
            cves_html = "—"
        html_doc += (
            f"<tr><td>{_esc(r.get('porta'))}</td><td>{servico}</td>"
            f"<td>{cves_html}</td></tr>\n"
        )
    html_doc += "</table>\n"

    html_doc += (
        "<footer>Gerado pelo NetScan · O score de risco é um auxílio de triagem, "
        "não um laudo. Use apenas em redes próprias ou autorizadas.</footer>\n"
        "</body>\n</html>\n"
    )
    return html_doc
