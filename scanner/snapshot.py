"""
Diff entre scans — detecção de mudança de postura ao longo do tempo.

Esta é a função que separa um scanner pontual de uma ferramenta de monitoramento.
Rodar um scan dá uma foto; comparar com o scan anterior responde a pergunta que o
SOC realmente faz: *o que mudou desde ontem?* "A porta 3389 (RDP) abriu no host X",
"surgiu um CVE crítico novo no Apache", "um Redis ficou exposto sem senha" — isso é
detecção de mudança, trabalho de rotina de um analista N1.

Como funciona:
- Depois de cada scan, salvamos um snapshot por alvo (JSON) num diretório de estado.
- No próximo scan do mesmo alvo, carregamos o snapshot anterior e comparamos.
- A comparação devolve só as DIFERENÇAS, já classificadas por relevância.

Tudo local, sem dependência externa. Se não houver snapshot anterior (primeiro
scan daquele alvo), o diff vem vazio e marcado como `primeira_vez`.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

# Diretório de estado padrão (segue o XDG; sobrescrevível por env ou CLI).
STATE_DIR = Path(
    os.getenv("NETSCAN_STATE", Path.home() / ".local" / "share" / "netscan" / "snapshots")
)


def _slug(alvo: str) -> str:
    """Nome de arquivo seguro a partir do alvo (ex.: '192.168.0.10' -> '192_168_0_10')."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", alvo)


def _resumo_portas(resultados: list[dict]) -> dict[int, dict]:
    """Mapa porta -> {servico, cves:set(ids)} para facilitar a comparação."""
    mapa = {}
    for r in resultados:
        mapa[r["porta"]] = {
            "servico": r.get("servico"),
            "cves": {v["id"] for v in r.get("cves", []) if v.get("id")},
            "kev": {v["id"] for v in r.get("cves", []) if v.get("kev")},
        }
    return mapa


def caminho_snapshot(alvo: str, state_dir: Path | None = None) -> Path:
    return (state_dir or STATE_DIR) / f"{_slug(alvo)}.json"


def carregar_snapshot(alvo: str, state_dir: Path | None = None) -> dict | None:
    """Carrega o último snapshot salvo do alvo, ou None se não existir."""
    p = caminho_snapshot(alvo, state_dir)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def salvar_snapshot(alvo: str, resultados: list[dict], achados_config: list[dict],
                    state_dir: Path | None = None) -> None:
    """Grava o snapshot do scan atual (sobrescreve o anterior do mesmo alvo)."""
    p = caminho_snapshot(alvo, state_dir)
    dados = {
        "alvo": alvo,
        "ts": time.time(),
        "portas": sorted(r["porta"] for r in resultados),
        "servicos": {str(r["porta"]): r.get("servico") for r in resultados},
        "cves": {str(r["porta"]): sorted(v["id"] for v in r.get("cves", []) if v.get("id"))
                 for r in resultados},
        "config": sorted(a.get("id", "") + ":" + str(a.get("porta", "")) for a in achados_config),
    }
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(dados, ensure_ascii=False, indent=2))
    except OSError:
        pass  # snapshot é best-effort; se falhar, o scan segue normal


def comparar(anterior: dict | None, resultados: list[dict],
             achados_config: list[dict]) -> dict:
    """Compara o scan atual com o snapshot anterior. Devolve só as diferenças.

    Campos retornados:
      primeira_vez      -> True se não havia snapshot anterior
      portas_novas      -> portas que abriram desde o último scan
      portas_fechadas   -> portas que fecharam
      servicos_alterados-> [(porta, antes, agora)] quando o serviço/versão mudou
      cves_novos        -> [(porta, cve_id)] CVEs que não existiam antes
      kev_novos         -> [(porta, cve_id)] CVEs novos que estão na KEV
      config_novos      -> achados de má configuração que surgiram
      houve_mudanca     -> True se qualquer uma das listas acima tem item
    """
    atual = _resumo_portas(resultados)
    kev_atual = {r["porta"]: {v["id"] for v in r.get("cves", []) if v.get("kev")}
                 for r in resultados}

    if anterior is None:
        return {
            "primeira_vez": True, "houve_mudanca": False,
            "portas_novas": [], "portas_fechadas": [], "servicos_alterados": [],
            "cves_novos": [], "kev_novos": [], "config_novos": [],
        }

    portas_antes = set(anterior.get("portas", []))
    portas_agora = set(atual.keys())
    serv_antes = {int(k): v for k, v in anterior.get("servicos", {}).items()}
    cves_antes = {int(k): set(v) for k, v in anterior.get("cves", {}).items()}
    config_antes = set(anterior.get("config", []))

    portas_novas = sorted(portas_agora - portas_antes)
    portas_fechadas = sorted(portas_antes - portas_agora)

    servicos_alterados = []
    for porta in sorted(portas_agora & portas_antes):
        antes = serv_antes.get(porta)
        agora = atual[porta]["servico"]
        if (antes or None) != (agora or None):
            servicos_alterados.append((porta, antes, agora))

    cves_novos, kev_novos = [], []
    for porta in sorted(portas_agora):
        novos = atual[porta]["cves"] - cves_antes.get(porta, set())
        for cid in sorted(novos):
            cves_novos.append((porta, cid))
            if cid in kev_atual.get(porta, set()):
                kev_novos.append((porta, cid))

    config_agora = set(a.get("id", "") + ":" + str(a.get("porta", "")) for a in achados_config)
    novos_ids = config_agora - config_antes
    config_novos = [a for a in achados_config
                    if (a.get("id", "") + ":" + str(a.get("porta", ""))) in novos_ids]

    houve = any([portas_novas, portas_fechadas, servicos_alterados,
                 cves_novos, config_novos])
    return {
        "primeira_vez": False, "houve_mudanca": houve,
        "portas_novas": portas_novas, "portas_fechadas": portas_fechadas,
        "servicos_alterados": servicos_alterados,
        "cves_novos": cves_novos, "kev_novos": kev_novos,
        "config_novos": config_novos,
    }


def diff_para_jsonl(alvo: str, diff: dict) -> list[dict]:
    """Converte o diff em eventos planos (um por mudança) para SIEM."""
    eventos = []
    for p in diff.get("portas_novas", []):
        eventos.append({"alvo": alvo, "tipo": "diff", "mudanca": "porta_aberta", "porta": p})
    for p in diff.get("portas_fechadas", []):
        eventos.append({"alvo": alvo, "tipo": "diff", "mudanca": "porta_fechada", "porta": p})
    for porta, antes, agora in diff.get("servicos_alterados", []):
        eventos.append({"alvo": alvo, "tipo": "diff", "mudanca": "servico_alterado",
                        "porta": porta, "antes": antes, "agora": agora})
    for porta, cid in diff.get("cves_novos", []):
        eventos.append({"alvo": alvo, "tipo": "diff", "mudanca": "cve_novo",
                        "porta": porta, "cve": cid,
                        "kev": (porta, cid) in diff.get("kev_novos", [])})
    for a in diff.get("config_novos", []):
        eventos.append({"alvo": alvo, "tipo": "diff", "mudanca": "config_novo", **a})
    return eventos
