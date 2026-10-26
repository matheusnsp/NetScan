"""
NetScan — ponto de entrada e orquestração.

Dois jeitos de usar:

  1. CLI (scriptável, como qualquer scanner de verdade):
       python3 main.py 192.168.0.10 --ports top100 --format html,json
       python3 main.py 192.168.0.0/24 --ports 1-1024
       python3 main.py alvos.txt --ports 22,80,443 --no-vuln
       python3 main.py --demo

  2. Menu interativo (sem argumentos), igual à versão anterior:
       python3 main.py

O fluxo por alvo: varre portas -> detecta serviço por protocolo -> cruza com
CVEs (NVD, via CPE) -> checa má configuração -> enriquece com KEV/EPSS ->
gera relatórios e imprime um resumo priorizado.

Uso restrito a redes próprias ou com autorização explícita (ver README).
"""
from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path

from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from reporter.csv_report import gerar_csv
from reporter.html_report import gerar_html
from reporter.json_report import gerar_json, gerar_jsonl
from scanner.enrich import enriquecer
from concurrent.futures import ThreadPoolExecutor

from scanner.host_discovery import read_arp_table, reverse_dns
from scanner.mac_lookup import buscar_fabricante, mac_aleatorio
from scanner.misconfig import checar_porta
from scanner.port_scanner import scan_port_list
from scanner.scoring import resumir
from scanner.service_detect import detectar_servico
from scanner.snapshot import (carregar_snapshot, comparar, diff_para_jsonl,
                              salvar_snapshot)
from scanner.targets import parse_alvos, parse_portas
from scanner.vuln_checker import buscar_vulnerabilidades

console = Console()
log = logging.getLogger("netscan")


NETSCAN_ASCII = r"""
███╗   ██╗███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
██╔██╗ ██║█████╗     ██║   ███████╗██║     ███████║██╔██╗ ██║
██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
██║ ╚████║███████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
"""


def banner_inicial():
    console.print(Align.center(Text(NETSCAN_ASCII, style="bold cyan")))
    console.print(Align.center(
        Text("Network Scanner & Vulnerability Reporter", style="dim italic")))
    console.print()


def cor_severidade(score):
    if score is None:
        return "grey50"
    if score >= 9.0:
        return "bold red"
    if score >= 7.0:
        return "dark_orange"
    if score >= 4.0:
        return "yellow"
    return "green"


def painel_alvo(ip, descricao=None, mac=None, portas=None):
    info = Table.grid(padding=(0, 2))
    info.add_column(justify="right", style="dim")
    info.add_column(style="bold cyan")
    info.add_row("IP", ip)
    if descricao:
        info.add_row("Tipo", f"[white]{descricao}[/]")
    if mac:
        info.add_row("MAC", f"[dim]{mac}[/]")
    if portas:
        info.add_row("Portas", f"[white]{portas}[/]")
    return Panel(info, title="[bold red]\U0001F3AF[/] [bold]ALVO[/]",
                 border_style="cyan", expand=False, padding=(1, 2))


def montar_tabela_resumo(resultados):
    tabela = Table(title="\U0001F4CB Resumo da Varredura", border_style="cyan", title_style="bold")
    tabela.add_column("Porta", justify="center", style="cyan")
    tabela.add_column("Serviço", style="white")
    tabela.add_column("Vulnerabilidades", justify="center")
    for r in resultados:
        cves = r["cves"]
        servico = r["servico"] or "[dim]—[/]"
        if cves:
            scores = [v["score"] for v in cves if v["score"] is not None]
            pior = max(scores) if scores else None
            kev = sum(1 for v in cves if v.get("kev"))
            txt = f"{len(cves)} CVE(s)" + (f" · {kev} KEV" if kev else "")
            vuln_txt = Text(txt, style=cor_severidade(pior))
        else:
            vuln_txt = Text("—", style="dim")
        tabela.add_row(str(r["porta"]), servico, vuln_txt)
    return tabela


def _nome_servico(info: dict | None) -> str | None:
    if not info or not info.get("produto"):
        return None
    return f"{info['produto']} {info['versao']}".strip() if info.get("versao") else info["produto"]


def escanear_alvo(alvo: str, portas: list[int], timeout: float, threads: int,
                  buscar_cve: bool = True, checar_config: bool = True,
                  narrar: bool = True) -> tuple[list[dict], list[dict]]:
    """Escaneia UM alvo. Devolve (resultados_por_porta, achados_de_config)."""
    if narrar:
        console.print(painel_alvo(alvo, portas=f"{len(portas)} porta(s)"))
        console.print("\n[bold yellow][*][/] Varredura de portas...")

    # Só as portas pedidas: um perfil esparso como top100 (7..54321) tem 100
    # portas, não 54 mil — varrer o intervalo inteiro levava minutos à toa.
    portas_abertas = scan_port_list(alvo, portas, timeout, threads)

    if narrar:
        console.print(f"[bold green][+][/] {len(portas_abertas)} aberta(s): [cyan]{portas_abertas}[/]\n")

    resultados, achados_config = [], []
    for porta in portas_abertas:
        if narrar:
            console.print(f"[bold yellow][*][/] Porta [cyan]{porta}[/]...")
        info = detectar_servico(alvo, porta, timeout)
        servico = _nome_servico(info)
        cves = []

        if servico and narrar:
            console.print(f"    [green][+][/] Serviço: [bold]{servico}[/]")
        if servico and buscar_cve:
            if narrar:
                console.print("    [yellow][*][/] Consultando NVD (CPE)...")
            cves = buscar_vulnerabilidades(info["produto"], info.get("versao"))
            if narrar and cves:
                console.print(f"    [bold red][!][/] {len(cves)} CVE(s)")

        if checar_config:
            novos = checar_porta(alvo, porta, info, timeout)
            for a in novos:
                a["alvo"] = alvo
            achados_config.extend(novos)
            if narrar and novos:
                for a in novos:
                    console.print(f"    [bold magenta][⚠][/] {a['titulo']}")

        resultados.append({
            "porta": porta,
            "banner": (info or {}).get("banner"),
            "servico": servico,
            "protocolo": (info or {}).get("protocolo"),
            "cves": cves,
        })

    if buscar_cve:
        if narrar:
            console.print("\n[bold yellow][*][/] Enriquecendo com CISA KEV + EPSS...")
        enriquecer(resultados)

    if narrar:
        console.print()
        console.print(montar_tabela_resumo(resultados))
        console.print("[bold green]✓ Varredura concluída.[/]\n")
    return resultados, achados_config


def salvar_relatorios(alvo: str, resultados: list[dict], achados_config: list[dict],
                      formatos: list[str], saida: Path, diff: dict | None = None) -> list[Path]:
    """Gera os relatórios nos formatos pedidos. Retorna os caminhos criados."""
    saida.mkdir(parents=True, exist_ok=True)
    # Não usar with_suffix: um alvo como "127.0.0.1" tem pontos e seria truncado.
    slug = (alvo.replace(" ", "_").replace("(", "").replace(")", "").replace("/", "_"))
    base = str(saida / f"relatorio_{slug}")
    criados = []
    if "html" in formatos:
        p = Path(base + ".html")
        p.write_text(gerar_html(alvo, resultados, achados_config, diff), encoding="utf-8")
        criados.append(p)
    if "json" in formatos:
        p = Path(base + ".json")
        gerar_json(alvo, resultados, str(p), achados_config)
        criados.append(p)
    if "jsonl" in formatos:
        p = Path(base + ".jsonl")
        gerar_jsonl(alvo, resultados, str(p), achados_config,
                    diff_para_jsonl(alvo, diff) if diff else None)
        criados.append(p)
    if "csv" in formatos:
        p = Path(base + ".csv")
        gerar_csv(resultados, str(p))
        criados.append(p)
    return criados


def imprimir_diff(diff: dict | None):
    """Imprime o painel 'mudanças desde o último scan' quando houver."""
    if not diff or diff.get("primeira_vez"):
        if diff and diff.get("primeira_vez"):
            console.print("[dim]Primeiro scan deste alvo — snapshot salvo como linha de base.[/]")
        return
    if not diff.get("houve_mudanca"):
        console.print("[dim]Sem mudanças desde o último scan.[/]")
        return

    linhas = []
    for p in diff["portas_novas"]:
        linhas.append(f"[bold green]+ porta {p} ABRIU[/]")
    for p in diff["portas_fechadas"]:
        linhas.append(f"[dim]- porta {p} fechou[/]")
    for porta, antes, agora in diff["servicos_alterados"]:
        linhas.append(f"[yellow]~ porta {porta}: {antes or '—'} → {agora or '—'}[/]")
    kev_set = set(diff.get("kev_novos", []))
    for porta, cid in diff["cves_novos"]:
        marca = " [bold red](KEV)[/]" if (porta, cid) in kev_set else ""
        linhas.append(f"[red]! CVE novo em {porta}: {cid}{marca}[/]")
    for a in diff["config_novos"]:
        linhas.append(f"[magenta]! config: {a.get('titulo')} (porta {a.get('porta')})[/]")

    console.print(Panel("\n".join(linhas),
                        title="[bold]🔔 Mudanças desde o último scan[/]",
                        border_style="yellow", expand=False))


# ----------------------------- MODO DEMONSTRAÇÃO -----------------------------

HOSTS_DEMO = [
    {"ip": "192.168.0.100", "mac": "00:1a:11:3c:4d:5e", "descricao": "Servidor Web",
     "servicos": [{"porta": 22, "produto": "openssh", "versao": "8.9"},
                  {"porta": 80, "produto": "apache httpd", "versao": "2.4.49"},
                  {"porta": 443, "produto": "nginx", "versao": "1.18.0"}]},
    {"ip": "192.168.0.101", "mac": "2c:dc:d7:8a:9b:0c", "descricao": "Banco de Dados",
     "servicos": [{"porta": 3306, "produto": "mysql", "versao": "5.5.0"},
                  {"porta": 6379, "produto": "redis", "versao": "5.0.0"}]},
]


def escanear_demo(host: dict) -> tuple[list[dict], list[dict]]:
    """Cenário fictício, mas com CVEs reais da NVD. Para apresentar sem rede exposta."""
    console.print(painel_alvo(host["ip"], descricao=host["descricao"], mac=host["mac"]))
    console.print()
    resultados = []
    for s in host["servicos"]:
        servico = f"{s['produto']} {s['versao']}"
        console.print(f"[bold yellow][*][/] Porta [cyan]{s['porta']}[/] — [bold]{servico}[/]")
        time.sleep(0.3)
        cves = buscar_vulnerabilidades(s["produto"], s["versao"])
        console.print(f"    [bold red][!][/] {len(cves)} CVE(s)" if cves
                      else "    [dim][-] Sem CVE conhecido.[/]")
        resultados.append({"porta": s["porta"], "banner": f"demo {servico}",
                           "servico": servico, "protocolo": "demo", "cves": cves})
    enriquecer(resultados)
    console.print()
    console.print(montar_tabela_resumo(resultados))
    return resultados, []


def listar_hosts():
    aparelhos = read_arp_table()
    console.print("[bold yellow][*][/] Descobrindo aparelhos (ARP + DNS reverso)...\n")

    # Enriquecimento concorrente: fabricante (OUI) e nome por DNS reverso.
    def _enriquecer(ap):
        ap["fabricante"] = buscar_fabricante(ap["mac"])
        ap["hostname"] = ap.get("hostname_arp") or reverse_dns(ap["ip"])
        ap["aleatorio"] = mac_aleatorio(ap["mac"])
        return ap

    with ThreadPoolExecutor(max_workers=16) as ex:
        aparelhos = list(ex.map(_enriquecer, aparelhos))

    tabela = Table(border_style="cyan", title="Aparelhos na rede", title_style="bold")
    tabela.add_column("#", style="bold yellow", justify="center")
    tabela.add_column("IP", style="cyan")
    tabela.add_column("Nome (DNS)", style="white")
    tabela.add_column("MAC", style="dim")
    tabela.add_column("Tipo", style="white", justify="center")
    tabela.add_column("Fabricante", style="white")
    tabela.add_column("Iface", style="dim", justify="center")

    for i, ap in enumerate(aparelhos, start=1):
        tipo = "[yellow]aleatório[/]" if ap["aleatorio"] else "[green]público[/]"
        nome = ap.get("hostname") or "[dim]—[/]"
        fab = ap["fabricante"]
        if fab == "Aleatório (privacidade)":
            fab = "[dim]— (MAC privado)[/]"
        elif fab == "Desconhecido":
            fab = "[dim]Desconhecido[/]"
        tabela.add_row(str(i), ap["ip"], nome, ap["mac"], tipo, fab,
                       ap.get("interface") or "—")

    console.print(tabela)
    n_aleatorios = sum(1 for a in aparelhos if a["aleatorio"])
    if n_aleatorios:
        console.print(
            f"[dim]ℹ {n_aleatorios} de {len(aparelhos)} usam MAC aleatório "
            f"(privacidade) — sem fabricante público; normal em celulares/notebooks.[/]\n")
    return aparelhos


def imprimir_veredito(resultados, achados_config):
    r = resumir(resultados, achados_config)
    cor = {"CRÍTICO": "bold red", "ALTO": "dark_orange", "MÉDIO": "yellow",
           "BAIXO": "green", "OK": "green"}.get(r["rotulo_risco"], "white")
    console.print(Panel(
        f"Risco do host: [{cor}]{r['rotulo_risco']}[/] ({r['score_risco']}/100)\n"
        f"CVEs: {r['total_cves']}  ·  KEV (exploração ativa): [bold red]{r['total_kev']}[/]  ·  "
        f"Má configuração: {r['total_config']}",
        title="[bold]Veredito[/]", border_style=cor.split()[-1], expand=False))


# ----------------------------------- CLI -----------------------------------

def construir_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netscan",
        description="Scanner de rede e relatório de vulnerabilidades (uso autorizado).")
    p.add_argument("alvo", nargs="?",
                   help="IP, hostname, CIDR (192.168.0.0/24) ou arquivo com um alvo por linha")
    p.add_argument("-p", "--ports", default="top100",
                   help="top100 | all | 1-1024 | 80,443,8080 (padrão: top100)")
    p.add_argument("-f", "--format", default="html,json",
                   help="html,json,jsonl,csv separados por vírgula (padrão: html,json)")
    p.add_argument("-o", "--output", default=".", help="diretório de saída")
    p.add_argument("-t", "--timeout", type=float, default=1.5, help="timeout por conexão (s)")
    p.add_argument("--threads", type=int, default=100, help="threads de varredura")
    p.add_argument("--no-vuln", action="store_true", help="não consultar CVEs (só portas/serviços)")
    p.add_argument("--no-config", action="store_true", help="pular checagens de má configuração")
    p.add_argument("--demo", action="store_true", help="modo demonstração (cenário fictício, CVEs reais)")
    p.add_argument("--no-diff", action="store_true", help="não comparar com o scan anterior")
    p.add_argument("--state-dir", help="diretório dos snapshots (padrão: ~/.local/share/netscan)")
    p.add_argument("--log", help="arquivo de log (opcional)")
    p.add_argument("-q", "--quiet", action="store_true", help="menos saída no terminal")
    return p


def rodar_cli(args) -> int:
    if args.log:
        logging.basicConfig(filename=args.log, level=logging.INFO,
                            format="%(asctime)s %(levelname)s %(message)s")
    formatos = [f.strip() for f in args.format.split(",") if f.strip()]
    saida = Path(args.output)

    if args.demo:
        resultados, config = escanear_demo(HOSTS_DEMO[0])
        criados = salvar_relatorios("DEMO_" + HOSTS_DEMO[0]["ip"], resultados, config, formatos, saida)
        imprimir_veredito(resultados, config)
        console.print(f"[green]✓[/] Relatórios: {', '.join(str(c) for c in criados)}")
        return 0

    try:
        portas = parse_portas(args.ports)
        alvos = parse_alvos(args.alvo)
    except ValueError as e:
        console.print(f"[bold red]Erro:[/] {e}")
        return 2

    state_dir = Path(args.state_dir) if args.state_dir else None
    log.info("iniciando scan de %d alvo(s) em %d porta(s)", len(alvos), len(portas))
    for alvo in alvos:
        resultados, config = escanear_alvo(
            alvo, portas, args.timeout, args.threads,
            buscar_cve=not args.no_vuln, checar_config=not args.no_config,
            narrar=not args.quiet)
        if not resultados and not config:
            console.print(f"[dim]{alvo}: nenhuma porta aberta.[/]")
            continue

        diff = None
        if not args.no_diff:
            diff = comparar(carregar_snapshot(alvo, state_dir), resultados, config)
            salvar_snapshot(alvo, resultados, config, state_dir)
            if not args.quiet:
                imprimir_diff(diff)

        criados = salvar_relatorios(alvo, resultados, config, formatos, saida, diff)
        imprimir_veredito(resultados, config)
        console.print(f"[green]✓[/] {alvo}: {', '.join(str(c) for c in criados)}\n")
        log.info("%s: %d portas, %d cves, %d config, mudanca=%s", alvo,
                 len(resultados), sum(len(r['cves']) for r in resultados), len(config),
                 bool(diff and diff.get("houve_mudanca")))
    return 0


def rodar_interativo() -> int:
    """Menu de sempre, para quem roda sem argumentos."""
    banner_inicial()
    console.print("[bold]Escolha o modo:[/]\n")
    console.print("  [bold yellow]1.[/] Scan real (descobre e escaneia a sua rede)")
    console.print("  [bold yellow]2.[/] Modo demonstração (cenário fictício, CVEs reais)")
    while True:
        modo = input("\nDigite 1 ou 2: ").strip()
        if modo in ("1", "2"):
            break
        print("Opção inválida.")

    if modo == "2":
        resultados, config = escanear_demo(HOSTS_DEMO[0])
        alvo = "DEMO_" + HOSTS_DEMO[0]["ip"]
    else:
        aparelhos = listar_hosts()
        while True:
            try:
                n = int(input("\nEscolha o número do aparelho: "))
                alvo = aparelhos[n - 1]["ip"]
                break
            except (ValueError, IndexError):
                print("Número inválido.")
        resultados, config = escanear_alvo(alvo, parse_portas("1-1024"), 1.5, 100)

    # Diff com o scan anterior do mesmo alvo.
    diff = comparar(carregar_snapshot(alvo), resultados, config)
    salvar_snapshot(alvo, resultados, config)
    imprimir_diff(diff)

    criados = salvar_relatorios(alvo, resultados, config, ["html", "json", "csv"], Path("."), diff)
    imprimir_veredito(resultados, config)
    console.print(Panel("\n".join(f"[green]✓[/] {c}" for c in criados),
                        title="[bold]\U0001F4C1 Relatórios[/]", border_style="green", expand=False))
    return 0


def main() -> int:
    if len(sys.argv) == 1:
        return rodar_interativo()
    return rodar_cli(construir_parser().parse_args())


if __name__ == "__main__":
    sys.exit(main())
