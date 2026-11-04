"""
NetScan — ponto de entrada e orquestração.

Dois jeitos de usar:

  1. CLI (scriptável, como qualquer scanner de verdade):
       python3 main.py 192.168.0.10 --ports top100 --format html,json
       python3 main.py 192.168.0.0/24 --ports 1-1024
       python3 main.py alvos.txt --ports 22,80,443 --no-vuln
       python3 main.py --demo

  2. Menu interativo (sem argumentos), restrito a uma faixa que você informa:
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
import warnings
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# O Python 3.9 que vem no macOS é compilado com LibreSSL, e o urllib3 v2 avisa
# disso a cada execução. O HTTPS para NVD/CISA/FIRST funciona normalmente, então
# silenciamos SÓ essa mensagem (precisa vir antes de importar o requests).
warnings.filterwarnings("ignore", message="urllib3 v2 only supports OpenSSL")

from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from reporter.csv_report import gerar_csv
from reporter.html_report import gerar_html
from reporter.json_report import gerar_json, gerar_jsonl
from scanner.enrich import enriquecer
from scanner.host_discovery import read_arp_table, reverse_dns
from scanner.mac_lookup import buscar_fabricante, mac_aleatorio
from scanner.misconfig import checar_porta
from scanner import port_scanner
from scanner.port_scanner import (LimitadorTaxa, descobrir_hosts, ip_local_para,
                                  scan_port_list)
from scanner.scoring import prioridade_cve, resumir
from scanner.service_detect import detectar_servico
from scanner.snapshot import (carregar_snapshot, comparar, diff_para_jsonl,
                              salvar_snapshot)
from scanner.targets import (e_privado, fora_do_escopo, parse_alvos,
                             parse_escopo, parse_portas, resolver)
from scanner.vuln_checker import consultar_cves

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
        if r.get("cve_erro"):
            vuln_txt = Text("⚠ NVD indisponível", style="bold red")
        elif cves:
            scores = [v["score"] for v in cves if v["score"] is not None]
            pior = max(scores) if scores else None
            kev = sum(1 for v in cves if v.get("kev"))
            total = r.get("cves_total", len(cves))
            qtd = f"{len(cves)} de {total}" if total > len(cves) else str(len(cves))
            txt = f"{qtd} CVE(s)" + (f" · {kev} KEV" if kev else "")
            vuln_txt = Text(txt, style=cor_severidade(pior))
        else:
            vuln_txt = Text("—", style="dim")
        tabela.add_row(str(r["porta"]), servico, vuln_txt)
    return tabela


def _nome_servico(info: dict | None) -> str | None:
    if not info or not info.get("produto"):
        return None
    return f"{info['produto']} {info['versao']}".strip() if info.get("versao") else info["produto"]


def _priorizar_e_cortar(resultados: list[dict], max_cves: int | None) -> None:
    """Ordena os CVEs de cada porta por prioridade (KEV → EPSS → CVSS) e corta.

    O corte vem DEPOIS do enriquecimento: assim um CVE da KEV com CVSS médio
    nunca some da lista por causa do limite.
    """
    for r in resultados:
        r["cves"].sort(key=prioridade_cve, reverse=True)
        if max_cves:
            r["cves"] = r["cves"][:max_cves]


def escanear_alvo(alvo: str, portas: list[int], timeout: float, threads: int,
                  buscar_cve: bool = True, checar_config: bool = True,
                  narrar: bool = True, limitador: LimitadorTaxa | None = None,
                  max_cves: int | None = 25) -> tuple[list[dict], list[dict]]:
    """Escaneia UM alvo. Devolve (resultados_por_porta, achados_de_config).

    Lança ValueError se o alvo não resolver.
    """
    ip = resolver(alvo)  # uma consulta DNS só, não uma por porta
    if narrar:
        rotulo = alvo if ip == alvo else f"{alvo} ({ip})"
        console.print(painel_alvo(rotulo, portas=f"{len(portas)} porta(s)"))
        console.print("\n[bold yellow][*][/] Varredura de portas...")

    port_scanner.zerar_contador_recursos()
    portas_abertas = scan_port_list(ip, portas, timeout, threads, limitador)
    if port_scanner.portas_sem_recurso:
        n = port_scanner.portas_sem_recurso
        log.warning("%s: %d porta(s) sem teste por falta de descritores", alvo, n)
        console.print(f"[bold red][!] {n} porta(s) não puderam ser testadas: o sistema "
                      "recusou abrir mais conexões (limite de arquivos abertos). "
                      "Reduza --threads ou aumente 'ulimit -n'.[/]")

    if narrar:
        console.print(f"[bold green][+][/] {len(portas_abertas)} aberta(s): [cyan]{portas_abertas}[/]\n")

    resultados, achados_config = [], []
    for porta in portas_abertas:
        if narrar:
            console.print(f"[bold yellow][*][/] Porta [cyan]{porta}[/]...")
        info = detectar_servico(ip, porta, timeout)
        servico = _nome_servico(info)
        cves, total, erro = [], 0, None

        if servico and narrar:
            console.print(f"    [green][+][/] Serviço: [bold]{servico}[/]")
        if servico and buscar_cve:
            if narrar:
                console.print("    [yellow][*][/] Consultando NVD (CPE)...")
            consulta = consultar_cves(info["produto"], info.get("versao"))
            cves, erro = consulta["cves"], consulta["erro"]
            total = len(cves)
            if erro:
                log.warning("%s:%d NVD falhou: %s", alvo, porta, erro)
                console.print(f"    [bold red][!] NVD indisponível ({erro}) — "
                              "checagem de CVE INCOMPLETA nesta porta[/]")
            elif narrar and cves:
                console.print(f"    [bold red][!][/] {total} CVE(s)")

        if checar_config:
            novos = checar_porta(ip, porta, info, timeout)
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
            "cves_total": total,
            "cve_erro": erro,
        })

    if buscar_cve:
        if narrar and any(r["cves"] for r in resultados):
            console.print("\n[bold yellow][*][/] Enriquecendo com CISA KEV + EPSS...")
        status = enriquecer(resultados)
        if not status["kev_ok"]:
            console.print("[bold red][!] Catálogo CISA KEV indisponível — selos KEV ausentes.[/]")
        if not status["epss_ok"]:
            console.print("[bold red][!] API EPSS indisponível — probabilidades ausentes.[/]")
    _priorizar_e_cortar(resultados, max_cves)

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
    {"ip": "192.168.0.101", "mac": "00:1a:11:aa:bb:02", "descricao": "Banco de Dados",
     "servicos": [{"porta": 3306, "produto": "mysql", "versao": "5.5.0"},
                  {"porta": 6379, "produto": "redis", "versao": "5.0.0"}]},
]




def escanear_demo(host: dict, max_cves: int | None = 25) -> tuple[list[dict], list[dict]]:
    """Cenário fictício, mas com CVEs reais da NVD. Não toca em nenhuma rede local."""
    console.print(painel_alvo(host["ip"], descricao=host["descricao"], mac=host["mac"]))
    console.print()
    resultados = []
    for s in host["servicos"]:
        servico = f"{s['produto']} {s['versao']}"
        console.print(f"[bold yellow][*][/] Porta [cyan]{s['porta']}[/] — [bold]{servico}[/]")
        time.sleep(0.3)
        consulta = consultar_cves(s["produto"], s["versao"])
        cves, erro = consulta["cves"], consulta["erro"]
        if erro:
            console.print(f"    [bold red][!] NVD indisponível ({erro})[/]")
        else:
            console.print(f"    [bold red][!][/] {len(cves)} CVE(s)" if cves
                          else "    [dim][-] Sem CVE conhecido.[/]")
        resultados.append({"porta": s["porta"], "banner": f"demo {servico}",
                           "servico": servico, "protocolo": "demo", "cves": cves,
                           "cves_total": len(cves), "cve_erro": erro})
    enriquecer(resultados)
    _priorizar_e_cortar(resultados, max_cves)
    console.print()
    console.print(montar_tabela_resumo(resultados))
    return resultados, []


def listar_hosts(escopo, consultar_fabricante: bool = False) -> list[dict]:
    """Lista os aparelhos do cache ARP do sistema que estão DENTRO do escopo.

    Não envia pacotes ARP: mostra só quem a máquina já conhece.
    """
    console.print("[bold yellow][*][/] Lendo o cache ARP do sistema (não envia pacotes)...\n")
    todos = read_arp_table()
    aparelhos = [a for a in todos if not fora_do_escopo(a["ip"], escopo)]
    if len(todos) != len(aparelhos):
        console.print(f"[dim]{len(todos) - len(aparelhos)} aparelho(s) fora do escopo "
                      "foram ocultados.[/]")

    def _enriquecer(ap):
        if mac_aleatorio(ap["mac"]):
            ap["fabricante"] = "Aleatório (privacidade)"
        elif consultar_fabricante:
            ap["fabricante"] = buscar_fabricante(ap["mac"])
        else:
            ap["fabricante"] = "não consultado"
        ap["hostname"] = ap.get("hostname_arp") or reverse_dns(ap["ip"])
        ap["aleatorio"] = mac_aleatorio(ap["mac"])
        return ap

    if aparelhos:
        with ThreadPoolExecutor(max_workers=16) as ex:
            aparelhos = list(ex.map(_enriquecer, aparelhos))

    tabela = Table(border_style="cyan", title="Aparelhos conhecidos (cache ARP)", title_style="bold")
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
        elif fab in ("Desconhecido", "não consultado"):
            fab = f"[dim]{fab}[/]"
        tabela.add_row(str(i), ap["ip"], nome, ap["mac"], tipo, fab,
                       ap.get("interface") or "—")

    if aparelhos:
        console.print(tabela)
    return aparelhos


def imprimir_veredito(resultados, achados_config):
    r = resumir(resultados, achados_config)
    cor = {"CRÍTICO": "bold red", "ALTO": "dark_orange", "MÉDIO": "yellow",
           "BAIXO": "green", "OK": "green", "INDETERMINADO": "bold magenta"}.get(
               r["rotulo_risco"], "white")
    linhas = (f"Risco do host: [{cor}]{r['rotulo_risco']}[/] ({r['score_risco']}/100)\n"
              f"CVEs: {r['total_cves']}  ·  KEV (exploração ativa): [bold red]{r['total_kev']}[/]  ·  "
              f"Má configuração: {r['total_config']}")
    if r["cves_nao_listados"]:
        linhas += f"\n[dim]+{r['cves_nao_listados']} CVE(s) de menor prioridade não listados (use --max-cves 0).[/]"
    if r["checagem_cve_incompleta"]:
        portas = ", ".join(str(i["porta"]) for i in r["checagem_cve_incompleta"])
        linhas += f"\n[bold red]⚠ Checagem de CVE incompleta (NVD falhou) nas portas: {portas}[/]"
    console.print(Panel(linhas, title="[bold]Veredito[/]", border_style=cor.split()[-1], expand=False))


# ----------------------------------- CLI -----------------------------------

FORMATOS_VALIDOS = ("html", "json", "jsonl", "csv")
AVISO_USO = ("[bold yellow]⚠ Use o NetScan apenas em redes próprias ou com autorização "
             "explícita do responsável. Varredura não autorizada é ilegal.[/]")


def _positivo(tipo, nome):
    def conv(texto):
        try:
            valor = tipo(texto)
        except ValueError:
            raise argparse.ArgumentTypeError(f"{nome} precisa ser um número: {texto!r}")
        if valor <= 0:
            raise argparse.ArgumentTypeError(f"{nome} precisa ser maior que zero: {texto!r}")
        return valor
    return conv


def _threads(texto):
    valor = _positivo(int, "--threads")(texto)
    if valor > 1000:
        raise argparse.ArgumentTypeError("--threads vai de 1 a 1000")
    return valor


def _nao_negativo(texto):
    try:
        valor = int(texto)
    except ValueError:
        raise argparse.ArgumentTypeError(f"--max-cves precisa ser um número: {texto!r}")
    if valor < 0:
        raise argparse.ArgumentTypeError("--max-cves não pode ser negativo")
    return valor


def _formatos(texto):
    formatos = [f.strip().lower() for f in texto.split(",") if f.strip()]
    invalidos = [f for f in formatos if f not in FORMATOS_VALIDOS]
    if invalidos or not formatos:
        raise argparse.ArgumentTypeError(
            f"formato inválido: {', '.join(invalidos) or texto!r} "
            f"(use {','.join(FORMATOS_VALIDOS)})")
    return formatos


def construir_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netscan",
        description="Scanner de rede e relatório de vulnerabilidades. "
                    "USO SOMENTE EM REDES PRÓPRIAS OU AUTORIZADAS.")
    p.add_argument("alvo", nargs="?",
                   help="IP, hostname, CIDR (172.30.99.0/24) ou arquivo com um alvo por linha")
    p.add_argument("-p", "--ports", default="top100",
                   help="top100 | all | 1-1024 | 80,443,8080 | top100,2222 (padrão: top100)")
    p.add_argument("-f", "--format", default="html,json", type=_formatos,
                   help="html,json,jsonl,csv separados por vírgula (padrão: html,json)")
    p.add_argument("-o", "--output", default=".", help="diretório de saída (padrão: atual)")
    p.add_argument("-t", "--timeout", type=_positivo(float, "--timeout"), default=1.5,
                   help="timeout por conexão em segundos (padrão: 1.5)")
    p.add_argument("--threads", type=_threads, default=100,
                   help="conexões simultâneas, 1 a 1000 (padrão: 100)")
    p.add_argument("--rate", type=_positivo(float, "--rate"), default=None,
                   help="máximo de conexões novas por segundo (padrão: sem limite)")
    p.add_argument("--scope", help="faixas autorizadas (ex.: 172.30.99.0/24,10.0.0.0/8); "
                                   "alvos fora delas são recusados")
    p.add_argument("--no-discovery", action="store_true",
                   help="em faixas/listas, não fazer o ping TCP antes (varre todos os IPs)")
    p.add_argument("--max-cves", type=_nao_negativo, default=25,
                   help="CVEs listados por porta, os mais prioritários (0 = todos; padrão: 25)")
    p.add_argument("-y", "--yes", action="store_true",
                   help="confirma sem perguntar (alvos públicos ou faixas grandes)")
    p.add_argument("--no-vuln", action="store_true", help="não consultar CVEs (só portas/serviços)")
    p.add_argument("--no-config", action="store_true", help="pular checagens de má configuração")
    p.add_argument("--demo", action="store_true", help="modo demonstração (cenário fictício, CVEs reais)")
    p.add_argument("--no-diff", action="store_true", help="não comparar com o scan anterior")
    p.add_argument("--state-dir", help="diretório dos snapshots (padrão: ~/.local/share/netscan/snapshots)")
    p.add_argument("--log", help="arquivo de log (opcional)")
    p.add_argument("-q", "--quiet", action="store_true", help="menos saída no terminal")
    return p


def _confirmar(pergunta: str, assumir_sim: bool) -> bool:
    if assumir_sim:
        return True
    if not sys.stdin.isatty():
        console.print(f"[bold red]{pergunta}[/] Sem terminal interativo: use --yes para confirmar.")
        return False
    return input(f"{pergunta} [s/N]: ").strip().lower() in ("s", "sim", "y", "yes")


def rodar_cli(args, parser: argparse.ArgumentParser | None = None) -> int:
    if args.log:
        logging.basicConfig(filename=args.log, level=logging.INFO,
                            format="%(asctime)s %(levelname)s %(message)s")
    formatos = args.format
    saida = Path(args.output)
    max_cves = args.max_cves or None

    if args.demo:
        resultados, config = escanear_demo(HOSTS_DEMO[0], max_cves)
        criados = salvar_relatorios("DEMO_" + HOSTS_DEMO[0]["ip"], resultados, config, formatos, saida)
        imprimir_veredito(resultados, config)
        console.print(f"[green]✓[/] Relatórios: {', '.join(str(c) for c in criados)}")
        return 0

    if not args.alvo:
        msg = "informe um alvo (IP, hostname, CIDR ou arquivo) ou use --demo"
        if parser:
            parser.error(msg)  # sai com código 2
        console.print(f"[bold red]Erro:[/] {msg}")
        return 2

    try:
        portas = parse_portas(args.ports)
        alvos = parse_alvos(args.alvo)
        escopo = parse_escopo(args.scope)
    except ValueError as e:
        console.print(f"[bold red]Erro:[/] {e}")
        return 2

    console.print(AVISO_USO)

    # Escopo: resolve cada alvo e recusa o que estiver fora.
    if escopo:
        dentro = []
        for alvo in alvos:
            try:
                ip = resolver(alvo)
            except ValueError as e:
                console.print(f"[bold red]Erro:[/] {e}")
                continue
            if fora_do_escopo(ip, escopo):
                console.print(f"[bold red]Recusado:[/] {alvo} ({ip}) está fora do escopo {args.scope}")
            else:
                dentro.append(alvo)
        alvos = dentro
        if not alvos:
            return 1

    # Confirmação para alvos públicos ou faixas grandes.
    publicos = []
    for alvo in alvos[:1024]:
        try:
            if not e_privado(resolver(alvo)):
                publicos.append(alvo)
        except ValueError:
            pass
    if publicos or len(alvos) > 256:
        motivo = (f"{len(publicos)} alvo(s) em IP PÚBLICO (ex.: {publicos[0]})" if publicos
                  else f"{len(alvos)} endereços a varrer")
        if not _confirmar(f"Atenção: {motivo}. Você tem autorização para varrer?", args.yes):
            console.print("Cancelado.")
            return 1

    limitador = LimitadorTaxa(args.rate) if args.rate else None

    # Descoberta: em faixas/listas, só varre quem responde ao ping TCP.
    if len(alvos) > 1 and not args.no_discovery:
        console.print(f"[bold yellow][*][/] Descobrindo hosts ativos em {len(alvos)} endereço(s) "
                      "(ping TCP nas portas 22,80,443,445,3389)...")
        total = len(alvos)
        alvos = descobrir_hosts(alvos, args.timeout, min(args.threads, 64), limitador)
        # Não varrer a própria máquina: ela sempre "responde" ao ping TCP.
        proprio = ip_local_para(alvos[0]) if alvos else None
        if proprio in alvos:
            alvos.remove(proprio)
            console.print(f"[dim]Ignorando {proprio}: é o IP desta máquina.[/]")
        console.print(f"[bold green][+][/] {len(alvos)} de {total} respondem: [cyan]{alvos}[/]\n")
        if not alvos:
            console.print("[dim]Nenhum host respondeu. Se houver firewall descartando "
                          "tudo, tente --no-discovery.[/]")
            return 0

    state_dir = Path(args.state_dir) if args.state_dir else None
    log.info("iniciando scan de %d alvo(s) em %d porta(s)", len(alvos), len(portas))
    falhas = 0
    for alvo in alvos:
        try:
            resultados, config = escanear_alvo(
                alvo, portas, args.timeout, args.threads,
                buscar_cve=not args.no_vuln, checar_config=not args.no_config,
                narrar=not args.quiet, limitador=limitador, max_cves=max_cves)
        except ValueError as e:
            console.print(f"[bold red]Erro:[/] {e}")
            falhas += 1
            continue
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
    return 1 if falhas else 0


def rodar_interativo() -> int:
    """Menu para quem roda sem argumentos. Sempre restrito a uma faixa informada."""
    banner_inicial()
    console.print(AVISO_USO + "\n")
    console.print("[bold]Escolha o modo:[/]\n")
    console.print("  [bold yellow]1.[/] Scan real (aparelhos já vistos pela sua máquina, numa faixa autorizada)")
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
        while True:
            texto = input("\nFaixa autorizada (CIDR, ex.: 172.30.99.0/24): ").strip()
            try:
                escopo = parse_escopo(texto)
                if escopo:
                    break
            except ValueError as e:
                print(e)
            print("Informe uma faixa válida.")
        consultar = input("Consultar o fabricante dos MACs em api.macvendors.com "
                          "(envia os MACs para a internet)? [s/N]: ").strip().lower() in ("s", "sim")
        aparelhos = listar_hosts(escopo, consultar)
        if not aparelhos:
            console.print("[yellow]Nenhum aparelho dessa faixa no cache ARP.[/] "
                          "Para descobrir hosts ativos, use a CLI: "
                          f"[cyan]python3 main.py {texto} --scope {texto}[/]")
            return 0
        while True:
            try:
                n = int(input("\nEscolha o número do aparelho: "))
                if n < 1:
                    raise IndexError
                alvo = aparelhos[n - 1]["ip"]
                break
            except (ValueError, IndexError):
                print("Número inválido.")
        resposta = input(f"Varrer as portas 1-1024 de {alvo}? [s/N]: ").strip().lower()
        if resposta not in ("s", "sim", "y", "yes"):
            console.print("Cancelado.")
            return 1
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
    try:
        if len(sys.argv) == 1:
            return rodar_interativo()
        parser = construir_parser()
        return rodar_cli(parser.parse_args(), parser)
    except (KeyboardInterrupt, EOFError):
        console.print("\n[yellow]Interrompido.[/]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
