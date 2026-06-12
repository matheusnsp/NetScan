from scanner.port_scanner import scan_ports_fast
from scanner.banner_grabber import grab_http_banner
from scanner.parser import extrair_servico
from scanner.vuln_checker import buscar_vulnerabilidades
from scanner.host_discovery import read_arp_table
from scanner.mac_lookup import buscar_fabricante
from reporter.html_report import gerar_html
from reporter.json_report import gerar_json
from reporter.csv_report import gerar_csv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align
import time

console = Console()


# Titulo NetScan em ASCII art (sem dependencia externa)
NETSCAN_ASCII = r"""
███╗   ██╗███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
████╗  ██║██╔═════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
██╔██╗ ██║█████╗     ██║   ███████╗██║     ███████║██╔██╗ ██║
██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
██║ ╚████║███████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
"""


def banner_inicial():
    """Mostra o titulo NetScan grande e centralizado."""
    console.print(Align.center(Text(NETSCAN_ASCII, style="bold cyan")))
    console.print(Align.center(
        Text("Network Scanner & Vulnerability Reporter", style="dim italic")
    ))
    console.print()


def cor_severidade(score):
    """Retorna a cor (rich) conforme a gravidade CVSS."""
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
    """Monta um painel bonito e padronizado com os dados do alvo."""
    from rich.table import Table as _T
    info = _T.grid(padding=(0, 2))
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
    """Monta a tabela-resumo final (usada pelos dois modos)."""
    tabela = Table(title="\U0001F4CB Resumo da Varredura", border_style="cyan", title_style="bold")
    tabela.add_column("Porta", justify="center", style="cyan")
    tabela.add_column("Servico", style="white")
    tabela.add_column("Vulnerabilidades", justify="center")

    for r in resultados:
        cves = r["cves"]
        servico = r["servico"] or "[dim]-[/]"
        if cves:
            scores = [v["score"] for v in cves if v["score"] is not None]
            pior = max(scores) if scores else None
            vuln_txt = Text(f"{len(cves)} CVE(s)", style=cor_severidade(pior))
        else:
            vuln_txt = Text("-", style="dim")
        tabela.add_row(str(r["porta"]), servico, vuln_txt)

    return tabela


def escanear(alvo, porta_inicial, porta_final):
    """Scan REAL: escaneia um alvo de verdade e narra cada etapa."""
    console.print(painel_alvo(alvo, portas=f"{porta_inicial}-{porta_final}"))
    console.print()

    console.print("[bold yellow][*][/] Iniciando varredura de portas...")
    portas_abertas = scan_ports_fast(alvo, porta_inicial, porta_final)
    console.print(f"[bold green][+][/] {len(portas_abertas)} porta(s) aberta(s): [cyan]{portas_abertas}[/]\n")

    resultados = []

    for porta in portas_abertas:
        console.print(f"[bold yellow][*][/] Analisando porta [cyan]{porta}[/]...")
        banner = grab_http_banner(alvo, porta)

        servico = None
        cves = []

        if banner:
            servico = extrair_servico(banner)
            if servico:
                console.print(f"    [green][+][/] Servico: [bold]{servico}[/]")
                console.print("    [yellow][*][/] Consultando NVD...")
                cves = buscar_vulnerabilidades(servico)
                if cves:
                    console.print(f"    [bold red][!][/] [bold]{len(cves)}[/] vulnerabilidade(s) encontrada(s)!")
                    for v in cves:
                        cor = cor_severidade(v["score"])
                        console.print(f"        [{cor}]* [{v['score']}] {v['id']}[/]")
                else:
                    console.print("    [dim][-] Nenhuma vulnerabilidade conhecida.[/]")
            else:
                console.print("    [dim][-] Servico nao identificado (banner sem versao).[/]")
        else:
            console.print("    [dim][-] Sem resposta de banner.[/]")

        resultados.append({
            "porta": porta,
            "banner": banner,
            "servico": servico,
            "cves": cves
        })

    console.print()
    console.print(montar_tabela_resumo(resultados))
    console.print("\n[bold green]Varredura concluida.[/]\n")
    return resultados


HOSTS_DEMO = [
    {
        "ip": "192.168.0.100",
        "mac": "00:1a:11:3c:4d:5e",
        "descricao": "Servidor Web",
        "servicos": [
            {"porta": 22, "servico": "OpenSSH 8.9"},
            {"porta": 80, "servico": "Apache 2.4.49"},
            {"porta": 443, "servico": "nginx 1.18.0"},
        ]
    },
    {
        "ip": "192.168.0.101",
        "mac": "2c:dc:d7:8a:9b:0c",
        "descricao": "Servidor de Banco de Dados",
        "servicos": [
            {"porta": 3306, "servico": "MySQL 5.5.0"},
            {"porta": 6379, "servico": "Redis 5.0.0"},
        ]
    },
    {
        "ip": "192.168.0.102",
        "mac": "b8:27:eb:1f:2a:3b",
        "descricao": "Servidor FTP",
        "servicos": [
            {"porta": 21, "servico": "ProFTPD 1.3.5"},
            {"porta": 22, "servico": "OpenSSH 7.4"},
        ]
    },
]


def escanear_demo(host):
    """Scan de DEMONSTRACAO de um host ficticio, com saida formatada (rich)."""
    resultados = []

    console.print(painel_alvo(host['ip'], descricao=host['descricao'], mac=host['mac']))
    console.print()

    console.print("[bold yellow][*][/] Iniciando varredura de portas...")
    time.sleep(1)
    portas = sorted(s["porta"] for s in host["servicos"])
    console.print(f"[bold green][+][/] {len(portas)} porta(s) aberta(s): [cyan]{portas}[/]\n")
    time.sleep(1)

    for s in host["servicos"]:
        porta = s["porta"]
        servico = s["servico"]

        console.print(f"[bold yellow][*][/] Analisando porta [cyan]{porta}[/]...")
        time.sleep(0.6)
        console.print(f"    [green][+][/] Servico: [bold]{servico}[/]")
        time.sleep(0.5)
        console.print("    [yellow][*][/] Consultando NVD...")

        cves = buscar_vulnerabilidades(servico)
        time.sleep(0.4)

        if cves:
            console.print(f"    [bold red][!][/] [bold]{len(cves)}[/] vulnerabilidade(s) encontrada(s)!")
            for v in cves:
                cor = cor_severidade(v["score"])
                console.print(f"        [{cor}]* [{v['score']}] {v['id']}[/]")
        else:
            console.print("    [dim][-] Nenhuma vulnerabilidade conhecida.[/]")

        resultados.append({
            "porta": porta,
            "banner": f"Server: {servico}",
            "servico": servico,
            "cves": cves
        })
        time.sleep(0.4)

    console.print()
    console.print(montar_tabela_resumo(resultados))
    console.print("\n[bold green]Varredura concluida.[/]\n")
    return resultados


def listar_hosts():
    """Descobre os aparelhos da rede (com fabricante) e os mostra numa tabela."""
    aparelhos = read_arp_table()

    console.print("[bold yellow][*][/] Descobrindo aparelhos na rede (via ARP)...\n")

    tabela = Table(border_style="cyan", title="Aparelhos na rede", title_style="bold")
    tabela.add_column("#", justify="center", style="bold yellow")
    tabela.add_column("IP", style="cyan")
    tabela.add_column("MAC", style="dim")
    tabela.add_column("Fabricante", style="white")

    for i, ap in enumerate(aparelhos, start=1):
        fabricante = buscar_fabricante(ap["mac"])
        ap["fabricante"] = fabricante
        tabela.add_row(str(i), ap["ip"], ap["mac"], fabricante)
        time.sleep(1)

    console.print(tabela)
    return aparelhos


if __name__ == "__main__":
    banner_inicial()

    # ---- Escolha do MODO primeiro (antes de tocar na rede real) ----
    console.print("[bold]Escolha o modo:[/]\n")
    console.print("  [bold yellow]1.[/] Scan real (descobre e escaneia aparelhos da sua rede)")
    console.print("  [bold yellow]2.[/] Modo demonstracao (cenario ficticio, CVEs reais da NVD)")

    while True:
        modo = input("\nDigite 1 ou 2: ").strip()
        if modo in ("1", "2"):
            break
        print("Opcao invalida. Digite 1 ou 2.")

    resultados = None
    alvo = None

    if modo == "2":
        # ===== MODO DEMONSTRACAO =====
        console.print()
        tabela_hosts = Table(title="Hosts disponiveis (demonstracao)",
                             border_style="cyan", title_style="bold")
        tabela_hosts.add_column("#", justify="center", style="bold yellow")
        tabela_hosts.add_column("IP", style="cyan")
        tabela_hosts.add_column("MAC", style="dim")
        tabela_hosts.add_column("Descricao", style="white")
        for i, h in enumerate(HOSTS_DEMO, start=1):
            tabela_hosts.add_row(str(i), h["ip"], h["mac"], h["descricao"])
        console.print(tabela_hosts)

        while True:
            escolha_demo = input("\nEscolha o host de demo: ")
            try:
                n = int(escolha_demo)
                if n < 1:
                    print("Numero invalido.")
                    continue
                host_demo = HOSTS_DEMO[n - 1]
                break
            except ValueError:
                print("Digite um numero.")
            except IndexError:
                print("Nao existe host com esse numero.")

        alvo = f"{host_demo['ip']} (DEMO - {host_demo['descricao']})"
        console.print()
        resultados = escanear_demo(host_demo)

    else:
        # ===== MODO REAL =====
        aparelhos = listar_hosts()

        while True:
            escolha = input("\nEscolha o numero do aparelho: ")
            try:
                numero = int(escolha)
                if numero < 1:
                    print("Numero invalido.")
                    continue
                alvo = aparelhos[numero - 1]["ip"]
                break
            except ValueError:
                print("Isso nao e um numero. Digite o numero da lista.")
            except IndexError:
                print("Nao existe aparelho com esse numero.")

        console.print()
        resultados = escanear(alvo, 1, 1024)

    # ---- Geracao de relatorios (igual pros dois modos) ----
    console.print("[bold yellow][*][/] Gerando relatorios...")
    nome_base = f"relatorio_{alvo}".replace(" ", "_").replace("(", "").replace(")", "")
    html = gerar_html(alvo, resultados)
    with open(f"{nome_base}.html", "w", encoding="utf-8") as f:
        f.write(html)
    gerar_json(alvo, resultados, f"{nome_base}.json")
    gerar_csv(resultados, f"{nome_base}.csv")

    console.print(Panel(
        f"[green]ok[/] [bold]{nome_base}.html[/]  [dim](visual)[/]\n"
        f"[green]ok[/] [bold]{nome_base}.json[/]  [dim](dados estruturados)[/]\n"
        f"[green]ok[/] [bold]{nome_base}.csv[/]   [dim](planilha)[/]",
        title="[bold]\U0001F4C1 Relatorios salvos[/]", border_style="green", expand=False
    ))