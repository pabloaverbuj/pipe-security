#!/usr/bin/env python3
"""
pipe-security CLI
Geo Labs Security Suite

Uso:
  pipe-security install              → configura Claude Desktop
  pipe-security domain add           → agrega un dominio
  pipe-security domain list          → lista dominios configurados
  pipe-security domain use <name>    → cambia el dominio activo
  pipe-security domain remove <name> → elimina un dominio
  pipe-security run                  → inicia el MCP server (usado por Claude Desktop)
"""

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich import print as rprint

from .config import ConfigManager

console = Console()
config = ConfigManager()

CLAUDE_CONFIG_PATHS = [
    Path.home() / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json",
    Path.home() / ".config" / "Claude" / "claude_desktop_config.json",
]

PYTHON_EXECUTABLE = sys.executable


@click.group()
@click.version_option(package_name="pipe-security")
def cli():
    """pipe-security — Geo Labs Security Suite\n\nAuditoría de seguridad para Windows, Active Directory y Cloud."""
    pass


# ─── install ──────────────────────────────────────────────────────────────────

@cli.command()
def install():
    """Configura pipe-security en Claude Desktop automáticamente."""
    console.print("\n[bold cyan]pipe-security[/bold cyan] — Geo Labs Security Suite")
    console.print("Configurando Claude Desktop...\n")

    claude_config_path = None
    for path in CLAUDE_CONFIG_PATHS:
        if path.exists():
            claude_config_path = path
            break

    if not claude_config_path:
        # Crear el archivo si no existe
        claude_config_path = CLAUDE_CONFIG_PATHS[0]
        claude_config_path.parent.mkdir(parents=True, exist_ok=True)
        claude_config_path.write_text(json.dumps({"mcpServers": {}}, indent=2))
        console.print(f"[yellow]Creado nuevo config en:[/yellow] {claude_config_path}")

    with open(claude_config_path, "r", encoding="utf-8") as f:
        config_data = json.load(f)

    if "mcpServers" not in config_data:
        config_data["mcpServers"] = {}

    mcp_entry = {
        "command": PYTHON_EXECUTABLE,
        "args": ["-m", "pipe_security.server"],
    }

    if "pipe-security" in config_data["mcpServers"]:
        console.print("[yellow]pipe-security ya estaba configurado. Actualizando...[/yellow]")
    else:
        console.print("[green]Agregando pipe-security a Claude Desktop...[/green]")

    config_data["mcpServers"]["pipe-security"] = mcp_entry

    with open(claude_config_path, "w", encoding="utf-8") as f:
        json.dump(config_data, f, indent=2)

    console.print(f"\n[bold green]✓ Instalación exitosa[/bold green]")
    console.print(f"  Config: [dim]{claude_config_path}[/dim]")
    console.print(f"  Python: [dim]{PYTHON_EXECUTABLE}[/dim]")
    console.print("\n[bold]Próximos pasos:[/bold]")
    console.print("  1. Reiniciá Claude Desktop")
    console.print("  2. Ejecutá: [cyan]pipe-security domain add[/cyan] para conectar tu primer dominio")
    console.print("  3. En Claude Desktop decí: [italic]'analizá la seguridad de este equipo'[/italic]\n")


# ─── domain ───────────────────────────────────────────────────────────────────

@cli.group()
def domain():
    """Gestión de dominios de Active Directory."""
    pass


@domain.command("add")
@click.option("--name", prompt="Nombre del dominio (ej: cliente-abc)", help="Identificador amigable")
@click.option("--dc", prompt="IP o hostname del Domain Controller", help="Ej: 192.168.1.10")
@click.option("--domain-fqdn", prompt="FQDN del dominio (ej: CORP.LOCAL)", help="Nombre DNS del dominio")
@click.option("--user", prompt="Usuario (ej: auditor@corp.local)", help="Cuenta con permisos de lectura en AD")
@click.option("--password", prompt=True, hide_input=True, help="Contraseña (se guarda en Credential Manager)")
@click.option("--port", default=389, help="Puerto LDAP (default: 389, SSL: 636)")
@click.option("--ssl", is_flag=True, default=False, help="Usar LDAPS")
def domain_add(name, dc, domain_fqdn, user, password, port, ssl):
    """Agrega un nuevo dominio de Active Directory."""
    config.add_domain(
        name=name,
        dc=dc,
        domain_fqdn=domain_fqdn,
        user=user,
        password=password,
        port=port,
        ssl=ssl,
    )
    console.print(f"\n[bold green]✓ Dominio '{name}' agregado correctamente[/bold green]")

    domains = config.list_domains()
    if len(domains) == 1:
        config.set_active_domain(name)
        console.print(f"[green]✓ '{name}' establecido como dominio activo[/green]\n")


@domain.command("list")
def domain_list():
    """Lista todos los dominios configurados."""
    domains = config.list_domains()
    active = config.get_active_domain()

    if not domains:
        console.print("[yellow]No hay dominios configurados.[/yellow]")
        console.print("Ejecutá: [cyan]pipe-security domain add[/cyan]\n")
        return

    table = Table(title="Dominios configurados", show_header=True, header_style="bold cyan")
    table.add_column("", width=3)
    table.add_column("Nombre", style="bold")
    table.add_column("Domain Controller")
    table.add_column("FQDN")
    table.add_column("Usuario")
    table.add_column("Puerto")

    for d in domains:
        is_active = "●" if d["name"] == active else " "
        style = "green" if d["name"] == active else ""
        table.add_row(
            is_active,
            d["name"],
            d["dc"],
            d["domain_fqdn"],
            d["user"],
            str(d.get("port", 389)),
            style=style,
        )

    console.print(table)
    console.print(f"\n[dim]● = dominio activo[/dim]\n")


@domain.command("use")
@click.argument("name")
def domain_use(name):
    """Cambia el dominio activo."""
    domains = config.list_domains()
    names = [d["name"] for d in domains]

    if name not in names:
        console.print(f"[red]Dominio '{name}' no encontrado.[/red]")
        console.print(f"Disponibles: {', '.join(names)}")
        return

    config.set_active_domain(name)
    console.print(f"[bold green]✓ Dominio activo: '{name}'[/bold green]")


@domain.command("remove")
@click.argument("name")
@click.confirmation_option(prompt=f"¿Seguro que querés eliminar este dominio?")
def domain_remove(name):
    """Elimina un dominio configurado."""
    config.remove_domain(name)
    console.print(f"[green]✓ Dominio '{name}' eliminado[/green]")


@domain.command("test")
@click.argument("name", required=False)
def domain_test(name):
    """Testea la conexión a un dominio."""
    from .utils.ldap_client import LDAPClient

    target = name or config.get_active_domain()
    if not target:
        console.print("[red]No hay dominio activo. Usá: pipe-security domain use <nombre>[/red]")
        return

    domain_config = config.get_domain(target)
    if not domain_config:
        console.print(f"[red]Dominio '{target}' no encontrado.[/red]")
        return

    console.print(f"Testeando conexión a [bold]{target}[/bold] ({domain_config['dc']})...")

    try:
        client = LDAPClient(domain_config)
        info = client.test_connection()
        console.print(f"[bold green]✓ Conexión exitosa[/bold green]")
        console.print(f"  Dominio: {info.get('domain', 'N/A')}")
        console.print(f"  Nivel funcional: {info.get('functional_level', 'N/A')}")
    except Exception as e:
        console.print(f"[bold red]✗ Error de conexión:[/bold red] {e}")


# ─── run (usado por Claude Desktop) ───────────────────────────────────────────

@cli.command(hidden=True)
def run():
    """Inicia el MCP server (usado internamente por Claude Desktop)."""
    from .server import main
    main()


if __name__ == "__main__":
    cli()
