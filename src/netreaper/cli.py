"""NETREAPER CLI interface using Typer."""
import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from netreaper import __version__
from netreaper.core.logging import get_logger

app = typer.Typer(
    name="netreaper",
    help="NETREAPER - Offensive Security Framework",
    add_completion=True,
    invoke_without_command=True,  # Allow running without subcommand
)

console = Console()
logger = get_logger(__name__)


# Version callback
def version_callback(value: bool):
    """Show version information."""
    if value:
        console.print(f"NETREAPER v{__version__}", style="bold cyan")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        None, "--version", "-v", callback=version_callback, is_eager=True
    ),
):
    """NETREAPER - Offensive Security Framework."""
    # If no subcommand given, launch TUI by default
    if ctx.invoked_subcommand is None:
        _launch_tui()


def _launch_tui():
    """Launch the interactive TUI."""
    try:
        from netreaper.tui.app import run_app

        run_app()
    except ImportError as e:
        console.print(
            f"[red]Error: TUI dependencies not available: {e}[/red]", style="bold"
        )
        console.print(
            "[yellow]Install with: pipx install 'netreaper[tui]'[/yellow]"
        )
        raise typer.Exit(1)


@app.command()
def tui():
    """Launch the interactive TUI."""
    _launch_tui()


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target IP, CIDR, or hostname"),
    scan_type: str = typer.Option(
        "standard", "--type", "-t", help="Scan type (quick/standard/full)"
    ),
    ports: str | None = typer.Option(None, "--ports", "-p", help="Port specification"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Output file"),
):
    """Run a network scan."""

    async def run_scan():
        from netreaper.tools.nmap import NmapTool

        console.print(f"[cyan]Scanning {target}...[/cyan]")

        nmap = NmapTool()
        await nmap.initialize()

        options = {"scan_type": scan_type}
        if ports:
            options["ports"] = ports

        result = await nmap.execute(target, options)

        if result.success:
            console.print("[green]Scan completed![/green]")
            summary = result.data.get("summary", {})
            console.print(f"Total hosts: {summary.get('total_hosts', 0)}")
            console.print(f"Up hosts: {summary.get('up_hosts', 0)}")
            console.print(f"Open ports: {summary.get('open_ports', 0)}")

            if output:
                import json

                output.write_text(json.dumps(result.data, indent=2))
                console.print(f"[green]Results saved to {output}[/green]")
        else:
            console.print(f"[red]Scan failed: {result.errors}[/red]")

    asyncio.run(run_scan())


@app.command()
def status():
    """Show system status and tool availability."""
    from netreaper.detection.tools import tool_registry

    tools = tool_registry.check_all()
    table = Table(title="NETREAPER System Status")
    table.add_column("Tool", style="cyan")
    table.add_column("Status")
    table.add_column("Version", style="yellow")
    table.add_column("Path", style="dim")
    available = 0
    for name in sorted(tools):
        info = tools[name]
        if info.available:
            available += 1
        mark = "[green]available[/green]" if info.available else "[red]missing[/red]"
        table.add_row(name, mark, info.version or "-", str(info.path) if info.path else "-")
    console.print(table)
    console.print(f"[dim]{available}/{len(tools)} tools available[/dim]")


def _coerce(value: str):
    low = value.lower()
    if low in ("true", "false"):
        return low == "true"
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        return value


def _persist_config(dotted_key: str, value: str) -> None:
    """Write a dotted key into the user config.toml (creating it if needed)."""
    import tomllib

    import tomli_w

    from netreaper.core.constants import NETREAPER_CONFIG_DIR

    cfg_path = NETREAPER_CONFIG_DIR / "config.toml"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    data: dict = {}
    if cfg_path.exists():
        with cfg_path.open("rb") as fh:
            data = tomllib.load(fh)
    parts = dotted_key.split(".")
    node = data
    for part in parts[:-1]:
        node = node.setdefault(part, {})
        if not isinstance(node, dict):
            raise typer.BadParameter(f"{dotted_key!r} conflicts with a non-table value")
    node[parts[-1]] = _coerce(value)
    with cfg_path.open("wb") as fh:
        tomli_w.dump(data, fh)


@app.command()
def config(
    action: str = typer.Argument(..., help="Action: show, get, set"),
    key: str | None = typer.Argument(None, help="Config key (dotted), e.g. safety.unsafe_mode"),
    value: str | None = typer.Argument(None, help="Value for 'set'"),
):
    """Manage configuration."""
    from netreaper.config.settings import get_settings, reload_settings

    settings = get_settings()

    if action in ("show", "list"):
        console.print(settings.model_dump_json(indent=2))
    elif action == "get" and key:
        val = settings
        try:
            for part in key.split("."):
                val = getattr(val, part)
        except AttributeError:
            console.print(f"[red]unknown key:[/red] {key}")
            raise typer.Exit(1) from None
        console.print(f"{key} = {val}")
    elif action == "set" and key and value is not None:
        _persist_config(key, value)
        reload_settings()
        console.print(f"[green]set[/green] {key} = {_coerce(value)}")
    else:
        console.print("[red]usage:[/red] config show | get <key> | set <key> <value>")
        raise typer.Exit(1)


# WiFi commands
wifi_app = typer.Typer(help="Wireless operations")
app.add_typer(wifi_app, name="wifi")


@wifi_app.command("scan")
def wifi_scan(
    interface: str = typer.Argument(..., help="Wireless interface"),
    timeout: int = typer.Option(30, "--timeout", "-t", help="Scan timeout in seconds"),
):
    """Scan for wireless networks."""

    async def run_wifi_scan():
        console.print(f"[cyan]Scanning wireless networks on {interface}...[/cyan]")
        console.print(
            "[yellow]This feature requires full wireless module implementation[/yellow]"
        )

    asyncio.run(run_wifi_scan())


@wifi_app.command("monitor")
def wifi_monitor(
    action: str = typer.Argument(..., help="Action: enable, disable, status"),
    interface: str = typer.Argument(..., help="Wireless interface"),
):
    """Manage monitor mode."""

    async def manage_monitor():
        from netreaper.wireless.monitor import (
            disable_monitor_mode,
            enable_monitor_mode,
            get_monitor_status,
        )

        if action == "enable":
            console.print(f"[cyan]Enabling monitor mode on {interface}...[/cyan]")
            monitor_iface = await enable_monitor_mode(interface)
            console.print(f"[green]Monitor mode enabled: {monitor_iface}[/green]")
        elif action == "disable":
            console.print(f"[cyan]Disabling monitor mode on {interface}...[/cyan]")
            result = await disable_monitor_mode(interface)
            console.print(f"[green]Monitor mode now: {result.get('current_mode')}[/green]")
        elif action == "status":
            status = await get_monitor_status(interface)
            console.print(f"Interface: {interface}")
            console.print(f"Is wireless: {status.get('is_wireless')}")
            console.print(f"Current mode: {status.get('current_mode')}")
            console.print(f"In monitor mode: {status.get('is_monitor')}")
            console.print(f"Supports monitor: {status.get('supports_monitor')}")
            console.print(f"Supports injection: {status.get('supports_injection')}")
        else:
            console.print("[red]Invalid action. Use: enable, disable, or status[/red]")
            raise typer.Exit(1)

    asyncio.run(manage_monitor())


# Plugin commands
plugin_app = typer.Typer(help="Plugin management")
app.add_typer(plugin_app, name="plugin")


@plugin_app.command("list")
def plugin_list():
    """List all available plugins."""

    async def list_plugins():
        from netreaper.plugins.registry import plugin_registry

        await plugin_registry.initialize()

        table = Table(title="Available Plugins")
        table.add_column("Name", style="cyan")
        table.add_column("Type", style="yellow")
        table.add_column("Version", style="green")
        table.add_column("Description", style="dim")

        for plugin in plugin_registry.list_all():
            table.add_row(
                plugin.name,
                plugin.metadata.plugin_type.value,
                plugin.metadata.version,
                plugin.metadata.description,
            )

        console.print(table)

    asyncio.run(list_plugins())


if __name__ == "__main__":
    app()
