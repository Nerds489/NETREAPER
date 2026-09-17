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
    # Arm the scope gate from the persisted engagement (if any) so a consent
    # established with `netreaper engage start` applies to this process too. A
    # malformed file must never crash a command, so failures are swallowed here
    # (load_engagement already logs) and the gate simply stays deny-by-default.
    try:
        from netreaper.safety.engagement_store import load_engagement
        from netreaper.safety.scope import get_scope_gate

        eng = load_engagement()
        if eng is not None:
            get_scope_gate().set_engagement(eng)
    except Exception:  # never let engagement hydration break the CLI
        logger.debug("engagement hydration skipped", exc_info=True)

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


# Engagement (authorisation) commands
engage_app = typer.Typer(help="Manage the authorisation engagement (scope gate)")
app.add_typer(engage_app, name="engage")

# An engagement is time-boxed on purpose; without a cap a grant replays
# for however long the issuer picked.
_MAX_ENGAGEMENT_HOURS = 48.0

_TIER_NAMES = "passive | active_scan | single_target | broadcast | mitm"


def _scope_summary(scope) -> str:
    return (
        f"cidrs={scope.cidrs or '-'} bssids={sorted(scope.bssids) or '-'} "
        f"essids={sorted(scope.essids) or '-'} "
        f"hostnames={sorted(scope.hostnames) or '-'}"
    )


@engage_app.command("start")
def engage_start(
    operator: str = typer.Option(..., "--operator", "-o", help="Who is authorised"),
    ref: str = typer.Option(
        ..., "--ref", "-r", help="Authorisation reference (engagement/RoE id)"
    ),
    cidr: list[str] = typer.Option(None, "--cidr", help="In-scope IP/CIDR (repeat)"),
    bssid: list[str] = typer.Option(None, "--bssid", help="In-scope BSSID (repeat)"),
    essid: list[str] = typer.Option(
        None, "--essid", help="In-scope ESSID/SSID (repeatable)"
    ),
    hostname: list[str] = typer.Option(
        None, "--hostname", help="In-scope hostname (repeatable)"
    ),
    deny: list[str] = typer.Option(
        None, "--deny", help="Explicitly out-of-scope IP/CIDR (repeatable)"
    ),
    hours: float = typer.Option(12.0, "--hours", help="Hours until expiry"),
    max_tier: str = typer.Option(
        "single_target", "--max-tier", help=f"Blast-radius ceiling: {_TIER_NAMES}"
    ),
    confirm_tier: list[str] = typer.Option(
        None,
        "--confirm-tier",
        help=(
            "Pre-confirm a tier so gated actions at it can run (repeatable). "
            "T2+ needs this: a ceiling says what MAY be reached, this says it "
            "was intended. Nothing prompts mid-run."
        ),
    ),
    accept_interception: bool = typer.Option(
        False,
        "--accept-interception",
        help=(
            "Required for MITM (T4) alongside --confirm-tier mitm. Records the "
            "dangerous-ops phrase acknowledging interception of third-party traffic."
        ),
    ),
):
    """Authorise a scope so gated actions can run, and persist it for later runs."""
    from datetime import UTC, datetime, timedelta

    from netreaper.safety.engagement_store import save_engagement
    from netreaper.safety.scope import (
        DANGEROUS_OPS_PHRASE,
        Engagement,
        Scope,
        Tier,
        get_scope_gate,
    )

    if not operator.strip():
        console.print("[red]--operator must not be empty[/red]")
        raise typer.Exit(2)
    if not ref.strip():
        console.print("[red]--ref must not be empty: give the authorisation ref[/red]")
        raise typer.Exit(2)
    if hours <= 0:
        console.print("[red]--hours must be positive (an engagement must last)[/red]")
        raise typer.Exit(2)
    if hours > _MAX_ENGAGEMENT_HOURS:
        console.print(
            f"[red]--hours {hours:g} exceeds the {_MAX_ENGAGEMENT_HOURS:g}h cap; an "
            f"authorisation that outlives its engagement is not an authorisation. "
            f"Re-run engage start when it expires.[/red]"
        )
        raise typer.Exit(2)
    try:
        tier = Tier[max_tier.strip().upper()]
    except KeyError:
        console.print(
            f"[red]invalid --max-tier {max_tier!r}; use one of: {_TIER_NAMES}[/red]"
        )
        raise typer.Exit(2) from None

    confirmed: set[Tier] = set()
    for name in confirm_tier or []:
        try:
            confirmed.add(Tier[name.strip().upper()])
        except KeyError:
            console.print(
                f"[red]invalid --confirm-tier {name!r}; use one of: {_TIER_NAMES}[/red]"
            )
            raise typer.Exit(2) from None
    above_ceiling = sorted(x.name for x in confirmed if x > tier)
    if above_ceiling:
        console.print(
            f"[red]--confirm-tier {', '.join(above_ceiling)} exceeds --max-tier "
            f"{tier.name}; raise the ceiling or drop the confirmation[/red]"
        )
        raise typer.Exit(2)
    if Tier.MITM in confirmed and not accept_interception:
        console.print(
            "[red]--confirm-tier mitm also requires --accept-interception: MITM "
            "intercepts traffic that is not yours[/red]"
        )
        raise typer.Exit(2)
    if accept_interception and Tier.MITM not in confirmed:
        console.print(
            "[yellow]warning: --accept-interception without --confirm-tier mitm "
            "does nothing[/yellow]"
        )

    scope = Scope(
        cidrs=list(cidr or []),
        hostnames=set(hostname or []),
        bssids=set(bssid or []),
        essids=set(essid or []),
        deny=list(deny or []),
    )
    if not (scope.cidrs or scope.hostnames or scope.bssids or scope.essids):
        console.print(
            "[yellow]warning: empty scope authorises no target (deny-by-default). "
            "Add --cidr/--bssid/--essid/--hostname.[/yellow]"
        )
    now = datetime.now(UTC)
    eng = Engagement(
        operator=operator,
        authorization_ref=ref.strip(),
        scope=scope,
        started_at=now,
        expires_at=now + timedelta(hours=hours),
        max_tier=tier,
        confirmed_tiers=frozenset(confirmed),
        dangerous_ops_phrase=(
            DANGEROUS_OPS_PHRASE
            if (accept_interception and Tier.MITM in confirmed)
            else ""
        ),
    )
    get_scope_gate().set_engagement(eng)
    path = save_engagement(eng)
    console.print(
        f"[green]Engagement active[/green] (operator={operator}, ref={ref.strip()})"
    )
    console.print(f"  scope: {_scope_summary(scope)}")
    console.print(f"  max tier: {tier.name}, expires: {eng.expires_at.isoformat()}")
    console.print(f"  [dim]saved to {path}[/dim]")


@engage_app.command("status")
def engage_status():
    """Show the current engagement, if any."""
    from netreaper.safety.engagement_store import load_engagement

    eng = load_engagement()
    if eng is None:
        console.print("[yellow]No active engagement.[/yellow] Run 'engage start'.")
        raise typer.Exit(1)
    active = eng.is_active()
    console.print(f"[{'green' if active else 'red'}]Engagement "
                  f"{'active' if active else 'EXPIRED'}[/]")
    console.print(f"  operator: {eng.operator}, ref: {eng.authorization_ref}")
    console.print(f"  scope: {_scope_summary(eng.scope)}")
    console.print(
        f"  max tier: {eng.max_tier.name}, expires: {eng.expires_at.isoformat()}"
    )
    if not active:
        # An expired record is present but authorises nothing: signal non-zero.
        raise typer.Exit(1)


@engage_app.command("end")
def engage_end():
    """Clear the current engagement (revoke the authorisation)."""
    from netreaper.safety.engagement_store import clear_engagement_file
    from netreaper.safety.scope import get_scope_gate

    get_scope_gate().clear_engagement()
    removed = clear_engagement_file()
    if removed:
        console.print("[green]Engagement cleared.[/green]")
    else:
        console.print("[yellow]No engagement file to clear.[/yellow]")


# WiFi commands
wifi_app = typer.Typer(help="Wireless operations")
app.add_typer(wifi_app, name="wifi")


@wifi_app.command("scan")
def wifi_scan(
    interface: str = typer.Argument(..., help="Monitor-mode interface"),
    timeout: int = typer.Option(30, "--timeout", "-t", help="Scan duration in seconds"),
):
    """Scan for nearby access points and clients."""

    async def run_wifi_scan():
        from netreaper.core.exceptions import TargetValidationError
        from netreaper.wireless.scan import scan_networks

        console.print(f"[cyan]Scanning on {interface} for {timeout}s...[/cyan]")
        try:
            result = await scan_networks(interface, duration=timeout)
        except TargetValidationError as exc:
            console.print(f"[red]Denied by scope gate: {exc}[/red]")
            raise typer.Exit(2) from exc

        aps = result.access_points
        if not aps:
            console.print("[yellow]No access points found.[/yellow]")
            return
        table = Table(title=f"Access points ({len(aps)})")
        table.add_column("BSSID")
        table.add_column("Ch", justify="right")
        table.add_column("Pwr", justify="right")
        table.add_column("Privacy")
        table.add_column("Clients", justify="right")
        table.add_column("ESSID")
        for ap in sorted(aps, key=lambda a: a.power or -999, reverse=True):
            table.add_row(
                ap.bssid,
                str(ap.channel or "-"),
                str(ap.power or "-"),
                ap.privacy or "-",
                str(len(result.clients_for(ap.bssid))),
                ap.essid or "(hidden)",
            )
        console.print(table)

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


@wifi_app.command("handshake")
def wifi_handshake(
    interface: str = typer.Argument(..., help="Monitor-mode interface"),
    bssid: str = typer.Argument(..., help="Target access point BSSID"),
    channel: int = typer.Argument(..., help="Target channel"),
    client: str = typer.Option(
        None, "--client", "-c", help="Client MAC to deauth (broadcast if unset)"
    ),
    output: str = typer.Option(None, "--output", "-o", help="Capture file prefix"),
    seconds: int = typer.Option(20, "--seconds", "-s", help="Capture window (s)"),
    deauth: int = typer.Option(5, "--deauth", "-d", help="Deauth frames (0=off)"),
    attempts: int = typer.Option(3, "--attempts", "-a", help="Capture rounds"),
):
    """Capture and verify a WPA/WPA2 handshake for an access point."""

    async def run_capture():
        from netreaper.core.exceptions import TargetValidationError
        from netreaper.wireless.handshake import capture_handshake

        console.print(
            f"[cyan]Capturing handshake for {bssid} on channel {channel}...[/cyan]"
        )
        try:
            result = await capture_handshake(
                interface,
                bssid,
                channel,
                client=client,
                output=output,
                capture_seconds=seconds,
                deauth_count=deauth,
                max_attempts=attempts,
            )
        except TargetValidationError as exc:
            console.print(f"[red]Denied by scope gate: {exc}[/red]")
            raise typer.Exit(2) from exc

        if result.captured:
            msgs = ", ".join(f"M{m}" for m in result.messages)
            console.print(
                f"[green]Handshake captured ({msgs}) "
                f"from client {result.client}[/green]"
            )
            console.print(f"Saved to: {result.cap_file}")
        else:
            console.print(
                f"[yellow]No handshake after {result.attempts} attempt(s). "
                "Try more attempts, a longer window, or a specific client.[/yellow]"
            )
            raise typer.Exit(1)

    asyncio.run(run_capture())


@wifi_app.command("pmkid")
def wifi_pmkid(
    interface: str = typer.Argument(..., help="Monitor-mode interface"),
    bssid: str = typer.Argument(..., help="Target access point BSSID"),
    channel: int = typer.Argument(..., help="Target channel"),
    essid: str = typer.Option("", "--essid", "-e", help="Network name (for the hash)"),
    output: str = typer.Option(None, "--output", "-o", help="Capture file prefix"),
    seconds: int = typer.Option(20, "--seconds", "-s", help="Capture window (s)"),
    deauth: int = typer.Option(0, "--deauth", "-d", help="Deauth frames (0=passive)"),
    attempts: int = typer.Option(3, "--attempts", "-a", help="Capture rounds"),
):
    """Capture a clientless PMKID and emit a hashcat 22000 hash."""

    async def run_pmkid():
        from netreaper.core.exceptions import TargetValidationError
        from netreaper.wireless.pmkid import capture_pmkid

        console.print(
            f"[cyan]Capturing PMKID for {bssid} on channel {channel}...[/cyan]"
        )
        try:
            result = await capture_pmkid(
                interface,
                bssid,
                channel,
                essid=essid,
                output=output,
                capture_seconds=seconds,
                deauth_count=deauth,
                max_attempts=attempts,
            )
        except TargetValidationError as exc:
            console.print(f"[red]Denied by scope gate: {exc}[/red]")
            raise typer.Exit(2) from exc

        if result.captured:
            console.print(f"[green]PMKID captured: {result.pmkid}[/green]")
            console.print(f"hashcat 22000: {result.hashcat}")
            console.print(f"Saved to: {result.cap_file}")
        else:
            console.print(
                f"[yellow]No PMKID after {result.attempts} attempt(s). "
                "The AP may not offer PMKID; try a handshake capture.[/yellow]"
            )
            raise typer.Exit(1)

    asyncio.run(run_pmkid())


@wifi_app.command("wps")
def wifi_wps(
    bssid: str = typer.Argument(..., help="Target access point BSSID"),
    interface: str = typer.Option(None, "--interface", "-i", help="Monitor interface"),
    channel: int = typer.Option(None, "--channel", "-c", help="Target channel"),
    essid: str = typer.Option("", "--essid", "-e", help="Network name (optional)"),
    compute: bool = typer.Option(
        False, "--compute", help="Only compute candidate PINs offline, no attack"
    ),
    no_pixie: bool = typer.Option(False, "--no-pixie", help="Skip pixie-dust"),
):
    """Compute offline WPS PINs, or run a WPS attack (pixie-dust then PIN list)."""
    from netreaper.wireless.wps import candidate_pins, format_pin

    if compute:
        console.print(f"[cyan]Candidate WPS PINs for {bssid}:[/cyan]")
        for pin in candidate_pins(bssid):
            console.print(format_pin(pin))
        return

    if not interface or channel is None:
        console.print("[red]--interface and --channel are required for an attack[/red]")
        raise typer.Exit(2)

    async def run_wps():
        from netreaper.core.exceptions import TargetValidationError
        from netreaper.wireless.wps import wps_attack

        console.print(f"[cyan]WPS attack on {bssid} (channel {channel})...[/cyan]")
        try:
            result = await wps_attack(
                interface, bssid, channel, essid=essid, try_pixie_dust=not no_pixie
            )
        except TargetValidationError as exc:
            console.print(f"[red]Denied by scope gate: {exc}[/red]")
            raise typer.Exit(2) from exc

        if result.success:
            console.print(f"[green]WPS PIN: {result.pin}[/green]")
            if result.psk:
                console.print(f"[green]PSK: {result.psk}[/green]")
        else:
            tried = result.tried
            console.print(
                f"[yellow]No PIN recovered ({tried} candidate(s) tried).[/yellow]"
            )
            raise typer.Exit(1)

    asyncio.run(run_wps())


@wifi_app.command("wep")
def wifi_wep(
    interface: str = typer.Argument(..., help="Monitor-mode interface"),
    bssid: str = typer.Argument(..., help="Target access point BSSID"),
    channel: int = typer.Argument(..., help="Target channel"),
    essid: str = typer.Option("", "--essid", "-e", help="Network name (for fakeauth)"),
    source_mac: str = typer.Option(
        None, "--source-mac", "-m", help="Attacker MAC (enables injection)"
    ),
    output: str = typer.Option(None, "--output", "-o", help="Capture file prefix"),
    seconds: int = typer.Option(30, "--seconds", "-s", help="IV window per round"),
    rounds: int = typer.Option(5, "--rounds", "-r", help="Capture+crack rounds"),
):
    """Recover a WEP key (IV collection, injection, aircrack-ng)."""

    async def run_wep():
        from netreaper.core.exceptions import TargetValidationError
        from netreaper.wireless.wep import crack_wep

        console.print(f"[cyan]WEP attack on {bssid} (channel {channel})...[/cyan]")
        try:
            result = await crack_wep(
                interface,
                bssid,
                channel,
                essid=essid,
                source_mac=source_mac,
                output=output,
                capture_seconds=seconds,
                max_rounds=rounds,
            )
        except TargetValidationError as exc:
            console.print(f"[red]Denied by scope gate: {exc}[/red]")
            raise typer.Exit(2) from exc

        if result.cracked:
            console.print(f"[green]WEP key: {result.key}[/green]")
            console.print(f"Saved to: {result.cap_file}")
        else:
            console.print(
                f"[yellow]No key after {result.rounds} round(s). "
                "Collect more IVs (longer window, injection).[/yellow]"
            )
            raise typer.Exit(1)

    asyncio.run(run_wep())


@wifi_app.command("eviltwin")
def wifi_eviltwin(
    interface: str = typer.Argument(..., help="Interface for the rogue AP"),
    ssid: str = typer.Argument(..., help="SSID to clone"),
    channel: int = typer.Argument(..., help="Channel (band is derived from it)"),
    gateway: str = typer.Option("10.0.0.1", "--gateway", "-g", help="Rogue gateway IP"),
    deauth_bssid: str = typer.Option(
        None, "--deauth-bssid", help="Deauth this real AP (needs --mon-interface)"
    ),
    mon_interface: str = typer.Option(
        None, "--mon-interface", help="Monitor interface for the deauth"
    ),
):
    """Stand up an evil-twin AP; press Ctrl-C to tear it down cleanly."""

    async def run_et():
        from netreaper.core.exceptions import TargetValidationError
        from netreaper.wireless.eviltwin import EvilTwin

        et = EvilTwin()
        try:
            try:
                await et.start(interface, ssid, channel, gateway_ip=gateway)
            except TargetValidationError as exc:
                console.print(f"[red]Denied by scope gate: {exc}[/red]")
                raise typer.Exit(2) from exc

            console.print(
                f"[green]Evil-twin '{ssid}' up on {interface} (ch {channel}). "
                "Press Ctrl-C to stop.[/green]"
            )
            if deauth_bssid and mon_interface:
                await et.deauth_real_ap(mon_interface, deauth_bssid)
            while True:
                await asyncio.sleep(3600)
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        finally:
            # Tear down whatever start() actually mutated, even if it failed
            # partway (state is published before the first mutation). A scope
            # denial before any mutation leaves state None, so nothing to undo.
            if et.state is not None:
                await et.stop()
                console.print("[cyan]Evil-twin torn down.[/cyan]")

    try:
        asyncio.run(run_et())
    except KeyboardInterrupt:
        pass


@wifi_app.command("enterprise")
def wifi_enterprise(
    interface: str = typer.Argument(..., help="Interface for the rogue AP"),
    ssid: str = typer.Argument(..., help="Enterprise SSID to clone"),
    channel: int = typer.Argument(..., help="Channel (band derived from it)"),
    gateway: str = typer.Option("10.0.0.1", "--gateway", "-g", help="Rogue gateway IP"),
    output: str = typer.Option(None, "--output", "-o", help="hashcat 5500 output file"),
):
    """Rogue WPA-Enterprise AP: capture MSCHAPv2 creds (hashcat 5500)."""

    async def run_ent():
        from netreaper.core.exceptions import TargetValidationError
        from netreaper.wireless.enterprise import EnterpriseAttack, export_hashcat

        ent = EnterpriseAttack()
        try:
            try:
                await ent.start(interface, ssid, channel, gateway_ip=gateway)
            except TargetValidationError as exc:
                console.print(f"[red]Denied by scope gate: {exc}[/red]")
                raise typer.Exit(2) from exc
            console.print(
                f"[green]Enterprise rogue AP '{ssid}' up on {interface}. "
                "Press Ctrl-C to stop.[/green]"
            )
            while True:
                await asyncio.sleep(3600)
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        finally:
            if ent.state is not None:
                creds = ent.read_credentials()
                await ent.stop()
                console.print("[cyan]Enterprise rogue AP torn down.[/cyan]")
                if creds:
                    n = len(creds)
                    console.print(f"[green]Captured {n} credential(s):[/green]")
                    for c in creds:
                        console.print(f"  {c.username}")
                    hashes = export_hashcat(creds)
                    if output:
                        Path(output).write_text(hashes + "\n")
                        console.print(f"hashcat 5500 written to: {output}")
                    else:
                        console.print(hashes)
                else:
                    console.print("[yellow]No credentials captured.[/yellow]")

    try:
        asyncio.run(run_ent())
    except KeyboardInterrupt:
        pass


@wifi_app.command("hidden")
def wifi_hidden(
    interface: str = typer.Argument(..., help="Monitor-mode interface"),
    bssid: str = typer.Argument(..., help="Target (hidden) AP BSSID"),
    channel: int = typer.Argument(..., help="Target channel"),
    wordlist: str = typer.Option(
        None, "--wordlist", "-w", help="Probe this SSID wordlist (mdk4) not deauth"
    ),
):
    """Reveal a cloaked ESSID: deauth clients (default) or probe a wordlist."""

    async def run_hidden():
        from netreaper.core.exceptions import TargetValidationError
        from netreaper.wireless.advanced import HiddenSSIDReveal

        reveal = HiddenSSIDReveal()
        try:
            if wordlist:
                await reveal.reveal_by_probe(interface, bssid, wordlist)
                console.print(
                    "[cyan]Probe sweep done. Watch a scan for the revealed SSID.[/cyan]"
                )
            else:
                essid = await reveal.reveal_by_deauth(interface, bssid, channel)
                if essid:
                    console.print(f"[green]Revealed SSID: {essid}[/green]")
                else:
                    console.print(
                        "[yellow]SSID stayed hidden (no clients/cloaked).[/yellow]"
                    )
                    raise typer.Exit(1)
        except TargetValidationError as exc:
            console.print(f"[red]Denied by scope gate: {exc}[/red]")
            raise typer.Exit(2) from exc
        except FileNotFoundError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(2) from exc

    asyncio.run(run_hidden())


@wifi_app.command("wpa3")
def wifi_wpa3(
    interface: str = typer.Argument(..., help="Monitor-mode interface"),
    bssid: str = typer.Argument(..., help="Target AP BSSID"),
    timeout: int = typer.Option(15, "--timeout", "-t", help="Scan window (seconds)"),
):
    """Classify an AP's security (WPA3/SAE, OWE, ...) and advise on Dragonblood."""

    async def run_wpa3():
        from netreaper.core.exceptions import TargetValidationError
        from netreaper.wireless.advanced import classify_security, dragonblood_advisory
        from netreaper.wireless.scan import scan_networks

        console.print(f"[cyan]Scanning {interface} for {timeout}s...[/cyan]")
        try:
            result = await scan_networks(interface, duration=timeout)
        except TargetValidationError as exc:
            console.print(f"[red]Denied by scope gate: {exc}[/red]")
            raise typer.Exit(2) from exc
        ap = result.find_ap(bssid)
        if ap is None:
            console.print(f"[yellow]{bssid} not seen in the scan.[/yellow]")
            raise typer.Exit(1)
        sec = classify_security(ap)
        console.print(f"[green]{bssid} security: {sec.upper()}[/green]")
        if "SAE" in ap.auth.upper() and "WPA2" in ap.privacy.upper():
            console.print(
                "[cyan]Transition mode (WPA2+WPA3): `wifi downgrade` applies.[/cyan]"
            )
        if sec == "wpa3":
            console.print(dragonblood_advisory().render())

    asyncio.run(run_wpa3())


@wifi_app.command("downgrade")
def wifi_downgrade(
    interface: str = typer.Argument(..., help="Interface for the WPA2 twin"),
    ssid: str = typer.Argument(..., help="SSID to clone (WPA3 transition target)"),
    channel: int = typer.Argument(..., help="Channel (band derived from it)"),
    passphrase: str = typer.Option(
        "12345678", "--passphrase", "-p", help="WPA2 passphrase for the twin"
    ),
):
    """WPA2-only twin to downgrade a WPA3 transition-mode AP; Ctrl-C to tear down."""

    async def run_dg():
        from netreaper.core.exceptions import TargetValidationError, ToolNotFoundError
        from netreaper.wireless.advanced import WPA3Downgrade

        dg = WPA3Downgrade()
        try:
            try:
                await dg.start(interface, ssid, channel, passphrase=passphrase)
            except TargetValidationError as exc:
                console.print(f"[red]Denied by scope gate: {exc}[/red]")
                raise typer.Exit(2) from exc
            except (ValueError, ToolNotFoundError) as exc:
                console.print(f"[red]{exc}[/red]")
                raise typer.Exit(2) from exc
            console.print(
                f"[green]WPA2 downgrade twin '{ssid}' up on {interface} "
                f"(ch {channel}). Press Ctrl-C to stop.[/green]"
            )
            while True:
                await asyncio.sleep(3600)
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        finally:
            if dg.state is not None:
                await dg.stop()
                console.print("[cyan]Downgrade twin torn down.[/cyan]")

    try:
        asyncio.run(run_dg())
    except KeyboardInterrupt:
        pass


@wifi_app.command("arpspoof")
def wifi_arpspoof(
    interface: str = typer.Argument(..., help="Interface on the target LAN"),
    gateway: str = typer.Argument(..., help="Gateway IP"),
    target: str = typer.Argument(..., help="Victim client IP"),
):
    """Bypass client isolation with a bidirectional ARP-spoof MITM; Ctrl-C to stop."""

    async def run_arp():
        from netreaper.core.exceptions import TargetValidationError, ToolNotFoundError
        from netreaper.wireless.advanced import ArpSpoof, check_isolation

        spoof = ArpSpoof()
        try:
            try:
                if await check_isolation(target):
                    console.print(
                        "[yellow]Target already reachable (no isolation). "
                        "Spoofing anyway.[/yellow]"
                    )
                await spoof.start(interface, gateway, target)
            except TargetValidationError as exc:
                console.print(f"[red]Denied by scope gate: {exc}[/red]")
                raise typer.Exit(2) from exc
            except (ValueError, ToolNotFoundError) as exc:
                console.print(f"[red]{exc}[/red]")
                raise typer.Exit(2) from exc
            console.print(
                f"[green]ARP spoof {gateway} <-> {target} on {interface}. "
                "Press Ctrl-C to stop.[/green]"
            )
            while True:
                await asyncio.sleep(3600)
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        finally:
            if spoof.state is not None:
                await spoof.stop()
                console.print("[cyan]ARP spoof torn down.[/cyan]")

    try:
        asyncio.run(run_arp())
    except KeyboardInterrupt:
        pass


@wifi_app.command("mac-random")
def wifi_mac_random(
    interface: str = typer.Argument(..., help="Wireless interface"),
    vendor: str = typer.Option(
        "random", "--vendor", help="OUI vendor: apple, samsung, intel, realtek, random"
    ),
):
    """Randomise the adapter MAC (WIDS evasion)."""

    async def run_r():
        from netreaper.core.exceptions import TargetValidationError, ToolNotFoundError
        from netreaper.wireless.advanced import randomize_mac

        try:
            mac = await randomize_mac(interface, vendor=vendor)
        except TargetValidationError as exc:
            console.print(f"[red]Denied: {exc}[/red]")
            raise typer.Exit(2) from exc
        except (ValueError, RuntimeError, ToolNotFoundError) as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(2) from exc
        console.print(f"[green]MAC on {interface} -> {mac}[/green]")

    asyncio.run(run_r())


@wifi_app.command("mac-clone")
def wifi_mac_clone(
    interface: str = typer.Argument(..., help="Wireless interface"),
    bssid: str = typer.Argument(..., help="AP BSSID to clone"),
    channel: int = typer.Argument(..., help="Channel to match"),
):
    """Clone a legitimate AP's BSSID + channel onto the adapter (WIDS evasion)."""

    async def run_c():
        from netreaper.core.exceptions import TargetValidationError, ToolNotFoundError
        from netreaper.wireless.advanced import clone_ap_mac

        try:
            mac = await clone_ap_mac(interface, bssid, channel)
        except TargetValidationError as exc:
            console.print(f"[red]Denied: {exc}[/red]")
            raise typer.Exit(2) from exc
        except (ValueError, RuntimeError, ToolNotFoundError) as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(2) from exc
        console.print(
            f"[green]{interface} now cloning {mac} on channel {channel}[/green]"
        )

    asyncio.run(run_c())


@wifi_app.command("plan")
def wifi_plan(
    goal: str = typer.Argument(
        "wifi.password", help="Goal capability to resolve (e.g. wifi.password)"
    ),
    have: list[str] = typer.Option(
        None, "--have", help="A known capability (repeatable): --have wifi.handshake"
    ),
):
    """Resolve and print the backward-chained plan for a goal (dry run)."""
    from netreaper.chaining.manifest import (
        MissingCapabilityError,
        manifest_registry,
        resolve_chain,
    )
    from netreaper.core.exceptions import ConfigurationError, PluginError
    from netreaper.wireless.manifests import register_wifi_manifests

    try:
        register_wifi_manifests()
        plan = resolve_chain(goal, manifest_registry, available=set(have or ()))
    except MissingCapabilityError as exc:
        console.print(
            f"[red]Cannot plan {goal!r}: {exc}[/red]\n"
            "[yellow]No registered tool provides that capability.[/yellow]"
        )
        raise typer.Exit(2) from exc
    except (ConfigurationError, PluginError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc
    console.print(plan.render())


@wifi_app.command("crack")
def wifi_crack(
    cap_file: str = typer.Argument(..., help="Captured handshake .cap file"),
    bssid: str = typer.Argument(..., help="Target AP BSSID"),
    wordlist: str = typer.Argument(..., help="Wordlist path"),
):
    """Crack a captured WPA handshake against a wordlist (aircrack-ng, offline)."""

    async def run_crack():
        from netreaper.core.exceptions import TargetValidationError
        from netreaper.wireless.crack import crack_handshake

        try:
            res = await crack_handshake(cap_file, bssid, wordlist)
        except FileNotFoundError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(2) from exc
        except TargetValidationError as exc:
            console.print(f"[red]Denied: {exc}[/red]")
            raise typer.Exit(2) from exc
        if res.cracked:
            console.print(
                f"[green]Password recovered for {bssid}: {res.password}[/green]"
            )
        else:
            console.print(
                "[yellow]Not cracked (passphrase not in the wordlist).[/yellow]"
            )
            raise typer.Exit(1)

    asyncio.run(run_crack())


@wifi_app.command("auto")
def wifi_auto(
    interface: str = typer.Option(..., "--interface", "-i", help="Wireless interface"),
    goal: str = typer.Option("wifi.password", "--goal", "-g", help="Goal capability"),
    target: str = typer.Option(None, "--target", "-t", help="Target BSSID (capture)"),
    channel: int = typer.Option(None, "--channel", "-c", help="Target channel"),
    wordlist: str = typer.Option(None, "--wordlist", "-w", help="Wordlist (crack)"),
    run: bool = typer.Option(
        False, "--run", help="Execute the chain (default: dry-run preview)"
    ),
):
    """Resolve a goal and auto-run its capability chain (dry run unless --run)."""

    async def _auto():
        from netreaper.chaining.executor import ChainExecutor
        from netreaper.chaining.manifest import MissingCapabilityError, resolve_chain
        from netreaper.chaining.plan_exec import manifest_step_runner, plan_to_chain
        from netreaper.core.exceptions import PluginError, TargetValidationError
        from netreaper.wireless.autochain import AutoContext, build_wifi_registry

        ctx = AutoContext(
            interface=interface, target_bssid=target,
            channel=channel, wordlist=wordlist,
        )
        reg = build_wifi_registry(ctx)
        try:
            plan = resolve_chain(goal, reg)
        except MissingCapabilityError as exc:
            console.print(f"[red]Cannot plan {goal!r}: {exc}[/red]")
            raise typer.Exit(2) from exc
        console.print(plan.render())
        if not run:
            console.print("[cyan]Dry run — re-run with --run to execute.[/cyan]")
            return
        try:
            result = await ChainExecutor(
                step_runner=manifest_step_runner(reg)
            ).execute(plan_to_chain(plan))
        except TargetValidationError as exc:
            console.print(f"[red]Denied by scope gate: {exc}[/red]")
            raise typer.Exit(2) from exc
        except PluginError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(1) from exc
        if result.success and ctx.password:
            console.print(f"[green]Recovered {goal}: {ctx.password}[/green]")
        elif result.success:
            console.print("[green]Chain completed.[/green]")
        else:
            failed = [s.tool for s in result.steps.values()
                      if s.status.value == "failed"]
            console.print(
                f"[yellow]Chain did not complete; step(s) failed: "
                f"{', '.join(failed) or '?'}[/yellow]"
            )
            raise typer.Exit(1)

    asyncio.run(_auto())


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
