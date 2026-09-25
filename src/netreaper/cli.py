"""NETREAPER CLI interface using Typer."""
import asyncio
import contextlib
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
    # Named with a leading underscore because nothing reads it: the flag exists
    # so typer registers --version/-v, and version_callback does the work
    # eagerly before any subcommand runs. The option names are given
    # explicitly above, so the parameter's Python name is free.
    _version: bool = typer.Option(
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


def _one_of(value: str, choices: tuple[str, ...], *, what: str) -> str:
    """Validate a free-string action argument as a USAGE error.

    `config` and `wifi monitor` take their action as a plain `str` argument, so
    Click accepts anything and the command discovers the problem itself, deep
    in its own body. Both then exited 1, which reads as "it ran and failed"
    rather than "that is not a thing you can type".

    The difference matters because tests/unit/test_readme_commands_exist.py
    treats any non-2 exit as success: a command that parses and then refuses
    for want of an engagement is correctly documented. So an invalid action
    that exited 1 was indistinguishable from a working command in a bare
    environment, and the README documented `wifi monitor start` and `config
    reset` through several releases with that guard green. Neither exists.

    typer.BadParameter is Click's usage error and exits 2, the same as an
    unknown option, which is exactly what a bad action value is.
    """
    if value not in choices:
        raise typer.BadParameter(
            f"{value!r} is not a valid {what}. Choose one of: {', '.join(choices)}"
        )
    return value


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


def _settings_key_paths() -> list[str]:
    """Every dotted key the Settings schema actually defines."""
    from pydantic import BaseModel

    from netreaper.config.settings import Settings

    out: list[str] = []

    def walk(model: type[BaseModel], prefix: str = "") -> None:
        for name, field in model.model_fields.items():
            annotation = field.annotation
            if isinstance(annotation, type) and issubclass(annotation, BaseModel):
                walk(annotation, f"{prefix}{name}.")
            else:
                out.append(f"{prefix}{name}")

    walk(Settings)
    return out


def _persist_config(dotted_key: str, value: str) -> None:
    """Write a dotted key into the user config.toml, but only if it validates.

    This used to write first and validate afterwards, via the reload_settings()
    call in its caller. Two ways that went wrong, both of which cost a real
    config file:

      the wrong type   `config set logging.level DEBUG` printed a pydantic
                       error AND stored the string. Every later load then
                       failed on it, so `config show` was broken until the file
                       was deleted by hand. A command that rejects your input
                       must not keep it.
      the wrong key    Settings is a plain BaseModel, so pydantic ignores extra
                       keys. `config set key value` therefore "succeeded",
                       silently writing a top-level `key = "value"` that no
                       consumer reads. The README's own example did exactly
                       this, on every machine that ran the docs test.

    So: the key is checked against the schema, the whole candidate config is
    validated as a unit, and only then does anything reach disk. The write is
    atomic, because a config truncated by a crash is the same outage as a
    config poisoned by a bad value.
    """
    import os
    import tempfile

    import tomli_w
    from pydantic import ValidationError

    from netreaper.config.settings import (
        _DEFAULTS_PATH,
        Settings,
        _deep_merge,
        _load_toml,
    )
    from netreaper.core.constants import NETREAPER_CONFIG_DIR

    valid = _settings_key_paths()
    if dotted_key not in valid:
        import difflib

        near = difflib.get_close_matches(dotted_key, valid, n=3, cutoff=0.5)
        hint = f" Did you mean: {', '.join(near)}?" if near else ""
        raise typer.BadParameter(
            f"unknown setting {dotted_key!r}; it is not in the schema.{hint}"
        )

    cfg_path = NETREAPER_CONFIG_DIR / "config.toml"
    data: dict = _load_toml(cfg_path)

    parts = dotted_key.split(".")
    node = data
    for part in parts[:-1]:
        node = node.setdefault(part, {})
        if not isinstance(node, dict):
            raise typer.BadParameter(f"{dotted_key!r} conflicts with a non-table value")
    node[parts[-1]] = _coerce(value)

    # Validate the WHOLE candidate, layered exactly as _build_settings does it,
    # so the check matches what the next load will actually attempt.
    try:
        Settings(**_deep_merge(_load_toml(_DEFAULTS_PATH), data))
    except ValidationError as exc:
        parts = []
        for e in exc.errors():
            loc = ".".join(str(p) for p in e["loc"])
            # Naming the key again when it is the key we were given reads as
            # "logging.level rejected: logging.level: ...".
            parts.append(e["msg"] if loc == dotted_key else f"{loc}: {e['msg']}")
        detail = "; ".join(parts)
        # Outcome first: Rich truncates a long message inside the usage box,
        # and "nothing was written" is the part the operator must not miss.
        raise typer.BadParameter(
            f"nothing written. {dotted_key} rejected: {detail}"
        ) from None

    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=cfg_path.parent, prefix=".config.", suffix=".toml")
    try:
        with os.fdopen(fd, "wb") as fh:
            tomli_w.dump(data, fh)
        os.replace(tmp, cfg_path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


@app.command()
def config(
    action: str = typer.Argument(..., help="Action: show, get, set"),
    key: str | None = typer.Argument(None, help="Config key (dotted), e.g. safety.unsafe_mode"),
    value: str | None = typer.Argument(None, help="Value for 'set'"),
):
    """Manage configuration."""
    from netreaper.config.settings import get_settings, reload_settings

    _one_of(action, ("show", "list", "get", "set"), what="config action")
    if action == "get" and not key:
        raise typer.BadParameter(
            "config get needs a key, e.g. config get logging.level"
        )
    if action == "set" and (not key or value is None):
        raise typer.BadParameter(
            "config set needs a key and a value, e.g. config set logging.level 10"
        )

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
    else:  # pragma: no cover - _one_of and the checks above cover every path
        raise typer.BadParameter(
            "usage: config show | get <key> | set <key> <value>"
        )


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


def _check_engagement_basics(operator: str, ref: str, hours: float) -> None:
    """Who, under what authority, for how long. All three are refusals, not
    warnings: an engagement missing any of them records no authorisation."""
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


def _parse_max_tier(max_tier: str):
    """The blast-radius ceiling: what this engagement MAY reach."""
    from netreaper.safety.scope import Tier

    try:
        return Tier[max_tier.strip().upper()]
    except KeyError:
        console.print(
            f"[red]invalid --max-tier {max_tier!r}; use one of: {_TIER_NAMES}[/red]"
        )
        raise typer.Exit(2) from None


def _parse_confirmed_tiers(confirm_tier: list[str] | None) -> set:
    """The grants: which tiers the operator states they intended."""
    from netreaper.safety.scope import Tier

    confirmed: set[Tier] = set()
    for name in confirm_tier or []:
        try:
            confirmed.add(Tier[name.strip().upper()])
        except KeyError:
            console.print(
                f"[red]invalid --confirm-tier {name!r}; use one of: {_TIER_NAMES}[/red]"
            )
            raise typer.Exit(2) from None
    return confirmed


def _check_tier_grants(tier, confirmed: set, accept_interception: bool) -> None:
    """A ceiling and a grant have to agree, and MITM costs a sentence.

    Kept as its own step because these are the two rules an operator gets
    wrong: confirming above the ceiling, and confirming MITM without the
    dangerous-ops phrase.
    """
    from netreaper.safety.scope import Tier

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

    _check_engagement_basics(operator, ref, hours)
    tier = _parse_max_tier(max_tier)
    confirmed = _parse_confirmed_tiers(confirm_tier)
    _check_tier_grants(tier, confirmed, accept_interception)

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
    # Up front, before asyncio.run and before the imports below: a typo should
    # not cost you an event loop, and it must exit 2 rather than 1.
    _one_of(action, ("enable", "disable", "status"), what="monitor action")

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
            mon_status = await get_monitor_status(interface)
            console.print(f"Interface: {interface}")
            console.print(f"Is wireless: {mon_status.get('is_wireless')}")
            console.print(f"Current mode: {mon_status.get('current_mode')}")
            console.print(f"In monitor mode: {mon_status.get('is_monitor')}")
            console.print(f"Supports monitor: {mon_status.get('supports_monitor')}")
            console.print(f"Supports injection: {mon_status.get('supports_injection')}")
        else:  # pragma: no cover - _one_of above rejects anything else
            raise typer.BadParameter(
                f"{action!r} is not a valid monitor action"
            )

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
    injection: str = typer.Option(
        "arpreplay",
        "--injection",
        "-i",
        help=(
            "IV-generation strategy: arpreplay, chopchop, fragment, "
            "caffe_latte, cfrag, interactive"
        ),
    ),
):
    """Recover a WEP key (IV collection, injection, aircrack-ng).

    --injection picks the strategy. The aireplay-ng primitives for chopchop,
    fragmentation, caffe-latte, cfrag and interactive replay all existed but
    were unreachable: wep.py only ever drove ARP replay and there was no flag
    to choose anything else (#47).
    """

    async def run_wep():
        from netreaper.core.exceptions import (
            ConfigurationError,
            TargetValidationError,
        )
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
                injection=injection,
            )
        except ConfigurationError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(2) from exc
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
    refresh: bool = typer.Option(
        False, "--refresh",
        help="Ignore and clear cached state for the target, re-deriving from scratch",
    ),
    run: bool = typer.Option(
        False, "--run", help="Execute the chain (default: dry-run preview)"
    ),
):
    """Resolve a goal and auto-run its capability chain (dry run unless --run)."""

    async def _auto():
        from netreaper.chaining.executor import ChainExecutor
        from netreaper.chaining.manifest import MissingCapabilityError, resolve_chain
        from netreaper.chaining.plan_exec import manifest_step_runner, plan_to_chain
        from netreaper.chaining.state_cache import (
            available_for,
            forget,
            record_plan_outputs,
        )
        from netreaper.core.exceptions import PluginError, TargetValidationError
        from netreaper.wireless.autochain import AutoContext, build_wifi_registry

        ctx = AutoContext(
            interface=interface, target_bssid=target,
            channel=channel, wordlist=wordlist,
        )
        reg = build_wifi_registry(ctx)

        # Feed the planner what this target already yielded on a prior run so it
        # can skip re-deriving it. Only with a target to key on; --refresh wipes
        # it first (a cracked network's password can change out of band).
        available: set[str] = set()
        if target:
            if refresh:
                await forget("bssid", target)
            else:
                available = await available_for("bssid", target)

        try:
            plan = resolve_chain(goal, reg, available=available or None)
        except MissingCapabilityError as exc:
            console.print(f"[red]Cannot plan {goal!r}: {exc}[/red]")
            raise typer.Exit(2) from exc
        if available:
            console.print(
                f"[dim]Cached for {target}: {', '.join(sorted(available))} "
                f"(--refresh to ignore)[/dim]"
            )
        console.print(plan.render())
        if not plan.steps:
            return  # goal already satisfied from cache; nothing to run or preview
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
        if result.success and target:
            # Remember the durable capabilities this run obtained, so the next
            # run for this target can skip them. record_plan_outputs drops the
            # ephemeral ones and the handshake whose temp file the auto path
            # already deleted.
            await record_plan_outputs("bssid", target, result.final_output)
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

# ─────────────────────────── resources (#33) ────────────────────────────────

resources_app = typer.Typer(help="External sources this build incorporates")
app.add_typer(resources_app, name="resources")


@resources_app.command("list")
def resources_list():
    """Show every external source, how it is incorporated, and its licence."""
    from netreaper.resources import SOURCES
    from netreaper.resources.registry import validate_registry

    table = Table(title="External sources")
    for col in ("Source", "Kind", "How", "Domain", "Licence"):
        table.add_column(col)
    for s in SOURCES:
        licence = s.licence if s.licence_verified else "[yellow]unverified[/yellow]"
        name = f"[red]{s.name}[/red]" if s.is_safety_restricted else s.name
        table.add_row(name, s.kind.value, s.incorporation.value, s.domain, licence)
    console.print(table)

    restricted = [s for s in SOURCES if s.is_safety_restricted]
    if restricted:
        console.print("\n[red]Safety-restricted (documented, not implemented):[/red]")
        for s in restricted:
            console.print(f"  [red]{s.name}[/red]: {s.safety_note}")

    problems = validate_registry()
    if problems:
        console.print("\n[red]Registry violations:[/red]")
        for pr in problems:
            console.print(f"  {pr}")
        raise typer.Exit(1)


@resources_app.command("show")
def resources_show(name: str = typer.Argument(..., help="Source name")):
    """Detail for one source."""
    from netreaper.resources import get_source

    s = get_source(name)
    if s is None:
        console.print(f"[red]no such source: {name}[/red]")
        raise typer.Exit(2)
    console.print(f"[cyan]{s.name}[/cyan]  {s.url}")
    console.print(f"  kind: {s.kind.value}   incorporation: {s.incorporation.value}")
    console.print(f"  domain: {s.domain}   licence: {s.licence}")
    console.print(f"  {s.summary}")
    if s.provides:
        console.print(f"  provides: {', '.join(s.provides)}")
    if s.safety_note:
        console.print(f"\n[red]SAFETY: {s.safety_note}[/red]")

# ───────── wiring the orphaned tool wrappers (#33 reachability) ─────────────
#
# GobusterTool, HydraTool, MasscanTool, SubfinderTool and WhatWebTool were
# complete, tested-in-isolation wrappers that NOTHING referenced: no CLI
# command, no chain, no manifest. Roughly 1,500 lines a user could not invoke.
# Each goes through BaseToolWrapper.execute(), so naming the target here is what
# makes the scope gate check it.

web_app = typer.Typer(help="Web application recon")
app.add_typer(web_app, name="web")

creds_app = typer.Typer(help="Credential attacks")
app.add_typer(creds_app, name="creds")

osint_app = typer.Typer(help="Open-source intelligence")
app.add_typer(osint_app, name="osint")

can_app = typer.Typer(help="Automotive CAN bus (read-only)")
app.add_typer(can_app, name="can")


def _run_tool(coro_factory, label: str):
    """Shared runner: gate denials and missing tools are reported, not tracebacks."""
    from netreaper.core.exceptions import (
        SubprocessError,
        TargetValidationError,
        ToolNotFoundError,
    )

    async def _go():
        try:
            return await coro_factory()
        except TargetValidationError as exc:
            console.print(f"[red]Denied by scope gate: {exc}[/red]")
            raise typer.Exit(2) from exc
        except ToolNotFoundError as exc:
            console.print(f"[yellow]{label} is not installed: {exc}[/yellow]")
            raise typer.Exit(3) from exc
        except SubprocessError as exc:
            console.print(f"[red]{label} failed: {exc}[/red]")
            raise typer.Exit(1) from exc

    return asyncio.run(_go())


@web_app.command("dirs")
def web_dirs(
    target: str = typer.Argument(..., help="Target URL"),
    wordlist: str = typer.Option(None, "--wordlist", "-w", help="Wordlist path"),
):
    """Directory and file discovery (gobuster)."""
    from netreaper.tools.gobuster import GobusterTool

    opts = {"wordlist": wordlist} if wordlist else {}
    res = _run_tool(lambda: GobusterTool().execute(target, opts), "gobuster")
    console.print(res.stdout if hasattr(res, "stdout") else res)


@web_app.command("fingerprint")
def web_fingerprint(target: str = typer.Argument(..., help="Target URL")):
    """Identify web technologies (whatweb)."""
    from netreaper.tools.whatweb import WhatWebTool

    res = _run_tool(lambda: WhatWebTool().execute(target, {}), "whatweb")
    console.print(res.stdout if hasattr(res, "stdout") else res)


@app.command("portscan")
def portscan(
    target: str = typer.Argument(..., help="Target IP or CIDR"),
    ports: str = typer.Option("1-65535", "--ports", "-p", help="Port range"),
):
    """Fast port sweep (masscan)."""
    from netreaper.tools.masscan import MasscanTool

    res = _run_tool(lambda: MasscanTool().execute(target, {"ports": ports}), "masscan")
    console.print(res.stdout if hasattr(res, "stdout") else res)


@osint_app.command("subdomains")
def osint_subdomains(domain: str = typer.Argument(..., help="Root domain")):
    """Passive subdomain enumeration (subfinder)."""
    from netreaper.tools.subfinder import SubfinderTool

    res = _run_tool(lambda: SubfinderTool().execute(domain, {}), "subfinder")
    console.print(res.stdout if hasattr(res, "stdout") else res)


@creds_app.command("attack")
def creds_attack(
    target: str = typer.Argument(
        ..., help="Target host (scheme and port are stripped)"
    ),
    service: str = typer.Option(
        "ssh", "--service", "-s", help="ssh/ftp/smb/rdp/mysql"
    ),
    username: str = typer.Option(None, "--username", "-l"),
    user_list: str = typer.Option(None, "--user-list", "-L"),
    pass_list: str = typer.Option(None, "--pass-list", "-P"),
):
    """Credential attack (hydra).

    Tiered SINGLE_TARGET, so it needs a confirmation grant on the engagement.
    """
    from netreaper.tools.hydra import HydraTool

    opts = {
        k: v
        for k, v in {
            "service": service,
            "username": username,
            "user_list": user_list,
            "pass_list": pass_list,
        }.items()
        if v
    }
    res = _run_tool(lambda: HydraTool().execute(target, opts), "hydra")
    console.print(res.stdout if hasattr(res, "stdout") else res)


@can_app.command("interfaces")
def can_interfaces():
    """List SocketCAN interfaces."""
    from netreaper.tools.canutils import CanUtilsTool

    found = _run_tool(lambda: CanUtilsTool().list_interfaces(), "ip")
    if not found:
        console.print(
            "[yellow]No CAN interfaces. `ip link add dev vcan0 type vcan` "
            "gives you a virtual one for testing.[/yellow]"
        )
        return
    for i in found:
        console.print(f"  {i}")


@can_app.command("dump")
def can_dump(
    interface: str = typer.Argument(
        ..., help="SocketCAN interface, e.g. can0 or vcan0"
    ),
    seconds: int = typer.Option(10, "--seconds", "-s", help="Capture window"),
    frames: int = typer.Option(
        0, "--frames", "-n", help="Stop after N frames (0 = time-bound)"
    ),
    database: str = typer.Option(
        None, "--db", "-d", help="CAN id database file or directory"
    ),
):
    """Read and decode a CAN bus. Read-only: this cannot transmit."""


    from netreaper.automotive import CanIdDatabase, decode_capture
    from netreaper.tools.canutils import CanUtilsTool

    cap = _run_tool(
        lambda: CanUtilsTool().dump(interface, seconds=seconds, max_frames=frames),
        "candump",
    )
    console.print(
        f"[green]{cap.frame_count} frames, "
        f"{len(cap.unique_ids)} unique ids[/green]"
    )
    if not database:
        for fid in sorted(cap.unique_ids):
            console.print(f"  {fid}")
        return
    db = CanIdDatabase.load(Path(database))
    table = Table(title=f"Decoded ({len(db)} known ids)")
    for col in ("CAN ID", "Signal", "Data"):
        table.add_column(col)
    seen = set()
    for f in decode_capture(cap, db):
        if f.can_id in seen:
            continue
        seen.add(f.can_id)
        table.add_row(f.can_id, f.name, f.data)
    console.print(table)

