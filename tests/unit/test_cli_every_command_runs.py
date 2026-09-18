# SPDX-License-Identifier: GPL-3.0-or-later
"""Every CLI command body executes. Discovered from the app, not listed by hand.

cli.py is 743 statements at 28% and it is the only path a user has. The 526
uncovered lines are the command bodies: 30-odd functions that no test had ever
entered. That is the gap that produced the last two defects of this shape.

  traffic.py had four undefined names after a mechanical gate insertion,
  including a call referencing an `interface` that was not in scope. No test
  could catch it because no test imported the module, let alone ran the body.
  Ruff found it.

  cli.py's own gate insertion had the same shape: a body that referenced a
  name the function never bound, which no test could see because no test
  entered the function.

So: discover the commands from the Typer app, require a table entry for each
(a new command with no entry fails here), and invoke every one of them with the
exec patched out and everything above it left real. The gate runs, the audit
records, the argv is assembled. Only the syscall is missing.

What counts as a failure is an unhandled exception. A command may legitimately
exit 1 (nothing captured) or 2 (denied by the gate); those are outcomes. A
NameError, AttributeError or TypeError from a command body is a defect.

WHAT THIS DOES NOT CATCH, measured rather than assumed. Reintroducing the
aireplay `-x`/`--ignore-negative-one` typo leaves all 36 tests green, because
running a body proves it runs and says nothing about whether the flags it built
are the right ones. Per-flag correctness belongs to the per-tool tests
(test_wep_injection_and_argv.py covers that one). What is asserted about argv
here is only the generic shape below: the kind of damage that shows up in every
tool at once, such as an unset option arriving as the string "None".
"""
from __future__ import annotations

import asyncio
import os
import signal
from contextlib import contextmanager

import click
import pytest
import typer
from typer.testing import CliRunner

from netreaper.cli import app
from netreaper.safety import engagement_store
from netreaper.safety.scope import Tier, get_scope_gate

runner = CliRunner()

IFACE = "wlan0mon"
BSSID = "AA:BB:CC:DD:EE:FF"
ESSID = "CorpWifi"
CIDR = "203.0.113.0/24"
HOST = "203.0.113.10"
DOMAIN = "example.test"

# argv per leaf command, keyed by its full path. Anything the command needs to
# get past argument parsing and into its own body.
ARGV: dict[str, list[str]] = {
    "status": [],
    "scan": [CIDR],  # positional, not --target
    "config": ["show"],
    "portscan": [HOST],  # positional, not --target
    "engage status": [],
    "engage end": [],
    "plugin list": [],
    "resources list": [],
    "resources show": ["--name", "can-utils"],
    "web dirs": ["--target", f"http://{HOST}"],
    "web fingerprint": ["--target", f"http://{HOST}"],
    "osint subdomains": ["--domain", DOMAIN],
    "creds attack": ["--target", HOST],
    "can interfaces": [],
    "can dump": ["--interface", "can0", "--seconds", "1"],
    "wifi scan": ["--interface", IFACE, "--timeout", "1"],
    "wifi monitor": ["--action", "start", "--interface", IFACE],
    "wifi handshake": [IFACE, BSSID, "6", "--seconds", "1",
                   "--deauth", "0", "--attempts", "1"],
    "wifi pmkid": [IFACE, BSSID, "6", "--seconds", "1", "--attempts", "1"],
    "wifi wps": ["--bssid", BSSID],
    "wifi wep": [IFACE, BSSID, "6", "--seconds", "1", "--rounds", "1"],
    "wifi eviltwin": [IFACE, ESSID, "6"],
    "wifi enterprise": [IFACE, ESSID, "6"],
    "wifi hidden": [IFACE, BSSID, "6"],
    "wifi wpa3": [IFACE, BSSID, "--timeout", "1"],
    "wifi downgrade": [IFACE, ESSID, "6"],
    "wifi arpspoof": [IFACE, HOST, HOST],
    "wifi mac-random": ["--interface", IFACE],
    "wifi mac-clone": [IFACE, BSSID, "6"],
    "wifi plan": [],
    "wifi crack": ["--cap-file", "/nonexistent.cap", "--bssid", BSSID,
                   "--wordlist", "/nonexistent.txt"],
    "wifi auto": ["--interface", IFACE],
}

# Commands that hold a process open until an operator stops them: an evil twin
# serves clients, arpspoof poisons until killed. They have no natural return, so
# for these the assertion is that the body got as far as spawning something and
# then blocked, which is the designed behaviour, not a hang.
LONG_RUNNING = frozenset({
    "wifi arpspoof",
    "wifi eviltwin",
    "wifi enterprise",
    "wifi downgrade",
})

# Every binary any command resolves through shutil.which (tools/base.py:80).
# Stubbed onto PATH so a command body runs to completion on a host with no
# wireless tooling installed. Without this the bodies stop at resolution and the
# test measures which packages the CI image happens to carry.
STUB_BINARIES = (
    "aircrack-ng aireplay-ng airmon-ng airodump-ng airbase-ng packetforge-ng "
    "ivstools amass arpspoof bettercap bully candump cansniffer cantools cewl "
    "crunch dirb dnsmasq dsniff ettercap ffuf gobuster hashcat hcxdumptool "
    "hcxpcapngtool hostapd hydra ip iw iwconfig ifconfig john macchanger "
    "masscan mdk4 medusa nikto nmap reaver sqlmap subfinder systemctl nmcli "
    "tcpdump theharvester tshark wash whatweb wifite wpscan xsstrike "
    "wpa_supplicant assetfinder "
    # Host tools the evil-twin and enterprise paths drive: NAT and forwarding,
    # certificate generation, a connectivity check. A hand-written grep for
    # binary names missed all four; the argv assertion below is what found
    # them, and it is what maintains this list from here on.
    "iptables sysctl openssl ping"
).split()


# Commands deliberately not smoke-run, each with the reason. A debt register:
# the test below fails if an entry here has gained an ARGV entry, or stops
# existing, so it cannot quietly become a dumping ground.
NOT_SMOKE_RUN: dict[str, str] = {
    # This reason used to read "launches a full-screen Textual app and blocks
    # on a real terminal". It did not: netreaper.tui.app did not exist, so the
    # command errored instantly. An exemption written from an assumption hid
    # the fact that the tool's default interface had never worked. The app is
    # real now and tests/unit/test_tui_app.py drives it headlessly.
    "tui": "takes over the terminal; driven headlessly in test_tui_app.py instead",
    "engage start": "covered in depth by test_cli_authorisation_ladder.py",
}


def _leaf_commands() -> dict[str, click.Command]:
    """Every leaf command in the app, keyed by full path."""
    found: dict[str, click.Command] = {}

    def walk(cmd: click.Command, path: tuple[str, ...] = ()) -> None:
        subs = getattr(cmd, "commands", None)
        if subs:
            for name, sub in subs.items():
                walk(sub, (*path, name))
        elif path:
            found[" ".join(path)] = cmd

    walk(typer.main.get_command(app))
    return found


# ── the table and the app cannot drift apart ─────────────────────────────────


def test_every_command_is_either_smoke_run_or_declared_unrun():
    """A command added with no entry here fails, rather than going untested."""
    commands = _leaf_commands()
    assert len(commands) > 25, "command discovery is broken"
    missing = sorted(set(commands) - set(ARGV) - set(NOT_SMOKE_RUN))
    assert not missing, (
        "CLI command(s) with no smoke-test entry. Add argv to ARGV, or add the "
        "name to NOT_SMOKE_RUN with a reason:\n  " + "\n  ".join(missing)
    )


def test_the_table_has_no_entries_for_commands_that_no_longer_exist():
    commands = _leaf_commands()
    stale = sorted((set(ARGV) | set(NOT_SMOKE_RUN)) - set(commands))
    assert not stale, "entries for commands that do not exist:\n  " + "\n  ".join(stale)


def test_nothing_is_both_run_and_declared_unrun():
    overlap = sorted(set(ARGV) & set(NOT_SMOKE_RUN))
    assert not overlap, f"contradictory entries: {overlap}"


def test_every_unrun_entry_gives_a_reason():
    for name, reason in NOT_SMOKE_RUN.items():
        assert len(reason) > 20, f"{name} needs a real reason, got {reason!r}"


# ── the bodies run ───────────────────────────────────────────────────────────


@pytest.fixture
def authorised(tmp_path, monkeypatch):
    """A broad engagement, established through the real CLI.

    Every tier confirmed and every identifier in scope, so a command is denied
    only for a reason of its own rather than for want of authorisation. Built
    with `engage start` instead of an Engagement literal, for the reason
    test_cli_authorisation_ladder.py exists.
    """
    monkeypatch.setattr(
        engagement_store, "engagement_file_path", lambda: tmp_path / "engagement.json"
    )
    argv = [
        "engage", "start",
        "--operator", "smoke",
        "--ref", "ROE-SMOKE",
        "--bssid", BSSID,
        "--essid", ESSID,
        "--cidr", CIDR,
        "--hostname", DOMAIN,
        "--max-tier", "mitm",
        "--accept-interception",
    ]
    for tier in Tier:
        argv += ["--confirm-tier", tier.name.lower()]
    result = runner.invoke(app, argv)
    assert result.exit_code == 0, result.stdout
    yield
    get_scope_gate().clear_engagement()


@pytest.fixture
def fake_bin(tmp_path, monkeypatch):
    """Put a stub for every tool on PATH so resolution is not the thing tested.

    The stubs are never executed: create_subprocess_exec is patched out. They
    exist only so shutil.which succeeds, which is what lets a command body run
    past its tool check on a host without aircrack-ng installed.
    """
    bin_dir = tmp_path / "stub-bin"
    bin_dir.mkdir()
    for name in STUB_BINARIES:
        stub = bin_dir / name
        stub.write_text("#!/bin/sh\nexit 0\n")
        stub.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    return bin_dir


@pytest.fixture
def no_exec(monkeypatch):
    """Patch out only the syscall. The gate, the audit and the argv stay real.

    Patching ProcessRunner.run instead would skip the gate check and the audit
    record, which are most of what makes a spawn in this codebase correct.
    """
    spawned: list[list[str]] = []

    class FakeProc:
        returncode = 0
        pid = 4242

        async def communicate(self):
            return (b"", b"")

        async def wait(self):
            return 0

        def kill(self):
            """A no-op on purpose: nothing here really spawned, so the test
            asserts on what was ASKED for, not on a process dying."""

        def terminate(self):
            """See kill()."""

        def send_signal(self, _sig):
            """See kill()."""

    async def fake_exec(*cmd, **kwargs):
        spawned.append(list(cmd))
        return FakeProc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr("os.killpg", lambda *a, **k: None, raising=False)
    return spawned


# A command that still runs for seconds with the exec stubbed out is polling,
# sleeping or waiting on something it should not be. The alarm turns that into
# a named failure instead of a suite that never finishes.
COMMAND_BUDGET_SECONDS = 20.0

# A run-until-stopped command only has to reach the seam, so it gets a short
# leash: the alarm is the expected outcome, not a failure, and waiting the full
# budget for four of them would add over a minute to the suite for nothing.
LONG_RUNNING_BUDGET_SECONDS = 3.0


@contextmanager
def hard_timeout(seconds: float, what: str):
    def _fire(_signum, _frame):
        raise TimeoutError(f"{what} did not return within {seconds:g}s")

    previous = signal.signal(signal.SIGALRM, _fire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def assert_argv_is_sane(spawned: list[list[str]], name: str) -> None:
    """Shape checks that apply to every spawn, whatever the tool.

    Not a substitute for knowing a tool's flags. These catch the damage that
    would otherwise appear identically across many commands: an Option left
    unset and stringified into argv, an empty argument that shifts every
    position after it, or a binary nothing declared.
    """
    known = set(STUB_BINARIES)
    for argv in spawned:
        assert argv, f"`netreaper {name}` spawned an empty argv"
        binary = os.path.basename(argv[0])
        assert binary in known, (
            f"`netreaper {name}` spawned {binary!r}, which is not in "
            f"STUB_BINARIES; declare it there so the suite stops depending on "
            f"what the host has installed"
        )
        for i, arg in enumerate(argv):
            assert arg != "None", (
                f"`netreaper {name}` argv[{i}] is the string \"None\": an unset "
                f"option was formatted into the command line\n  {argv}"
            )
            assert arg != "", (
                f"`netreaper {name}` argv[{i}] is empty, which shifts every "
                f"argument after it\n  {argv}"
            )
            assert "{" not in arg and "}" not in arg, (
                f"`netreaper {name}` argv[{i}] still contains a placeholder: "
                f"{arg!r}\n  {argv}"
            )


@pytest.mark.parametrize("name", sorted(ARGV), ids=lambda n: n.replace(" ", "-"))
def test_the_command_body_runs_without_an_unhandled_exception(
    name, authorised, fake_bin, no_exec, tmp_path, monkeypatch
):
    """The one question no other test in this repo asks: does the body run?

    Exit code is not asserted. A command that cannot find a capture file or is
    refused by the gate has still executed, which is the thing being measured.
    An unhandled NameError, AttributeError, TypeError or ImportError has not.
    """
    monkeypatch.chdir(tmp_path)
    budget = (
        LONG_RUNNING_BUDGET_SECONDS if name in LONG_RUNNING
        else COMMAND_BUDGET_SECONDS
    )
    with hard_timeout(budget, f"`netreaper {name}`"):
        result = runner.invoke(app, name.split() + ARGV[name])

    assert_argv_is_sane(no_exec, name)

    exc = result.exception
    if exc is None or isinstance(exc, (SystemExit, click.exceptions.Exit, typer.Exit)):
        return
    if isinstance(exc, TimeoutError) and name in LONG_RUNNING:
        # Designed to hold until stopped. What is being asserted for these is
        # that the body reached the seam and spawned, rather than falling over
        # on the way: a body that raised before spawning would have no entry.
        assert no_exec, (
            f"`netreaper {name}` blocked without spawning anything, so it did "
            f"not reach the seam; that is a hang, not a long-running action"
        )
        return
    raise AssertionError(
        f"`netreaper {name}` raised {type(exc).__name__}: {exc}\n"
        f"--- stdout ---\n{result.stdout}"
    ) from exc
