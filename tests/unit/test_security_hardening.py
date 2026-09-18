# SPDX-License-Identifier: GPL-3.0-or-later
"""The findings from the full security sweep, each pinned so it cannot come back.

Seven defects, found by scanning the AST rather than the prose and by running
the code rather than reading it. Each is guarded here in the form it actually
took, because a fix with no test is a fix with a shelf life.

  mktemp pcap         tempfile.mktemp() names a file without creating it, and
                      tcpdump here runs as root, so any local account could win
                      the race with a symlink and have root write the capture
                      wherever it pointed. The same call left plaintext
                      credentials world-readable in /tmp.
  /tmp/payload        a fixed name in a world-writable directory, same symlink
                      class, plus the finished artefact readable by everyone.
  audit mode          the trail names every target, operator and command line of
                      an engagement and inherited the umask (0644), while
                      engagement_store wrote its record 0600. One kind of
                      material, two policies.
  root install        `sudo apt-get install -y` ran with no gate, no audit and
                      no timeout: a larger consequence than most of what the
                      gate does cover.
  nmap XML            output written by one call and re-read by another, parsed
                      with internal entity expansion enabled.
  MAC randomisation   Mersenne Twister. A MAC is randomised to avoid being
                      tracked, and MT's state is recoverable from its output.
  renderer hang       wkhtmltopdf awaited with no timeout and no teardown.
"""
from __future__ import annotations

import ast
import os
import stat
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "netreaper"


def _tree(rel: str) -> ast.AST:
    return ast.parse((SRC / rel).read_text(encoding="utf-8"))


def _calls(tree: ast.AST) -> set[str]:
    return {
        n.func.attr if isinstance(n.func, ast.Attribute) else n.func.id
        for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, (ast.Name, ast.Attribute))
    }


# ── the two symlink races ────────────────────────────────────────────────────


def test_a_capture_path_is_created_private_and_outside_tmp(tmp_path, monkeypatch):
    """The file must already exist, owner-only, so there is no name to race for."""
    from netreaper.tui.screens import traffic

    caps = tmp_path / "captures"
    monkeypatch.setattr(traffic, "NETREAPER_WIRED_CAPTURES_DIR", caps)

    path = Path(traffic._new_capture_path())

    assert path.exists(), "mktemp's whole bug: the name was returned uncreated"
    assert path.parent == caps, f"capture landed in {path.parent}, not our own dir"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600, (
        f"capture is {oct(stat.S_IMODE(path.stat().st_mode))}; a pcap of "
        f"plaintext credentials must not be readable by other accounts"
    )
    assert stat.S_IMODE(caps.stat().st_mode) == 0o700


def test_the_real_capture_directory_is_not_a_shared_one():
    """The constant the screen actually uses must be private to this user."""
    from netreaper.core.constants import NETREAPER_WIRED_CAPTURES_DIR

    parts = NETREAPER_WIRED_CAPTURES_DIR.parts
    assert parts[:2] != ("/", "tmp"), (
        f"captures are configured to land in {NETREAPER_WIRED_CAPTURES_DIR}, "
        f"a world-writable directory"
    )


def test_capture_paths_do_not_repeat(tmp_path, monkeypatch):
    from netreaper.tui.screens import traffic

    monkeypatch.setattr(traffic, "NETREAPER_WIRED_CAPTURES_DIR", tmp_path / "c")
    assert len({traffic._new_capture_path() for _ in range(25)}) == 25


def test_mktemp_is_gone_from_the_whole_tree():
    """mktemp is insecure by documentation, not by accident. Nothing may use it."""
    offenders = []
    for path in SRC.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "mktemp"
            ):
                offenders.append(f"{path.relative_to(SRC)}:{node.lineno}")
    assert not offenders, (
        "tempfile.mktemp() returns a name without creating the file, which is a "
        "symlink race wherever the writer is privileged. Use mkstemp:\n  "
        + "\n  ".join(offenders)
    )


def test_no_fixed_world_writable_output_paths():
    """A constant /tmp path is the same race with the timing removed."""
    offenders = []
    for path in SRC.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                v = node.value
                # noqa on the next line, not this comment: the literal this
                # test searches FOR is the literal bandit objects to.
                if v.startswith("/tmp/") and len(v) > len("/tmp/"):  # noqa: S108
                    offenders.append(f"{path.relative_to(SRC)}:{node.lineno}: {v!r}")
    assert not offenders, (
        "hardcoded path(s) under world-writable /tmp; write to an owner-only "
        "directory with mkstemp instead:\n  " + "\n  ".join(offenders)
    )


def test_the_payload_writer_uses_mkstemp_not_a_fixed_name():
    calls = _calls(_tree("tui/screens/exploit.py"))
    assert "mkstemp" in calls, "msfvenom output is written to a predictable path"


# ── the audit trail's own permissions ────────────────────────────────────────


def test_the_audit_trail_is_written_owner_only(tmp_path):
    from netreaper.core.audit import AuditTrail

    trail = AuditTrail(path=tmp_path / "audit.jsonl")
    trail.record(
        outcome="executed", tool="nmap", argv=["nmap", "-sS"], targets=["10.0.0.1"]
    )

    mode = stat.S_IMODE((tmp_path / "audit.jsonl").stat().st_mode)
    assert mode == 0o600, (
        f"audit trail is {oct(mode)}. It names every target, operator and "
        f"command line of an engagement; engagement_store writes 0600 and this "
        f"must match it."
    )


def test_an_audit_file_left_world_readable_by_an_older_version_is_repaired(tmp_path):
    p = tmp_path / "audit.jsonl"
    p.write_text("")
    p.chmod(0o644)

    from netreaper.core.audit import AuditTrail

    AuditTrail(path=p).record(outcome="executed", tool="nmap", argv=["nmap"], targets=[])
    assert stat.S_IMODE(p.stat().st_mode) == 0o600, "an existing 0644 file stays exposed"


def test_hardening_never_widens_permissions(tmp_path):
    from netreaper.core.audit import _harden

    p = tmp_path / "already-tight"
    p.write_text("")
    p.chmod(0o400)
    _harden(p)
    assert stat.S_IMODE(p.stat().st_mode) & 0o077 == 0


# ── the root package install ─────────────────────────────────────────────────


def test_the_installer_authorises_and_audits_before_it_spawns():
    """`sudo apt-get install -y` modifies the host as root. It gets recorded."""
    tree = _tree("detection/tools.py")
    for fn in ast.walk(tree):
        if isinstance(fn, ast.AsyncFunctionDef) and fn.name == "_run_install_cmd":
            spawn = min(
                n.lineno
                for n in ast.walk(fn)
                if isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr == "create_subprocess_exec"
            )
            gates = [
                n.lineno
                for n in ast.walk(fn)
                if isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr in {"authorize", "record"}
            ]
            assert any(g < spawn for g in gates), (
                "_run_install_cmd spawns a root package install with no "
                "authorisation and no audit line before it"
            )
            assert len([g for g in gates if g < spawn]) >= 2, (
                "the install must both authorise AND record; one of the two is missing"
            )
            return
    raise AssertionError("_run_install_cmd not found")


# ── nmap XML ─────────────────────────────────────────────────────────────────


def test_normal_nmap_output_still_parses(tmp_path):
    from netreaper.tools.nmap import _parse_scan_xml

    p = tmp_path / "scan.xml"
    p.write_text(
        "<nmaprun><host><address addrtype='ipv4' addr='198.51.100.7'/></host></nmaprun>"
    )
    assert _parse_scan_xml(p).find(".//address").get("addr") == "198.51.100.7"


def test_a_dtd_in_a_scan_result_is_refused(tmp_path):
    """nmap emits no DOCTYPE, so one means the file is not what it claims."""
    from netreaper.tools.nmap import _parse_scan_xml

    p = tmp_path / "bomb.xml"
    p.write_text(
        '<!DOCTYPE lol [<!ENTITY a "aaaaaaaaaa">'
        '<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>'
        "<nmaprun><host>&b;</host></nmaprun>"
    )
    with pytest.raises(ValueError, match="DTD"):
        _parse_scan_xml(p)


# ── MAC randomisation ────────────────────────────────────────────────────────


def test_mac_randomisation_does_not_use_the_mersenne_twister():
    """`random` is seeded predictably and its state recovers from ~624 outputs.

    A MAC is randomised so the host cannot be followed between networks. A
    predictable generator hands that back.
    """
    src = (SRC / "wireless" / "mac.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    imported = {
        alias.name
        for n in ast.walk(tree)
        if isinstance(n, ast.Import)
        for alias in n.names
    }
    assert "random" not in imported, "wireless/mac.py still imports random"
    assert "secrets" in imported, "wireless/mac.py should use secrets"


def test_generated_macs_are_unique_and_locally_administered():
    from netreaper.wireless.mac import generate_mac

    macs = {generate_mac() for _ in range(200)}
    assert len(macs) == 200, "collisions in 200 draws"
    for mac in macs:
        first = int(mac.split(":")[0], 16)
        assert first & 0x02, f"{mac} is not locally administered"
        assert not first & 0x01, f"{mac} is a multicast address"


# ── the renderer hand-off ────────────────────────────────────────────────────


def test_the_pdf_renderer_cannot_hang_the_export():
    """`await proc.wait()` with no timeout waits on a hung child forever."""
    tree = _tree("export/exporters.py")
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.AsyncFunctionDef):
            continue
        spawns = [
            n
            for n in ast.walk(fn)
            if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute)
            and n.func.attr == "create_subprocess_exec"
        ]
        if not spawns:
            continue
        calls = _calls(fn)
        assert "wait_for" in calls, (
            f"{fn.name}() spawns a renderer and waits on it with no timeout; a "
            f"child that never exits hangs the export"
        )
        assert "kill" in calls, f"{fn.name}() times out but never kills the child"
        return
    raise AssertionError("no spawning coroutine found in exporters.py")


# ── the scan that found these must keep working ──────────────────────────────


def test_no_bare_eval_or_exec_anywhere_in_the_tree():
    offenders = []
    for path in SRC.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in {"eval", "exec"}
            ):
                offenders.append(f"{path.relative_to(SRC)}:{node.lineno}")
    assert not offenders, "eval/exec in source:\n  " + "\n  ".join(offenders)


def test_this_module_can_actually_detect_a_loose_permission(tmp_path):
    """Negative control: the permission assertions are not trivially true."""
    p = tmp_path / "loose"
    p.write_text("")
    p.chmod(0o644)
    assert stat.S_IMODE(p.stat().st_mode) == 0o644
    os.chmod(p, 0o600)
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
