# SPDX-License-Identifier: GPL-3.0-or-later
"""Issue #46: credentials must not reach the audit trail, and an engagement
must name its authorisation.

``core/process.py`` recorded ``argv`` verbatim, so ``hydra -p <password>`` wrote
the password into a permanent hash-chained log. Redaction happens at the sink
(``AuditTrail.record``) rather than at the one call site, so no future caller
can forget.

The redaction is deliberately per-tool. ``-p`` is a password to hydra and a
recovered WPS PIN to reaver, but a port list to nmap and masscan, a parameter
name to sqlmap and a plugin list to whatweb. Blanket-redacting ``-p`` would
blank the port list on every scan in the trail, destroying the detail the audit
exists to hold.
"""
from __future__ import annotations

import pytest

from netreaper.core.audit import REDACTED, AuditTrail, redact_argv
from netreaper.safety.scope import Engagement, Scope


# ── the value is masked, the shape is kept ────────────────────────────────────


def test_hydra_password_is_redacted():
    out = redact_argv(["hydra", "-l", "admin", "-p", "hunter2", "ssh://10.0.0.5"])
    assert out == ["hydra", "-l", "admin", "-p", REDACTED, "ssh://10.0.0.5"]
    assert "hunter2" not in out


def test_reaver_pin_is_redacted():
    out = redact_argv(["reaver", "-i", "wlan0mon", "-p", "12345670"])
    assert out[-1] == REDACTED
    assert "12345670" not in out


def test_username_and_credential_file_paths_are_kept():
    """-l/-L/-C are the audit's substance: who was tried and from which file."""
    out = redact_argv(
        ["hydra", "-L", "/tmp/users.txt", "-P", "/tmp/rockyou.txt", "-p", "s3cret"]
    )
    assert "/tmp/users.txt" in out
    assert "/tmp/rockyou.txt" in out
    assert "s3cret" not in out


# ── the part a naive implementation gets wrong ────────────────────────────────


@pytest.mark.parametrize(
    "argv",
    [
        ["nmap", "-p", "80,443,8080", "10.0.0.5"],
        ["masscan", "-p", "1-65535", "10.0.0.0/24"],
        ["sqlmap", "-u", "http://x/?id=1", "-p", "id"],
        ["whatweb", "-p", "plugin-a,plugin-b"],
        ["gobuster", "-p", "pattern.txt"],
        ["nikto", "-p", "8443"],
    ],
)
def test_dash_p_is_not_redacted_for_tools_where_it_is_not_a_secret(argv):
    assert redact_argv(argv) == argv, (
        "-p is a port list / parameter / plugin here. Blanket redaction would "
        "destroy exactly the detail the audit trail exists to record."
    )


# ── forms and edges ───────────────────────────────────────────────────────────


def test_equals_form_is_redacted_and_keeps_the_flag_name():
    out = redact_argv(["sometool", "--password=hunter2", "target"])
    assert out == ["sometool", f"--password={REDACTED}", "target"]


def test_long_flags_are_secret_for_any_tool():
    """A tool added later is covered without updating the per-tool map."""
    for flag in ("--passphrase", "--psk", "--api-key", "--token", "--secret"):
        out = redact_argv(["brand-new-tool", flag, "topsecret"])
        assert out == ["brand-new-tool", flag, REDACTED], flag


def test_trailing_secret_flag_with_no_value_does_not_crash():
    assert redact_argv(["hydra", "-p"]) == ["hydra", "-p"]


def test_empty_argv():
    assert redact_argv([]) == []


def test_absolute_tool_path_still_resolves_the_tool_name():
    out = redact_argv(["/usr/bin/hydra", "-p", "hunter2"])
    assert out[-1] == REDACTED


def test_a_value_that_merely_looks_like_a_flag_is_still_redacted():
    out = redact_argv(["hydra", "-p", "--not-really-a-flag"])
    assert out == ["hydra", "-p", REDACTED]


# ── the sink actually applies it ──────────────────────────────────────────────


def test_record_redacts_so_no_caller_can_leak(tmp_path):
    trail = AuditTrail(path=tmp_path / "audit.jsonl")
    entry = trail.record(
        outcome="executed",
        tool="hydra",
        argv=["hydra", "-l", "admin", "-p", "hunter2", "ssh://10.0.0.5"],
    )
    assert REDACTED in entry.argv
    assert "hunter2" not in entry.argv
    # and not on disk either
    assert "hunter2" not in (tmp_path / "audit.jsonl").read_text()


def test_redaction_does_not_break_the_hash_chain(tmp_path):
    trail = AuditTrail(path=tmp_path / "audit.jsonl")
    trail.record(outcome="executed", tool="hydra", argv=["hydra", "-p", "a"])
    trail.record(outcome="executed", tool="nmap", argv=["nmap", "-p", "80", "10.0.0.5"])
    assert trail.verify()


# ── an engagement must name its authorisation ─────────────────────────────────


def _scope():
    return Scope(cidrs=["10.0.0.0/24"])


@pytest.mark.parametrize("ref", ["", "   ", "\t\n"])
def test_blank_authorization_ref_is_refused(ref):
    with pytest.raises(ValueError, match="authorization_ref"):
        Engagement(operator="tester", authorization_ref=ref, scope=_scope())


@pytest.mark.parametrize("operator", ["", "  "])
def test_blank_operator_is_refused(operator):
    with pytest.raises(ValueError, match="operator"):
        Engagement(operator=operator, authorization_ref="SOW-1", scope=_scope())


def test_a_properly_referenced_engagement_still_builds():
    eng = Engagement(operator="tester", authorization_ref="SOW-1", scope=_scope())
    assert eng.consent_hash
    assert eng.verify_consent()


# ── the event bus: a hole found in my own event-bus fix, an hour later ───────


def test_credential_cracked_events_do_not_log_the_secret():
    """CREDENTIAL_CRACKED carries {"password": <the recovered secret>}.

    The first event-bus pass redacted the command line and the tool's output
    but not the structured credential field, which is the most direct leak of
    the three. Four call sites emit it: wireless/wep.py, tools/hydra.py,
    tools/john.py and tools/reaver.py.
    """
    import json

    from netreaper.orchestration.events import _redact_event

    payloads = [
        {"type": "wep", "bssid": "AA:BB:CC:DD:EE:FF", "password": "abcd1234"},
        {"type": "ssh", "target": "10.0.0.5", "username": "root", "password": "hunter2"},
        {"type": "wps", "bssid": "AA:BB", "pin": "12345670", "psk": "CorrectHorse"},
        {"type": "hash", "password": "letmein"},
    ]
    secrets = ("abcd1234", "hunter2", "12345670", "CorrectHorse", "letmein")
    for p in payloads:
        blob = json.dumps(_redact_event(p))
        for s in secrets:
            assert s not in blob, f"{s} leaked from {p}"


def test_the_event_still_says_what_was_found_and_where():
    """Masking must not destroy the finding: only the secret goes."""
    from netreaper.orchestration.events import _redact_event

    out = _redact_event(
        {"type": "ssh", "target": "10.0.0.5", "username": "root", "password": "x"}
    )
    assert out["target"] == "10.0.0.5"
    assert out["username"] == "root"
    assert out["type"] == "ssh"
    assert out["password"] == REDACTED


def test_tool_output_lines_are_masked_by_shape_not_by_flag():
    """A tool REPORTS credentials in a shape no flag matches."""
    from netreaper.core.audit import redact_output

    assert "hunter2" not in redact_output(
        "[22][ssh] host: 10.0.0.5   login: root   password: hunter2"
    )
    assert "***" in redact_output("KEY FOUND! [ 61:62:63:64:65 ]")
    assert "12345670" not in redact_output("WPS PIN: '12345670'")
    # and a harmless line is untouched
    line = "Scanning 10.0.0.5 ports 80,443 - 2 open"
    assert redact_output(line) == line
