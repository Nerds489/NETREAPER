# SPDX-License-Identifier: GPL-3.0-or-later
"""`$` is not the end of the string, and a validator that believes it is lies.

Python's ``$`` matches at the end of the string OR immediately before a single
trailing newline. So ``re.match(r"^...$", value)`` accepts ``value + "\\n"``, and
every validator in this tree written that way blessed a string carrying a
trailing control character.

The one that mattered was live. ``wireless/mac.py:validate_mac`` guarded
``change_mac()``, a destructive host action, and returned True for
``"aa:bb:cc:dd:ee:ff\\n"``. The blessed value then went to a command line and
into the logs. Three more were in ``safety/validators.py``
(``validate_hostname``, ``validate_domain``, ``validate_url``), where the same
bug was latent rather than live, because nothing calls that module at all.

``core/validation.py`` had it right the whole time: ``fullmatch``, with a
comment explaining why. The fix everywhere else is to match it.

WHAT THIS REVEALED ABOUT THE TREE. There are THREE independent implementations
of "is this a valid IP / MAC / URL / hostname": ``safety/validators.py``,
``core/validation.py`` and ``automation/handlers/validate.py``. They disagree
with each other (``validate_cidr`` accepts ``0.0.0.0/0``; the handler's
``_validate_cidr`` explicitly refuses it as "Cannot target entire internet"),
and the one living in the package named ``safety`` is the one nothing calls.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "netreaper"

# Anything ending in a newline that a validator previously accepted.
TRAILING_NEWLINE_PROBES = ("evil.com\n", "example.test\n")


# ── the live one ─────────────────────────────────────────────────────────────


def test_the_mac_validator_guarding_change_mac_rejects_a_trailing_newline():
    """wireless/mac.py:validate_mac gates a destructive host action."""
    from netreaper.wireless.mac import validate_mac

    assert validate_mac("aa:bb:cc:dd:ee:ff") is True, "regression: valid MAC refused"
    assert validate_mac("aa:bb:cc:dd:ee:ff\n") is False, (
        "a MAC with a trailing newline passed validation and went on to a "
        "command line; `$` matches before one trailing \\n, fullmatch does not"
    )
    assert validate_mac("\naa:bb:cc:dd:ee:ff") is False
    assert validate_mac("aa:bb:cc:dd:ee:ff\n\n") is False


@pytest.mark.parametrize(
    "bad",
    ["-a:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:fz", "aa:bb:cc:dd:ee", "", "aa-bb-cc-dd-ee-ff"],
)
def test_the_mac_validator_still_refuses_what_it_always_refused(bad):
    from netreaper.wireless.mac import validate_mac

    assert validate_mac(bad) is False


# ── the latent ones ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("probe", TRAILING_NEWLINE_PROBES)
def test_hostname_and_domain_reject_a_trailing_newline(probe):
    from netreaper.safety.validators import validate_domain, validate_hostname

    for fn in (validate_hostname, validate_domain):
        with pytest.raises(ValueError):
            fn(probe)


def test_url_rejects_a_trailing_newline():
    from netreaper.safety.validators import validate_url

    with pytest.raises(ValueError):
        validate_url("http://evil.com/\n")
    with pytest.raises(ValueError):
        validate_url("http://evil.com\n")


def test_url_rejects_an_impossible_ip_literal():
    """\\d{1,3} per octet has no 0-255 bound."""
    from netreaper.safety.validators import validate_url

    with pytest.raises(ValueError):
        validate_url("http://999.999.999.999/")


def test_a_target_that_looks_like_an_ip_is_not_reclassified_as_a_hostname():
    """validate_target fell through to the broken hostname branch.

    ipaddress is strict, so "8.8.8.8\\n" failed the IP and CIDR checks, then the
    hostname check accepted it: the caller was told it had a hostname, carrying
    a hidden trailing newline.
    """
    from netreaper.safety.validators import validate_target

    with pytest.raises(ValueError):
        validate_target("8.8.8.8\n")


@pytest.mark.parametrize(
    "good", ["evil.com", "example.test", "a.b.c.example.test", "localhost"]
)
def test_valid_hostnames_are_still_accepted(good):
    """The fix must not over-reject; that would be its own outage."""
    from netreaper.safety.validators import validate_hostname

    assert validate_hostname(good) == good


@pytest.mark.parametrize(
    "good",
    ["http://10.0.0.1:8080/a", "https://example.com/", "http://localhost:80",
     "https://sub.example.test/path?q=1"],
)
def test_valid_urls_are_still_accepted(good):
    from netreaper.safety.validators import validate_url

    assert validate_url(good) == good


# ── the class, not just the instances ────────────────────────────────────────


def _string_constants(tree: ast.AST) -> dict[str, str]:
    """Every name bound to a string literal, or to ``re.compile("literal")``.

    So a pattern held in a variable resolves. That is the shape wireless/mac.py
    used, and a literal-only scan missed it on the first pass.
    """
    assigned: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue

        value = None
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            value = node.value.value
        elif isinstance(node.value, ast.Call):
            fn = node.value.func
            if getattr(fn, "attr", None) == "compile" and node.value.args:
                first = node.value.args[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    value = first.value
        if value is None:
            continue

        for target in node.targets:
            if isinstance(target, ast.Name):
                assigned[target.id] = value
    return assigned


def _pattern_of(call: ast.Call, assigned: dict[str, str]) -> str | None:
    """The regex a .match()/.search() call runs, literal or resolved."""
    if (
        call.args
        and isinstance(call.args[0], ast.Constant)
        and isinstance(call.args[0].value, str)
    ):
        return call.args[0].value

    # `PATTERN.match(x)`: the pattern is the receiver, not the argument.
    receiver = getattr(getattr(call.func, "value", None), "id", None)
    return assigned.get(receiver)


def _dollar_anchored_matches() -> list[str]:
    """re.match/search whose pattern ends in `$`, resolved through the AST."""
    import re as _re

    offenders = []
    for path in SRC.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        assigned = _string_constants(tree)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if getattr(node.func, "attr", None) not in ("match", "search"):
                continue
            pattern = _pattern_of(node, assigned)
            if pattern and _re.sub(r"\s+#.*$", "", pattern).rstrip().endswith("$"):
                offenders.append(
                    f"{path.relative_to(SRC).as_posix()}:{node.lineno}: {pattern[:50]}"
                )
    return offenders


# Sites where a `$`-anchored match is deliberate and not a validation decision,
# each with the reason. A validator must never appear here.
ALLOWED_DOLLAR_ANCHORED: dict[str, str] = {
    "core/audit.py": (
        "the user%password redactor. re.DOTALL means a trailing newline is "
        "consumed INTO the masked group, so the secret is still masked; "
        "verified by test_audit_redaction"
    ),
    "wireless/advanced.py": (
        "parses a hostapd-wpe log line, not a validation allow/deny decision"
    ),
    "tools/reaver.py": (
        "parses reaver output ONE LINE AT A TIME, so `$` is the end of that "
        "line and the trailing-newline carve-out cannot apply. Checked rather "
        "than assumed: against whole multi-line output these would match "
        "nothing without re.MULTILINE, but the loop never gives them that"
    ),
    "tools/john.py": (
        "parses john --show output line by line; same reasoning as reaver, and "
        "\\S cannot match a newline in any case"
    ),
}


def test_no_validator_decides_with_a_dollar_anchored_match():
    offenders = _dollar_anchored_matches()
    unexplained = [
        o for o in offenders if o.split(":")[0] not in ALLOWED_DOLLAR_ANCHORED
    ]
    assert not unexplained, (
        "`$` matches before a single trailing newline, so this accepts "
        "value + '\\n'. Use re.fullmatch (and drop the ^/$), as "
        "core/validation.py does. If the site is not an allow/deny decision, "
        "add it to ALLOWED_DOLLAR_ANCHORED with a reason:\n  "
        + "\n  ".join(unexplained)
    )


def test_the_anchor_scan_is_not_vacuous():
    """It must still be able to SEE a `$`-anchored match, or it proves nothing."""
    import re as _re

    assert _re.match(r"^abc$", "abc\n"), "Python changed; this whole file is moot"
    assert not _re.fullmatch(r"abc", "abc\n"), "fullmatch is the fix; verify it"


def test_every_allowed_entry_gives_a_reason():
    for name, reason in ALLOWED_DOLLAR_ANCHORED.items():
        assert len(reason) > 30, f"{name} needs a real reason, got {reason!r}"
