# SPDX-License-Identifier: GPL-3.0-or-later
"""Two chaining designs exist. One of them is wired; the other runs nothing.

Hunting for argument injection in the chaining layer turned up something else.
The hypothesis was sound: a chain feeds one tool's output into the next tool's
arguments, and tool output is attacker-influenced. A target chooses its own
hostname, its banners, its HTTP headers, and the subdomains and paths that
discovery tools report back. Eight of the transforms pass an attacker-chosen
``--script=http-shellshock`` straight through untouched, and an argv element
beginning with ``-`` is read by every one of these tools as a FLAG, not a value.
Exec arrays stop shell metacharacters; they do not stop argument injection.

The risk is not live, and the reason is worth more than the risk would have
been: **the data never flows.** Resolved with the AST rather than grep, because
this repo's comments have satisfied a regex before:

    target_option     0 attribute reads in the entire tree
    source_path       0
    transform         0 (as an attribute)
    apply_transform   0 calls
    paths.py          all four public functions, 0 callers outside their module

``DataBinding`` is the declared mechanism for threading one step's output into
the next step's input, and nothing reads it. ``transforms.py`` and ``paths.py``
are 588 lines and 36 transforms that nothing invokes.

``chaining/builtin/`` used to declare eleven ``DataBinding(...)`` across its
scanning and web chains, so those chains READ as though they threaded data
between steps while doing nothing at all. That package has been deleted: its
registrar had no caller, the manifest planner replaced the mechanism, and its
wireless, credentials and recon modules were three-line stubs that registered
nothing. The declarations went with it. The mechanism did not, which is why
this guard still matters.

What IS wired is the other design: ``wifi auto`` resolves a goal through
``manifest_registry`` and ``resolve_chain``, compiles it with ``plan_to_chain``
and runs it on ``ChainExecutor`` with ``manifest_step_runner``. That path is
covered (91-100%) and each step dispatches to its manifest's own runner. It
never touches DataBinding.

So this file does two things. It records the inert state, so nobody reads
``transforms.py`` and believes its 36 transforms feed something. And it fails
the moment the wiring appears without a validator in front of it, because that
is the moment the injection stops being theoretical.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "netreaper"

# Declarations. A DataBinding written here is describing intent, not consuming.
DECLARATION_SITES = ("chaining/models.py", "chaining/__init__.py")

BINDING_FIELDS = ("target_option", "source_path")


def _attribute_reads(name: str) -> list[str]:
    """Real attribute accesses, AST-only. A comment cannot satisfy this."""
    hits = []
    for path in SRC.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Attribute) and node.attr == name:
                hits.append(f"{path.relative_to(SRC).as_posix()}:{node.lineno}")
    return hits


def _calls(name: str) -> list[str]:
    hits = []
    for path in SRC.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            called = getattr(fn, "id", None) or getattr(fn, "attr", None)
            if called == name:
                hits.append(f"{path.relative_to(SRC).as_posix()}:{node.lineno}")
    return hits


def _consumers(hits: list[str]) -> list[str]:
    return [h for h in hits if not h.startswith(DECLARATION_SITES)]


# ── the transforms really do pass hostile values through ─────────────────────


def test_transforms_pass_an_attacker_chosen_flag_straight_through():
    """Not a defect on its own. It is the reason the wiring guard below exists.

    A transform is supposed to pass values through; that is its job. What makes
    it matter is that the values come from a machine the operator does not
    control, and the destination is a command line.
    """
    from netreaper.chaining.transforms import TRANSFORMS

    hostile = "--script=http-shellshock"
    hosts = [{"ip": hostile, "hostname": hostile, "state": "up",
              "ports": [{"port": 80, "state": "open", "service": hostile}]}]

    passed_through = []
    for name, fixture in (
        ("flatten_ips", (hosts,)),
        ("first", ([hostile],)),
        ("unique", ([hostile],)),
        ("join", ([hostile],)),
    ):
        fn = TRANSFORMS.get(name)
        if fn is None:
            continue
        out = fn(*fixture)
        flat = out if isinstance(out, list) else [out]
        if any(isinstance(v, str) and v.startswith("-") for v in flat):
            passed_through.append(name)

    assert passed_through, (
        "the fixtures no longer reach the transforms; this test has stopped "
        "measuring anything and the guard below rests on it"
    )


# ── the wiring guard: fails when the data starts flowing ─────────────────────


@pytest.mark.parametrize("field", BINDING_FIELDS)
def test_databinding_is_still_inert_or_has_gained_a_validator(field):
    """The one that matters.

    While nothing reads a DataBinding, attacker-controlled transform output
    cannot reach a command line and there is nothing to defend. The moment
    something does read it, every value produced by those 36 transforms becomes
    an argv element, and an element beginning with '-' is a flag.

    So: if a consumer appears, a validator must appear in the same module. This
    costs nothing today and fires on exactly the change that creates the risk.
    """
    consumers = _consumers(_attribute_reads(field))
    if not consumers:
        return  # still inert, nothing to defend

    modules = {c.split(":")[0] for c in consumers}
    guarded = []
    for rel in modules:
        text = (SRC / rel).read_text(encoding="utf-8")
        if any(
            token in text
            for token in ("validate_", "reject_argument", "sanitise", "sanitize",
                          "startswith(\"-\")", "startswith('-')")
        ):
            guarded.append(rel)
    unguarded = sorted(modules - set(guarded))
    assert not unguarded, (
        f"DataBinding.{field} now has a consumer, so transform output reaches a "
        f"command line. Those values come from the target: a hostname, a banner, "
        f"an HTTP header, a discovered path. Any of them beginning with '-' is "
        f"read as a flag by nmap, hydra, gobuster and the rest, and an exec "
        f"array does not prevent that. Reject argument-shaped values before "
        f"binding them. Unguarded: {unguarded}"
    )


def test_apply_transform_is_still_unreachable_or_guarded():
    consumers = _consumers(_calls("apply_transform"))
    if not consumers:
        return
    pytest.fail(
        "apply_transform() now has a caller: "
        + ", ".join(consumers)
        + ". Its output flows to a command line; see the module docstring."
    )


# ── record the inert state so nobody mistakes it for working ─────────────────

# test_the_declared_bindings_outnumber_their_readers lived here and counted the
# DataBinding(...) calls in chaining/, asserting they outnumbered their readers.
# Every one of them was in chaining/builtin/, which has been deleted, so it
# ended with `assert declared > 0, "DataBinding declarations vanished; drop
# this file"` and it was right about its own subject.
#
# The file stays because the rest of it did not depend on those declarations.
# DataBinding still exists in models.py and the 36 transforms still exist, so
# the wiring guard above still fires on the change that creates the risk. What
# went away is the misleading appearance of data flow, not the mechanism.


def test_the_wired_chain_path_is_the_manifest_one():
    """`wifi auto` runs. It just does not run through DataBinding.

    Guards against the opposite mistake: concluding from the above that chaining
    does not work at all, and removing the part that does.
    """
    cli = (SRC / "cli.py").read_text(encoding="utf-8")
    for needed in ("plan_to_chain", "manifest_step_runner", "ChainExecutor"):
        assert needed in cli, f"the wired chain path lost {needed}"


def test_the_ast_scan_is_not_vacuous():
    """If attribute resolution broke, every assertion here goes quietly green."""
    assert _attribute_reads("provides"), "AST attribute scan found nothing at all"
    assert _calls("get_transform"), "AST call scan found nothing at all"
