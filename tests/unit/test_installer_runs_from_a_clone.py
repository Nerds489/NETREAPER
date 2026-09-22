# SPDX-License-Identifier: GPL-3.0-or-later
"""`bin/netreaper-install` could not run at all, and nothing noticed.

Two independent faults, both on the second command the README told a new
operator to type:

  the marker    `_resolve_netreaper_root` decided a directory was a NETREAPER
                tree by testing for `lib/`. No `lib/` has ever been committed,
                and nothing in the script sources anything from one: the
                resolved root is read for exactly one thing, the VERSION file.
                So a fresh clone exited 1 with "Cannot locate NETREAPER
                installation" before parsing an argument, gated on a marker
                that did not exist, to find a version string.
  the mode      the file is tracked 100644, so `sudo bin/netreaper-install`
                fails on the execute bit even once the root resolves.

`--dry-run` was separately useless: `pkg_update` had no guard and ran a real
`apt-get update`, and every method's success test was "is the tool present
now?", which after a simulated install is always false, so a dry run reported
"no installation method available" for every tool it would in fact have
installed.

None of this was caught because CI runs pytest and shellcheck, and the only
installer tests are bats, which CI does not run. This file is pytest, so it
runs.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "bin" / "netreaper-install"
SOURCE = INSTALLER.read_text(encoding="utf-8")


def test_the_installer_is_executable():
    """Tracked mode, not the working-tree mode: a clone gets what git records."""
    out = subprocess.run(
        ["git", "ls-files", "-s", "bin/netreaper-install"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    mode = out.split()[0]
    assert mode == "100755", (
        f"tracked mode is {mode}; a clone cannot run `sudo bin/netreaper-install`"
    )


def test_the_root_marker_is_a_file_the_repository_actually_contains():
    """The whole defect. `lib/` was the marker and has never existed."""
    markers = re.findall(r'_is_netreaper_root\(\)\s*\{\s*\[\[\s*-f\s*"\$1/([^"]+)"', SOURCE)
    assert markers, "no _is_netreaper_root marker found; has the resolver changed shape?"
    for marker in markers:
        assert (ROOT / marker).exists(), (
            f"the resolver looks for `{marker}` to identify a NETREAPER tree, "
            f"and this repository does not contain it"
        )


def test_no_check_survives_for_a_directory_the_repository_lacks():
    """Guards the specific regression rather than the general shape."""
    assert "/lib" not in SOURCE, (
        "the root resolver is testing for a lib/ directory again; nothing is "
        "sourced from one and the repository does not ship it"
    )


def test_it_runs_from_a_checkout_and_prints_its_usage():
    r = subprocess.run(
        ["bash", str(INSTALLER), "--help"],
        cwd=ROOT, capture_output=True, text=True, timeout=60,
    )
    assert r.returncode == 0, (
        f"`netreaper-install --help` exited {r.returncode} from a clone:\n"
        f"{(r.stderr or r.stdout).strip()[:400]}"
    )
    assert "Usage:" in r.stdout


def test_it_reports_the_repository_version_not_a_hardcoded_one():
    """The fallback said 10.0.0 while the repository was on 12."""
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    r = subprocess.run(
        ["bash", str(INSTALLER), "--help"],
        cwd=ROOT, capture_output=True, text=True, timeout=60,
    )
    assert f"v{version}" in r.stdout, (
        f"installer does not report v{version}; first line was "
        f"{r.stdout.splitlines()[0] if r.stdout else '(no output)'!r}"
    )


def _dispatcher_categories() -> set[str]:
    """The category arm of the command case statement."""
    m = re.search(
        r"^\s+(scanning(?:\|[a-z]+)+)\)\s*$", SOURCE, re.M
    )
    assert m, "could not find the category dispatch arm"
    return set(m.group(1).split("|"))


def _usage_commands() -> set[str]:
    body = SOURCE[SOURCE.index("Commands:") : SOURCE.index("Options:")]
    return set(re.findall(r"^\s{4}([a-z]+)\s{2,}", body, re.M))


def test_every_installable_category_is_documented_in_the_usage():
    """`utils` dispatched but was absent from --help, so nobody could find it."""
    missing = sorted(_dispatcher_categories() - _usage_commands())
    assert not missing, f"installable but undocumented: {', '.join(missing)}"


def test_the_usage_does_not_advertise_a_category_that_cannot_run():
    extra = sorted(
        _usage_commands()
        - _dispatcher_categories()
        - {"all", "essentials", "status", "menu"}
    )
    assert not extra, f"documented but not dispatched: {', '.join(extra)}"


def test_the_interactive_menu_reaches_every_category():
    """stress and utils were installable and unreachable from the menu."""
    body = SOURCE[SOURCE.index("show_menu() {") : SOURCE.index("show_usage() {")]
    reached = set(re.findall(r'install_category "([a-z]+)"', body))
    missing = sorted(_dispatcher_categories() - reached)
    assert not missing, f"menu cannot reach: {', '.join(missing)}"


@pytest.mark.parametrize("func", ["pkg_update", "pkg_install"])
def test_anything_that_writes_honours_dry_run(func):
    """pkg_update had no guard, so --dry-run ran a real apt-get update."""
    start = SOURCE.index(f"{func}() {{")
    body = SOURCE[start : start + 1200]
    assert "DRY_RUN" in body, f"{func} does not check DRY_RUN; --dry-run would mutate"


def test_a_dry_run_does_not_verify_an_install_that_never_happened():
    """Every method's success test was `is_installed`, always false on a dry
    run, so --dry-run reported no method for every tool it would install."""
    start = SOURCE.index("install_tool() {")
    end = SOURCE.index('FAILED_TOOLS+=("$tool:no_method")', start)
    body = SOURCE[start:end]
    # The one legitimate is_installed is the "already installed?" short-circuit.
    assert body.count('is_installed "$tool"') == 1, (
        "install_tool re-checks is_installed after a simulated install; use "
        "_install_verified, which short-circuits under --dry-run"
    )
    assert "_install_verified" in body
