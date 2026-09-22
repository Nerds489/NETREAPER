# SPDX-License-Identifier: GPL-3.0-or-later
"""The bats suite reported 20/20 while testing nothing, for two reasons.

FIRST, IT NEVER RAN. `.github/workflows/ci.yml` ran pytest and shellcheck and
never invoked bats, and bats is not installed on a default runner. So the file
was inert in CI regardless of what it contained.

SECOND, ITS ASSERTIONS COULD NOT FAIL. `setup()` called `set +e` twice, and the
second one should have been `set -e`. bats detects a failed assertion through
errexit's ERR trap, so with errexit off a failing `[ ... ]` is a no-op that
still reports ok. Measured on bats 1.14: under `set +e` a bare `false` reports
ok, `return 1` reports ok, and only `exit 1` still fails.

Together those hid the fact that installer.bats tested six names that do not
exist anywhere in `bin/netreaper-install`:

    verify_tool_installed  get_package_name  detect_distro_family
    SUCCESS_TOOLS          TOOL_SEARCH_PATHS  TOOLS

and, underneath all of it, an installer that could not run at all.

These tests are pytest because pytest is what CI reliably runs. They check the
things that would have caught the original defect: that the names the bats
files use exist, that the suite is wired into CI, and that nothing has turned
errexit off again.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "bin" / "netreaper-install"
CI = ROOT / ".github" / "workflows" / "ci.yml"
BATS_FILES = sorted((ROOT / "tests").glob("*.bats"))

INSTALLER_SOURCE = INSTALLER.read_text(encoding="utf-8")

# Names that belong to bats, to the shell, or to the test file itself rather
# than to the installer.
_NOT_THE_INSTALLERS = {
    "BATS_TEST_FILENAME", "BATS_TEST_DIRNAME", "BATS_TEST_TMPDIR", "BATS_TMPDIR",
    "NETREAPER_ROOT", "NETREAPER_INSTALL", "NR_NON_INTERACTIVE", "NO_COLOR",
    "REPO_ROOT", "TEST_TEMP", "IFS", "PATH", "HOME",
}


def test_there_are_bats_files_to_check():
    """If the glob stops matching, every check below passes for nothing."""
    assert BATS_FILES, "no .bats files found; has tests/ been restructured?"
    assert len(BATS_FILES) >= 3, f"expected at least 3 bats files, found {len(BATS_FILES)}"


def _installer_functions() -> set[str]:
    return set(re.findall(r"^([a-zA-Z_][a-zA-Z0-9_]*)\(\)", INSTALLER_SOURCE, re.M))


def _installer_variables() -> set[str]:
    out = set(re.findall(r"^declare -[gaA]+ ([A-Za-z_][A-Za-z0-9_]*)", INSTALLER_SOURCE, re.M))
    out |= set(re.findall(r"^([A-Z_][A-Z0-9_]*)=", INSTALLER_SOURCE, re.M))
    # assigned inside functions too, e.g. DISTRO_FAMILY="debian"
    out |= set(re.findall(r"^\s+([A-Z_][A-Z0-9_]{2,})=", INSTALLER_SOURCE, re.M))
    return out


@pytest.mark.parametrize("bats", BATS_FILES, ids=lambda p: p.name)
def test_every_function_the_bats_files_call_exists(bats):
    """`verify_tool_installed`, `get_package_name`, `detect_distro_family`."""
    text = bats.read_text(encoding="utf-8")
    called = set(re.findall(r"^\s*run\s+([a-z_][a-z0-9_]*)\b", text, re.M))
    # `run "$NETREAPER_INSTALL"` and shell builtins are not installer functions
    called -= {"bash", "true", "false", "echo", "test"}

    missing = sorted(called - _installer_functions())
    assert not missing, (
        f"{bats.name} calls functions that do not exist in the installer:\n  "
        + "\n  ".join(missing)
    )


@pytest.mark.parametrize("bats", BATS_FILES, ids=lambda p: p.name)
def test_every_installer_variable_the_bats_files_read_exists(bats):
    """`SUCCESS_TOOLS`, `TOOL_SEARCH_PATHS` and `TOOLS` never existed."""
    text = bats.read_text(encoding="utf-8")
    used = set(re.findall(r"\$\{?([A-Z_][A-Z0-9_]{2,})[\[\}:+]", text))
    used |= set(re.findall(r'declare -p "?([A-Z_][A-Z0-9_]{2,})', text))
    used -= _NOT_THE_INSTALLERS

    missing = sorted(used - _installer_variables())
    assert not missing, (
        f"{bats.name} reads variables the installer never defines:\n  "
        + "\n  ".join(missing)
    )


@pytest.mark.parametrize("bats", BATS_FILES, ids=lambda p: p.name)
def test_no_bats_file_leaves_errexit_off(bats):
    """The one character that made 20 tests inert.

    `set +e` is legitimate around the `source`, because the installer has
    top-level statements that return non-zero. It must be paired with a
    `set -e` afterwards, or every assertion in the file silently stops
    working while still reporting ok.
    """
    text = bats.read_text(encoding="utf-8")
    off = len(re.findall(r"^\s*set \+e\s*$", text, re.M))
    on = len(re.findall(r"^\s*set -e\s*$", text, re.M))
    assert off <= on, (
        f"{bats.name} turns errexit off {off} time(s) and back on {on}. "
        f"Every assertion after the unpaired `set +e` is a no-op that still "
        f"reports ok."
    )


def test_the_installer_suite_carries_a_canary():
    """A test that fails via `exit 1` if errexit is ever off.

    `exit 1` specifically: under `set +e` neither a failing `[ ... ]` nor
    `return 1` fails a bats test, so the canary cannot be written with either.
    """
    text = (ROOT / "tests" / "installer.bats").read_text(encoding="utf-8")
    assert "$- != *e*" in text or "$- == *e*" in text, (
        "installer.bats has no errexit canary; add a test that checks $- and "
        "calls `exit 1`"
    )
    canary = text[text.index("$- != *e*") : text.index("$- != *e*") + 400]
    assert "exit 1" in canary, (
        "the canary must use `exit 1`; `return 1` and a failed assertion are "
        "both no-ops under set +e, so neither can report the problem"
    )


def test_ci_actually_runs_the_bats_suite():
    """The suite existed for releases and CI never invoked it."""
    ci = CI.read_text(encoding="utf-8")
    assert re.search(r"^\s+run:.*\bbats\b", ci, re.M), (
        "no CI step runs bats; the suite is inert in CI no matter what it "
        "contains"
    )
    assert re.search(r"install.*-y.*\bbats\b|\bbats\b.*install", ci, re.I), (
        "CI runs bats but never installs it; the step will fail on a default "
        "runner"
    )


def test_the_bats_run_is_blocking():
    """shellcheck is advisory on purpose. This must not be."""
    ci = CI.read_text(encoding="utf-8")
    for line in ci.splitlines():
        if re.search(r"^\s+run:.*\bbats\b", line):
            assert "|| true" not in line, (
                "the bats step swallows its own failure with `|| true`, which "
                "puts it back where it started"
            )


def test_the_installer_arrays_are_global():
    """A plain `declare` inside a sourced-from-a-function script is LOCAL.

    bats sources the installer from inside its own function, so every
    `declare -A` without -g vanished when setup() returned, leaving CATEGORIES
    and the tracking arrays undefined. The installer already declared its
    scalars with -g; the arrays now agree.
    """
    plain = re.findall(r"^declare -([aA]) ([A-Z_]+)", INSTALLER_SOURCE, re.M)
    assert not plain, (
        "these arrays are not declared global, so the installer cannot be "
        "sourced for testing:\n  "
        + "\n  ".join(name for _, name in plain)
    )
