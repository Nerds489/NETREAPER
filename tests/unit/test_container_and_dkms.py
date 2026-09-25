# SPDX-License-Identifier: GPL-3.0-or-later
"""The optional container image and DKMS driver provisioning (#94, #33 slice 5).

These are static guards, not a Docker build: CI must not build a 400 MB image or
compile a kernel module. They pin the shape of the artefacts (the entry point,
the real driver names, the run capabilities, the not-verified caveat) so the
files cannot rot into referencing things that do not exist. The image itself was
built and `netreaper --version` run inside it during development; that is
recorded in the PR, not re-run here.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = ROOT / "docker" / "Dockerfile"
DKMS = ROOT / "docker" / "dkms-drivers.sh"
DOCKER_README = ROOT / "docker" / "README.md"
DOCKERIGNORE = ROOT / ".dockerignore"

DRIVERS = ("rtl8812au", "rtl8814au", "rtl8821au")


# ── the image ─────────────────────────────────────────────────────────────────


def test_the_dockerfile_exists():
    assert DOCKERFILE.is_file()


def test_the_image_installs_netreaper_and_runs_the_installed_cli():
    text = DOCKERFILE.read_text()
    assert "pip install" in text and "." in text
    # invokes the installed console script, not a re-derived root (the bug the
    # installer used to have)
    assert 'ENTRYPOINT ["netreaper"]' in text


def test_the_image_uses_a_supported_python_base():
    text = DOCKERFILE.read_text()
    assert "FROM python:3.1" in text  # 3.11+, matching requires-python


def test_the_image_has_a_light_cli_stage_and_a_heavy_tools_stage():
    text = DOCKERFILE.read_text()
    assert "AS cli" in text
    assert "AS full" in text
    # the tools go in the heavy stage, via the bundled installer
    assert "netreaper-install" in text


def test_the_build_context_excludes_the_venv_and_git():
    assert DOCKERIGNORE.is_file()
    ignore = DOCKERIGNORE.read_text()
    assert ".venv" in ignore
    assert ".git" in ignore


# ── the DKMS script ────────────────────────────────────────────────────────────


def test_the_dkms_script_exists_and_is_tracked_executable():
    import subprocess

    assert DKMS.is_file()
    mode = subprocess.run(
        ["git", "ls-files", "-s", "docker/dkms-drivers.sh"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout.split()[0]
    assert mode == "100755", f"tracked mode is {mode}; a clone cannot run it"


def test_the_dkms_script_targets_the_three_recommended_drivers():
    text = DKMS.read_text()
    for driver in DRIVERS:
        assert driver in text, f"{driver} not provisioned"


def test_the_script_covers_the_readme_recommended_driver():
    """The README recommends the RTL8812AU (rtl8812au) for injection; the script
    must provision it. It also covers the wider 8814au/8821au family, which the
    README's curated adapter table does not list, and that is fine."""
    readme = (ROOT / "README.md").read_text()
    assert "rtl8812au" in readme
    assert "rtl8812au" in DKMS.read_text()


def test_the_dkms_script_requires_root():
    text = DKMS.read_text()
    assert "EUID" in text or "geteuid" in text or "id -u" in text


def test_the_dkms_script_is_syntactically_valid_bash():
    import subprocess

    r = subprocess.run(["bash", "-n", str(DKMS)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


# ── the docs ───────────────────────────────────────────────────────────────────


def test_the_docs_spell_out_the_wireless_run_capabilities():
    text = DOCKER_README.read_text()
    # wireless from a container needs these explicitly, not baked into the image
    assert "NET_ADMIN" in text and "NET_RAW" in text


def test_the_docs_are_honest_that_the_build_is_unverified_here():
    lowered = DOCKER_README.read_text().lower()
    assert "not verified" in lowered
