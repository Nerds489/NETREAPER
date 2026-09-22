# SPDX-License-Identifier: GPL-3.0-or-later
"""`config set` stored values it had just rejected, and keys it did not have.

Two defects in one command, both of which damaged the file they wrote to.

THE WRONG TYPE. `_persist_config` wrote to disk and its caller then called
`reload_settings()`, so validation happened AFTER the write. `netreaper config
set logging.level DEBUG` printed a pydantic error and kept the string. Every
later load then failed on it, which meant `config show`, the TUI settings
screen and anything else reading settings were broken until the operator found
and deleted `~/.netreaper/config/config.toml` by hand. A command that refuses
your input must not keep it.

THE WRONG KEY. `Settings` is a plain `BaseModel`, so pydantic's default
`extra="ignore"` silently drops unknown top-level keys. `config set key value`
therefore reported success while writing a `key = "value"` no consumer reads.
That is not hypothetical either: the README documented `netreaper config set
key value` as its example, and `test_readme_commands_exist.py` executes every
command on the page, so the docs test wrote that literal junk into the real
user config on every run, on every machine, including CI.

Both are now checked before anything is written, and the write is atomic.
"""
from __future__ import annotations

import pytest
from typer.testing import CliRunner

from netreaper.cli import app

GOOD = "10"          # logging.level is an int; 10 is DEBUG
BAD = "DEBUG"        # the name, not the number: the exact thing that broke it


@pytest.fixture
def config_dir(tmp_path, monkeypatch):
    """Point both the writer and the reader at a temporary config."""
    from netreaper.config.settings import get_settings
    from netreaper.core import constants
    from netreaper.config import settings as settings_mod

    monkeypatch.setattr(constants, "NETREAPER_CONFIG_DIR", tmp_path)
    monkeypatch.setattr(settings_mod, "_USER_CONFIG_PATH", tmp_path / "config.toml")
    get_settings.cache_clear()
    yield tmp_path
    get_settings.cache_clear()


def _run(*argv):
    return CliRunner().invoke(app, list(argv))


def test_a_valid_set_is_written_and_reads_back(config_dir):
    assert _run("config", "set", "logging.level", GOOD).exit_code == 0
    assert (config_dir / "config.toml").exists()
    out = _run("config", "get", "logging.level").output
    assert "10" in out


def test_a_value_of_the_wrong_type_is_refused(config_dir):
    result = _run("config", "set", "logging.level", BAD)
    assert result.exit_code != 0, "a rejected value must not report success"
    assert "nothing written" in result.output.lower(), (
        "the refusal must say that the file was untouched, early enough\n"
        "that Rich does not truncate it away: " + result.output[-200:]
    )


def test_a_refused_value_never_reaches_the_file(config_dir):
    """The damage, not just the message."""
    _run("config", "set", "logging.level", BAD)
    assert not (config_dir / "config.toml").exists(), (
        "config.toml was created by a set that was refused"
    )


def test_a_refused_value_does_not_corrupt_an_existing_file(config_dir):
    _run("config", "set", "logging.level", GOOD)
    before = (config_dir / "config.toml").read_bytes()

    _run("config", "set", "logging.level", BAD)

    assert (config_dir / "config.toml").read_bytes() == before, (
        "a refused set rewrote the config anyway"
    )


def test_the_config_still_loads_after_a_refused_set(config_dir):
    """The whole outage in one assertion: `config show` used to stop working."""
    _run("config", "set", "logging.level", GOOD)
    _run("config", "set", "logging.level", BAD)

    result = _run("config", "show")
    assert result.exit_code == 0, (
        "config show is broken after a refused set:\n" + result.output[:300]
    )


def test_a_key_outside_the_schema_is_refused(config_dir):
    """`config set key value`, straight from the old README."""
    result = _run("config", "set", "key", "value")
    assert result.exit_code != 0
    assert "unknown setting" in result.output
    assert not (config_dir / "config.toml").exists()


def test_an_unknown_key_suggests_the_near_miss(config_dir):
    result = _run("config", "set", "logging.levl", GOOD)
    assert result.exit_code != 0
    assert "logging.level" in result.output, "no suggestion offered for a typo"


def test_a_nested_key_that_exists_is_accepted(config_dir):
    assert _run("config", "set", "safety.unsafe_mode", "true").exit_code == 0
    assert "True" in _run("config", "get", "safety.unsafe_mode").output


def test_every_schema_key_is_settable(config_dir):
    """The allow-list must be derived from the model, not hand-listed."""
    from netreaper.cli import _settings_key_paths

    paths = _settings_key_paths()
    assert "logging.level" in paths
    assert "safety.unsafe_mode" in paths
    assert "output_dir" in paths, "top-level scalars must be settable too"
    assert "key" not in paths
    # Nested tables are containers, not leaves: you set logging.level, not logging.
    assert "logging" not in paths
