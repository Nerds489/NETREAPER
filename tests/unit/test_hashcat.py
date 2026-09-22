# SPDX-License-Identifier: GPL-3.0-or-later
"""The cracker this tool has been producing hashes for, and could not run.

`wifi pmkid` prints a mode-22000 hash. `wifi enterprise` writes a mode-5500
file. The credentials screen offers a hash-type picker and five attack modes.
bootstrap detects a GPU "for hashcat acceleration" and the preflight warns that
hashcat on CPU is slow. hashcat is in the tool catalogue. None of it could run,
because `netreaper.tools.hashcat` did not exist, and the screen caught the
ImportError and told the operator to use John instead.

Three of these tests exist because of details that decide whether the wrapper is
usable rather than merely present:

  the potfile      hashcat records a cracked hash and then declines to print it
                   again, exiting 1. Without --potfile-disable the second run
                   against a hash you have already broken looks like a failure.
  exhausted        exit 1 also means "tried everything, found nothing", which is
                   a finished run. The base wrapper maps non-zero to
                   success=False and the screen renders that as "Cracking
                   failed", blaming the tool for an absent password.
  the last colon   a cracked line is <hash>:<password>, and mode 5500 hashes
                   contain colons of their own. Splitting on the first one
                   returns a username as the hash.
"""
from __future__ import annotations

import asyncio

import pytest

from netreaper.core.exceptions import ConfigurationError
from netreaper.plugins.base import Capability, PluginResult, PluginType
from netreaper.safety.scope import Tier
from netreaper.tools.base import ToolExecution
from netreaper.tools.hashcat import EXIT_EXHAUSTED, HashcatTool

# Paths are argv strings only: nothing here touches the filesystem.
HASHES = "hashes.22000"
WORDS = "/usr/share/wordlists/rockyou.txt"
# A value hashcat "recovers" in these fixtures. Not a credential to anything.
SECRET = "Summer2026!"  # noqa: S105


# ── it exists, and the places that already reference it can reach it ─────────


def test_the_credentials_screen_can_now_import_it():
    """The screen catches ImportError and falls back to telling the operator
    to run hashcat by hand. That branch should now be unreachable."""
    from netreaper.tools.hashcat import HashcatTool as Imported

    assert Imported.TOOL_BINARY == "hashcat"


def test_catalogue_entry_and_adapter_agree():
    from netreaper.detection.tools import ToolCategory, ToolRegistry

    entry = ToolRegistry.TOOL_DEFINITIONS["hashcat"]
    assert entry.name == HashcatTool.TOOL_BINARY
    assert entry.category is ToolCategory.CREDENTIALS
    assert entry.requires_root is False


def test_it_is_a_local_cracker_with_no_network_target():
    """Same posture as the john wrapper beside it: it burns local compute and
    opens no socket, so there is nothing to scope."""
    t = HashcatTool()
    assert t.DEFAULT_TIER is Tier.PASSIVE
    assert t.execution_tier(HASHES, {}) is Tier.PASSIVE
    assert t.target_identifiers(HASHES, {"hash_mode": 22000}) == []
    assert t.METADATA.plugin_type is PluginType.CRACKER
    assert Capability.PASSWORD_CRACK in t.METADATA.capabilities


# ── the command ──────────────────────────────────────────────────────────────


def test_a_straight_attack_names_mode_file_and_wordlist():
    argv = HashcatTool().build_command(
        HASHES, {"hash_mode": 22000, "attack_mode": 0, "wordlist": WORDS}
    )
    assert argv[:4] == ["-m", "22000", "-a", "0"]
    assert argv[-2:] == [HASHES, WORDS], argv


def test_the_potfile_is_disabled_by_default():
    """Otherwise the second run against an already-cracked hash prints nothing
    and exits 1, which reads as a failure against a hash you have broken."""
    argv = HashcatTool().build_command(HASHES, {"hash_mode": 22000, "wordlist": WORDS})
    assert "--potfile-disable" in argv


def test_the_potfile_can_be_opted_back_in():
    argv = HashcatTool().build_command(
        HASHES, {"hash_mode": 22000, "wordlist": WORDS, "potfile": True}
    )
    assert "--potfile-disable" not in argv


def test_show_is_its_own_invocation_and_keeps_the_potfile():
    """--show reads the potfile. Disabling it there would guarantee no output."""
    argv = HashcatTool().build_command(HASHES, {"hash_mode": 22000, "show": True})
    assert argv == ["-m", "22000", "--show", HASHES]
    assert "--potfile-disable" not in argv


@pytest.mark.parametrize(
    "attack,options,tail",
    [
        (0, {"wordlist": WORDS}, [WORDS]),
        (1, {"wordlist": WORDS, "wordlist2": "second.txt"}, [WORDS, "second.txt"]),
        (3, {"mask": "?d?d?d?d?d?d?d?d"}, ["?d?d?d?d?d?d?d?d"]),
        (6, {"wordlist": WORDS, "mask": "?d?d"}, [WORDS, "?d?d"]),
        (7, {"mask": "?d?d", "wordlist": WORDS}, ["?d?d", WORDS]),
    ],
)
def test_each_attack_mode_gets_its_operands_in_hashcat_order(attack, options, tail):
    """Mode 6 is wordlist then mask and mode 7 is the reverse. Swapping them
    hands hashcat a mask where it wants a dictionary path."""
    argv = HashcatTool().build_command(HASHES, {"hash_mode": 22000, "attack_mode": attack, **options})
    assert argv[-len(tail):] == tail, argv


def test_a_mode_missing_its_operand_is_refused_before_the_spawn():
    with pytest.raises(ConfigurationError, match="wordlist"):
        HashcatTool().build_command(HASHES, {"hash_mode": 22000, "attack_mode": 0})


def test_an_unsupported_attack_mode_is_refused_and_lists_the_real_ones():
    with pytest.raises(ConfigurationError, match="attack mode 9"):
        HashcatTool().build_command(
            HASHES, {"hash_mode": 22000, "attack_mode": 9, "wordlist": WORDS}
        )


def test_a_missing_hash_mode_is_refused_with_the_useful_examples():
    with pytest.raises(ConfigurationError, match="22000"):
        HashcatTool().build_command(HASHES, {"wordlist": WORDS})


def test_a_missing_hash_file_is_refused():
    with pytest.raises(ConfigurationError, match="hash file"):
        HashcatTool().build_command("", {"hash_mode": 22000, "wordlist": WORDS})


def test_the_tui_options_build_a_command():
    """The exact option keys tui/screens/credentials.py assembles."""
    argv = HashcatTool().build_command(
        HASHES, {"hash_mode": 22000, "attack_mode": 0, "wordlist": WORDS, "hash_file": HASHES}
    )
    assert "-m" in argv and "-a" in argv


# ── the parse, and the colon that matters ────────────────────────────────────


def test_a_cracked_pair_is_split_on_the_last_colon_not_the_first():
    """Mode 5500 is user::domain:challenge:response:response. Splitting on the
    first colon returns the username as the hash and the rest as the password."""
    netntlm = "alice::CORP:1122334455667788:aabbcc:ddeeff"
    parsed = HashcatTool().parse_output(f"{netntlm}:{SECRET}\n")
    assert parsed["cracked"] == [{"hash": netntlm, "password": SECRET}]


def test_a_wpa_hash_survives_the_same_path():
    wpa = "WPA*01*abc*aabbccddeeff*112233445566*4e455452*"
    parsed = HashcatTool().parse_output(f"{wpa}:hunter2\n")
    assert parsed["cracked"][0]["hash"] == wpa
    assert parsed["cracked"][0]["password"] == "hunter2"  # noqa: S105


def test_the_recovered_line_gives_the_total():
    parsed = HashcatTool().parse_output(
        "Recovered........: 1/2 (50.00%) Digests\n"
        "abc:letmein\n"
    )
    assert parsed["total"] == 2
    assert len(parsed["cracked"]) == 1


def test_status_lines_are_not_mistaken_for_cracked_pairs():
    """Almost every status line contains a colon."""
    parsed = HashcatTool().parse_output(
        "Session..........: hashcat\n"
        "Status...........: Exhausted\n"
        "Speed.#1.........:    7670 H/s\n"
        "Progress.........: 14344385/14344385 (100.00%)\n"
    )
    assert parsed["cracked"] == []
    assert parsed["exhausted"] is True


def test_total_falls_back_to_the_number_cracked():
    parsed = HashcatTool().parse_output("abc:one\ndef:two\n")
    assert parsed["total"] == 2


# ── exhausted is a result, not a failure ─────────────────────────────────────


def _run_with_exit(monkeypatch, code: int, data: dict):
    """Drive execute() with a stubbed base so only the exit-code handling runs."""
    tool = HashcatTool()
    tool._execution = ToolExecution(tool_name="hashcat", command=[], target=HASHES)

    async def fake_execute(self, target, options):
        self._execution.exit_code = code
        return PluginResult(success=(code == 0), data=data)

    monkeypatch.setattr("netreaper.tools.base.BaseToolWrapper.execute", fake_execute)
    return tool, asyncio.run(tool.execute(HASHES, {"hash_mode": 22000, "wordlist": WORDS}))


def test_an_exhausted_run_is_reported_as_a_finished_run(monkeypatch):
    """hashcat exits 1 having tried everything. The base maps non-zero to
    success=False and the credentials screen prints 'Cracking failed', blaming
    the tool for a password that was not in the wordlist."""
    _, result = _run_with_exit(monkeypatch, EXIT_EXHAUSTED, {"cracked": [], "total": 1})
    assert result.success is True
    assert result.data["exhausted"] is True
    assert result.data["cracked"] == []
    assert result.warnings, "the operator should be told the keyspace ran out"


def test_a_crack_is_still_a_success(monkeypatch):
    _, result = _run_with_exit(
        monkeypatch, 0, {"cracked": [{"hash": "abc", "password": SECRET}], "total": 1}
    )
    assert result.success is True
    assert result.data["cracked"][0]["password"] == SECRET


def test_a_real_failure_is_still_a_failure(monkeypatch):
    """Exit 2 is aborted. Only exhausted gets the reinterpretation."""
    _, result = _run_with_exit(monkeypatch, 2, {"cracked": [], "total": 0})
    assert result.success is False
