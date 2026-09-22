# SPDX-License-Identifier: GPL-3.0-or-later
"""The keystream that nothing read, and the frame nothing could forge from it.

chopchop and fragmentation exist to recover a PRGA keystream. Both printed
``Saving keystream in <file>.xor`` on every successful run, and nothing in this
tree ever parsed that line or opened that file. packetforge-ng, the tool whose
whole job is turning that keystream into a frame, had no adapter at all, while
``test_cli_every_command_runs`` had been stubbing the binary onto PATH for a
harness that was never written against it.

So the attack could recover the thing and could not use it. That is the same
shape as every other defect found here: a declaration with nothing connecting
it to anything. These tests pin the connection, not the declaration.

Two defects were found while wiring it, and both get a regression here:

  -h was never emitted   caffe-latte, cfrag and interactive replay were driven
                         through a lazy dispatch that passed "source_mac", and
                         _common_args reads "source". Three of the six
                         strategies ran with no source MAC set.
  -r would have doubled  _common_args already emits -r from "read_file", so
                         adding a second emitter to the interactive builder put
                         the flag in the argv twice.
"""
from __future__ import annotations

import asyncio

import pytest

from netreaper.core.exceptions import ConfigurationError
from netreaper.detection.tools import ToolCategory
from netreaper.safety.scope import Tier
from netreaper.tools.aireplay import AireplayTool, AttackMode
from netreaper.tools.packetforge import PacketforgeTool
from netreaper.wireless.wep import KEYSTREAM_MODES, ForgeResult, WepAttack

IFACE = "wlan0mon"
BSSID = "AA:BB:CC:DD:EE:FF"
SMAC = "00:11:22:33:44:55"
# Paths are argv strings only: nothing here touches the filesystem.
XOR = "replay_dec-0627-100929.xor"


# ── the adapter exists, and is registered where something can find it ────────


def test_packetforge_is_in_the_catalogue_and_has_an_adapter():
    """The registration test the issue asked for.

    An adapter that is written but never registered cannot be installed or
    reported by `netreaper status`, and passes every other test in the suite.
    subfinder shipped in exactly that state.
    """
    from netreaper.detection.tools import ToolRegistry

    # TOOL_DEFINITIONS is the typed source of truth; TOOLS is a derived legacy
    # view of it, so registering once reaches both.
    catalogue = ToolRegistry.TOOL_DEFINITIONS
    assert "packetforge-ng" in catalogue, (
        "packetforge-ng has an adapter but no catalogue entry, so it can be "
        "spawned and never installed or reported"
    )
    entry = catalogue["packetforge-ng"]
    assert entry.category is ToolCategory.WIRELESS
    assert PacketforgeTool.TOOL_BINARY == entry.name


def test_the_forge_is_passive_but_still_scoped_to_the_ap():
    """It touches no radio, so it is PASSIVE. That is not the same as unscoped.

    Forging a frame aimed at an access point outside the engagement is refused
    at the seam, because the scope identifier is the BSSID rather than the
    local filename that happens to be the positional argument.
    """
    t = PacketforgeTool()
    assert t.DEFAULT_TIER is Tier.PASSIVE
    assert t.DESTRUCTIVE is False
    assert t.target_identifiers(XOR, {"bssid": BSSID}) == [BSSID]
    assert t.target_identifiers(XOR, {}) == [], "a missing BSSID must not scope to the file"


# ── the forge command is one the real binary would accept ────────────────────


def test_forge_command_carries_every_mandatory_operand():
    argv = PacketforgeTool().build_command(
        XOR, {"bssid": BSSID, "source_mac": SMAC, "output": "arp.cap"}
    )
    assert argv[0] == "-0", "ARP mode selector must lead"
    for flag, value in (("-a", BSSID), ("-h", SMAC), ("-y", XOR), ("-w", "arp.cap")):
        assert flag in argv, f"{flag} missing from {argv}"
        assert argv[argv.index(flag) + 1] == value
    # Both IPs default to broadcast, which is the canonical WEP ARP form.
    assert argv[argv.index("-k") + 1] == "255.255.255.255"
    assert argv[argv.index("-l") + 1] == "255.255.255.255"


@pytest.mark.parametrize("missing", ["bssid", "source_mac", "output"])
def test_a_missing_operand_is_refused_here_not_by_exit_code_1(missing):
    """packetforge-ng exits 1 on a missing operand, which surfaces as a failed
    spawn with no useful message. Refuse it while the names are still in hand."""
    options = {"bssid": BSSID, "source_mac": SMAC, "output": "arp.cap"}
    del options[missing]
    with pytest.raises(ConfigurationError, match=missing):
        PacketforgeTool().build_command(XOR, options)


def test_a_missing_keystream_is_refused():
    with pytest.raises(ConfigurationError, match="keystream"):
        PacketforgeTool().build_command(
            "", {"bssid": BSSID, "source_mac": SMAC, "output": "arp.cap"}
        )


def test_the_written_packet_is_read_back_out_of_the_output():
    parsed = PacketforgeTool().parse_output("Wrote packet to: arp-request\n")
    assert parsed["success"] is True
    assert parsed["packet_file"] == "arp-request"


def test_silence_is_not_success():
    """A zero exit with no 'Wrote packet to' line must not be read as a packet."""
    parsed = PacketforgeTool().parse_output("")
    assert parsed["success"] is False
    assert parsed["packet_file"] is None


# ── the two defects found while wiring it ────────────────────────────────────


@pytest.mark.parametrize(
    "mode", [AttackMode.CAFFE_LATTE, AttackMode.CFRAG, AttackMode.INTERACTIVE]
)
@pytest.mark.parametrize("key", ["source", "source_mac"])
def test_the_source_mac_reaches_the_argv_under_either_key(mode, key):
    """Regression: these three emitted no -h at all.

    The named helpers pass "source"; the lazy dispatch in wep.py passed
    "source_mac", and _common_args read only the former. Identical in shape to
    the ignore_negative / ignore_negative_ack mismatch fixed in the same file.
    """
    argv = AireplayTool().build_command(
        IFACE, {"attack": mode, "bssid": BSSID, key: SMAC}
    )
    assert "-h" in argv, f"{mode.value} with {key!r} emitted no source MAC: {argv}"
    assert argv[argv.index("-h") + 1] == SMAC


def test_the_replay_file_flag_is_emitted_exactly_once():
    """-r comes from _common_args via "read_file". A second emitter in the
    interactive builder would have put it in the argv twice."""
    argv = AireplayTool().build_command(
        IFACE,
        {
            "attack": AttackMode.INTERACTIVE,
            "bssid": BSSID,
            "source": SMAC,
            "read_file": "arp.cap",
        },
    )
    assert argv.count("-r") == 1, argv
    assert argv[argv.index("-r") + 1] == "arp.cap"


def test_the_keystream_filename_is_parsed_out_of_the_attack_output():
    """It was printed on every successful chopchop run and never read."""
    parsed = AireplayTool().parse_output(
        "Saving keystream in replay_dec-0627-100929.xor\n"
        "Saving plaintext in replay_dec-0627-100929.cap\n"
    )
    assert parsed["keystream_file"] == "replay_dec-0627-100929.xor"
    assert parsed["plaintext_file"] == "replay_dec-0627-100929.cap"
    assert parsed["success"] is True


# ── the chain, end to end, against doubles ───────────────────────────────────


class _Aireplay:
    """Yields a keystream from the attack, and records the replay it is given."""

    def __init__(self, keystream: str | None = XOR):
        self._keystream = keystream
        self.replayed_with: dict | None = None

    async def chopchop_attack(self, *a, **k):
        return {"success": True, "keystream_file": self._keystream} if self._keystream else {}

    async def fragment_attack(self, *a, **k):
        return await self.chopchop_attack(*a, **k)

    async def execute(self, iface, options):
        self.replayed_with = options
        return {"success": True}


class _Forge:
    def __init__(self, ok: bool = True):
        self.ok = ok
        self.called_with: tuple | None = None

    async def forge_arp(self, keystream, bssid, source_mac, output, **kw):
        self.called_with = (keystream, bssid, source_mac, output)
        return {"success": self.ok, "packet_file": output if self.ok else None}


def _run(**kw):
    a = kw.pop("aireplay", None) or _Aireplay()
    f = kw.pop("forge", None) or _Forge()
    w = WepAttack(aireplay=a, packetforge=f)
    return w, a, f, asyncio.run(w.forge_and_replay(IFACE, BSSID, SMAC, **kw))


def test_the_whole_chain_runs_keystream_to_forge_to_replay():
    _w, a, f, result = _run(output="arp.cap")
    assert isinstance(result, ForgeResult)
    assert result.keystream_file == XOR
    assert f.called_with == (XOR, BSSID, SMAC, "arp.cap")
    assert result.packet_file == "arp.cap"
    assert result.replayed is True
    # The forged frame must actually be handed to the replay, which is the
    # step that was impossible before -r was reachable.
    assert a.replayed_with["read_file"] == "arp.cap"
    assert a.replayed_with["attack"] is AttackMode.INTERACTIVE
    assert a.replayed_with["source"] == SMAC


def test_no_keystream_is_an_outcome_not_an_error():
    """chopchop against a quiet AP recovers nothing. That is not a failure."""
    _w, _a, f, result = _run(aireplay=_Aireplay(keystream=None))
    assert result.keystream_file is None
    assert result.replayed is False
    assert result.reason == "no keystream recovered"
    assert f.called_with is None, "nothing should be forged from a keystream that does not exist"


def test_a_failed_forge_stops_before_the_replay():
    _w, a, _f, result = _run(forge=_Forge(ok=False))
    assert result.keystream_file == XOR
    assert result.packet_file is None
    assert result.replayed is False
    assert a.replayed_with is None, "a frame that was never forged must not be replayed"


def test_the_default_output_sits_beside_the_keystream():
    _w, _a, f, _result = _run()
    assert f.called_with[3].endswith(".forged.cap")


@pytest.mark.parametrize("strategy", sorted(KEYSTREAM_MODES))
def test_every_declared_keystream_mode_is_dispatchable(strategy):
    """KEYSTREAM_MODES and the injector dispatch must not drift apart."""
    assert callable(WepAttack(aireplay=_Aireplay())._injector(strategy))


def test_arpreplay_is_refused_because_it_recovers_no_keystream():
    """It replays a captured ARP. There is no PRGA to forge from."""
    w = WepAttack(aireplay=_Aireplay(), packetforge=_Forge())
    with pytest.raises(ConfigurationError, match="recovers no keystream"):
        asyncio.run(w.forge_and_replay(IFACE, BSSID, SMAC, strategy="arpreplay"))
