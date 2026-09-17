# SPDX-License-Identifier: GPL-3.0-or-later
"""The new domains from #33, and the two boundaries that define them.

Seven external sources were supplied for incorporation. Research established
that three of them are not what a name-based guess would suggest, and the
difference matters:

  OSCC actuates a real vehicle's steering, throttle and brakes.
  CBM ("Car Backdoor Maker") programs an SMS-commanded hardware CAN implant
    with payloads triggered on GPS position, speed or fuel level, and carries
    no licence at all.
  idevicerestore is a firmware flashing tool whose own README warns it can
    destroy user data irreversibly.

None of those is an assessment capability, and none of the failure modes is one
an authorisation tier improves: a scope gate is an information-security control
and cannot stop a car hitting someone or a client's phone being bricked. So the
domains are read-only, and that is enforced here rather than trusted to a
comment, because this codebase has a long history of controls that were
documented and enforced nowhere.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from netreaper.automotive import AUTOMOTIVE_MANIFESTS, CanIdDatabase, decode_capture
from netreaper.mobile.devices import (
    ANDROID_READ_BINARIES,
    IOS_READ_BINARIES,
    REFUSED_DEVICE_WRITERS,
    _guard,
)
from netreaper.resources import SOURCES, Incorporation, Kind, get_source
from netreaper.resources.registry import validate_registry
from netreaper.tools.canutils import (
    REFUSED_WRITE_BINARIES,
    CanUtilsTool,
)

# ── the registry is coherent and honest ──────────────────────────────────────


def test_the_registry_obeys_its_own_rules():
    assert validate_registry() == []


def test_no_licence_is_left_as_a_guess():
    unverified = [s.name for s in SOURCES if not s.licence_verified]
    assert unverified == [], f"unverified licences: {unverified}"


def test_nothing_unlicensed_is_vendored():
    """MITM-cheatsheet and CBM have no LICENSE file at all: default copyright
    means no reproduction and no derivative works."""
    for name in ("MITM-cheatsheet", "CBM"):
        s = get_source(name)
        assert s is not None
        assert "NONE" in s.licence
        assert s.incorporation is Incorporation.REFERENCED


def test_gpl2_only_tooling_is_never_vendored():
    """can-utils carries GPL-2.0-only parts, which are not upward-compatible
    with this project's GPL-3.0-or-later. Spawning is fine; copying is not."""
    s = get_source("can-utils")
    assert s is not None
    assert "GPL-2.0-only" in s.licence
    assert s.incorporation is Incorporation.WRAPPED


@pytest.mark.parametrize("name", ["oscc", "CBM", "idevicerestore"])
def test_safety_restricted_sources_are_reference_only(name):
    s = get_source(name)
    assert s is not None
    assert s.is_safety_restricted, f"{name} must carry a safety_note"
    assert s.incorporation is Incorporation.REFERENCED


def test_reference_material_declares_no_capability():
    for s in SOURCES:
        if s.kind is Kind.REFERENCE:
            assert not s.provides, f"{s.name} is reference but declares {s.provides}"


def test_every_supplied_source_is_accounted_for():
    """All seven of the supplied URLs appear, none quietly dropped."""
    supplied = (
        "iDoka/awesome-automotive-can-id",
        "kennyn510/wpa2-wordlists",
        "frostbits-security/MITM-cheatsheet",
        "libimobiledevice/idevicerestore",
        "jaredthecoder/awesome-vehicle-security",
        "UnaPibaGeek/CBM",
        "PolySync/oscc",
    )
    urls = " ".join(s.url for s in SOURCES)
    for frag in supplied:
        assert frag in urls, f"{frag} was not incorporated anywhere"


# ── the automotive boundary: read, never write ───────────────────────────────


@pytest.mark.parametrize("binary", sorted(REFUSED_WRITE_BINARIES))
def test_can_transmitters_are_refused_by_name(binary):
    with pytest.raises(ValueError, match=r"physical-safety|transmits"):
        CanUtilsTool()._guard(binary)


def test_can_readers_are_permitted():
    for binary in ("candump", "cansniffer", "cantools"):
        assert CanUtilsTool()._guard(binary) is None


def test_an_unknown_can_binary_is_refused():
    with pytest.raises(ValueError, match="not a permitted CAN binary"):
        CanUtilsTool()._guard("dd")


def test_no_can_transmitter_appears_in_the_module_source():
    """A guard is only as good as the absence of a code path around it."""
    src = Path(CanUtilsTool.__module__.replace(".", "/") + ".py")
    text = (Path("src") / src).read_text(encoding="utf-8")
    body = text.split("REFUSED_WRITE_BINARIES", 1)[1]
    for writer in ("cansend", "cangen", "canplayer"):
        assert f'"{writer}",' not in body.split("})", 1)[1], (
            f"{writer} is referenced outside the refusal set"
        )


def test_no_automotive_manifest_is_destructive():
    for m in AUTOMOTIVE_MANIFESTS:
        assert m.destructive is False, m.name
        assert m.requires_confirmation is False, m.name


# ── the mobile boundary ──────────────────────────────────────────────────────


@pytest.mark.parametrize("binary", sorted(REFUSED_DEVICE_WRITERS))
def test_device_writers_are_refused_by_name(binary):
    with pytest.raises(ValueError, match="writes to or re-images"):
        _guard(binary, IOS_READ_BINARIES)


def test_device_readers_are_permitted():
    assert _guard("idevice_id", IOS_READ_BINARIES) is None
    assert _guard("ideviceinfo", IOS_READ_BINARIES) is None
    assert _guard("adb", ANDROID_READ_BINARIES) is None


def test_adb_is_not_permitted_as_an_ios_binary():
    """The two allow-lists are separate on purpose."""
    with pytest.raises(ValueError, match="not a permitted binary"):
        _guard("adb", IOS_READ_BINARIES)


# ── CAN decoding ─────────────────────────────────────────────────────────────


def test_candump_output_is_parsed_and_garbage_is_skipped():
    cap = CanUtilsTool._parse(
        "can0",
        "  can0  1A0   [8]  11 22 33 44 55 66 77 88\n"
        "  can0  0C9   [3]  DE AD BE\n"
        "not a frame at all\n",
    )
    assert cap.frame_count == 2
    assert cap.unique_ids == {"1A0", "0C9"}
    assert cap.frames[0].arbitration_id == 0x1A0


def _db_dir():
    d = Path(tempfile.mkdtemp())
    (d / "a.csv").write_text("can_id,name\n0x1A0,Steering angle\n0C9,Brake pressure\n,x\n")
    (d / "b.json").write_text(json.dumps({"2FF": "Wheel speed"}))
    (d / "c.json").write_text(json.dumps({"ids": [{"can_id": "3AB", "name": "Gear"}]}))
    (d / "broken.csv").write_text("\x00 not csv")
    return d


def test_all_three_real_world_shapes_load():
    """A bare {id: name} mapping, a wrapped {"ids": [...]} list, and CSV.

    The first version looked for an ids/signals wrapper and fell back to an
    empty list, so a bare mapping contributed nothing at all, silently.
    """
    db = CanIdDatabase.load(_db_dir())
    for cid, expected in (("1A0", "Steering angle"), ("2FF", "Wheel speed"), ("3AB", "Gear")):
        hit = db.lookup(cid)
        assert hit is not None, f"{cid} missing"
        assert hit.name == expected


def test_identifier_notation_is_normalised():
    db = CanIdDatabase.load(_db_dir())
    assert db.lookup("0x1A0") and db.lookup("1a0") and db.lookup("01A0")


def test_a_malformed_file_does_not_lose_the_database():
    db = CanIdDatabase.load(_db_dir())
    assert len(db) >= 4
    assert db.unparsed_rows >= 1, "rows it could not read must be counted, not hidden"


def test_an_unknown_id_is_reported_unknown_not_guessed():
    """A mislabelled signal on a vehicle bus is worse than an unlabelled one."""
    cap = CanUtilsTool._parse("can0", "  can0  7FF   [1]  00\n")
    decoded = decode_capture(cap, CanIdDatabase.load(_db_dir()))
    assert decoded[0].name == "unknown"
    assert decoded[0].known is False
