# SPDX-License-Identifier: GPL-3.0-or-later
"""Native EAPOL handshake parser tests (crafted pcap bytes, no radio)."""
from __future__ import annotations

import struct

import pytest

from netreaper.wireless.eapol import (
    LINKTYPE_IEEE802_11,
    LINKTYPE_IEEE802_11_RADIO,
    EapolParseError,
    cap_has_handshake,
    handshakes_for,
    parse_handshakes,
    read_handshakes,
)

AP = "AA:BB:CC:DD:EE:01"
STA = "11:22:33:44:55:66"
AP2 = "AA:BB:CC:DD:EE:02"

# Key Information field values for each 4-way message (pairwise bit always set).
KI_M1 = 0x0088  # ACK + pairwise
KI_M2 = 0x0108  # MIC + pairwise
KI_M3 = 0x03C8  # ACK + MIC + INSTALL + SECURE + pairwise
KI_M4 = 0x0308  # MIC + SECURE + pairwise
KI_GROUP = 0x0388  # ACK + MIC + SECURE, no pairwise bit -> group handshake


def _mac_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(":"))


def dot11_eapol(key_info: int, *, from_ds: bool, ap: str, sta: str, qos: bool = False) -> bytes:
    """Build one 802.11 data frame carrying an EAPOL-Key of the given key_info."""
    subtype = 0x08 if qos else 0x00
    fc0 = (2 << 2) | (subtype << 4)  # type=Data(2)
    fc1 = 0x02 if from_ds else 0x01  # FromDS or ToDS
    fc = bytes([fc0, fc1])
    dur = b"\x00\x00"
    if from_ds:  # AP -> STA: addr1=STA(dest), addr2=AP(bssid)
        addr1, addr2 = sta, ap
    else:  # STA -> AP: addr1=AP(bssid), addr2=STA(source)
        addr1, addr2 = ap, sta
    hdr = fc + dur + _mac_bytes(addr1) + _mac_bytes(addr2) + _mac_bytes(ap) + b"\x00\x00"
    if qos:
        hdr += b"\x00\x00"  # QoS Control field
    llc = bytes([0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E])
    keyframe = bytes([0x02]) + key_info.to_bytes(2, "big") + b"\x00" * 90
    eapol = bytes([0x02, 0x03]) + len(keyframe).to_bytes(2, "big") + keyframe
    return hdr + llc + eapol


def make_pcap(linktype: int, frames: list[bytes], endian: str = "<") -> bytes:
    """Wrap 802.11 frames in a classic libpcap file (radiotap when requested)."""
    gh = struct.pack(endian + "IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    out = gh
    for frame in frames:
        if linktype == LINKTYPE_IEEE802_11_RADIO:
            frame = bytes([0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00]) + frame
        out += struct.pack(endian + "IIII", 0, 0, len(frame), len(frame)) + frame
    return out


def _cap(*key_infos: int, **kw) -> bytes:
    """Radiotap cap with M-frames; odd messages are AP->STA, even are STA->AP."""
    ap = kw.get("ap", AP)
    sta = kw.get("sta", STA)
    frames = []
    for ki in key_infos:
        from_ds = ki in (KI_M1, KI_M3)
        frames.append(dot11_eapol(ki, from_ds=from_ds, ap=ap, sta=sta))
    return make_pcap(LINKTYPE_IEEE802_11_RADIO, frames)


def test_all_four_messages_classified():
    hs = parse_handshakes(_cap(KI_M1, KI_M2, KI_M3, KI_M4))
    assert len(hs) == 1
    assert hs[0].messages == {1, 2, 3, 4}
    assert hs[0].full is True
    assert hs[0].complete is True
    assert hs[0].bssid == AP
    assert hs[0].client == STA


def test_complete_requires_anonce_and_snonce():
    assert parse_handshakes(_cap(KI_M1))[0].complete is False       # ANonce only
    assert parse_handshakes(_cap(KI_M2))[0].complete is False       # SNonce only
    assert parse_handshakes(_cap(KI_M1, KI_M2))[0].complete is True  # M1+M2 crackable
    assert parse_handshakes(_cap(KI_M3, KI_M2))[0].complete is True  # M3+M2 crackable
    assert parse_handshakes(_cap(KI_M1, KI_M2))[0].full is False


def test_group_key_frame_is_ignored():
    assert parse_handshakes(_cap(KI_GROUP)) == []


def test_qos_data_offset_still_finds_eapol():
    frame = dot11_eapol(KI_M2, from_ds=False, ap=AP, sta=STA, qos=True)
    cap = make_pcap(LINKTYPE_IEEE802_11_RADIO, [frame])
    hs = parse_handshakes(cap)
    assert len(hs) == 1 and hs[0].messages == {2}


def test_raw_80211_linktype():
    frames = [
        dot11_eapol(KI_M1, from_ds=True, ap=AP, sta=STA),
        dot11_eapol(KI_M2, from_ds=False, ap=AP, sta=STA),
    ]
    hs = parse_handshakes(make_pcap(LINKTYPE_IEEE802_11, frames))
    assert len(hs) == 1 and hs[0].complete is True


def test_big_endian_pcap():
    frames = [
        dot11_eapol(KI_M1, from_ds=True, ap=AP, sta=STA),
        dot11_eapol(KI_M2, from_ds=False, ap=AP, sta=STA),
    ]
    cap = make_pcap(LINKTYPE_IEEE802_11, frames, endian=">")
    hs = parse_handshakes(cap)
    assert len(hs) == 1 and hs[0].complete is True


def test_handshakes_for_and_cap_has_handshake_filter_bssid():
    frames = [
        dot11_eapol(KI_M1, from_ds=True, ap=AP, sta=STA),
        dot11_eapol(KI_M2, from_ds=False, ap=AP, sta=STA),
        dot11_eapol(KI_M1, from_ds=True, ap=AP2, sta=STA),  # AP2: incomplete
    ]
    cap = make_pcap(LINKTYPE_IEEE802_11_RADIO, frames)
    assert len(parse_handshakes(cap)) == 2
    assert cap_has_handshake_bytes(cap, AP) is True
    assert cap_has_handshake_bytes(cap, AP2) is False
    assert cap_has_handshake_bytes(cap, None) is True


def cap_has_handshake_bytes(cap: bytes, bssid, tmp=[]):  # noqa: B006 - test helper
    """cap_has_handshake works on paths; write bytes and delegate."""
    import tempfile
    from pathlib import Path

    p = Path(tempfile.mkstemp(suffix=".cap")[1])
    p.write_bytes(cap)
    try:
        return cap_has_handshake(p, bssid)
    finally:
        p.unlink()


def test_read_and_handshakes_for_from_disk(tmp_path):
    cap = _cap(KI_M1, KI_M2)
    path = tmp_path / "capture-01.cap"
    path.write_bytes(cap)
    assert len(read_handshakes(path)) == 1
    assert len(handshakes_for(path, AP.lower())) == 1  # case-insensitive
    assert handshakes_for(path, AP2) == []


def test_pcapng_rejected():
    with pytest.raises(EapolParseError, match="pcapng"):
        parse_handshakes(struct.pack(">I", 0x0A0D0D0A) + b"\x00" * 40)


def test_non_pcap_rejected():
    with pytest.raises(EapolParseError):
        parse_handshakes(b"not a capture file at all........")


def test_truncated_file_rejected():
    with pytest.raises(EapolParseError):
        parse_handshakes(b"\x00\x01")
