# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""Native EAPOL 4-way-handshake detection for captured .cap files.

No external tools and no radio: this walks a classic libpcap file, locates the
802.1X/EAPOL-Key frames of the WPA/WPA2 4-way handshake, classifies each as
message M1-M4 from its Key Information field, and decides whether the capture
holds a crackable handshake for a given BSSID.

Being pure byte-parsing, it is fully unit-testable with crafted fixtures, which
is why verification lives here rather than shelling out to aircrack-ng/cowpatty.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

from netreaper.core.logging import get_logger

logger = get_logger(__name__)

# libpcap global-header magic numbers (little/big endian, us/ns timestamps).
_PCAP_MAGICS_LE = (0xA1B2C3D4, 0xA1B23C4D)
_PCAP_MAGICS_BE = (0xD4C3B2A1, 0x4D3CB2A1)
_PCAPNG_MAGIC = 0x0A0D0D0A

# Link-layer header types we know how to strip down to the 802.11 MAC header.
LINKTYPE_IEEE802_11 = 105
LINKTYPE_PRISM = 119
LINKTYPE_IEEE802_11_RADIO = 127  # radiotap
LINKTYPE_PPI = 192

_ETHERTYPE_EAPOL = 0x888E
_EAPOL_TYPE_KEY = 3  # EAPOL packet-body type: EAPOL-Key

# Key Information bit masks (IEEE 802.11 EAPOL-Key descriptor).
_KI_PAIRWISE = 0x0008
_KI_INSTALL = 0x0040
_KI_ACK = 0x0080
_KI_MIC = 0x0100
_KI_SECURE = 0x0200

# EAPOL-Key fixed-field layout up to Key Data (WPA2 PSK: 16-byte MIC), used to
# locate the Key Data that carries the PMKID KDE in message 1.
_KEY_DATA_LEN_OFFSET = 93  # descriptor(1)+info(2)+len(2)+replay(8)+nonce(32)
_KEY_DATA_OFFSET = 95      # +iv(16)+rsc(8)+id(8)+mic(16)+key_data_len(2)
_KDE_VENDOR_TYPE = 0xDD    # vendor-specific KDE element id
_RSN_OUI = b"\x00\x0f\xac"  # 00-0F-AC
_KDE_PMKID = 0x04          # RSN KDE data type for a PMKID


class EapolParseError(ValueError):
    """The bytes handed in are not a libpcap capture we can read."""


@dataclass
class Handshake:
    """The EAPOL messages seen between one AP and one client."""

    bssid: str
    client: str
    messages: set[int] = field(default_factory=set)

    @property
    def complete(self) -> bool:
        """True when the capture is crackable: an ANonce (M1 or M3) plus the
        client's SNonce+MIC (M2). M4 is not required to mount an offline crack."""
        has_anonce = 1 in self.messages or 3 in self.messages
        has_snonce = 2 in self.messages
        return has_anonce and has_snonce

    @property
    def full(self) -> bool:
        """True when all four messages M1-M4 were observed."""
        return {1, 2, 3, 4}.issubset(self.messages)


@dataclass
class _Frame:
    bssid: str
    client: str
    msg: int
    pmkid: str | None = None


@dataclass
class Pmkid:
    """A PMKID captured from an access point's EAPOL message 1."""

    bssid: str
    client: str
    pmkid: str  # 32 lowercase hex chars


def _mac(raw: bytes) -> str:
    return ":".join(f"{b:02X}" for b in raw)


def _extract_pmkid_from_keydata(kd: bytes) -> str | None:
    """Walk the EAPOL-Key Key Data KDEs and return the PMKID hex, if present."""
    i = 0
    while i + 2 <= len(kd):
        kde_type, kde_len = kd[i], kd[i + 1]
        if kde_type == 0x00:  # padding: end of key data
            break
        body = kd[i + 2 : i + 2 + kde_len]
        if (
            kde_type == _KDE_VENDOR_TYPE
            and len(body) >= 20
            and body[0:3] == _RSN_OUI
            and body[3] == _KDE_PMKID
        ):
            pmkid = body[4:20]
            if pmkid != b"\x00" * 16:  # all-zero PMKID means "not supported"
                return pmkid.hex()
        i += 2 + kde_len
    return None


def _classify(key_info: int) -> int | None:
    """Map an EAPOL-Key Key-Information field to a 4-way message number (1-4)."""
    if not key_info & _KI_PAIRWISE:
        return None  # group-key handshake, not the pairwise 4-way
    ack = bool(key_info & _KI_ACK)
    mic = bool(key_info & _KI_MIC)
    install = bool(key_info & _KI_INSTALL)
    secure = bool(key_info & _KI_SECURE)
    if ack and not mic:
        return 1  # M1: AP -> STA, carries ANonce
    if mic and not ack and not secure and not install:
        return 2  # M2: STA -> AP, carries SNonce + MIC
    if ack and mic and install and secure:
        return 3  # M3: AP -> STA
    if mic and not ack and secure and not install:
        return 4  # M4: STA -> AP
    return None


def _strip_link_header(linktype: int, pkt: bytes) -> bytes | None:
    """Return the 802.11 MAC frame, stripping any radiotap/prism/ppi wrapper."""
    if linktype == LINKTYPE_IEEE802_11:
        return pkt
    if linktype == LINKTYPE_IEEE802_11_RADIO:
        if len(pkt) < 4:
            return None
        rt_len = pkt[2] | (pkt[3] << 8)  # radiotap it_len is little-endian
        return pkt[rt_len:] if rt_len <= len(pkt) else None
    if linktype == LINKTYPE_PPI:
        if len(pkt) < 4:
            return None
        ppi_len = pkt[2] | (pkt[3] << 8)
        return pkt[ppi_len:] if ppi_len <= len(pkt) else None
    if linktype == LINKTYPE_PRISM:
        return pkt[144:] if len(pkt) > 144 else None  # fixed 144-byte header
    return None


def _parse_dot11(data: bytes) -> _Frame | None:
    """Extract (bssid, client, message) from one 802.11 data frame, or None."""
    if len(data) < 24:
        return None
    fc = data[0] | (data[1] << 8)
    if (fc >> 2) & 0x3 != 2:  # frame type must be Data
        return None
    to_ds = bool(fc & 0x0100)
    from_ds = bool(fc & 0x0200)
    subtype = (fc >> 4) & 0xF

    addr1, addr2, addr3 = data[4:10], data[10:16], data[16:22]
    offset = 24
    if to_ds and from_ds:  # 4-address WDS frame
        offset += 6
    if subtype & 0x08:  # QoS Data: 2-byte QoS Control field
        offset += 2
    if fc & 0x8000:  # Order bit set: 4-byte HT Control field
        offset += 4

    snap = data[offset : offset + 8]
    if len(snap) < 8 or snap[0] != 0xAA or snap[1] != 0xAA or snap[2] != 0x03:
        return None
    if (snap[6] << 8) | snap[7] != _ETHERTYPE_EAPOL:
        return None

    body = data[offset + 8 :]
    if len(body) < 4 or body[1] != _EAPOL_TYPE_KEY:
        return None
    keyframe = body[4:]
    if len(keyframe) < 3:
        return None
    key_info = (keyframe[1] << 8) | keyframe[2]
    msg = _classify(key_info)
    if msg is None:
        return None

    # Message 1 (AP -> STA) may carry the PMKID in its Key Data KDEs.
    pmkid = None
    if msg == 1 and len(keyframe) >= _KEY_DATA_OFFSET:
        o = _KEY_DATA_LEN_OFFSET
        kd_len = (keyframe[o] << 8) | keyframe[o + 1]
        key_data = keyframe[_KEY_DATA_OFFSET : _KEY_DATA_OFFSET + kd_len]
        pmkid = _extract_pmkid_from_keydata(key_data)

    if from_ds and not to_ds:
        bssid, client = addr2, addr1  # AP -> STA
    elif to_ds and not from_ds:
        bssid, client = addr1, addr2  # STA -> AP
    elif not to_ds and not from_ds:
        bssid, client = addr3, addr2  # IBSS: addr3 is the BSSID
    else:
        bssid, client = addr1, addr2  # WDS: best effort
    return _Frame(_mac(bssid), _mac(client), msg, pmkid)


def iter_dot11_frames(raw: bytes):
    """Yield each 802.11 MAC frame from a classic libpcap byte string."""
    if len(raw) < 24:
        raise EapolParseError("file too short to be a libpcap capture")
    magic = struct.unpack("<I", raw[:4])[0]
    if magic in _PCAP_MAGICS_LE:
        endian = "<"
    elif magic in _PCAP_MAGICS_BE:
        endian = ">"
    elif magic == _PCAPNG_MAGIC:
        raise EapolParseError("pcapng unsupported; capture classic .cap format")
    else:
        raise EapolParseError("not a libpcap capture file")

    linktype = struct.unpack(endian + "I", raw[20:24])[0]
    off, n = 24, len(raw)
    while off + 16 <= n:
        _ts, _tu, incl, _orig = struct.unpack(endian + "IIII", raw[off : off + 16])
        off += 16
        if incl == 0 or off + incl > n:
            break
        pkt = raw[off : off + incl]
        off += incl
        frame = _strip_link_header(linktype, pkt)
        if frame:
            yield frame


def parse_handshakes(raw: bytes) -> list[Handshake]:
    """Group every EAPOL-Key frame in the capture by (BSSID, client)."""
    pairs: dict[tuple[str, str], Handshake] = {}
    for frame in iter_dot11_frames(raw):
        parsed = _parse_dot11(frame)
        if parsed is None:
            continue
        key = (parsed.bssid, parsed.client)
        hs = pairs.get(key)
        if hs is None:
            hs = pairs[key] = Handshake(bssid=parsed.bssid, client=parsed.client)
        hs.messages.add(parsed.msg)
    return list(pairs.values())


def parse_pmkids(raw: bytes) -> list[Pmkid]:
    """Return every distinct PMKID (from EAPOL message 1) in the capture."""
    seen: dict[tuple[str, str], Pmkid] = {}
    for frame in iter_dot11_frames(raw):
        parsed = _parse_dot11(frame)
        if parsed is None or parsed.pmkid is None:
            continue
        key = (parsed.bssid, parsed.client)
        if key not in seen:
            seen[key] = Pmkid(
                bssid=parsed.bssid, client=parsed.client, pmkid=parsed.pmkid
            )
    return list(seen.values())


def read_handshakes(path: str | Path) -> list[Handshake]:
    """Parse handshakes from a .cap file on disk."""
    return parse_handshakes(Path(path).read_bytes())


def read_pmkids(path: str | Path) -> list[Pmkid]:
    """Parse PMKIDs from a .cap file on disk."""
    return parse_pmkids(Path(path).read_bytes())


def pmkids_for(path: str | Path, bssid: str) -> list[Pmkid]:
    """Return PMKIDs captured for a specific BSSID (case-insensitive)."""
    want = bssid.upper()
    return [p for p in read_pmkids(path) if p.bssid.upper() == want]


def handshakes_for(path: str | Path, bssid: str) -> list[Handshake]:
    """Return handshakes captured for a specific BSSID (case-insensitive)."""
    want = bssid.upper()
    return [hs for hs in read_handshakes(path) if hs.bssid.upper() == want]


def cap_has_handshake(path: str | Path, bssid: str | None = None) -> bool:
    """True when the capture holds a crackable handshake (optionally for bssid)."""
    want = bssid.upper() if bssid else None
    for hs in read_handshakes(path):
        if hs.complete and (want is None or hs.bssid.upper() == want):
            return True
    return False
