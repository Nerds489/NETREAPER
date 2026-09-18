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

# EAPOL-Key fixed fields before the MIC: descriptor(1)+info(2)+len(2)+replay(8)
# +nonce(32)+iv(16)+rsc(8)+id(8) = 77. The MIC length varies by AKM (16 bytes for
# WPA2-PSK, 24 for SHA-384/802.11r), so Key Data is located per candidate MIC
# length rather than a single fixed offset.
_MIC_OFFSET = 77
_MIC_LENGTHS = (16, 24)
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


def _pmkid_from_m1(keyframe: bytes) -> str | None:
    """Locate the Key Data (trying each MIC length) and extract any PMKID KDE."""
    for mic_len in _MIC_LENGTHS:
        kdl_off = _MIC_OFFSET + mic_len
        kd_off = kdl_off + 2
        if len(keyframe) < kd_off:
            continue
        kd_len = (keyframe[kdl_off] << 8) | keyframe[kdl_off + 1]
        # Key Data is the final field of an EAPOL-Key frame: a MIC-length guess
        # whose declared length does not consume the frame exactly is wrong, so
        # trailing bytes cannot be misread as a fabricated PMKID.
        if kd_off + kd_len != len(keyframe):
            continue
        pmkid = _extract_pmkid_from_keydata(keyframe[kd_off : kd_off + kd_len])
        if pmkid:
            return pmkid
    return None


# The 4-way handshake as a truth table rather than as control flow, because
# that is what it is. Each row is (ack, mic, install, secure) -> message, with
# None meaning the bit is not part of that message's signature. Read in order,
# first match wins, which is the order the original `if` ladder had.
_MESSAGE_SIGNATURES: tuple[tuple[tuple[bool | None, ...], int], ...] = (
    ((True, False, None, None), 1),   # M1: AP -> STA, carries ANonce
    ((False, True, False, False), 2),  # M2: STA -> AP, carries SNonce + MIC
    ((True, True, True, True), 3),     # M3: AP -> STA
    ((False, True, False, True), 4),   # M4: STA -> AP
)


def _classify(key_info: int) -> int | None:
    """Map an EAPOL-Key Key-Information field to a 4-way message number (1-4)."""
    if not key_info & _KI_PAIRWISE:
        return None  # group-key handshake, not the pairwise 4-way
    bits = (
        bool(key_info & _KI_ACK),
        bool(key_info & _KI_MIC),
        bool(key_info & _KI_INSTALL),
        bool(key_info & _KI_SECURE),
    )
    for signature, message in _MESSAGE_SIGNATURES:
        if all(w is None or w == b for w, b in zip(signature, bits, strict=True)):
            return message
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


def _dot11_header_length(fc: int) -> int:
    """Where the payload starts, given the Frame Control field.

    24 bytes of MAC header, plus the optional fields whose presence is encoded
    in fc: a fourth address on a WDS frame, QoS Control on a QoS subtype, and
    HT Control when the Order bit is set.
    """
    to_ds = bool(fc & 0x0100)
    from_ds = bool(fc & 0x0200)
    subtype = (fc >> 4) & 0xF

    offset = 24
    if to_ds and from_ds:  # 4-address WDS frame
        offset += 6
    if subtype & 0x08:  # QoS Data: 2-byte QoS Control field
        offset += 2
    if fc & 0x8000:  # Order bit set: 4-byte HT Control field
        offset += 4
    return offset


def _eapol_keyframe(data: bytes, offset: int) -> bytes | None:
    """The EAPOL-Key frame behind the SNAP header at ``offset``, or None."""
    snap = data[offset : offset + 8]
    if len(snap) < 8 or snap[0] != 0xAA or snap[1] != 0xAA or snap[2] != 0x03:
        return None
    if (snap[6] << 8) | snap[7] != _ETHERTYPE_EAPOL:
        return None

    body = data[offset + 8 :]
    if len(body) < 4 or body[1] != _EAPOL_TYPE_KEY:
        return None
    # Bound the EAPOL-Key frame by its declared body length (802.1X header bytes
    # 2-3) so a trailing FCS or other padding after Key Data is not treated as
    # frame content (which would otherwise defeat the PMKID exact-length check).
    pkt_len = (body[2] << 8) | body[3]
    bounded = body[4 : 4 + pkt_len] if 0 < pkt_len <= len(body) - 4 else body[4:]
    # A too-short declared length must not drop an otherwise-valid frame: fall back
    # to the unbounded body so key_info can still be read and the frame classified.
    keyframe = bounded if len(bounded) >= 3 else body[4:]
    return keyframe if len(keyframe) >= 3 else None


def _address_roles(fc: int, addr1: bytes, addr2: bytes, addr3: bytes):
    """Which of the three addresses is the AP and which is the station.

    The DS bits say who sent the frame in which direction, and that is the only
    thing that decides it. Getting this backwards silently attributes a
    handshake to the wrong BSSID.
    """
    to_ds = bool(fc & 0x0100)
    from_ds = bool(fc & 0x0200)
    if from_ds and not to_ds:
        return addr2, addr1  # AP -> STA
    if to_ds and not from_ds:
        return addr1, addr2  # STA -> AP
    if not to_ds and not from_ds:
        return addr3, addr2  # IBSS: addr3 is the BSSID
    return addr1, addr2  # WDS: best effort


def _parse_dot11(data: bytes) -> _Frame | None:
    """Extract (bssid, client, message) from one 802.11 data frame, or None."""
    if len(data) < 24:
        return None
    fc = data[0] | (data[1] << 8)
    if (fc >> 2) & 0x3 != 2:  # frame type must be Data
        return None

    keyframe = _eapol_keyframe(data, _dot11_header_length(fc))
    if keyframe is None:
        return None

    msg = _classify((keyframe[1] << 8) | keyframe[2])
    if msg is None:
        return None

    # Message 1 (AP -> STA) may carry the PMKID in its Key Data KDEs.
    pmkid = _pmkid_from_m1(keyframe) if msg == 1 else None

    bssid, client = _address_roles(fc, data[4:10], data[10:16], data[16:22])
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
        if off + incl > n:
            break  # truncated final record
        pkt = raw[off : off + incl]
        off += incl
        if incl == 0:
            continue  # empty record: skip it, do not end the whole parse
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
