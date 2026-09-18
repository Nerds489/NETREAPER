# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""The declared registry of external sources (#33).

Every entry states what the source IS, under what licence, and how it is
incorporated. Nothing here guesses: a licence is either verified against the
source's own LICENSE file or marked UNVERIFIED, and an UNVERIFIED licence blocks
vendoring by construction (see :func:`validate_registry`).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

UNVERIFIED = "UNVERIFIED"


class Kind(StrEnum):
    """What the source fundamentally is."""

    DATA = "data"  # consumable content: wordlists, ID databases
    TOOL = "tool"  # an executable we drive through the spawn seam
    REFERENCE = "reference"  # knowledge; documentation, never code


class Incorporation(StrEnum):
    """How it enters the project."""

    VENDORED = "vendored"  # copied into the tree; needs a compatible licence
    FETCHED = "fetched"  # downloaded on demand by the operator, never shipped
    WRAPPED = "wrapped"  # an external binary driven through ProcessRunner
    REFERENCED = "referenced"  # documented and linked; no code, no copy


@dataclass(frozen=True)
class ExternalSource:
    name: str
    url: str
    kind: Kind
    incorporation: Incorporation
    domain: str
    summary: str
    licence: str = UNVERIFIED
    # Set where the source's capability carries a risk that a scope gate does
    # not address. Presence of a safety_note forces REFERENCED.
    safety_note: str = ""
    provides: tuple[str, ...] = field(default_factory=tuple)

    @property
    def licence_verified(self) -> bool:
        return self.licence != UNVERIFIED

    @property
    def is_safety_restricted(self) -> bool:
        return bool(self.safety_note)


SOURCES: tuple[ExternalSource, ...] = (
    # ── automotive / CAN ────────────────────────────────────────────────────
    ExternalSource(
        name="awesome-automotive-can-id",
        url="https://github.com/iDoka/awesome-automotive-can-id",
        kind=Kind.REFERENCE,
        incorporation=Incorporation.REFERENCED,
        domain="automotive",
        licence="CC0-1.0",
        summary=(
            "An INDEX, not a dataset: 92 KB of README linking out to DBC, CSV "
            "and spreadsheet data held elsewhere. Verified: there is no dbc/ or "
            "csv/ directory. CC0 covers the list, NOT the third-party data it "
            "points at, which carries its own terms. For actual DBC data use "
            "commaai/opendbc (MIT)."
        ),
    ),
    ExternalSource(
        name="awesome-vehicle-security",
        url="https://github.com/jaredthecoder/awesome-vehicle-security",
        kind=Kind.REFERENCE,
        incorporation=Incorporation.REFERENCED,
        domain="automotive",
        licence="CC0-1.0",
        summary=(
            "Curated index of vehicle and IoT security research, tooling and "
            "talks. The scoping input for a CAN domain, nothing more."
        ),
    ),
    ExternalSource(
        name="oscc",
        url="https://github.com/PolySync/oscc",
        kind=Kind.REFERENCE,
        incorporation=Incorporation.REFERENCED,
        domain="automotive",
        licence="MIT (firmware/software) + CC BY-SA 4.0 (hardware)",
        summary=(
            "Open Source Car Control: a drive-by-wire retrofit whose firmware "
            "and boards actuate a real vehicle's steering, throttle and brakes. "
            "It makes a car controllable; it does not test one. Dormant since "
            "December 2019, 47 MB including hardware CAD. Incorporated for its "
            "protocol and interface documentation only. GitHub reports "
            "NOASSERTION because of the split licence, which matters for SBOM "
            "scanning."
        ),
        safety_note=(
            "ACTUATION, NOT ANALYSIS. This drives the physical controls of a "
            "moving vehicle. That is not an information-security capability and "
            "no authorisation tier makes it one: a scope gate cannot stop a car "
            "from hitting someone. NETREAPER documents how these interfaces "
            "work and does not implement control of them."
        ),
    ),
    # ── wireless (feeds the existing domain) ────────────────────────────────
    ExternalSource(
        name="wpa2-wordlists",
        url="https://github.com/kennyn510/wpa2-wordlists",
        kind=Kind.DATA,
        incorporation=Incorporation.FETCHED,
        domain="wifi",
        licence="CC0-1.0",
        summary=(
            "Real data, in-repo: nine directories of gzipped breach lists plus "
            "a prep script that filters to WPA2-valid 8-63 character "
            "candidates. Fetched, never vendored. CC0 covers the author's "
            "compilation, not the underlying breach material, and redistributing "
            "credential corpora in a wheel is a distribution-policy question "
            "regardless of licence. Fills a real gap: the code hardcodes "
            "/usr/share/wordlists/rockyou.txt in several places and the "
            "installer provisions nothing."
        ),
        provides=("wifi.wordlist",),
    ),
    # ── network / MITM (feeds the existing capability) ──────────────────────
    ExternalSource(
        name="MITM-cheatsheet",
        url="https://github.com/frostbits-security/MITM-cheatsheet",
        kind=Kind.REFERENCE,
        incorporation=Incorporation.REFERENCED,
        domain="network",
        licence="NONE (no LICENSE file; all rights reserved)",
        summary=(
            "Catalogue of ~25-30 MITM techniques across L2/L3/L4 and wireless, "
            "with mechanics, example commands and defences. Useful as a "
            "coverage checklist against the existing T4 tier. NO LICENCE AT "
            "ALL, so it may be linked and cited and must never be copied: "
            "default copyright means no reproduction or derivative works. "
            "Dormant since December 2021."
        ),
    ),
    # ── mobile ──────────────────────────────────────────────────────────────
    ExternalSource(
        name="idevicerestore",
        url="https://github.com/libimobiledevice/idevicerestore",
        kind=Kind.TOOL,
        incorporation=Incorporation.REFERENCED,
        domain="mobile",
        licence="LGPL-3.0",
        summary=(
            "Firmware restore/update for iOS, not an assessment tool. Its own "
            "README warns it can 'easily destroy your user data irreversibly'. "
            "The assessment-shaped pieces of the same project ARE wrapped: "
            "idevice_id and ideviceinfo enumerate and read. Maintained and "
            "distro-packaged, so the licence is clean; the scope is the problem."
        ),
        safety_note=(
            "FLASHING, NOT ASSESSMENT. Wrapping this would give the framework "
            "the ability to brick a client's device inside an authorised "
            "engagement, with no offsetting assessment value. The same applies "
            "to the Android equivalents (edl, mtkclient, Heimdall). Enumeration "
            "and property reads are implemented; restore and flash are not."
        ),
    ),
    ExternalSource(
        name="android-platform-tools",
        url="https://developer.android.com/tools/releases/platform-tools",
        kind=Kind.TOOL,
        incorporation=Incorporation.WRAPPED,
        domain="mobile",
        licence="Apache-2.0",
        summary=(
            "The Android counterpart asked for alongside idevicerestore: adb "
            "and fastboot. Device enumeration and property reads through the "
            "seam; nothing that modifies a device is wired."
        ),
        provides=("mobile.android_device_info",),
    ),
    # ── what the automotive domain actually stands on ───────────────────────
    # None of these were in the supplied list; they are what the supplied list
    # points at once you follow it. Recorded here so the domain's real
    # dependencies are declared rather than implied.
    ExternalSource(
        name="can-utils",
        url="https://github.com/linux-can/can-utils",
        kind=Kind.TOOL,
        incorporation=Incorporation.WRAPPED,
        domain="automotive",
        licence="BSD-3-Clause + GPL-2.0-only (mixed)",
        summary=(
            "SocketCAN userspace tools. candump and cansniffer are driven "
            "through the seam; cansend, cangen and canplayer transmit and are "
            "refused by name in netreaper.tools.canutils. The GPL-2.0-only "
            "parts are NOT upward-compatible with GPL-3.0, so this must never "
            "be vendored. Spawning it is unaffected, which the existing "
            "architecture already gets right by accident of design."
        ),
        provides=("automotive.can_capture",),
    ),
    ExternalSource(
        name="caringcaribou",
        url="https://github.com/CaringCaribou/caringcaribou",
        kind=Kind.TOOL,
        incorporation=Incorporation.REFERENCED,
        domain="automotive",
        licence="GPL-3.0",
        summary=(
            "The actual pentest-shaped CAN tool: ECU discovery, UDS, XCP. "
            "Licence-identical to NETREAPER and actively maintained, so this is "
            "what an automotive domain should wrap rather than CBM. Held as "
            "REFERENCED until the two prerequisites below are resolved."
        ),
    ),
    ExternalSource(
        name="opendbc",
        url="https://github.com/commaai/opendbc",
        kind=Kind.DATA,
        incorporation=Incorporation.FETCHED,
        domain="automotive",
        licence="MIT",
        summary=(
            "Where the real DBC signal data lives, which "
            "awesome-automotive-can-id only indexes. MIT, actively pushed, and "
            "the input netreaper.automotive.decode is built to consume."
        ),
        provides=("automotive.can_id_database",),
    ),
    ExternalSource(
        name="libimobiledevice",
        url="https://github.com/libimobiledevice/libimobiledevice",
        kind=Kind.TOOL,
        incorporation=Incorporation.WRAPPED,
        domain="mobile",
        licence="LGPL-2.1-or-later",
        summary=(
            "The assessment-shaped half of the iOS toolchain: idevice_id and "
            "ideviceinfo enumerate devices and read properties. Spawned, never "
            "linked, so the LGPL is not a constraint here."
        ),
        provides=("mobile.ios_device_info",),
    ),
    # ── pending identification ──────────────────────────────────────────────
    ExternalSource(
        name="CBM",
        url="https://github.com/UnaPibaGeek/CBM",
        kind=Kind.REFERENCE,
        incorporation=Incorporation.REFERENCED,
        domain="automotive",
        licence="NONE (no LICENSE file; all rights reserved)",
        summary=(
            "Car Backdoor Maker: a Qt5 desktop GUI that authors attack "
            "templates and loads them into 'The Bicho', a PIC18F2580 + SIM800L "
            "hardware CAN implant commanded by SMS, with payloads triggerable "
            "on GPS position, speed, fuel level or an observed CAN frame. By "
            "Berta and Caracciolo. Dormant since October 2018. Its value here "
            "is conceptual: it is the clearest published taxonomy of CAN "
            "payload triggers, which a threat model should cover. Cite the "
            "conference material, not the repository."
        ),
        safety_note=(
            "IMPLANT TOOLING, AND UNLICENSED. Three independent blockers, any "
            "one sufficient: no licence at all, so it cannot legally be "
            "vendored; it requires a bespoke SMS-commanded backdoor to be "
            "physically installed in the target vehicle, which is persistence "
            "rather than assessment and sits badly with a consent-gated "
            "framework; and it is a GUI that programs a microcontroller, so "
            "there is no CLI for the spawn seam to wrap."
        ),
    ),
)


def get_source(name: str) -> ExternalSource | None:
    for s in SOURCES:
        if s.name == name:
            return s
    return None


def by_domain(domain: str) -> tuple[ExternalSource, ...]:
    return tuple(s for s in SOURCES if s.domain == domain)


def fetchable() -> tuple[ExternalSource, ...]:
    """Sources an operator can pull on demand. Never shipped in the package."""
    return tuple(s for s in SOURCES if s.incorporation is Incorporation.FETCHED)


def unverified_licences() -> tuple[ExternalSource, ...]:
    return tuple(s for s in SOURCES if not s.licence_verified)


def validate_registry(sources: tuple[ExternalSource, ...] = SOURCES) -> list[str]:
    """Return the registry's own rule violations. Empty means it is coherent.

    Two rules, both learned the hard way elsewhere in this codebase: a control
    that is documented but unenforced is not a control.
    """
    problems: list[str] = []
    for s in sources:
        if s.incorporation is Incorporation.VENDORED and not s.licence_verified:
            problems.append(
                f"{s.name}: cannot be VENDORED with an {UNVERIFIED} licence"
            )
        if s.is_safety_restricted and s.incorporation is not Incorporation.REFERENCED:
            problems.append(
                f"{s.name}: carries a safety_note, so it must be REFERENCED "
                f"(is {s.incorporation.value})"
            )
        if s.kind is Kind.REFERENCE and s.provides:
            problems.append(
                f"{s.name}: reference material must not declare capabilities"
            )
    names = [s.name for s in sources]
    dupes = {n for n in names if names.count(n) > 1}
    problems.extend(f"duplicate source name: {n}" for n in sorted(dupes))
    return problems
