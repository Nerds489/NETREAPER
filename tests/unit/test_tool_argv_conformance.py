# SPDX-License-Identifier: GPL-3.0-or-later
"""Every constructed command line must be one the real binary would accept.

Six argv defects shipped at once, and all but one of them meant the command
exited 1 before sending a single frame:

  --arpreplay -a BSSID    aireplay's getnet(filter=1) reads f_bssid (-b), not
                          r_bssid (-a), so this printed "Please specify at least
                          a BSSID (-b) or an ESSID (-e)" and exited. It was the
                          DEFAULT WEP injection strategy.
  --caffe-latte -N 10     there is no -N in aireplay-ng. Not in the short
                          options, not in long_options[], no case 'N'.
  --cfrag 10              --cfrag is declared no_argument, so the "10" became a
                          second positional and tripped argc - optind != 1.
  --fakeauth (no -e)      mandatory, and every caller defaulted essid to "".
  iw wlan0mon set channel without the `dev` command group. The only one of
                          eight iw call sites in the tree missing it.
  reaver -K 1             -K is no_argument; the stray 1 was ignored.

WHY THE EXISTING TESTS DID NOT CATCH THEM. tests/unit/test_wep_injection_and_argv
asks whether each strategy reaches its own primitive, which is a dispatch
question. tests/unit/test_wireless_host_action_seam asks whether a call routes
through the gated seam, and pinned `iw wlan0mon set channel 6` verbatim on the
way past, so it locked the bug in rather than finding it. Neither asks the
question the binary asks: are these flags real, and do they take what they were
given?

So that question is asked here, against a declared spec. The spec is the part
worth maintaining: when a tool's flags are written down, a typo becomes a test
failure instead of an exit code nobody sees until they are standing next to the
target.
"""
from __future__ import annotations

import pytest

# For each binary: the flags it accepts, and whether each consumes the next
# argument. Sourced from the tools' own option parsing (aireplay-ng.c's
# long_options[] and short-option string; reaver-wps-fork-t6x's argsparser.c;
# iw's command table), not from memory of how they are usually typed.
#
# VALUE means "takes the next argv element". FLAG means "takes nothing".
FLAG = False
VALUE = True

AIREPLAY_FLAGS: dict[str, bool] = {
    # attack selectors: only deauth and fakeauth carry a value
    "--deauth": VALUE, "-0": VALUE,
    "--fakeauth": VALUE, "-1": VALUE,
    "--interactive": FLAG, "-2": FLAG,
    "--arpreplay": FLAG, "-3": FLAG,
    "--chopchop": FLAG, "-4": FLAG,
    "--fragment": FLAG, "-5": FLAG,
    "--caffe-latte": FLAG, "-6": FLAG,
    "--cfrag": FLAG, "-7": FLAG,
    "--migmode": FLAG, "-8": FLAG,
    "--test": FLAG, "-9": FLAG,
    # targeting and tuning
    "-a": VALUE, "-b": VALUE, "-c": VALUE, "-e": VALUE, "-h": VALUE,
    "-x": VALUE, "-q": VALUE, "-Q": VALUE, "-y": VALUE, "-j": FLAG,
    "-D": FLAG, "-F": FLAG, "-R": FLAG,
    "--ignore-negative-one": FLAG,
    # Source option: extract packets from this pcap. It is how a forged ARP
    # gets replayed, so the WEP forge path depends on it being real.
    "-r": VALUE,
}

# packetforge-ng. Mode selectors take no argument; everything else that
# configures the frame takes one. Sourced from packetforge-ng's own usage
# output, not from how it is usually typed.
PACKETFORGE_FLAGS: dict[str, bool] = {
    # modes
    "--arp": FLAG, "-0": FLAG,
    "--udp": FLAG, "-1": FLAG,
    "--tcp": FLAG, "-2": FLAG,
    "--custom": FLAG, "-3": FLAG,
    "--null": FLAG, "-4": FLAG,
    # frame construction
    "-p": VALUE, "-a": VALUE, "-c": VALUE, "-h": VALUE,
    "-k": VALUE, "-l": VALUE, "-t": VALUE, "-w": VALUE,
    "-s": VALUE, "-n": VALUE,
    "-j": FLAG, "-o": FLAG, "-e": FLAG,
    # sources
    "-y": VALUE, "-r": VALUE,
}

REAVER_FLAGS: dict[str, bool] = {
    "-i": VALUE, "-b": VALUE, "-e": VALUE, "-c": VALUE, "-m": VALUE,
    "-d": VALUE, "-t": VALUE, "-T": VALUE, "-r": VALUE, "-p": VALUE,
    "-s": VALUE, "-C": VALUE, "-l": VALUE, "-o": VALUE,
    "-K": FLAG, "-Z": FLAG, "-a": FLAG, "-S": FLAG, "-N": FLAG,
    "-f": FLAG, "-g": VALUE, "-w": FLAG, "-n": FLAG, "-L": FLAG,
    "-v": FLAG, "-vv": FLAG, "-vvv": FLAG, "-q": FLAG,
}

# hashcat. Sourced from its own usage output. The attack-mode and hash-type
# selectors take a number; the potfile and status switches take nothing.
HASHCAT_FLAGS: dict[str, bool] = {
    "-m": VALUE, "-a": VALUE,
    "-o": VALUE, "--outfile": VALUE, "--outfile-format": VALUE,
    "-w": VALUE, "--workload-profile": VALUE,
    "-d": VALUE, "--backend-devices": VALUE,
    "--session": VALUE, "--status-timer": VALUE,
    "--potfile-disable": FLAG, "--quiet": FLAG, "--increment": FLAG,
    "--show": FLAG, "--restore": FLAG, "--status": FLAG, "--force": FLAG,
}

SPECS: dict[str, dict[str, bool]] = {
    "aireplay-ng": AIREPLAY_FLAGS,
    "reaver": REAVER_FLAGS,
    "packetforge-ng": PACKETFORGE_FLAGS,
    "hashcat": HASHCAT_FLAGS,
}


def check_argv(argv: list[str], *, trailing_positionals: int = 1) -> list[str]:
    """Return the problems with ``argv``, or an empty list.

    ``trailing_positionals`` is how many bare arguments the tool expects at the
    end (aireplay-ng and reaver both take the interface, though reaver takes it
    via -i, so its count is 0).
    """
    binary = argv[0]
    spec = SPECS[binary]
    problems: list[str] = []
    positionals: list[str] = []

    i = 1
    while i < len(argv):
        arg = argv[i]
        if arg.startswith("-"):
            if arg not in spec:
                problems.append(f"{arg!r} is not a flag {binary} accepts")
                i += 1
                continue
            if spec[arg] is VALUE:
                if i + 1 >= len(argv) or argv[i + 1].startswith("-"):
                    problems.append(f"{arg!r} takes a value and was given none")
                    i += 1
                else:
                    i += 2
            else:
                i += 1
        else:
            positionals.append(arg)
            i += 1

    if len(positionals) != trailing_positionals:
        problems.append(
            f"expected {trailing_positionals} positional argument(s), got "
            f"{len(positionals)}: {positionals}. A value passed to a flag that "
            f"takes none lands here, which is how --cfrag 10 and -N 10 failed."
        )
    return problems


# ── the spec itself must be sane ─────────────────────────────────────────────


def test_the_checker_rejects_each_of_the_six_real_defects():
    """Negative control. A checker that passes everything proves nothing."""
    broken = {
        "unknown flag (-N)": ["aireplay-ng", "--caffe-latte", "-N", "10", "wlan0"],
        "value on a no-arg flag (--cfrag)": ["aireplay-ng", "--cfrag", "10", "wlan0"],
        "reaver -K with a value": ["reaver", "-i", "wlan0", "-b", "AA", "-K", "1"],
    }
    for name, argv in broken.items():
        tp = 1 if argv[0] == "aireplay-ng" else 0
        assert check_argv(argv, trailing_positionals=tp), f"{name} was not caught"


def test_the_checker_accepts_a_known_good_command():
    assert not check_argv(
        ["aireplay-ng", "--arpreplay", "-b", "AA:BB:CC:DD:EE:FF", "-h", "11:22:33:44:55:66", "wlan0mon"]
    )


# ── the real builders ────────────────────────────────────────────────────────


def _aireplay_argv(attack, **options) -> list[str]:
    """The real builder, with the binary name prepended as base.py does.

    build_command() returns the arguments only; tools/base.py puts the resolved
    tool path in front. The checker needs the whole line, so it is assembled the
    same way here.
    """
    from netreaper.tools.aireplay import AireplayTool

    options.setdefault("bssid", "AA:BB:CC:DD:EE:FF")
    options.setdefault("source", "11:22:33:44:55:66")
    # Optional parameters are supplied deliberately. Most of the builders guard
    # their extras behind `if count:` / `if client:`, so a helper that passes
    # only the mandatory fields never enters those branches and cannot see what
    # they emit. That is exactly how a restored `-N <count>` slipped past this
    # file on its first run: the flag was only added when count was set, and
    # nothing set it.
    options.setdefault("count", 10)
    options.setdefault("client", "99:88:77:66:55:44")
    options["attack"] = attack
    return ["aireplay-ng", *AireplayTool().build_command("wlan0mon", options)]


def test_every_aireplay_attack_builds_a_command_aireplay_would_accept():
    from netreaper.tools.aireplay import AttackMode

    failures: list[str] = []
    for attack in AttackMode:
        opts = {}
        if attack is AttackMode.FAKEAUTH:
            opts["essid"] = "CorpWifi"  # mandatory; refused without it
        try:
            argv = _aireplay_argv(attack, **opts)
        except ValueError as e:
            failures.append(f"{attack.name}: builder refused: {e}")
            continue
        for problem in check_argv(argv):
            failures.append(f"{attack.name}: {problem}\n    {' '.join(argv)}")
    assert not failures, "aireplay argv defects:\n  " + "\n  ".join(failures)


def test_the_capture_filter_attacks_name_the_ap_with_dash_b():
    """-a and -b are not interchangeable: getnet() reads a different field."""
    from netreaper.tools.aireplay import AttackMode

    for attack in (AttackMode.ARPREPLAY, AttackMode.CAFFE_LATTE,
                   AttackMode.CHOPCHOP, AttackMode.FRAGMENT):
        argv = _aireplay_argv(attack)
        assert "-b" in argv, f"{attack.name} must filter on -b, got: {' '.join(argv)}"
        assert "-a" not in argv, f"{attack.name} used -a: {' '.join(argv)}"


def test_the_transmitting_attacks_still_name_the_ap_with_dash_a():
    """The fix must not invert the ones that were already right."""
    from netreaper.tools.aireplay import AttackMode

    for attack, opts in ((AttackMode.DEAUTH, {}), (AttackMode.FAKEAUTH, {"essid": "X"})):
        argv = _aireplay_argv(attack, **opts)
        assert "-a" in argv, f"{attack.name} lost -a: {' '.join(argv)}"


def test_fakeauth_refuses_to_build_without_an_essid():
    from netreaper.tools.aireplay import AttackMode

    with pytest.raises(ValueError, match="ESSID"):
        _aireplay_argv(AttackMode.FAKEAUTH)


def test_reaver_pixiedust_passes_a_bare_switch():
    from netreaper.tools.reaver import ReaverTool

    argv = [
        "reaver",
        *ReaverTool().build_command(
            "AA:BB:CC:DD:EE:FF", {"interface": "wlan0mon", "pixiedust": True}
        ),
    ]
    assert "-K" in argv
    assert argv[argv.index("-K") + 1 :] == [] or argv[argv.index("-K") + 1].startswith("-"), (
        f"-K takes no argument, got: {' '.join(argv)}"
    )
    assert not check_argv(argv, trailing_positionals=0)


# ── iw, which is not flag-shaped but has the same failure mode ───────────────


def test_every_iw_invocation_uses_a_real_command_group():
    """`iw <iface> set channel N` is not iw syntax; `iw dev <iface> ...` is."""
    import ast
    from pathlib import Path

    src = Path(__file__).resolve().parents[2] / "src" / "netreaper"
    groups = {"dev", "phy", "reg", "list", "help", "event"}
    offenders = []
    for path in src.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.List) or not node.elts:
                continue
            first = node.elts[0]
            if not (isinstance(first, ast.Constant) and first.value == "iw"):
                continue
            if len(node.elts) < 2:
                continue
            second = node.elts[1]
            if isinstance(second, ast.Constant) and second.value in groups:
                continue
            if isinstance(second, ast.Constant):
                offenders.append(
                    f"{path.relative_to(src)}:{node.lineno}: iw {second.value!r}"
                )
            else:
                # a variable in the command-group slot is an interface name
                offenders.append(
                    f"{path.relative_to(src)}:{node.lineno}: iw <variable> "
                    f"(missing the 'dev' command group?)"
                )
    assert not offenders, (
        "iw invocation(s) with no command group; iw parses the second word as a "
        "command, not an interface:\n  " + "\n  ".join(offenders)
    )


# ── packetforge-ng, and the replay leg that consumes what it writes ──────────


def test_the_forge_builds_a_command_packetforge_would_accept():
    """packetforge-ng takes no positional arguments: everything is a flag."""
    from netreaper.tools.packetforge import PacketforgeTool

    argv = [
        "packetforge-ng",
        *PacketforgeTool().build_command(
            "/tmp/replay_dec.xor",
            {
                "bssid": "AA:BB:CC:DD:EE:FF",
                "source_mac": "11:22:33:44:55:66",
                "dest_mac": "FF:FF:FF:FF:FF:FF",
                "output": "/tmp/arp-request.cap",
            },
        ),
    ]
    problems = check_argv(argv, trailing_positionals=0)
    assert not problems, "packetforge argv defects:\n  " + "\n  ".join(problems) + f"\n  {' '.join(argv)}"


def test_replaying_a_forged_frame_builds_a_command_aireplay_would_accept():
    """The last leg of the forge chain. -r must be real and must take a value."""
    argv = _aireplay_argv(
        __import__("netreaper.tools.aireplay", fromlist=["AttackMode"]).AttackMode.INTERACTIVE,
        read_file="/tmp/arp-request.cap",
    )
    problems = check_argv(argv)
    assert not problems, "\n  ".join(problems) + f"\n  {' '.join(argv)}"
    assert argv.count("-r") == 1, argv


# ── hashcat ──────────────────────────────────────────────────────────────────


def _hashcat_argv(**options) -> list[str]:
    from netreaper.tools.hashcat import HashcatTool

    options.setdefault("hash_mode", 22000)
    return ["hashcat", *HashcatTool().build_command("hashes.22000", options)]


def test_a_straight_crack_builds_a_command_hashcat_would_accept():
    """hashfile + dictionary is two trailing operands."""
    argv = _hashcat_argv(attack_mode=0, wordlist="/usr/share/wordlists/rockyou.txt")
    problems = check_argv(argv, trailing_positionals=2)
    assert not problems, "\n  ".join(problems) + f"\n  {' '.join(argv)}"


def test_a_hybrid_crack_carries_three_operands():
    """Mode 6 is hashfile + dictionary + mask."""
    argv = _hashcat_argv(attack_mode=6, wordlist="words.txt", mask="?d?d")
    problems = check_argv(argv, trailing_positionals=3)
    assert not problems, "\n  ".join(problems) + f"\n  {' '.join(argv)}"


def test_show_carries_only_the_hash_file():
    argv = _hashcat_argv(show=True)
    problems = check_argv(argv, trailing_positionals=1)
    assert not problems, "\n  ".join(problems) + f"\n  {' '.join(argv)}"
