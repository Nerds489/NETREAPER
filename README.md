<div align="center">

```
    ███╗   ██╗███████╗████████╗██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗ 
    ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
    ██╔██╗ ██║█████╗     ██║   ██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝
    ██║╚██╗██║██╔══╝     ██║   ██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
    ██║ ╚████║███████╗   ██║   ██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║
    ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝

                 Some tools scan. Some tools attack. I do both.

```

[![Version](https://img.shields.io/badge/version-12.0.0-ff0040?style=for-the-badge&logo=github&logoColor=white)](https://github.com/Nerds489/NETREAPER/releases)
[![License](https://img.shields.io/badge/license-GPLv3-blue?style=for-the-badge)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)](https://kernel.org)

**Offensive security framework** • **102 tools** • **Deny by default** • **Audited**

[Install](#installation) • [The engagement](#the-engagement) • [Commands](#commands) • [Tools](#tool-catalogue)

</div>

---

## What is NETREAPER?

NETREAPER plans the chain for you. Name a goal and an interface, and it works out which
tools are needed, in what order, and runs them behind a scope gate that logs every step to
a hash chain.

```bash
# By hand
airmon-ng check kill
airmon-ng start wlan0
airodump-ng wlan0mon                                     # wait, watch, copy the BSSID
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF wlan0mon      # wait again, find a client
aireplay-ng --deauth 0 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon

# NETREAPER
netreaper wifi auto -i wlan0mon --run
```

It knows 102 tools across nine categories, drives 14 of them through native adapters that
parse their output rather than shelling out and hoping, and refuses to touch anything you
have not put in scope.

Two things it deliberately does not do. It does not choose your adapter or bring up monitor
mode behind your back: every command takes its interface by name. And it never prompts you
mid-run for permission, because a prompt at three in the morning is not consent. Everything
dangerous is authorised up front or refused.

---

## The engagement

NETREAPER is deny by default. With no active engagement, every targeted action fails
closed. This is the part of the tool most worth understanding before you use it.

```bash
sudo netreaper engage start \
    --operator "your name" --ref "ROE-001" \
    --essid "YourNetwork" --bssid AA:BB:CC:DD:EE:FF \
    --max-tier mitm --hours 8 \
    --confirm-tier single_target --confirm-tier broadcast \
    --confirm-tier mitm --accept-interception
```

**Scope** is what you may touch: `--cidr`, `--bssid`, `--essid` and `--hostname` put things
in, `--deny` carves them back out, and anything unlisted is refused. Protected and reserved
address ranges are refused outright, in bare and CIDR notation both.

**Tiers** are blast radius. Every gated action declares one.

| Tier | Value | What it covers |
|:--|:--|:--|
| `passive` | 0 | Read-only recon. No packets reach the target |
| `active_scan` | 1 | Scans and probes against a named target |
| `single_target` | 2 | One client or AP, such as a directed deauth |
| `broadcast` | 3 | Mass or broadcast traffic: mdk4 amok, beacon floods, DoS |
| `mitm` | 4 | Evil twin, MITM, traffic interception |

**A ceiling is not a confirmation, and this trips people up.** `--max-tier` says what this
engagement *may* reach. `--confirm-tier` says you meant it. Anything at `single_target` or
above needs both. `mitm` additionally needs `--accept-interception`, which records an
acknowledgement that you are about to intercept third-party traffic. `broadcast` can never
be confirmed mid-run.

**Engagements expire.** `--hours` defaults to 12 and is capped at 48. `netreaper engage
status` shows the current scope, ceiling and expiry; `netreaper engage end` revokes it.

**Everything is logged.** Every spawn appends to a hash-chained trail at
`~/.netreaper/logs/audit.jsonl`, mode `0600`, recording the outcome as one of `denied`,
`dry-run`, `executed` or `spawn-error`. A refusal is written before the exception is
raised, so a denial leaves a record too. Credentials are stripped at the sink, including
ones a tool announces itself, such as aircrack-ng's `KEY FOUND!`. A companion anchor file
records the chain length and head, because a prefix of a valid chain is also a valid
chain, and truncation would otherwise be invisible.

Be clear about what that is worth: the chain and the engagement's consent hash are both
unkeyed and on the same disk as the thing they attest. They make casual editing and
accidental loss obvious. They do not stop someone with write access who is willing to
recompute two files, and the source says so in as many words.

---

## Installation

```bash
git clone https://github.com/Nerds489/NETREAPER.git
cd NETREAPER
pip install .            # or, isolated:  pipx install .
```

```bash
sudo bin/netreaper-install all        # the security tools themselves
```

`pip install .` gives you the `netreaper` command. The tools it drives are separate, which
is what the installer is for. `netreaper status` tells you which of them are present, and
`bin/netreaper-install --dry-run all` shows what would be fetched and how, without root and
without touching anything.

---

## Quick start

```bash
# 1. Authorise a scope. Without one, every targeted action is denied.
sudo netreaper engage start --operator "your name" --ref "ROE-001" \
    --essid "YourNetwork" --bssid AA:BB:CC:DD:EE:FF --hours 8 \
    --max-tier single_target --confirm-tier single_target

# 2. Work. Name the interface; NETREAPER resolves the rest.
sudo netreaper wifi monitor enable wlan0
sudo netreaper wifi scan wlan0mon
sudo netreaper wifi handshake wlan0mon AA:BB:CC:DD:EE:FF 6
sudo netreaper scan 192.168.1.0/24

# 3. Revoke when you are done.
sudo netreaper engage end
```

---

## Planning

`wifi plan` resolves a goal into a chain of capabilities and prints it. `wifi auto` does
the same and then runs it. Both work backwards from what you want to what you have.

```bash
netreaper wifi plan wifi.password                    # what would it take?
netreaper wifi plan wifi.password --have wifi.handshake   # given I already have this
netreaper wifi auto -i wlan0mon                      # preview the chain
netreaper wifi auto -i wlan0mon --run                # run it
netreaper wifi auto -i wlan0mon -g wifi.handshake --run   # a different goal
```

`wifi auto` is a dry run unless you pass `--run`. Every step of a resolved chain goes
through the same scope gate and the same audit trail as a command you typed yourself.
Nothing in a chain is exempt, and a chain cannot reach a tier the engagement has not
confirmed.

---

## Commands

### Wireless

```bash
netreaper wifi monitor enable wlan0        # enable, disable or status
netreaper wifi scan wlan0mon               # find APs and clients; -t sets the window
netreaper wifi handshake wlan0mon AA:BB:CC:DD:EE:FF 6
                                           # WPA/WPA2 capture; -d deauth frames,
                                           # -c targets one client, -a capture rounds
netreaper wifi pmkid wlan0mon AA:BB:CC:DD:EE:FF 6
                                           # clientless PMKID, emits a hashcat 22000 hash
netreaper wifi wps AA:BB:CC:DD:EE:FF -i wlan0mon -c 6
                                           # pixie-dust then PIN list; --compute for
                                           # offline PIN candidates only
netreaper wifi wep wlan0mon AA:BB:CC:DD:EE:FF 6 --injection chopchop
                                           # arpreplay (default), chopchop, fragment,
                                           # caffe_latte, cfrag, interactive
netreaper wifi crack <capture.cap> <bssid> <wordlist>
                                           # offline, aircrack-ng
```

Rogue APs and interception. All of these sit at `mitm`, so they need the tier confirmed
and `--accept-interception` on the engagement.

```bash
netreaper wifi eviltwin wlan0 "YourNetwork" 6          # rogue AP; Ctrl-C tears it down
netreaper wifi enterprise wlan0 "CorpWiFi" 6           # rogue WPA-Enterprise, hashcat 5500
netreaper wifi downgrade wlan0 "YourNetwork" 6         # WPA2 twin of a WPA3 transition AP
netreaper wifi arpspoof wlan0 192.168.1.1 192.168.1.50 # bidirectional ARP-spoof MITM
```

Reconnaissance and evasion.

```bash
netreaper wifi wpa3 wlan0mon AA:BB:CC:DD:EE:FF      # classify WPA3/SAE, OWE, Dragonblood
netreaper wifi hidden wlan0mon AA:BB:CC:DD:EE:FF 6  # reveal a cloaked ESSID
netreaper wifi mac-random wlan0 --vendor apple      # randomise the adapter MAC
netreaper wifi mac-clone wlan0 AA:BB:CC:DD:EE:FF 6  # clone an AP's BSSID and channel
```

### Network

```bash
netreaper scan 192.168.1.0/24              # target is positional; -t is --type
netreaper scan 10.0.0.1 --type full        # quick, standard (default) or full
netreaper portscan 10.0.0.1 -p 1-1024      # fast sweep via masscan
```

### Web, credentials and OSINT

```bash
netreaper web dirs https://example.com            # directory discovery (gobuster)
netreaper web fingerprint https://example.com     # identify technologies (whatweb)
netreaper creds attack 10.0.0.1 -s ssh -l root -P rockyou.txt
                                                  # ssh, ftp, smb, rdp or mysql (hydra)
netreaper osint subdomains example.com            # passive enumeration (subfinder)
```

### Automotive

```bash
netreaper can interfaces                   # list SocketCAN interfaces
netreaper can dump vcan0 -s 30             # read and decode; -n stops after N frames
```

Read-only by design. The CAN module drives `candump`, `cansniffer` and `cantools`, and
refuses `cansend`, `cangen`, `canplayer` and `canfdtest` by name. It cannot transmit.

### System

```bash
netreaper status                           # system info and tool availability
netreaper engage status                    # the active authorisation
netreaper config show                      # show, get <key> or set <key> <value>
netreaper plugin list                      # loaded plugins
netreaper resources list                   # external sources, how used, licence
netreaper --help                           # everything
netreaper --version
```

Per-command options live in each command's `--help`. There are no global `--dry-run`,
`--quiet`, `--verbose` or `--target` flags.

---

## Interactive mode

```bash
netreaper            # no arguments starts the TUI
netreaper tui        # the same call, explicitly
```

A Textual terminal UI. Five screens ship: **Traffic Analysis**, **Credential Attacks**,
**Exploitation**, **Settings** and **Help**. Everything else lives on the CLI, and the
main menu says so rather than pretending otherwise: pick an item with no screen and it
names the command that does the job.

`Ctrl+P` opens the command palette. `?` opens help, `Ctrl+Q` quits, and `j`/`k` move on
the main menu.

The wireless and scanning work is CLI-only by design. There is a great deal of it, and
`netreaper wifi --help` is a better interface for seventeen subcommands than a menu would
be.

---

## Tool catalogue

102 tools across nine categories. NETREAPER can detect, install and report on every one.
The 14 marked with an asterisk it also drives through a native adapter, which means it
parses their output and feeds the result into the next step rather than printing it and
leaving you to read.

**Wireless** (18)  
`aircrack-ng` `airodump-ng`* `aireplay-ng`* `packetforge-ng`* `airmon-ng` `hostapd` `dnsmasq` `reaver`* `bully` `wash` `wifite` `hcxdumptool` `hcxpcapngtool` `mdk4` `fern-wifi-cracker` `kismet` `iw` `macchanger`

**Scanning** (11)  
`nmap`* `masscan`* `rustscan` `netdiscover` `arp-scan` `unicornscan` `nbtscan` `enum4linux` `enum4linux-ng` `smbclient` `onesixtyone`

**Credentials** (11)  
`hashcat`* `john`* `hydra`* `medusa` `ncrack` `cewl` `crunch` `ophcrack` `mimikatz` `responder` `secretsdump.py`

**OSINT** (13)  
`subfinder`* `theHarvester` `whois` `dnsrecon` `dnsenum` `sublist3r` `amass` `maltego` `spiderfoot` `shodan` `recon-ng` `exiftool` `metagoofil`

**Recon** (12)  
`nikto`* `whatweb`* `dirb` `gobuster`* `feroxbuster` `ffuf` `wfuzz` `wpscan` `joomscan` `wafw00f` `sslyze` `sslscan`

**Traffic** (12)  
`tcpdump` `tshark` `wireshark` `ettercap` `bettercap` `arpspoof` `mitmproxy` `dnsspoof` `sslstrip` `scapy` `netcat` `socat`

**Exploit** (10)  
`msfconsole` `searchsploit` `sqlmap`* `nuclei` `commix` `beef-xss` `evil-winrm` `crackmapexec` `empire` `covenant`

**Stress** (5)  
`hping3` `iperf3` `slowloris` `siege` `ab`

**Utility** (10)  
`curl` `wget` `git` `python3` `pip3` `proxychains` `tor` `openvpn` `tmux` `screen`

`netreaper status` reports which of them are present on this machine.

---

## Tool installer

`bin/netreaper-install` installs the tools above across nine categories: `scanning`,
`wireless`, `web`, `exploit`, `osint`, `creds`, `traffic`, `stress`, `utils`. It also
takes `all`, `essentials`, `status` and `menu`, and honours `--dry-run`, `--verbose`,
`--force`, `--offline` and `--no-verify`.

It works out your package manager and falls back through a chain: the native manager
(apt, dnf, yum, pacman, zypper, apk, xbps, emerge, nix, eopkg, rpm-ostree), then AUR,
pip, go, cargo, a GitHub release, gem, snap and flatpak. Distro families it detects are
Debian, Red Hat, Arch, SUSE, Alpine, Void, Gentoo, NixOS and Solus, including immutable
systems and WSL.

```bash
bin/netreaper-install status               # what is present, by category (no root)
sudo bin/netreaper-install all             # everything
sudo bin/netreaper-install essentials      # the short list
sudo bin/netreaper-install wireless        # one category
bin/netreaper-install --dry-run all        # preview; no root, writes nothing
```

`--dry-run` needs no privileges and reports the method it would use for each tool, so you
can see what a real run would do before committing to it.

---

## Configuration

```bash
netreaper config show                      # the whole tree as JSON
netreaper config get logging.level         # one dotted key
netreaper config set <key> <value>         # e.g. logging.level 10
```

Settings are nested, and `get`/`set` take the dotted path.

`set` validates before it writes. A key outside the schema is refused with the nearest
match suggested, a value of the wrong type is refused with the reason, and in both cases
the file on disk is left exactly as it was. Log levels are integers: 10 debug, 20 info,
30 warning, 40 error.

| Section | Keys |
|:--|:--|
| `database` | `path`, `wal_mode`, `busy_timeout` |
| `logging` | `level`, `file_logging`, `log_dir`, `max_file_size`, `backup_count` |
| `wireless` | `monitor_interface_prefix`, `deauth_count`, `deauth_delay`, `channel_hop_interval`, `handshake_timeout` |
| `scanning` | `default_scan_type`, `default_ports`, `timing_template`, `max_concurrent_hosts` |
| `credentials` | `default_wordlist`, `hashcat_workload` |
| `safety` | `confirm_dangerous`, `warn_public_ip`, `require_authorization`, `dry_run`, `unsafe_mode` |
| `ui` | `theme`, `show_banner`, `animation_speed`, `vim_bindings` |

Two `safety` keys are inert. `confirm_dangerous` and `warn_public_ip` are read by the TUI
settings screen and nothing else. Confirmation is `--confirm-tier` on the engagement, and
protected ranges are refused by the scope gate whether or not you ask for a warning.
Neither setting can weaken the gate, which is the point.

---

## Requirements

| | |
|:--|:--|
| **OS** | Linux, kernel 4.x or newer |
| **Python** | 3.11 or newer |
| **Privileges** | Root for wireless work and packet capture |
| **Adapter** | Monitor mode and injection, for the wireless attacks |

Recommended chipsets, all of which do injection: Atheros AR9271 (`ath9k_htc`), Ralink
RT3070 (`rt2800usb`), Realtek RTL8812AU (`rtl8812au`), MediaTek MT7612U (`mt76x2u`).

---

## Project structure

```
NETREAPER/
├── src/netreaper/
│   ├── cli.py             # the `netreaper` entry point (Typer)
│   ├── core/              # process seam, hash-chained audit, logging, validation
│   ├── safety/            # the scope gate: engagement, tiers, protected ranges
│   ├── wireless/          # scan, monitor, handshake, pmkid, wps, wep, eviltwin,
│   │                      #   enterprise, wpa3, hidden, evasion
│   ├── tools/             # 14 native tool adapters, plus read-only CAN
│   ├── automation/        # capability planner and tool requirements
│   ├── detection/         # the 102-tool catalogue
│   ├── db/                # SQLite schema and async engine
│   └── tui/               # Textual UI, 5 screens
├── bin/netreaper-install  # the security-tool installer
├── completions/           # bash, zsh and fish completions
├── tests/                 # 876 tests across 54 files, plus installer bats
└── pyproject.toml         # hatchling; the `netreaper` console script
```

Every spawn goes through one seam, `core/process.py`, which is where the scope gate is
consulted and the audit entry is written. That is why no command can quietly skip either.

---

## Legal

> **For authorised security testing only.**
>
> Unauthorised access to computer systems is illegal. Making sure you have permission is
> your responsibility, not this tool's.
>
> Authorised uses: penetration testing with written permission, security research on
> systems you own, educational environments, and CTF competitions.

## Licence

**GPL-3.0-or-later.** Copyright (c) 2025-2026 Nerds489. Full text: [LICENSE](LICENSE).

Every source file carries an `SPDX-License-Identifier: GPL-3.0-or-later` header, and
`pyproject.toml` declares the same, so the licence travels with the code rather than living
only in one file.

**What it means in practice.** You may use, study, modify and redistribute NETREAPER,
including commercially. If you distribute it or anything derived from it, you must pass on
those same freedoms and make the corresponding source available under GPL-3.0-or-later.

**The "authorised security testing only" notice above is a condition we ask of you, not a
term of the licence.** GPL-3.0 does not restrict the field of use, and an open-source licence
that tried to would stop being open source (clause 6 of the Open Source Definition). Using
this tool without authorisation is your own legal exposure, not a licence breach.

## Sponsor

This is built and maintained by one person. If it saves you time, you can put something
back:

<p align="left">
  <a href="https://github.com/sponsors/Nerds489"><img height="36" alt="Sponsor on GitHub" src="https://img.shields.io/badge/Sponsor-GitHub-ea4aaa?style=for-the-badge&logo=githubsponsors&logoColor=white"></a>
  <a href="https://liberapay.com/Nerds489/donate"><img height="36" alt="Donate using Liberapay" src="https://liberapay.com/assets/widgets/donate.svg"></a>
  <a href="https://www.buymeacoffee.com/abbeyandlaf"><img height="36" alt="Buy Me a Coffee" src="https://cdn.buymeacoffee.com/buttons/v2/default-violet.png"></a>
</p>

GitHub Sponsors, Liberapay and Buy Me a Coffee all reach the same person. Pick whichever
one you already have an account with.

---

<div align="center">

**NETREAPER** v12.0.0 • GPL-3.0-or-later

*The airwaves belong to those who listen*

</div>
