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

**Offensive Security Framework** | **124 Tools** | **Zero Configuration** | **Just Works**

[Installation](#installation) • [Quick Start](#quick-start) • [Commands](#commands) • [Tools](#tool-arsenal)

</div>

---

## What is NETREAPER?

NETREAPER is an offensive security framework that plans the chain for you. Name a goal and an interface, and it resolves which tools are needed, in what order, and runs them behind a scope gate with a hash-chained audit trail.

It does not pick your interface for you. Every command takes it explicitly; see Commands below.

```bash
# Old way
airmon-ng check kill
airmon-ng start wlan0
airodump-ng wlan0mon          # wait, watch, copy BSSID...
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF wlan0mon  # find clients...
aireplay-ng --deauth 0 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon

# NETREAPER way
netreaper wifi auto -i wlan0mon --run    # resolve the chain and run it
```

---

## Installation

```bash
git clone https://github.com/Nerds489/NETREAPER.git
cd NETREAPER

# Install NETREAPER (the Python CLI)
pip install .
# or, isolated:  pipx install .

# Install the security tools (optional)
sudo bin/netreaper-install all
```

---

## Quick Start

```bash
# 1. Authorise a scope. Every targeted action is denied without one.
#    --max-tier is the CEILING (what may be reached).
#    --confirm-tier is the CONFIRMATION (that you meant it). T2+ needs both.
sudo netreaper engage start \
    --operator "your name" --ref "ROE-001" \
    --essid "YourNetwork" --bssid AA:BB:CC:DD:EE:FF \
    --max-tier mitm --hours 8 \
    --confirm-tier single_target --confirm-tier broadcast \
    --confirm-tier mitm --accept-interception

# 2. Work. Name the interface; NETREAPER resolves the tool chain.
sudo netreaper wifi scan wlan0mon                       # scan for access points
sudo netreaper wifi handshake wlan0mon AA:BB:CC:DD:EE:FF 6   # capture a handshake
sudo netreaper wifi auto -i wlan0mon --run              # plan and run the chain
sudo netreaper scan 192.168.1.0/24                      # scan the local network

# 3. Revoke when you are done.
sudo netreaper engage end
```

> **The engagement is not optional.** NETREAPER is deny-by-default: with no active
> engagement every targeted action fails closed, by design. `engage status` shows the
> current scope, tier ceiling and expiry.

> **A ceiling is not a confirmation.** `--max-tier` says what this engagement *may*
> reach; `--confirm-tier` says you intended it. Anything at SINGLE_TARGET or above
> needs the tier pre-confirmed, MITM additionally needs `--accept-interception`, and
> BROADCAST can never be confirmed mid-run. Nothing prompts: a confirmation is
> recorded in the authorisation up front, inside its consent hash, or the action is
> refused. An engagement lasts at most 48 hours.

---

## Planning

`wifi auto` is the part that does the thinking. Give it a goal capability and an
interface and it resolves which tools are required, orders them by dependency,
and previews the chain. It is a dry run unless you pass `--run`.

```bash
netreaper wifi auto -i wlan0mon                      # preview the chain
netreaper wifi auto -i wlan0mon --run                # run it
netreaper wifi auto -i wlan0mon -g wifi.handshake    # a different goal
```

Every step in the resolved chain goes through the same scope gate and the same
audit trail as a hand-run command. Nothing in a chain is exempt.

### What is NOT automatic

This section previously advertised auto-selection of the interface, monitor
mode, network, target, AP and client, and on-the-fly tool installation, in a
table and a seven-box diagram. None of it was wired to the CLI.
`AutoIfaceHandler` (`automation/handlers/iface.py`) does enumerate wireless
adapters and can bring one into monitor mode, but `cli.py` never calls it, so
every command needs its interface named. `tests/unit/test_readme_commands_exist.py`
now runs every command on this page, so the page cannot drift from the CLI again.

## Commands

### Network Scanning

```bash
netreaper scan 192.168.1.0/24      # scan a network (target is positional)
netreaper scan 10.0.0.1 --type full    # scan one host; -t is --type, not target
netreaper portscan 10.0.0.1            # port scan one host
```

### WiFi Operations

```bash
netreaper wifi monitor start wlan0       # enable monitor mode
netreaper wifi monitor stop wlan0mon     # disable monitor mode
netreaper wifi scan wlan0mon             # scan for access points
netreaper wifi handshake wlan0mon AA:BB:CC:DD:EE:FF 6
                                   # capture a handshake; --deauth N sends N
                                   # deauth frames, --client targets one station
netreaper wifi pmkid wlan0mon AA:BB:CC:DD:EE:FF 6
                                   # clientless PMKID capture
netreaper wifi wep <if> <bssid> <ch> --injection chopchop
                                   # WEP: arpreplay (default), chopchop,
                                   # fragment, caffe_latte, cfrag, interactive
```

### System

```bash
netreaper status                   # show system info and tool status
netreaper config show              # show configuration
netreaper config set log_level DEBUG
netreaper engage status            # show the active authorisation
```

### Flags

```bash
netreaper --help                   # show all commands
netreaper --version                # show version

# --dry-run, --quiet, --verbose and --target were listed here as global flags.
# None of them exist. Per-command options are in each command's --help.
```

---

## Interactive Mode

> **Ships in v12.0.0.** The Textual TUI exists now: `netreaper` with no arguments starts it,
> and `netreaper tui` does the same thing explicitly. Earlier releases documented this menu
> while `netreaper.tui.app` was absent, so the command failed with a misleading hint to install
> a `[tui]` extra that would not have helped, because nothing was missing from the environment.
> The categories below are the planned set; the shipped build covers a subset of them as
> screens, and the command palette names the CLI equivalent for anything without a screen yet.

```bash
netreaper                        # starts the TUI
netreaper tui                    # the same thing, explicitly
netreaper --help                 # the CLI, if you prefer it
```

```
┌─────────────────────────────────────────────────────────────────────┐
│  [1] WIRELESS      WPA/WPA2/WPS/Evil Twin/Deauth/PMKID             │
│  [2] SCANNING      Port scans, service detection, host discovery   │
│  [3] CREDENTIALS   Password cracking, brute force, responder       │
│  [4] OSINT         Email harvesting, subdomain enum, recon         │
│  [5] RECON         Web fuzzing, directory brute force, CMS scans   │
│  [6] TRAFFIC       Packet capture, MITM, ARP spoofing              │
│  [7] EXPLOIT       Metasploit, SQLMap, searchsploit                │
│  [8] STRESS        Load testing, SYN floods                        │
│  [9] STATUS        System info, tool status                        │
│  [0] EXIT                                                          │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Tool Arsenal

124 security tools across 9 categories:

### Wireless
`aircrack-ng` `airmon-ng` `airodump-ng` `aireplay-ng` `reaver` `bully` `wifite` `hcxdumptool` `hcxtools` `mdk4` `hostapd` `dnsmasq` `kismet` `pixiewps` `cowpatty` `wash` `macchanger` `iw`

### Scanning
`nmap` `masscan` `rustscan` `zmap` `enum4linux` `nbtscan` `onesixtyone` `smbclient` `smbmap` `ldapsearch` `snmpwalk` `nfs-utils`

### Credentials
`hashcat` `john` `hydra` `medusa` `responder` `impacket` `crackmapexec` `evil-winrm` `kerbrute` `patator` `crowbar` `thc-pptp-bruter` `hash-identifier`

### OSINT
`theHarvester` `subfinder` `amass` `recon-ng` `sherlock` `holehe` `spiderfoot` `maltego` `shodan` `censys` `emailharvester` `whois` `dnsrecon` `fierce` `dmitry`

### Recon
`gobuster` `ffuf` `feroxbuster` `dirb` `dirbuster` `nikto` `nuclei` `wpscan` `whatweb` `wafw00f` `httpx` `httprobe` `aquatone` `eyewitness` `gowitness` `arjun`

### Traffic
`tcpdump` `wireshark` `tshark` `ettercap` `bettercap` `mitmproxy` `arpspoof` `dnsspoof` `sslstrip` `netsniff-ng`

### Exploit
`metasploit` `sqlmap` `searchsploit` `commix` `xsser` `beef-xss` `social-engineer-toolkit` `veil` `empire` `covenant` `chisel` `ligolo-ng`

### Stress
`hping3` `slowloris` `siege` `ab` `wrk` `iperf3` `stress-ng` `t50`

### Utility
`curl` `wget` `git` `proxychains` `tor` `socat` `netcat` `tmux` `screen` `jq` `yq` `xxd` `binwalk` `foremost` `steghide` `exiftool` `pwncat` `rlwrap` `sshpass` `fcrackzip`

---

## Tool Installer

```bash
sudo bin/netreaper-install status       # show installed tools and status
sudo bin/netreaper-install all          # install everything
sudo bin/netreaper-install essentials   # essential tools only
sudo bin/netreaper-install wireless     # install a category (wireless, web, exploit, osint, ...)
sudo bin/netreaper-install --dry-run all # preview without installing
```

Installation methods: `apt` `dnf` `pacman` `zypper` `apk` `pipx` `pip` `go` `cargo` `gem` `snap` `flatpak` `github releases` `git clone`

---

## Supported Distros

| Family | Distributions |
|:-------|:--------------|
| **Debian** | Debian, Ubuntu, Kali, Parrot, Linux Mint |
| **Red Hat** | Fedora, RHEL, Rocky, AlmaLinux, CentOS |
| **Arch** | Arch, Manjaro, BlackArch, EndeavourOS |
| **SUSE** | openSUSE Leap, Tumbleweed |
| **Alpine** | Alpine Linux |
| **Void** | Void Linux |

---

## Wireless Attacks

| Attack | Description |
|:-------|:------------|
| **WPS Pixie-Dust** | Offline WPS PIN recovery |
| **WPS Brute Force** | Online PIN enumeration |
| **WPA Handshake** | 4-way handshake capture + crack |
| **PMKID** | Clientless WPA attack |
| **Deauth** | Client disconnection |
| **Evil Twin** | Rogue AP with captive portal |
| **Beacon Flood** | Fake network spam |
| **WEP** | Legacy encryption attacks |

### Recommended Adapters

| Chipset | Driver | Injection |
|:--------|:-------|:---------:|
| Atheros AR9271 | ath9k_htc | ✓ |
| Ralink RT3070 | rt2800usb | ✓ |
| Realtek RTL8812AU | rtl8812au | ✓ |
| MediaTek MT7612U | mt76x2u | ✓ |

---

## Configuration

```bash
netreaper config show              # all settings
netreaper config get log_level     # get value
netreaper config set key value     # set value
netreaper config reset             # restore defaults
```

| Setting | Default | Description |
|:--------|:--------|:------------|
| `log_level` | INFO | DEBUG, INFO, WARNING, ERROR |
| `file_logging` | true | Write logs to file |
| `confirm_dangerous` | true | **Not implemented.** Nothing reads it outside the TUI settings screen, and nothing prompts anywhere. Confirmation is `--confirm-tier` on the engagement |
| `warn_public_ip` | true | **Not implemented.** Nothing reads it outside the TUI settings screen. Protected and reserved ranges are refused outright by the scope gate, in both bare and CIDR notation |

---

## Requirements

| Requirement | Details |
|:------------|:--------|
| **OS** | Linux (kernel 4.x+) |
| **Python** | 3.11+ |
| **Privileges** | Root for wireless/packet capture |
| **WiFi Adapter** | Monitor mode + injection (for wireless attacks) |

---

## Project Structure

```
NETREAPER/
├── src/netreaper/         # Python package (the CLI + core)
│   ├── cli.py             # `netreaper` entry point (Typer)
│   ├── core/              # process seam, logging, validation
│   ├── safety/            # engagement scope gate (deny-by-default)
│   ├── wireless/          # scan, monitor, handshake, pmkid, wps,
│   │                      #   wep, eviltwin, enterprise, advanced
│   └── tools/             # external-tool adapters
├── bin/netreaper-install  # security-tool installer
├── tests/                 # pytest suite (+ installer bats)
└── pyproject.toml         # packaging; `netreaper` console script
```

---

## Legal

> **For authorized security testing only.**
>
> Unauthorized access to computer systems is illegal. You are responsible for ensuring proper authorization before use.
>
> Authorized uses:
> - Penetration testing with written permission
> - Security research on systems you own
> - Educational environments
> - CTF competitions

## Licence

**GPL-3.0-or-later.** Copyright (c) 2025-2026 Nerds489. Full text: [LICENSE](LICENSE).

Every source file carries an `SPDX-License-Identifier: GPL-3.0-or-later` header, and
`pyproject.toml` declares the same, so the licence travels with the code rather than living
only in one file.

**What it means in practice.** You may use, study, modify and redistribute NETREAPER,
including commercially. If you distribute it or anything derived from it, you must pass on
those same freedoms and make the corresponding source available under GPL-3.0-or-later.

**The "authorized security testing only" notice above is a condition we ask of you, not a
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
