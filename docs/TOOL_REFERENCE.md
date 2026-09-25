# NETREAPER Tool Reference

NETREAPER drives its tool catalogue behind one interface. This page maps the
tools to what they do; the **authoritative command reference is the top-level
[README](../README.md)**, which the CLI's own tests keep in step with the code.
Run the CLI via `netreaper` after `pip install .`, or `netreaper` with no
arguments for the TUI.

The real command surface (see the README for options and details):
- `netreaper scan <target> --type quick|standard|full` — network scan
- `netreaper wifi monitor enable <iface>` then `wifi scan` / `wifi handshake` / `wifi wep` / `wifi auto`
- `netreaper wifi crack <capture> <bssid> <wordlist>` — offline WPA crack
- `netreaper web auto <url>`, `netreaper ble plan`, `netreaper can dump <iface>`
- `netreaper status`, `netreaper config`, `netreaper engage`, `netreaper --version`

Install tooling with `sudo bin/netreaper-install essentials|all|<category>` and
confirm with `netreaper status`.

> An earlier version of this page was headed v10.0.0 and documented
> `session`, `crack --hashcat`, `install` and `help` subcommands plus
> `--quick`/`--monitor` flags, none of which exist. The commands above are the
> real ones; the per-tool "Menu" notes further down predate the current TUI and
> are indicative, not literal.

## Recon & Discovery
| Tool | Purpose | Access in NETREAPER |
|------|---------|----------------------|
| nmap | TCP/UDP scans, service/vuln scripts | CLI: `netreaper scan ...`; Menu: Recon -> nmap (quick/full/stealth/UDP/vuln) |
| masscan | Fast port sweeps | Menu: Recon -> Masscan |
| rustscan | Rapid discovery feeding nmap | Menu: Recon -> Rustscan |
| netdiscover | ARP live host discovery | Menu: Recon -> Netdiscover |
| dnsenum | DNS/WHOIS/bruteforce | Menu: Recon -> DNSenum |
| sslscan | SSL/TLS cipher/protocol analysis | Menu: Recon -> SSLScan |
| enum4linux | SMB enumeration | Menu: Recon -> enum4linux |

## Wireless
| Tool | Purpose | Access in NETREAPER |
|------|---------|----------------------|
| aircrack-ng suite (airodump/aireplay) | Capture handshakes, deauth, crack WPA/WPA2 | CLI: `netreaper wifi --monitor <iface>` to start capture; Menu: Wireless -> Capture/Deauth |
| reaver | WPS exploitation | Menu: Wireless -> Reaver |
| bettercap | MITM and wireless attacks | Menu: Wireless -> Bettercap |
| wifite | Automated WiFi audit | Menu: Wireless -> Wifite |
| hostapd | Evil twin access point | Menu: Wireless -> Evil Twin |

## Web & Exploit
| Tool | Purpose | Access in NETREAPER |
|------|---------|----------------------|
| metasploit | Exploitation framework | Menu: Exploit -> Metasploit |
| sqlmap | Automated SQL injection | Menu: Exploit -> SQLMap |
| gobuster | Directory brute force | Menu: Exploit -> Gobuster |
| nikto | Web server vuln scan | Menu: Exploit -> Nikto |
| wpscan | WordPress security scan | Menu: Exploit -> WPScan |
| nuclei | Template-based scanning | Menu: Exploit -> Nuclei |
| searchsploit | Local exploit DB search | Menu: Exploit -> Searchsploit |

## Credentials & Access
| Tool | Purpose | Access in NETREAPER |
|------|---------|----------------------|
| hashcat | GPU hash cracking | CLI: `netreaper wifi crack <cap> <bssid> <wordlist>` for WPA; the credentials screen for arbitrary hashes |
| john | CPU hash cracking | Menu: Credentials -> John |
| hydra | Online brute force (SSH/HTTP/DB) | Menu: Credentials -> Hydra |
| medusa | Parallel brute force | Menu: Credentials -> Medusa |
| crackmapexec | SMB/WinRM/LDAP abuse | Menu: Credentials -> CrackMapExec |
| impacket suite | Windows protocols, secrets, tickets | Menu: Post-Exploit -> Impacket |

## Intel & OSINT
| Tool | Purpose | Access in NETREAPER |
|------|---------|----------------------|
| theHarvester | Email/host OSINT collection | Menu: Intel -> theHarvester |
| recon-ng | Modular recon framework | Menu: Intel -> Recon-NG |
| shodan CLI | Internet search engine interface | Menu: Intel -> Shodan |
| tcpdump | Packet capture | Menu: Intel -> Packet Capture |
| wireshark | GUI traffic analysis | Menu: Intel -> Wireshark |

## Stress & Network Performance
| Tool | Purpose | Access in NETREAPER |
|------|---------|----------------------|
| hping3 | Packet flooding/firewall testing | Menu: Stress -> hping3 |
| iperf3 | Throughput testing | Menu: Stress -> iperf3 |
| ab (ApacheBench) | HTTP load testing | Menu: Stress -> HTTP Load |
| tc/netem | Latency/loss/jitter impairment | Menu: Stress -> Netem (add/remove qdisc) |

## Utilities & Post-Exploitation
| Tool | Purpose | Access in NETREAPER |
|------|---------|----------------------|
| ssh/socat/nc | Connectivity checks, tunnels, pivots | Menu: Post-Exploit -> Tunnels/Utilities |
| mimikatz (helpers) | Credential extraction on Windows targets | Menu: Post-Exploit -> Mimikatz helpers |
| loot manager | View/export captured credentials/artifacts | Menu: Sessions/Loot -> View/Export |

Notes:
- Outputs are stored under `~/.netreaper/output/` per session; loot under `~/.netreaper/loot/`.
- Many actions provide previews/logs before execution; review them in `~/.netreaper/logs/` if something fails.
- Keep tools fresh with `sudo netreaper-install all` after pulling new versions of NETREAPER.
