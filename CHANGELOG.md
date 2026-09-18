# Changelog

All notable changes to NETREAPER.

## [12.0.0] - 2026-09-18

Safety-spine release. Four independent reviews of the v11 spine found controls
that were documented and enforced nowhere, and one that was enforced so hard it
made the tool unusable. **Breaking**: authorising a targeted action now takes two
parts, and engagement files from 11.x are rejected.

### Breaking
- **A ceiling is no longer an authorisation.** `--max-tier` says what an
  engagement may reach; the new `--confirm-tier` (repeatable) says you intended
  it. Anything at SINGLE_TARGET or above needs the tier pre-confirmed. MITM also
  needs `--accept-interception`. BROADCAST can never be confirmed mid-run, on a
  TTY or otherwise: nothing in the gate prompts.
- **Engagement files from 11.x are rejected.** The consent digest now covers the
  confirmation grants, so an older record cannot hash-match. The file carries a
  schema version and says "re-run engage start" instead of reporting tampering.
- **`engage start --hours` is capped at 48.** An authorisation that outlives its
  engagement is not an authorisation.

### Security
- **Credentials no longer reach the logs.** The audit sink redacts argv, the
  free-text detail field and targets; per-tool, so `hydra -p` is masked while
  `nmap -p 80,443` is not. The event bus redacts too: it was logging the raw
  joined argv, raw tool stdout, and `CREDENTIAL_CRACKED` payloads carrying the
  recovered secret, at DEBUG, with the file handler pinned to DEBUG regardless
  of console level.
- **Protected-address bypass closed.** A reserved address was refused bare and
  allowed with a netmask (`200::1` refused, `200::1/128` allowed) because the
  CIDR and bare-address branches used two different lists. One policy now.
- **`requires_confirmation` is enforced.** It was accepted by `authorize()`,
  forwarded by the seam, and read nowhere but a `[confirm]` badge.
- **A manifest's declared cost binds.** `destructive` and
  `requires_confirmation` drove nothing; the live auto-chain ran a targeted
  deauth with no engagement at all and passed its tests.
- **The wireless host actions go through the seam.** `wireless/mac.py` and
  `channels.py` spawned `ip`/`iw`/`ethtool` directly, skipping the gate, the
  timeout, the process-group teardown and the audit trail.
- **The TUI no longer spawns an ungated attack console.** `searchsploit`,
  `msfconsole`, `msfvenom` and a live `xsstrike` run against a user-supplied URL
  all went out with no engagement, no tier and no audit line. All routed; packet
  captures authorise before they spawn.
- **T4 teardown survives SIGTERM.** It was wired to `KeyboardInterrupt` only, so
  `kill` left hostapd and dnsmasq intercepting traffic indefinitely.
  `CleanupRegistry` had SIGTERM handlers and no callers.

### Fixed
- **The audit chain survives concurrency and crashes.** Two processes sharing one
  trail produced duplicate sequence numbers and silently discarded 200 recorded
  actions; appends are serialised with a file lock. A torn final line no longer
  poisons the file permanently. `verify_file()` is new and catches truncation,
  reordering and edits that the in-memory check structurally cannot.
- **The report carries the real audit trail** and states whether it verifies,
  instead of an always-empty database table whose INSERT omitted the column the
  query filtered on.
- **`aireplay-ng` argv.** `ignore_negative` emitted a bare `-x`, which is
  packets-per-second and takes a number, landing immediately before the
  interface so the command could not run. It is `--ignore-negative-one` now, and
  the option key matches the config field it was always meant to read.

### Added
- **Every WEP injection strategy is reachable.** `wifi wep --injection` selects
  arpreplay, chopchop, fragment, caffe_latte, cfrag or interactive. The
  aireplay-ng primitives already existed; `wep.py` only ever drove ARP replay and
  the CLI offered no choice.
- 458 tests, up from 333.

### Known
- WPS parity (easybox, arcadyan, the known-PIN database, online brute force,
  lockout back-off) is still open on #47 and needs a restore-versus-descope
  decision rather than code.
- `confirm_dangerous` and `warn_public_ip` are config fields with no
  implementation; the README now says so.
- `tui/screens/traffic.py` does not import (`netreaper.automation.preflight` is
  missing), which predates this release.

## [11.0.0] - 2026-09-12

First GA of the Python rebuild: a single-language, gated, wireless-focused
framework. This is a **breaking** release. The Bash runtime is gone.

### Removed
- **The entire Bash runtime** (~27k lines). It lives on the `legacy` tag only.
  The CLI is now a single `netreaper` entrypoint from the Python package; the old
  `bin/netreaper`, `lib/*.sh` and `NR_*` interface are no longer shipped.

### Added
- **Safety spine.** A single spawn seam (`ProcessRunner.run` + `ScopeGate`,
  deny-by-default), engagement-scoped authorisation with a consent hash, T0-T4
  tiers, and a hash-chained audit trail.
- **Backward-chaining planner.** `ToolManifest` (provides/requires,
  domain-namespaced) + `resolve_chain` compile a goal into an ordered plan that
  runs on the existing `ChainExecutor`.
- **Live wifi auto-chain.** `wifi auto` resolves `wifi.password` and drives
  enable_monitor_mode -> scan -> capture -> crack end to end; dry-run by default,
  `--run` to execute. A missed passphrase fails the chain (non-zero exit).
- **Wireless migration.** Monitor mode, scanning, handshake capture, WPA/WEP/WPS
  and PMKID paths, each routed through the gated spawn seam.
- **Release engineering.** CycloneDX SBOM in CI; a tag-triggered pipeline that
  builds, checksums, keyless-signs (Sigstore) and publishes releases, with SemVer
  pre-release channels. See `docs/RELEASING.md`.

### Changed
- Version is single-sourced from `VERSION` via hatchling.
- CI type-checks the safety spine and runs the full pytest suite on every PR.

## [10.2.3] - 2026-09-11

### Fixed
- **Restore-to-running.** Recovered `lib/version.sh`, `lib/config.sh`, and `lib/wireless.sh`, which were
  absent from the tree while still sourced by `bin/netreaper` under `set -euo pipefail` — the CLI aborted at
  startup. The tool boots again.
- **Safety: `confirm_dangerous()`** no longer auto-accepts on `NR_FORCE_DANGEROUS=1` alone; it now also
  requires unsafe mode (`lib/ui.sh`).
- **`config reset`** now honours `NR_NON_INTERACTIVE` instead of the dead `NR_NON_INTERACTIVE` (`bin/netreaper`).

### Notes
- Baseline snapshot for the rebuild. The Bash CLI boots; the Python package (`src/netreaper`) does not yet
  import and is addressed next.
- **Renamed VOIDWAVE -> NETREAPER** across the tree (command `netreaper`, `~/.netreaper`, `NR_*`/`NETREAPER_*`,
  banners) and **relicensed Apache-2.0 -> GPL-3.0-or-later** (SPDX headers + LICENSE + pyproject).
- The `recon.sh`/`scanning.sh` function collision is deferred to consolidation.

## [10.2.2] - 2025-01-03

### Changed
- **Replaced TUI installer with simple bash CLI installer** - No more Python dependencies
- Install script now defaults to system-wide installation (`/usr/local/bin`)
- Added `--user` flag for user-local installation to `~/.local/bin`

### Fixed
- `sudo netreaper` now works out of the box with system-wide install

---

## [10.2.1] - 2025-01-03

### Fixed
- **Wrapper symlink resolution** - Fixed issue where symlinks weren't properly resolved for system-wide installs

---

## [10.2.0] - 2025-01-03

### Changed
- **README rewritten** - Focus on bash CLI with automation features
- Added automation documentation showing auto-detect capabilities
- Removed Python TUI references from main documentation

### Added
- **Auto-detection system** - Automatically detects interfaces, networks, and targets
- **Auto-fix capabilities** - Enables monitor mode and installs missing tools on the fly

---

## [10.1.0] - 2025-12-30

### Added
- **Universal Tool Installer** (`install-tools.sh`) - Comprehensive multi-method installer with:
  - **9 Installation Methods**: pkg, pip, pipx, pygithub, github, go, cargo, snap, flatpak, gem, git
  - **Smart Fallback Chain**: Automatically tries alternative methods when primary fails
  - **Python GitHub Install**: Clones repos, creates virtualenvs, installs dependencies, generates wrapper scripts
  - **Non-interactive Mode**: `DEBIAN_FRONTEND=noninteractive` for unattended apt installs
  - **One-time apt update**: Optimized to run `apt-get update` only once per session
  - **Auto-confirm flag**: `-y/--yes` option for scripted installations
  - **Category-based installation**: Install tools by category (wireless, osint, recon, etc.)
  - **Search functionality**: Find tools by name
  - **100+ tool definitions** with distro-specific package mappings

- **Python Tool Detection Enhancements** (`src/netreaper/detection/tools.py`):
  - `pip_package` field for pip/pipx fallback installation
  - `binary_names` field for alternative binary name detection
  - Async pip/pipx fallback when system packages unavailable

### Changed
- **README.md** - Complete rewrite with:
  - Modern badge styling (for-the-badge)
  - Comprehensive tool installer documentation
  - Clear installation instructions
  - Full feature overview
  - Updated project structure

- **install.sh** - Added stress tools (hping3, iperf3) to bash installer

### Fixed
- **theHarvester installation** - Now works via pygithub method with isolated virtualenv
- **iperf3 installation** - Added to package mappings for all distros
- **Interactive apt dialogs** - Fixed blocking prompts with non-interactive mode

---

## [10.0.0] - 2025-12-18

### Major Release: NETREAPER Evolution

This release marks the v10 architecture overhaul (the project briefly used the name VOIDWAVE for the v10 line; it is NETREAPER again). Complete framework overhaul with unified architecture.

### Added
- **New README** - Professional, modern design with ASCII banner and clean structure
- **Universal Installer** (`bin/netreaper-install`) - Truly distro-agnostic with support for:
  - Debian/Ubuntu/Kali/Parrot (apt)
  - Fedora/RHEL/Rocky/Alma (dnf/yum)
  - Arch/Manjaro/BlackArch/EndeavourOS (pacman + AUR)
  - openSUSE (zypper)
  - Alpine (apk)
  - Void Linux (xbps)
  - Gentoo (emerge)
  - NixOS (nix-env)
- **Fallback Installation Chain** - pkg manager → pip → go install → cargo → GitHub releases → snap/flatpak
- **Package Name Mapping** - Handles distro-specific package name differences
- **Tool Verification** - Post-install validation with --version/--help checks
- **Installation Summary** - Clean [OK]/[FAIL]/[SKIP] output with detailed logging

### Changed
- Renamed to VOIDWAVE for the v10 line (since reverted to NETREAPER)
- Version jump from 8.x to 10.0.0 to mark the evolution
- All documentation updated to reflect 10.0.0
- Installer now generates manual installation guide for failed tools

### Heritage
- NETREAPER v1-9: Original development
- NETREAPER v10+: Rebuilt architecture, expanded toolset, unified interface

---

## [8.2.0] - 2025-12-15

### Added
- **Session Memory System** (`lib/memory.sh`)
  - Intelligent resource tracking across sessions for networks, hosts, interfaces, and wireless APs
  - `get_resource_with_memory()` universal resource acquisition with auto-scan capability
  - Memory types: `network`, `host`, `interface`, `wireless`
  - Auto-scan functions: `_scan_local_networks`, `_scan_local_hosts`, `_scan_wireless_aps`, `_scan_wireless_interfaces`
  - File-based storage in `~/.netreaper/memory/` with `timestamp|value|metadata` format

- **Memory CLI Commands** (`bin/netreaper`)
  - `netreaper memory show [type]` - View session memory (all or specific type)
  - `netreaper memory clear [type]` - Clear memory entries
  - `netreaper memory add <type> <value> [metadata]` - Add entry manually
  - `netreaper memory list` - List all memory entries

### Changed
- **All Menus Integrated with Memory System**
  - Scan Menu: Target selection uses memory with auto-scan option
  - Recon Menu: Network/host targets use `_get_target_or_network()` helper
  - Wireless Menu: Interface and AP selection via `_select_wireless_interface()` and `_get_target_info()`
  - Traffic Menu: Interface and gateway/target selection with memory
  - Stress Menu: Target and interface selection with memory
  - Credentials Menu: Host targets for password attacks use memory
  - Pillage Menu: BSSID targets use memory

- **Menu Error Handling**
  - Added `2>/dev/null || true` to all tool calls to prevent menu exits on tool failures
  - Menus now properly return to menu after operations instead of exiting to terminal
  - `wait_for_keypress` ensures user sees output before returning to menu

### Fixed
- Fixed menus exiting to terminal after network scans, tool checks, and ARP discovery
- Fixed syntax error in traffic menu Wireshark background execution

## [8.1.0] - 2025-12-14

### Added
- NETREAPER v8 improvements - logging, debugging, docs, CI
- Comprehensive man page for netreaper
- Improvement roadmap from multi-agent analysis

### Fixed
- Made coverage job non-blocking and removed kcov dependency

## [6.3.4] - 2025-12-13

### Fixed
- **install.sh – Sourcery review fixes**
  - `_verify_installation`: Guard `--version` execution when `wrapper_path` is empty/invalid
  - `_cleanup_legacy`: Relax failure for `--user` installs when system legacy binaries exist but can't be removed (warn-only for non-root)
  - `_do_uninstall`: Proper success/failure tracking with distinct `uninstall_removed_any` and `uninstall_failed_any` flags; exits non-zero on partial failure

### Changed
- Version consistency enforcement across all files (6.3.4 is now the single source of truth)

## [6.3.3] - 2025-12-12

### Added
- **install.sh – Callable Command Guarantee**
  - `_dir_in_path()` helper to check if a directory is in PATH
  - `_select_install_dir()` choosing best install directory (`/usr/local/bin` → `/usr/bin` → fallback with PATH fix)
  - `_create_path_dropin()` to create `/etc/profile.d/netreaper.sh` if needed for PATH augmentation
  - Installer creates wrapper scripts in install directory pointing to `bin/netreaper` and `bin/netreaper-install`
  - Post-install verification **hard-fails** if `command -v netreaper` fails
  - `bin/netreaper-install` only runs if arguments are provided (prevents accidental execution)

- **lib/detection.sh – Tool Detection Fixes**
  - New `TOOL_SEARCH_PATHS` constant covering comprehensive search locations:
    `/usr/bin /usr/local/bin /usr/sbin /usr/local/sbin /sbin /bin /opt/bin ~/.local/bin ~/go/bin`
  - `check_tool()` and `get_tool_path()` now search all directories in `TOOL_SEARCH_PATHS`
  - Empty tool names are rejected (return 1)
  - New `tool_package_name()` function with distro-family mappings:
    - Aircrack suite tools (`aircrack-ng`, `airodump-ng`, `aireplay-ng`, etc.) → `aircrack-ng` package
    - `dig`: debian → `dnsutils`, redhat → `bind-utils`, arch → `bind`
    - `tshark`: debian → `tshark`, redhat/arch → `wireshark-cli`
    - `netcat`: debian → `netcat-openbsd`, redhat → `nmap-ncat`, arch → `openbsd-netcat`
  - `auto_install_tool()` now uses `tool_package_name()` for correct per-distro resolution

- **tests/detection.bats**
  - 14 new tests covering empty args, path list validation, and package name mappings

## [6.3.2] - 2025-12-12

### Fixed
- **CI correctness**: All log output now goes to stderr, preserving stdout for data
- **`config get` output**: Now returns raw values only (no colors, headers, or logging)
- Installer hard-fails if legacy v5.x binaries cannot be removed (prevents broken hybrid state)
- Post-install verification ensures only the modular wrapper is installed

### Changed
- `reinstall-netreaper.sh` rewritten with strict CI safety:
  - Requires explicit confirmation in interactive mode
  - Non-interactive mode requires `NR_NON_INTERACTIVE=1` AND `NR_FORCE_REINSTALL=1`
  - Uses `umask 077` and bash strict mode
  - Verifies `netreaper --version` matches VERSION file after install

### Added
- Environment variables for CI/automation: `NR_FORCE_REINSTALL`, `NR_KEEP_CONFIG`, `NR_REMOVE_CONFIG`

## [6.3.1] - 2025-12-12

### Added
- Protection against legacy v5.x monolithic installs (auto-removed during install)
- Reinstall script (`reinstall-netreaper.sh`) for clean installation

### Changed
- Finalized Phase 3 core infrastructure (tools, progress, config)

## [6.2.4] - 2025-12-10

### Added
- Modular dispatcher architecture (`bin/netreaper` as thin dispatcher)
- Version handling via `lib/version.sh` (single source of truth)
- Centralized logging system with log levels (DEBUG, INFO, SUCCESS, WARNING, ERROR, FATAL)
- File logging to `~/.netreaper/logs/netreaper_YYYYMMDD.log`
- Audit trail logging to `~/.netreaper/logs/audit_YYYYMMDD.log`
- Smart sudo/privilege helpers: `is_root()`, `require_root()`, `run_with_sudo()`, `elevate_if_needed()`, `can_get_root()`
- Target validation system: `is_valid_ip()`, `is_valid_cidr()`, `is_private_ip()`, `is_protected_ip()`, `validate_target()`
- Public IP warnings and authorization checks with `confirm_dangerous()` integration
- Protected IP ranges blocking (loopback, multicast, broadcast, link-local, reserved)
- Confirmation prompts: `confirm()`, `confirm_dangerous()`, `prompt_input()`, `select_option()`
- Input validators: `validate_not_empty()`, `validate_integer()`, `validate_positive_integer()`, `validate_port_range()`
- `NR_UNSAFE_MODE` environment variable to bypass safety checks
- `NR_NON_INTERACTIVE` mode for CI/headless environments
- Dispatcher commands: `--dry-run`, `help`, `config path`
- Unified error-handling framework: `die()`, `assert()`, `try()`, `error_handler()` with stack traces
- Exit code constants: `EXIT_CODE_SUCCESS`, `EXIT_CODE_FAILURE`, `EXIT_CODE_INVALID_ARGS`, `EXIT_CODE_PERMISSION`, `EXIT_CODE_NETWORK`, `EXIT_CODE_TARGET_INVALID`, `EXIT_CODE_TOOL_MISSING`
- Tool checking utilities: `require_tool()`, `check_tool()`, `get_tool_path()`
- Safe file operations: `safe_rm()`, `safe_mkdir()`, `safe_copy()`, `safe_move()` with protected path blocking
- Log utilities: `set_log_level()`, `show_logs()`, `rotate_logs()`, `init_logging()`

### Changed
- `bin/netreaper` refactored into thin dispatcher sourcing modular libs
- Core logic moved into `lib/core.sh`, `lib/ui.sh`, `lib/safety.sh`, `lib/detection.sh`, `lib/utils.sh`
- All scripts now read version and `NETREAPER_ROOT` from `lib/version.sh`
- Improved CI behavior with non-interactive logic (auto-accept prompts, skip wizards)
- `validate_target()` now uses `confirm_dangerous()` for public IP confirmation
- All confirmation/input functions respect `NR_NON_INTERACTIVE` mode
- Enhanced `error_handler()` with stack trace support and audit logging

### Fixed
- Legacy CLI incompatibilities with dispatcher
- Public IP scanning without warnings now properly blocked or confirmed
- `--dry-run` flag not being recognized
- `help` command failing previously
- `config path` command failing previously
- `ORIGINAL_ARGS` unbound variable error with `set -u`
- Inconsistent privilege handling and unclear root requirements
- Lack of audit trail for security-relevant operations

## [6.2.2] - 2025-12-10

### Fixed
- Resolved E2BIG "argument list too long" error when invoking sudo with large argument expansion

## [6.2.1] - 2025-12-09

### Added
- Root-level wrapper binaries (`netreaper`, `netreaper-install`) that forward to the executables in `bin/`, preserving historical `./netreaper` workflows.
- Dedicated Bash, Zsh, and Fish completion scripts in `completions/` plus documentation explaining how to enable them.
- Smoke tests under `tests/smoke/` (`test_help.sh`, `test_version.sh`) that mirror the CI entrypoints.

### Changed
- Repository layout and quickstart docs now highlight the `bin/` directory, wrapper scripts, and the clean root-level structure.
- `install.sh` strictly delegates to `bin/netreaper-install`, and the README/HowTo/Quick Reference call out the wrapper usage.
- Non-interactive detection honors `NR_NON_INTERACTIVE=1` **and** TTY absence, skipping the wizard, legal prompts, and auto-marking `FIRST_RUN_COMPLETE`.

### Fixed
- CI runs without blocking prompts—no more wizard/legal interaction required for headless environments.
- Version reporting is consistent across the CLI, installer, and core libraries (single source of truth via `VERSION`).

### Removed
- Remaining EULA language; Apache 2.0 is now the only license mentioned anywhere.

## [6.2.0] - 2024-12-09

### Added
- `bin/` directory for executables (professional structure)
- `tests/smoke/` directory with smoke tests
- `docs/images/` directory for screenshots
- `--dry-run` flag for safe command preview
- `nr_run()` and `nr_run_eval()` wrapper functions in lib/core.sh
- "First 60 Seconds" quickstart section in README
- "Why NETREAPER?" comparison table in README
- "Dry-Run Mode" documentation in README
- "Project History" section in README
- CI badge in README
- Release workflow (.github/workflows/release.yml)

### Changed
- Moved `netreaper` → `bin/netreaper`
- Moved `netreaper-install` → `bin/netreaper-install`
- `install.sh` is now thin wrapper calling `bin/netreaper-install`
- CI workflow updated for `bin/` structure
- README completely overhauled with landing page style
- Installer version synced to main version (6.2.0)

### Fixed
- uninstall.sh now removes both netreaper and netreaper-install

### Structure
```
bin/
  netreaper           # Main toolkit
  netreaper-install   # Tool installer
lib/                  # Core libraries
modules/              # Feature modules
tests/
  smoke/              # Smoke tests
  *.bats              # Bats tests
docs/
  images/             # Screenshots
install.sh            # System installer (wrapper)
uninstall.sh          # Uninstaller
```

## [6.1.0] - 2024-12-09

### Changed
- **License Clarification**: NETREAPER is 100% Apache 2.0 with no additional restrictions
- Removed EULA directory and all associated acceptance language
- Version standardization: single source of truth from VERSION file
- Code cleanup: added shellcheck disable directives for intentionally exported variables

### Fixed
- ShellCheck warnings properly addressed (not hidden with severity config)
- SC2034: Added explicit directives for exported variables (colors, PKG_*, TOOLS_*)
- Syntax error in first_run_wizard() from empty if-then block
- Version inconsistencies across all script files

### Removed
- `EULA/` directory completely removed
- All EULA/terms acceptance language from scripts
- Unused `term_cmd` variable from netreaper-install

## [6.0.1] - 2024-12-09

### Fixed
- CI test fixes for detection.bats
- Prevented log_to_file from failing in CI environments

## [6.0.0] - 2024-12-09

### Added
- Modular architecture with `lib/` and `modules/` directories
- Authorization flow on first run
- Target validation (blocks dangerous operations by default)
- `NR_UNSAFE_MODE` environment variable for advanced users
- Bats test suite (47 tests)
- GitHub Actions CI with ShellCheck
- `--dry-run` flag for installer

### Changed
- Main script refactored to thin dispatcher
- Installer refactored with clear functions
- Installer version bumped to 3.0.0

### Structure
```
lib/core.sh        - Logging, colors, paths
lib/ui.sh          - Menus, prompts, banners
lib/safety.sh      - Authorization, validation
lib/detection.sh   - Distro/tool detection
lib/utils.sh       - Helper functions

modules/recon.sh       - Network reconnaissance
modules/wireless.sh    - WiFi operations
modules/scanning.sh    - Port scanning
modules/exploit.sh     - Exploitation
modules/credentials.sh - Password cracking
modules/traffic.sh     - Packet analysis
modules/osint.sh       - OSINT gathering
```

## [5.3.1] - 2024-12-08

### Fixed
- Interface validation improvements
- Installer compatibility fixes

## [5.3.0] - 2024-12-07

### Added
- Multi-distro support (Fedora, RHEL, Arch, openSUSE, Alpine)
- Improved wizard mode
- JSON output for status

---

## [6.4.0] - 2025-12-13

### Added
- **Interactive Menu System**: Full TUI with 10 submenus
  - Reconnaissance, Scanning, Wireless, Exploitation, Credentials
  - Traffic Analysis, OSINT, Stress Testing, Status, Settings
- **CLI Flags**: --dry-run, --json, --quiet, --verbose, --target, --output
- **Guided Wizards**: wizard_first_run, wizard_scan, wizard_wifi, wizard_pentest, wizard_recon
- **Session Management**: Pause/resume long-running operations
- **UI Helpers**: select_multiple, show_progress, select_from_list, select_interface, show_table, mask_string
- **Tool Status Dashboard**: 30 tools tracked across 8 categories with version detection
- **Settings Persistence**: API keys, paths, logging config saved to ~/.netreaper/config/
- **Stress Testing Safety**: Private IP enforcement, hardcoded limits, authorization confirmations

### Changed
- `netreaper` with no arguments now launches interactive menu
- Added `-i, --interactive` flag for explicit menu launch

### Security
- Stress testing blocked for public IPs unless NR_UNSAFE_MODE=1
- API keys stored with chmod 600 permissions
- Authorization confirmations for destructive operations
