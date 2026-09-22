#!/usr/bin/env bats
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Tests for bin/netreaper-install.
#
# THIS FILE USED TO PASS 20/20 WHILE TESTING NOTHING AT ALL.
#
# Its setup() called `set +e`. bats detects a failed assertion through
# errexit's ERR trap, so with errexit off a failing `[ ... ]` is a no-op that
# still reports ok. Measured: under `set +e` a bare `false` reports ok, and so
# does `return 1`. Only `exit 1` still fails.
#
# That is how eleven of these tests named functions and variables which do not
# exist anywhere in the installer, and reported ok for it:
#
#     verify_tool_installed   ->  verify_tool
#     get_package_name        ->  get_pkg_name
#     detect_distro_family    ->  detect_distro, which sets globals and echoes
#                                 nothing
#     SUCCESS_TOOLS           ->  INSTALLED_TOOLS
#     TOOL_SEARCH_PATHS       ->  does not exist, in any form
#     TOOLS                   ->  does not exist; the catalogue is CATEGORIES
#
# The `set +e` was there because sourcing the installer used to `exit 1` when
# it could not find its root. That defect is fixed, the source is clean, and
# the guard is gone with it. The first test below is a canary: it fails, via
# `exit 1`, if errexit is ever turned off again.

setup() {
    NETREAPER_ROOT="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
    NETREAPER_INSTALL="$NETREAPER_ROOT/bin/netreaper-install"
    export NETREAPER_ROOT
    export NR_NON_INTERACTIVE=1
    export NO_COLOR=1

    # Source the function definitions with `main "$@"` removed, so the script
    # does not run itself. Sourcing has no side effects beyond setting
    # pipefail, resolving the root, reading VERSION and choosing colours.
    #
    # Sourcing is done with errexit off, because the installer has top-level
    # statements that legitimately return non-zero (probing for a package
    # manager that is not present, for one), and under bats' errexit the first
    # of them aborts the source half way, leaving CATEGORIES and the tracking
    # arrays undefined.
    #
    # Errexit is then turned back ON. The original setup() called `set +e`
    # twice, and that second one should have been `set -e`. One character is
    # the whole reason this file passed 20/20 while asserting nothing.
    #
    # shellcheck disable=SC1090  # the source IS the point: a filtered copy of
    # the installer. There is no constant path to follow, by design.
    set +e
    source <(sed '/^main "\$@"/d' "$NETREAPER_INSTALL")
    set -e
}

#===============================================================================
# The canary. If this fails, nothing else in the file means anything.
#===============================================================================

@test "assertions in this file can actually fail" {
    if [[ $- != *e* ]]; then
        echo "errexit is OFF inside the test body." >&2
        echo "Every [ ... ] in this file is now a no-op that still reports ok." >&2
        echo "Something in setup() ran 'set +e'. Remove it." >&2
        exit 1   # the only signal that survives set +e
    fi
}

#===============================================================================
# Root resolution: the defect that made the installer unrunnable
#===============================================================================

@test "the repository is recognised as a NETREAPER root" {
    _is_netreaper_root "$NETREAPER_ROOT"
}

@test "a directory without the marker is not a root" {
    run _is_netreaper_root "$BATS_TEST_TMPDIR"
    [ "$status" -ne 0 ]
}

@test "the root resolves from a checkout" {
    run _resolve_netreaper_root
    [ "$status" -eq 0 ]
    [ "$output" = "$NETREAPER_ROOT" ]
}

@test "VERSION is read from the repository, not hardcoded" {
    [ "$VERSION" = "$(tr -d '[:space:]' < "$NETREAPER_ROOT/VERSION")" ]
    [ "$VERSION" != "unknown" ]
}

#===============================================================================
# get_pkg_name / get_binary_name
#===============================================================================

@test "get_pkg_name returns a package for a known tool" {
    run get_pkg_name "nmap"
    [ "$status" -eq 0 ]
    [ -n "$output" ]
}

@test "get_pkg_name falls back to the tool name when unmapped" {
    run get_pkg_name "definitely_not_a_real_tool_xyz"
    [ "$output" = "definitely_not_a_real_tool_xyz" ]
}

@test "get_binary_name maps a package name to its binary" {
    run get_binary_name "netcat"
    [ "$output" = "nc" ]
    run get_binary_name "exploitdb"
    [ "$output" = "searchsploit" ]
}

@test "get_binary_name passes an unmapped tool straight through" {
    run get_binary_name "nmap"
    [ "$output" = "nmap" ]
}

#===============================================================================
# is_installed / verify_tool
#===============================================================================

@test "is_installed finds a command that exists" {
    run is_installed "bash"
    [ "$status" -eq 0 ]
}

@test "is_installed rejects one that does not" {
    run is_installed "definitely_nonexistent_tool_xyz123"
    [ "$status" -ne 0 ]
}

@test "verify_tool succeeds for a real binary" {
    NO_VERIFY=0
    run verify_tool "bash"
    [ "$status" -eq 0 ]
}

@test "verify_tool fails for a binary that is absent" {
    NO_VERIFY=0
    run verify_tool "definitely_nonexistent_tool_xyz123"
    [ "$status" -ne 0 ]
}

@test "--no-verify short-circuits verification" {
    NO_VERIFY=1
    run verify_tool "definitely_nonexistent_tool_xyz123"
    [ "$status" -eq 0 ]
}

#===============================================================================
# Detection. These set globals rather than echoing, so they are NOT run in a
# subshell: `run detect_distro` would discard everything it sets.
#===============================================================================

@test "detect_distro sets the distro globals" {
    detect_distro
    [ -n "$DISTRO" ]
    [ -n "$DISTRO_FAMILY" ]
}

@test "detect_distro picks a family it has package mappings for" {
    detect_distro
    case "$DISTRO_FAMILY" in
        debian|redhat|arch|suse|alpine|void|gentoo|nix|solus|unknown) ;;
        *) echo "unexpected family: $DISTRO_FAMILY" >&2; return 1 ;;
    esac
}

@test "detect_package_manager sets PKG_MANAGER" {
    detect_distro
    detect_package_manager
    [ -n "$PKG_MANAGER" ]
}

#===============================================================================
# The catalogue
#===============================================================================

@test "CATEGORIES is populated" {
    [ "${#CATEGORIES[@]}" -gt 0 ]
}

@test "CATEGORIES holds the nine documented categories" {
    for c in scanning wireless web exploit osint creds traffic stress utils; do
        [ -n "${CATEGORIES[$c]:-}" ] || { echo "missing category: $c" >&2; return 1; }
    done
}

@test "the scanning category includes nmap" {
    [[ "${CATEGORIES[scanning]}" == *nmap* ]]
}

@test "ESSENTIALS is a non-empty list" {
    [ -n "$ESSENTIALS" ]
}

@test "every category name the dispatcher accepts exists in CATEGORIES" {
    local arm
    arm=$(grep -oE '^\s+scanning(\|[a-z]+)+\)' "$NETREAPER_INSTALL" | tr -d ' )')
    [ -n "$arm" ]
    local IFS='|'
    for c in $arm; do
        [ -n "${CATEGORIES[$c]:-}" ] || { echo "dispatched but absent: $c" >&2; return 1; }
    done
}

#===============================================================================
# Tracking arrays
#===============================================================================

@test "the tracking arrays are declared, and declared global" {
    # `${arr+x}` expands ${arr[0]+x}, which is unset for an empty array, so it
    # cannot answer "does this array exist". `declare -p` can.
    #
    # The -g matters and is not cosmetic: this file sources the installer from
    # inside a bats function, and a plain `declare` there is FUNCTION LOCAL, so
    # every array vanished the moment setup() returned. The installer already
    # declared its scalars with -g and its arrays without; they agree now.
    local decl
    for name in INSTALLED_TOOLS FAILED_TOOLS SKIPPED_TOOLS INSTALL_METHODS CATEGORIES; do
        decl=$(declare -p "$name" 2>/dev/null) || {
            echo "$name is not declared at all" >&2
            return 1
        }
        [[ "$decl" == "declare -"[aA]* ]] || {
            echo "$name is not an array: $decl" >&2
            return 1
        }
    done
}

#===============================================================================
# --dry-run must not write, and must still report a method
#===============================================================================

@test "pkg_update does nothing under DRY_RUN" {
    DRY_RUN=1
    PKG_MANAGER=apt
    run pkg_update
    [ "$status" -eq 0 ]
    [[ "$output" != *"Updating package lists"* ]]
}

@test "pkg_install does nothing under DRY_RUN" {
    DRY_RUN=1
    run pkg_install "nmap"
    [ "$status" -eq 0 ]
}

@test "_install_verified short-circuits under DRY_RUN" {
    DRY_RUN=1
    run _install_verified "definitely_nonexistent_tool_xyz123"
    [ "$status" -eq 0 ]
}

@test "_install_verified really checks when not a dry run" {
    DRY_RUN=0
    run _install_verified "definitely_nonexistent_tool_xyz123"
    [ "$status" -ne 0 ]
}

#===============================================================================
# The command line
#===============================================================================

@test "--help exits 0 and shows usage" {
    run "$NETREAPER_INSTALL" --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Usage"* ]]
}

@test "--help documents every dispatched category" {
    run "$NETREAPER_INSTALL" --help
    [ "$status" -eq 0 ]
    for c in scanning wireless web exploit osint creds traffic stress utils; do
        [[ "$output" == *"$c"* ]] || { echo "undocumented: $c" >&2; return 1; }
    done
}

@test "the installer is executable" {
    [ -x "$NETREAPER_INSTALL" ]
}

@test "--dry-run is accepted and announced" {
    run "$NETREAPER_INSTALL" --dry-run --help
    [ "$status" -eq 0 ]
}

@test "an unknown command is refused" {
    run "$NETREAPER_INSTALL" definitely_not_a_command
    [ "$status" -ne 0 ]
}
