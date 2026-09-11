#!/usr/bin/env bats
# ═══════════════════════════════════════════════════════════════════════════════
# NETREAPER - Test Suite: Installer Help and Version
# ═══════════════════════════════════════════════════════════════════════════════
# The Bash CLI has been retired; the `netreaper` command is now the Python CLI
# (installed via pip, covered by pytest). What remains here is the thin Bash
# tool-installer, bin/netreaper-install.
# ═══════════════════════════════════════════════════════════════════════════════

# Get the project root directory
NETREAPER_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
INSTALL="$NETREAPER_ROOT/bin/netreaper-install"

@test "netreaper-install --help exits with code 0" {
    run "$INSTALL" --help
    [ "$status" -eq 0 ]
}

@test "netreaper-install -h exits with code 0" {
    run "$INSTALL" -h
    [ "$status" -eq 0 ]
}

@test "netreaper-install --help shows usage information" {
    run "$INSTALL" --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Usage"* ]] || [[ "$output" == *"usage"* ]] || [[ "$output" == *"USAGE"* ]] || [[ "$output" == *"install"* ]]
}

@test "netreaper-install --help mentions tool installation" {
    run "$INSTALL" --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"tool"* ]] || [[ "$output" == *"Tool"* ]] || [[ "$output" == *"install"* ]] || [[ "$output" == *"Install"* ]]
}

@test "netreaper-install help shows version in output" {
    run "$INSTALL" --help
    [ "$status" -eq 0 ]
    [[ "$output" =~ [0-9]+\.[0-9]+\.[0-9]+ ]]
}
