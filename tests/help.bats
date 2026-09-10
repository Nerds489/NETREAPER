#!/usr/bin/env bats
# ═══════════════════════════════════════════════════════════════════════════════
# NETREAPER - Test Suite: Help and Version
# ═══════════════════════════════════════════════════════════════════════════════
# Tests for CLI help output and version information
# ═══════════════════════════════════════════════════════════════════════════════

# Get the project root directory
NETREAPER_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"

#───────────────────────────────────────────────────────────────────────────────
# netreaper help tests
#───────────────────────────────────────────────────────────────────────────────

@test "netreaper --help exits with code 0" {
    run "$NETREAPER_ROOT/netreaper" --help
    [ "$status" -eq 0 ]
}

@test "netreaper -h exits with code 0" {
    run "$NETREAPER_ROOT/netreaper" -h
    [ "$status" -eq 0 ]
}

@test "netreaper --help shows usage information" {
    run "$NETREAPER_ROOT/netreaper" --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Usage"* ]] || [[ "$output" == *"usage"* ]] || [[ "$output" == *"USAGE"* ]]
}

@test "netreaper --help mentions available commands" {
    run "$NETREAPER_ROOT/netreaper" --help
    [ "$status" -eq 0 ]
    # Check for common command references
    [[ "$output" == *"scan"* ]] || [[ "$output" == *"recon"* ]] || [[ "$output" == *"--"* ]]
}

#───────────────────────────────────────────────────────────────────────────────
# netreaper version tests
#───────────────────────────────────────────────────────────────────────────────

@test "netreaper --version exits with code 0" {
    run "$NETREAPER_ROOT/netreaper" --version
    [ "$status" -eq 0 ]
}

@test "netreaper --version outputs version number" {
    run "$NETREAPER_ROOT/netreaper" --version
    [ "$status" -eq 0 ]
    # Version should contain a version pattern (e.g., 5.3.1)
    [[ "$output" =~ [0-9]+\.[0-9]+\.[0-9]+ ]]
}

@test "netreaper version matches VERSION file" {
    # Read version from VERSION file
    version_file=$(cat "$NETREAPER_ROOT/VERSION" 2>/dev/null | tr -d '[:space:]')

    # Get version from netreaper --version
    run "$NETREAPER_ROOT/netreaper" --version
    [ "$status" -eq 0 ]

    # Check if version file content appears in output
    [[ "$output" == *"$version_file"* ]]
}

#───────────────────────────────────────────────────────────────────────────────
# netreaper-install help tests
#───────────────────────────────────────────────────────────────────────────────

@test "netreaper-install --help exits with code 0" {
    run "$NETREAPER_ROOT/netreaper-install" --help
    [ "$status" -eq 0 ]
}

@test "netreaper-install -h exits with code 0" {
    run "$NETREAPER_ROOT/netreaper-install" -h
    [ "$status" -eq 0 ]
}

@test "netreaper-install --help shows usage information" {
    run "$NETREAPER_ROOT/netreaper-install" --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Usage"* ]] || [[ "$output" == *"usage"* ]] || [[ "$output" == *"USAGE"* ]] || [[ "$output" == *"install"* ]]
}

@test "netreaper-install --help mentions tool installation" {
    run "$NETREAPER_ROOT/netreaper-install" --help
    [ "$status" -eq 0 ]
    # Should mention tools or installation
    [[ "$output" == *"tool"* ]] || [[ "$output" == *"Tool"* ]] || [[ "$output" == *"install"* ]] || [[ "$output" == *"Install"* ]]
}

@test "netreaper-install help shows version in output" {
    run "$NETREAPER_ROOT/netreaper-install" --help
    [ "$status" -eq 0 ]
    # Version appears in help/usage output
    [[ "$output" =~ [0-9]+\.[0-9]+\.[0-9]+ ]]
}
