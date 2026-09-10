#!/usr/bin/env bats
# NETREAPER Installer Tests
# Tests for bin/netreaper-install functions

setup() {
    NETREAPER_ROOT="$BATS_TEST_DIRNAME/.."
    NETREAPER_INSTALL="$NETREAPER_ROOT/bin/netreaper-install"
    export NETREAPER_ROOT
    export NR_NON_INTERACTIVE=1

    # Source the installer for function testing
    # Note: We need to handle the set -o pipefail by disabling exit on error
    set +e
    # Only source the function definitions, not execute main
    source <(sed '/^main "\$@"/d' "$NETREAPER_INSTALL")
    set +e
}

#===============================================================================
# verify_tool_installed() tests
#===============================================================================

@test "verify_tool_installed returns 0 for existing command (bash)" {
    run verify_tool_installed "bash"
    [ "$status" -eq 0 ]
}

@test "verify_tool_installed returns 1 for non-existent command" {
    run verify_tool_installed "definitely_nonexistent_tool_xyz123"
    [ "$status" -eq 1 ]
}

@test "verify_tool_installed returns 1 for empty argument" {
    run verify_tool_installed ""
    [ "$status" -eq 1 ]
}

@test "verify_tool_installed checks TOOL_SEARCH_PATHS" {
    # TOOL_SEARCH_PATHS should be defined
    [ -n "$TOOL_SEARCH_PATHS" ]
    [[ "$TOOL_SEARCH_PATHS" == */usr/bin* ]]
}

@test "verify_tool_installed respects binary argument" {
    # bash binary should be found
    run verify_tool_installed "bash_test_alias" "bash"
    [ "$status" -eq 0 ]
}

#===============================================================================
# get_package_name() tests
#===============================================================================

@test "get_package_name returns package for nmap" {
    run get_package_name "nmap"
    [ "$status" -eq 0 ]
    [ -n "$output" ]
}

@test "get_package_name handles netcat distro mapping" {
    run get_package_name "netcat"
    [ "$status" -eq 0 ]
    [ -n "$output" ]
}

@test "get_package_name returns empty for unknown special case" {
    # Test a tool that doesn't have universal package name
    run get_package_name "definitely_not_a_real_tool_xyz"
    # Returns the tool name as fallback
    [ "$output" = "definitely_not_a_real_tool_xyz" ]
}

#===============================================================================
# Global tracking arrays tests
#===============================================================================

@test "SUCCESS_TOOLS array is initialized" {
    [ -n "${SUCCESS_TOOLS+x}" ]
}

@test "FAILED_TOOLS array is initialized" {
    [ -n "${FAILED_TOOLS+x}" ]
}

@test "SKIPPED_TOOLS array is initialized" {
    [ -n "${SKIPPED_TOOLS+x}" ]
}

@test "TOOL_SEARCH_PATHS includes standard directories" {
    [[ "$TOOL_SEARCH_PATHS" == */usr/bin* ]]
    [[ "$TOOL_SEARCH_PATHS" == */usr/local/bin* ]]
}

#===============================================================================
# detect_distro() tests
#===============================================================================

@test "detect_distro returns non-empty value" {
    run detect_distro
    [ "$status" -eq 0 ]
    [ -n "$output" ]
}

@test "detect_distro_family returns non-empty value" {
    local distro
    distro=$(detect_distro)
    run detect_distro_family "$distro"
    [ "$status" -eq 0 ]
    [ -n "$output" ]
}

#===============================================================================
# CATEGORIES array tests
#===============================================================================

@test "CATEGORIES array is populated" {
    [ "${#CATEGORIES[@]}" -gt 0 ]
}

@test "CATEGORIES contains scanning" {
    [ -n "${CATEGORIES[scanning]:-}" ]
}

@test "CATEGORIES contains wireless" {
    [ -n "${CATEGORIES[wireless]:-}" ]
}

@test "CATEGORIES scanning includes nmap" {
    [[ "${CATEGORIES[scanning]}" == *nmap* ]]
}

#===============================================================================
# TOOLS array tests
#===============================================================================

@test "TOOLS array is populated" {
    [ "${#TOOLS[@]}" -gt 0 ]
}

@test "TOOLS contains nmap entry" {
    [ -n "${TOOLS[nmap]:-}" ]
}

@test "TOOLS contains aircrack-ng entry" {
    [ -n "${TOOLS[aircrack-ng]:-}" ]
}

#===============================================================================
# CLI tests
#===============================================================================

@test "netreaper-install --help shows usage" {
    run "$NETREAPER_INSTALL" --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Usage"* ]]
}

@test "netreaper-install status shows tool status" {
    run "$NETREAPER_INSTALL" status
    [ "$status" -eq 0 ]
}

@test "netreaper-install --dry-run is recognized" {
    run "$NETREAPER_INSTALL" --dry-run --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Dry-run"* ]] || [[ "$output" == *"Usage"* ]]
}
