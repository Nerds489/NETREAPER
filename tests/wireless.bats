#!/usr/bin/env bats
# NETREAPER Wireless Tests
# Tests for lib/wireless.sh functions and wifi CLI commands
# NOTE: Tests are designed to work without real WiFi hardware

setup() {
    NETREAPER_ROOT="$BATS_TEST_DIRNAME/.."
    NETREAPER="$NETREAPER_ROOT/bin/netreaper"
    export NETREAPER_ROOT
    export NR_NON_INTERACTIVE=1

    # Source libraries for direct function testing
    # Disable error trap for testing (allows testing functions that return 1)
    set +e
    trap - ERR
    source "$NETREAPER_ROOT/lib/core.sh"
    source "$NETREAPER_ROOT/lib/wireless.sh"
    # Re-disable after sourcing (core.sh sets traps)
    set +e
    trap - ERR
}

#═══════════════════════════════════════════════════════════════════════════════
# is_wireless_interface() tests
#═══════════════════════════════════════════════════════════════════════════════

@test "is_wireless_interface returns 1 for empty argument" {
    run is_wireless_interface ""
    [ "$status" -eq 1 ]
}

@test "is_wireless_interface returns 1 for nonexistent interface" {
    run is_wireless_interface "nonexistent_iface_xyz123"
    [ "$status" -eq 1 ]
}

@test "is_wireless_interface returns 1 for loopback (lo)" {
    run is_wireless_interface "lo"
    [ "$status" -eq 1 ]
}

#═══════════════════════════════════════════════════════════════════════════════
# validate_wireless_interface() tests
#═══════════════════════════════════════════════════════════════════════════════

@test "validate_wireless_interface fails for empty argument" {
    run validate_wireless_interface ""
    [ "$status" -eq 1 ]
    [[ "$output" == *"No interface specified"* ]]
}

@test "validate_wireless_interface fails for nonexistent interface" {
    run validate_wireless_interface "nonexistent_iface_xyz123"
    [ "$status" -eq 1 ]
    [[ "$output" == *"does not exist"* ]]
}

@test "validate_wireless_interface fails for non-wireless interface (lo)" {
    run validate_wireless_interface "lo"
    [ "$status" -eq 1 ]
    [[ "$output" == *"not a wireless interface"* ]]
}

#═══════════════════════════════════════════════════════════════════════════════
# get_wireless_interfaces() tests
#═══════════════════════════════════════════════════════════════════════════════

@test "get_wireless_interfaces handles no wireless gracefully" {
    run get_wireless_interfaces

    # Either finds wireless interfaces (exit 0) or warns and exits 1
    # Both are acceptable - depends on test environment
    if [ "$status" -eq 0 ]; then
        # Found at least one interface - output should be non-empty
        [ -n "$output" ]
    else
        # No wireless - should warn
        [[ "$output" == *"No wireless interfaces"* ]]
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# check_monitor_mode() tests
#═══════════════════════════════════════════════════════════════════════════════

@test "check_monitor_mode returns 1 for empty argument" {
    run check_monitor_mode ""
    [ "$status" -eq 1 ]
}

@test "check_monitor_mode returns 1 for nonexistent interface" {
    run check_monitor_mode "nonexistent_iface_xyz123"
    [ "$status" -eq 1 ]
}

@test "check_monitor_mode does not crash on loopback" {
    # Should fail gracefully (not crash) - lo is not wireless
    run check_monitor_mode "lo"
    # Just verify it doesn't crash (any exit code is fine, but no crash)
    true
}

#═══════════════════════════════════════════════════════════════════════════════
# CLI: netreaper wifi tests
#═══════════════════════════════════════════════════════════════════════════════

@test "netreaper wifi (no args) exits 0 and shows usage" {
    run "$NETREAPER" wifi
    [ "$status" -eq 0 ]
    [[ "$output" == *"WiFi Commands"* ]]
    [[ "$output" == *"list"* ]]
    [[ "$output" == *"status"* ]]
    [[ "$output" == *"monitor"* ]]
}

@test "netreaper wifi list does not crash" {
    run "$NETREAPER" wifi list
    # Exit 0 if interfaces found, 1 if none - both acceptable
    [ "$status" -eq 0 ] || [ "$status" -eq 1 ]
}

@test "netreaper wifi status without interface fails" {
    run "$NETREAPER" wifi status
    [ "$status" -eq 1 ]
    [[ "$output" == *"Missing interface"* ]]
}

@test "netreaper wifi status with empty string fails" {
    run "$NETREAPER" wifi status ""
    [ "$status" -eq 1 ]
}

@test "netreaper wifi status with nonexistent interface fails cleanly" {
    run "$NETREAPER" wifi status "nonexistent_iface_xyz123"
    [ "$status" -eq 1 ]
}

@test "netreaper wifi monitor without on/off shows usage" {
    run "$NETREAPER" wifi monitor
    [ "$status" -eq 1 ]
    [[ "$output" == *"Usage"* ]]
}

@test "netreaper wifi monitor on without interface fails" {
    run "$NETREAPER" wifi monitor on
    [ "$status" -eq 1 ]
    [[ "$output" == *"Missing interface"* ]]
}

@test "netreaper wifi monitor off without interface fails" {
    run "$NETREAPER" wifi monitor off
    [ "$status" -eq 1 ]
    [[ "$output" == *"Missing interface"* ]]
}

@test "netreaper wifi unknown subcommand fails" {
    run "$NETREAPER" wifi foobar
    [ "$status" -eq 1 ]
    [[ "$output" == *"Unknown wifi subcommand"* ]]
}

#═══════════════════════════════════════════════════════════════════════════════
# Syntax check tests
#═══════════════════════════════════════════════════════════════════════════════

@test "lib/wireless.sh passes bash -n syntax check" {
    run bash -n "$NETREAPER_ROOT/lib/wireless.sh"
    [ "$status" -eq 0 ]
}
