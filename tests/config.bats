#!/usr/bin/env bats
# ═══════════════════════════════════════════════════════════════════════════════
# NETREAPER - Test Suite: Configuration System
# ═══════════════════════════════════════════════════════════════════════════════
# Tests for persistent configuration management
# ═══════════════════════════════════════════════════════════════════════════════

# Get the project root directory
NETREAPER_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"

# Setup - use temporary HOME to avoid modifying real config
setup() {
    # Create temporary home directory for test isolation
    export TEST_HOME="$BATS_TEST_TMPDIR/home"
    mkdir -p "$TEST_HOME"

    # Override HOME and NETREAPER paths to use temp directory
    export HOME="$TEST_HOME"
    export NETREAPER_HOME="$TEST_HOME/.netreaper"
    export NETREAPER_CONFIG_DIR="$NETREAPER_HOME/config"
    export NETREAPER_CONFIG_FILE="$NETREAPER_CONFIG_DIR/config.conf"

    # Suppress extraneous output during tests
    export NR_SUPPRESS_OUTPUT=1

    # Path to netreaper CLI
    NETREAPER="$BATS_TEST_DIRNAME/../bin/netreaper"
}

# Teardown - cleanup temp files
teardown() {
    rm -rf "$TEST_HOME" 2>/dev/null || true
}

#───────────────────────────────────────────────────────────────────────────────
# Config show tests
#───────────────────────────────────────────────────────────────────────────────

@test "netreaper config show returns 0" {
    run "$NETREAPER" config show
    [ "$status" -eq 0 ]
}

@test "netreaper config show displays configuration header" {
    run "$NETREAPER" config show
    [ "$status" -eq 0 ]
    [[ "$output" == *"Configuration"* ]]
}

@test "netreaper config show displays config file path" {
    run "$NETREAPER" config show
    [ "$status" -eq 0 ]
    [[ "$output" == *".netreaper"* ]]
}

@test "netreaper config (no subcommand) shows config" {
    run "$NETREAPER" config
    [ "$status" -eq 0 ]
    [[ "$output" == *"Configuration"* ]]
}

#───────────────────────────────────────────────────────────────────────────────
# Config get tests
#───────────────────────────────────────────────────────────────────────────────

@test "netreaper config get log_level returns non-empty value" {
    run "$NETREAPER" config get log_level
    [ "$status" -eq 0 ]
    [ -n "$output" ]
}

@test "netreaper config get log_level returns INFO by default" {
    run "$NETREAPER" config get log_level
    [ "$status" -eq 0 ]
    [ "$output" = "INFO" ]
}

@test "netreaper config get file_logging returns true by default" {
    run "$NETREAPER" config get file_logging
    [ "$status" -eq 0 ]
    [ "$output" = "true" ]
}

@test "netreaper config get without key fails" {
    run "$NETREAPER" config get
    [ "$status" -ne 0 ]
}

@test "netreaper config get nonexistent_key fails" {
    run "$NETREAPER" config get nonexistent_key_xyz123
    [ "$status" -ne 0 ]
}

#───────────────────────────────────────────────────────────────────────────────
# Config set tests
#───────────────────────────────────────────────────────────────────────────────

@test "netreaper config set test_key test_value persists" {
    # Set a test key
    run "$NETREAPER" config set test_key test_value
    [ "$status" -eq 0 ]

    # Get should return the value
    run "$NETREAPER" config get test_key
    [ "$status" -eq 0 ]
    [ "$output" = "test_value" ]
}

@test "netreaper config set updates existing key" {
    # Set initial value
    run "$NETREAPER" config set log_level DEBUG
    [ "$status" -eq 0 ]

    # Verify it was set
    run "$NETREAPER" config get log_level
    [ "$status" -eq 0 ]
    [ "$output" = "DEBUG" ]
}

@test "netreaper config set without key fails" {
    run "$NETREAPER" config set
    [ "$status" -ne 0 ]
}

@test "netreaper config set without value fails" {
    run "$NETREAPER" config set somekey
    [ "$status" -ne 0 ]
}

#───────────────────────────────────────────────────────────────────────────────
# Config path tests
#───────────────────────────────────────────────────────────────────────────────

@test "netreaper config path returns correct path" {
    run "$NETREAPER" config path
    [ "$status" -eq 0 ]
    [[ "$output" == *".netreaper/config/config.conf"* ]]
}

#───────────────────────────────────────────────────────────────────────────────
# Config edit tests (non-interactive behavior)
#───────────────────────────────────────────────────────────────────────────────

@test "netreaper config edit fails in non-interactive mode" {
    export NR_NON_INTERACTIVE=1
    run "$NETREAPER" config edit
    [ "$status" -ne 0 ]
}

@test "netreaper config edit fails without TTY" {
    # Run without TTY by piping input
    run bash -c "echo '' | $NETREAPER config edit"
    [ "$status" -ne 0 ]
}

#───────────────────────────────────────────────────────────────────────────────
# Config reset tests
#───────────────────────────────────────────────────────────────────────────────

@test "netreaper config reset restores defaults in non-interactive mode" {
    # First, change a value
    run "$NETREAPER" config set log_level DEBUG
    [ "$status" -eq 0 ]

    # Reset in non-interactive mode (skips confirmation)
    export NR_NON_INTERACTIVE=1
    run "$NETREAPER" config reset
    [ "$status" -eq 0 ]

    # Verify it was reset to default
    unset NR_NON_INTERACTIVE
    run "$NETREAPER" config get log_level
    [ "$status" -eq 0 ]
    [ "$output" = "INFO" ]
}

#───────────────────────────────────────────────────────────────────────────────
# Config file creation tests
#───────────────────────────────────────────────────────────────────────────────

@test "config file is created on first run" {
    # Remove any existing config
    rm -f "$NETREAPER_CONFIG_FILE"

    # Run a command that triggers init_config
    run "$NETREAPER" config show
    [ "$status" -eq 0 ]

    # Verify config file was created
    [ -f "$NETREAPER_CONFIG_FILE" ]
}

@test "config file has correct permissions" {
    run "$NETREAPER" config show
    [ "$status" -eq 0 ]

    # Check permissions (should be 600)
    perms=$(stat -c %a "$NETREAPER_CONFIG_FILE" 2>/dev/null || stat -f %Lp "$NETREAPER_CONFIG_FILE" 2>/dev/null)
    [ "$perms" = "600" ]
}

@test "config directory is created if missing" {
    # Remove config directory
    rm -rf "$NETREAPER_CONFIG_DIR"

    # Run command
    run "$NETREAPER" config show
    [ "$status" -eq 0 ]

    # Verify directory was created
    [ -d "$NETREAPER_CONFIG_DIR" ]
}

#───────────────────────────────────────────────────────────────────────────────
# Invalid subcommand tests
#───────────────────────────────────────────────────────────────────────────────

@test "netreaper config invalid_subcommand fails" {
    run "$NETREAPER" config invalid_subcommand_xyz
    [ "$status" -ne 0 ]
}

#───────────────────────────────────────────────────────────────────────────────
# Custom key persistence tests
#───────────────────────────────────────────────────────────────────────────────

@test "custom keys survive config reload" {
    # Set a custom key
    run "$NETREAPER" config set my_custom_setting my_custom_value
    [ "$status" -eq 0 ]

    # Set another key to trigger a file rewrite
    run "$NETREAPER" config set log_level WARNING
    [ "$status" -eq 0 ]

    # Custom key should still be there
    run "$NETREAPER" config get my_custom_setting
    [ "$status" -eq 0 ]
    [ "$output" = "my_custom_value" ]
}
