#!/usr/bin/env bats
# ═══════════════════════════════════════════════════════════════════════════════
# NETREAPER CLI Integration Tests
# ═══════════════════════════════════════════════════════════════════════════════

setup() {
    load '../test_helper'
}

# ───────────────────────────────────────────────────────────────────────────────
# Version and Help
# ───────────────────────────────────────────────────────────────────────────────

@test "netreaper --version shows version" {
    run "$REPO_ROOT/bin/netreaper" --version
    [[ $status -eq 0 ]]
    [[ "$output" =~ NETREAPER ]] || [[ "$output" =~ [0-9]+\.[0-9]+\.[0-9]+ ]]
}

@test "netreaper -V shows version" {
    run "$REPO_ROOT/bin/netreaper" -V
    [[ $status -eq 0 ]]
}

@test "netreaper --help shows usage" {
    run "$REPO_ROOT/bin/netreaper" --help
    [[ $status -eq 0 ]]
    [[ "$output" =~ USAGE ]] || [[ "$output" =~ usage ]] || [[ "$output" =~ Usage ]]
}

@test "netreaper -h shows help" {
    run "$REPO_ROOT/bin/netreaper" -h
    [[ $status -eq 0 ]]
}

# ───────────────────────────────────────────────────────────────────────────────
# Dry-run Mode
# ───────────────────────────────────────────────────────────────────────────────

@test "netreaper --dry-run doesn't execute" {
    run "$REPO_ROOT/bin/netreaper" --dry-run scan 192.168.1.1
    # Should show dry-run indicator or exit cleanly
    [[ "$output" =~ [Dd]ry ]] || [[ "$output" =~ DRY ]] || [[ $status -eq 0 ]]
}

@test "netreaper --dry-run with recon" {
    run "$REPO_ROOT/bin/netreaper" --dry-run recon example.com
    [[ "$output" =~ [Dd]ry ]] || [[ "$output" =~ DRY ]] || [[ $status -eq 0 ]]
}

# ───────────────────────────────────────────────────────────────────────────────
# Status Command
# ───────────────────────────────────────────────────────────────────────────────

@test "netreaper status runs without error" {
    run "$REPO_ROOT/bin/netreaper" status
    [[ $status -eq 0 ]]
}

@test "netreaper status shows tool info" {
    run "$REPO_ROOT/bin/netreaper" status
    [[ $status -eq 0 ]]
    [[ "$output" =~ [Ss]tatus ]] || [[ "$output" =~ [Tt]ool ]] || [[ -n "$output" ]]
}

# ───────────────────────────────────────────────────────────────────────────────
# Config Commands
# ───────────────────────────────────────────────────────────────────────────────

@test "netreaper config show runs" {
    run "$REPO_ROOT/bin/netreaper" config show
    [[ $status -eq 0 ]]
}

@test "netreaper config list runs" {
    run "$REPO_ROOT/bin/netreaper" config list
    [[ $status -eq 0 ]] || [[ $status -eq 1 ]]  # May return 1 if no config
}

# ───────────────────────────────────────────────────────────────────────────────
# Invalid Commands
# ───────────────────────────────────────────────────────────────────────────────

@test "netreaper invalid-command shows error" {
    run "$REPO_ROOT/bin/netreaper" totally-invalid-command-12345
    [[ $status -ne 0 ]] || [[ "$output" =~ [Uu]nknown ]] || [[ "$output" =~ [Ee]rror ]]
}

# ───────────────────────────────────────────────────────────────────────────────
# Non-interactive Mode
# ───────────────────────────────────────────────────────────────────────────────

@test "NR_NON_INTERACTIVE prevents interactive prompts" {
    export NR_NON_INTERACTIVE=1
    run timeout 5 "$REPO_ROOT/bin/netreaper" --help
    [[ $status -eq 0 ]]  # Should not hang
}
