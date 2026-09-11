#!/usr/bin/env bats
# ═══════════════════════════════════════════════════════════════════════════════
# NETREAPER - Test Suite: Syntax Validation
# ═══════════════════════════════════════════════════════════════════════════════
# Tests that the remaining shell scripts pass bash -n syntax checking.
# The Bash runtime has been retired; only the thin tool-installer and the
# top-level maintenance scripts remain. The Python CLI is covered by pytest.
# ═══════════════════════════════════════════════════════════════════════════════

# Get the project root directory
NETREAPER_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"

@test "netreaper-install passes bash -n syntax check" {
    run bash -n "$NETREAPER_ROOT/bin/netreaper-install"
    [ "$status" -eq 0 ]
}

@test "All .sh files in project pass bash -n syntax check" {
    failed_files=""
    while IFS= read -r -d '' file; do
        if ! bash -n "$file" 2>/dev/null; then
            failed_files="$failed_files $file"
        fi
    done < <(find "$NETREAPER_ROOT" -name "*.sh" -type f -not -path "*/.venv/*" -print0 2>/dev/null)

    if [ -n "$failed_files" ]; then
        echo "Failed files:$failed_files"
        return 1
    fi
}
