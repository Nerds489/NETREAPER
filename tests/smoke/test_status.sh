#!/bin/bash
#═══════════════════════════════════════════════════════════════════════════════
# NETREAPER Smoke Test: Status Command
#═══════════════════════════════════════════════════════════════════════════════

set -e
cd "$(dirname "$0")/../.."
export NR_NON_INTERACTIVE=1

# Status command
./bin/netreaper status > /dev/null

echo "Status smoke test passed"
