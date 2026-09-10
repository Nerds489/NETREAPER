#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# NETREAPER - Version Resolution Helper
# ═══════════════════════════════════════════════════════════════════════════════
# Copyright (c) 2025 Nerds489
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Shared helper for resolving NETREAPER_ROOT and VERSION.
# This centralizes version handling to prevent drift between CLI output,
# VERSION file, documentation, and release workflow.
#
# Usage:
#   source "$NETREAPER_ROOT/lib/version.sh"   # If NETREAPER_ROOT is already set
#   source "/path/to/lib/version.sh"          # Auto-detects NETREAPER_ROOT
#
# NETREAPER_ROOT Resolution Order:
#   1. NETREAPER_ROOT environment variable (if set and valid)
#   2. Script's actual location (following symlinks)
#   3. /usr/local/share/netreaper (system install)
#   4. /opt/netreaper (alternative system install)
#   5. ~/.local/share/netreaper (user install)
# ═══════════════════════════════════════════════════════════════════════════════

# Prevent multiple sourcing
[[ -n "${_NETREAPER_VERSION_LOADED:-}" ]] && return 0
readonly _NETREAPER_VERSION_LOADED=1

# --- NETREAPER_ROOT Resolution ------------------------------------------------
# If NETREAPER_ROOT is not already set, compute it from this file's location.
# This file lives in lib/, so the root is one directory up.
if [[ -z "${NETREAPER_ROOT:-}" ]]; then
    # Follow symlinks to get actual script location
    _vw_script_path=""
    if command -v readlink &>/dev/null; then
        _vw_script_path="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null)" || _vw_script_path="${BASH_SOURCE[0]}"
    else
        _vw_script_path="${BASH_SOURCE[0]}"
    fi

    if ! NETREAPER_ROOT="$(cd "$(dirname "$_vw_script_path")/.." 2>/dev/null && pwd)"; then
        # Fallback: check standard locations
        if [[ -d "/usr/local/share/netreaper/lib" ]]; then
            NETREAPER_ROOT="/usr/local/share/netreaper"
        elif [[ -d "/opt/netreaper/lib" ]]; then
            NETREAPER_ROOT="/opt/netreaper"
        elif [[ -d "${HOME}/.local/share/netreaper/lib" ]]; then
            NETREAPER_ROOT="${HOME}/.local/share/netreaper"
        else
            echo "ERROR: Failed to resolve NETREAPER_ROOT from ${BASH_SOURCE[0]}" >&2
            return 1
        fi
    fi
    unset _vw_script_path
fi
readonly NETREAPER_ROOT 2>/dev/null || true  # May already be readonly

# --- VERSION Resolution -------------------------------------------------------
# Read VERSION file (first line, strip whitespace). Fallback to "unknown".
if [[ -z "${VERSION:-}" ]]; then
    if [[ -f "$NETREAPER_ROOT/VERSION" ]]; then
        IFS= read -r VERSION < "$NETREAPER_ROOT/VERSION"
        VERSION="${VERSION//[[:space:]]/}"
    else
        VERSION="unknown"
    fi
fi
readonly VERSION 2>/dev/null || true  # May already be readonly

# --- Exports ------------------------------------------------------------------
export NETREAPER_ROOT VERSION
