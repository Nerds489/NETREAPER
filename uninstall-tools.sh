#!/usr/bin/env bash
# shellcheck shell=bash
# Uninstall all NETREAPER tools for testing the installer
#
# The directive above says bash, and so does line 1, but the analyser kept
# reading this as POSIX sh regardless. Rather than keep arguing with it, the
# two constructs it objected to are now written the portable way. `case` is
# clearer than `[[ =~ ]]` here anyway: it puts the accept and the reject side
# by side instead of hiding the reject in an && chain.

set -uo pipefail

RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
RESET=$(tput sgr0)

echo ""
echo "${YELLOW}═══════════════════════════════════════════════════════════════${RESET}"
echo "${YELLOW}  NETREAPER Tool Uninstaller - FOR TESTING ONLY${RESET}"
echo "${YELLOW}═══════════════════════════════════════════════════════════════${RESET}"
echo ""

# Critical packages we should NOT remove
KEEP="curl wget git python3 python3-pip bash coreutils"

echo "${RED}[!] This will remove all pentesting tools, and cannot be undone${RESET}"
echo ""
read -p "Continue? [y/N] " -n 1 -r
echo ""

case "$REPLY" in
    [Yy]) ;;
    *) echo "Aborted."; exit 0 ;;
esac

# Extract all package names from install-tools.sh
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGES=$(grep -oP 'pkg:\K[^,"|]+' "$SCRIPT_DIR/install-tools.sh" | sort -u)

echo ""
echo "${GREEN}[*] Removing apt packages...${RESET}"
for pkg in $PACKAGES; do
    case " $KEEP " in
        *" $pkg "*) continue ;;
    esac
    if dpkg -l "$pkg" &>/dev/null; then
        echo "    Removing: $pkg"
        sudo apt-get remove --purge -y "$pkg" 2>/dev/null || true
    fi
done

echo ""
echo "${GREEN}[*] Removing all pipx packages...${RESET}"
command -v pipx &>/dev/null && pipx uninstall-all 2>/dev/null || true

echo ""
echo "${GREEN}[*] Clearing ~/.local/bin...${RESET}"
rm -rf "$HOME/.local/bin"/* 2>/dev/null || true

echo ""
echo "${GREEN}[*] Clearing ~/.local/opt...${RESET}"
rm -rf "$HOME/.local/opt"/* 2>/dev/null || true

echo ""
echo "${GREEN}[*] Clearing ~/go/bin...${RESET}"
rm -rf "$HOME/go/bin"/* 2>/dev/null || true

echo ""
echo "${GREEN}[*] Clearing ~/.cargo/bin...${RESET}"
rm -rf "$HOME/.cargo/bin"/* 2>/dev/null || true

echo ""
echo "${GREEN}[*] Apt cleanup...${RESET}"
sudo apt-get autoremove --purge -y 2>/dev/null || true
sudo apt-get clean 2>/dev/null || true

echo ""
echo "${GREEN}════════════════════════════════════════════════════════════════${RESET}"
echo "${GREEN}  Done! Run: ./install-tools.sh install-all${RESET}"
echo "${GREEN}════════════════════════════════════════════════════════════════${RESET}"
