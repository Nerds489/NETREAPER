#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# NETREAPER Installer
# ═══════════════════════════════════════════════════════════════════════════════
# Installs the NETREAPER bash CLI to your system.
#
# Usage:
#   sudo ./install.sh         # Install system-wide to /usr/local/bin (recommended)
#   ./install.sh --user       # Install to ~/.local/bin (user only)
#   ./install.sh --uninstall  # Remove installation
#   ./install.sh --tools      # Also install security tools
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly VERSION=$(cat "$SCRIPT_DIR/VERSION" 2>/dev/null || echo "unknown")

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

log()     { echo -e "${CYAN}[*]${RESET} $*"; }
success() { echo -e "${GREEN}[✓]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
error()   { echo -e "${RED}[✗]${RESET} $*" >&2; }

# Determine install location
USER_MODE=false
if [[ "${1:-}" == "--user" || "${2:-}" == "--user" ]]; then
    USER_MODE=true
fi

if [[ "$USER_MODE" == true ]]; then
    BIN_DIR="$HOME/.local/bin"
elif [[ $EUID -eq 0 ]]; then
    BIN_DIR="/usr/local/bin"
else
    # Not root and not --user, default to user install with warning
    BIN_DIR="$HOME/.local/bin"
    USER_MODE=true
fi

#═══════════════════════════════════════════════════════════════════════════════
# INSTALL
#═══════════════════════════════════════════════════════════════════════════════

install_netreaper() {
    echo ""
    echo -e "${BOLD}NETREAPER ${VERSION} Installer${RESET}"
    echo ""

    # Create bin directory
    mkdir -p "$BIN_DIR"

    # Remove old pipx installation if exists
    if command -v pipx &>/dev/null; then
        if pipx list 2>/dev/null | grep -q netreaper; then
            log "Removing old Python TUI installation..."
            pipx uninstall netreaper 2>/dev/null || true
        fi
    fi

    # Remove existing symlinks from both locations
    for dir in "/usr/local/bin" "$HOME/.local/bin"; do
        if [[ -e "$dir/netreaper" ]]; then
            rm -f "$dir/netreaper" 2>/dev/null || true
        fi
    done

    # Set permissions
    chmod +x "$SCRIPT_DIR/netreaper"
    chmod +x "$SCRIPT_DIR/bin/netreaper"

    # Create symlink
    ln -sf "$SCRIPT_DIR/netreaper" "$BIN_DIR/netreaper"

    # Verify
    if [[ -L "$BIN_DIR/netreaper" ]]; then
        success "Installed to $BIN_DIR/netreaper"
    else
        error "Failed to create symlink"
        exit 1
    fi

    # Check PATH for user installs
    if [[ "$USER_MODE" == true ]] && [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
        warn "$BIN_DIR not in PATH"
        echo ""
        echo "Add to your shell config:"
        echo "  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc"
        echo "  source ~/.bashrc"
    fi

    echo ""
    success "NETREAPER ${VERSION} installed"
    echo ""
    if [[ "$USER_MODE" == true ]]; then
        echo "  Run: netreaper"
        warn "Note: 'sudo netreaper' won't work with user install"
        echo "  For sudo support, reinstall with: sudo ./install.sh"
    else
        echo "  Run: sudo netreaper"
    fi
    echo "  Help: netreaper --help"
    echo ""
}

#═══════════════════════════════════════════════════════════════════════════════
# UNINSTALL
#═══════════════════════════════════════════════════════════════════════════════

uninstall_netreaper() {
    echo ""
    echo -e "${BOLD}NETREAPER Uninstaller${RESET}"
    echo ""

    # Remove symlinks from both locations
    for dir in "/usr/local/bin" "$HOME/.local/bin"; do
        if [[ -e "$dir/netreaper" ]]; then
            rm -f "$dir/netreaper" 2>/dev/null || sudo rm -f "$dir/netreaper" 2>/dev/null || true
            success "Removed $dir/netreaper"
        fi
    done

    # Remove pipx if installed
    if command -v pipx &>/dev/null; then
        pipx uninstall netreaper 2>/dev/null && success "Removed pipx installation" || true
    fi

    # Ask about config
    if [[ -d "$HOME/.netreaper" ]]; then
        echo ""
        read -r -p "Remove config directory ~/.netreaper? [y/N]: " ans
        if [[ "${ans,,}" == y* ]]; then
            rm -rf "$HOME/.netreaper"
            success "Removed ~/.netreaper"
        fi
    fi

    echo ""
    success "Uninstall complete"
}

#═══════════════════════════════════════════════════════════════════════════════
# TOOLS
#═══════════════════════════════════════════════════════════════════════════════

install_tools() {
    if [[ -x "$SCRIPT_DIR/install-tools.sh" ]]; then
        exec "$SCRIPT_DIR/install-tools.sh" install-all
    else
        error "install-tools.sh not found"
        exit 1
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# MAIN
#═══════════════════════════════════════════════════════════════════════════════

# Parse arguments (handle --user appearing anywhere)
ACTION=""
for arg in "$@"; do
    case "$arg" in
        --uninstall|-u) ACTION="uninstall" ;;
        --tools|-t)     ACTION="tools" ;;
        --help|-h)      ACTION="help" ;;
        --user)         ;; # Already handled above
        *)              ;;
    esac
done

case "$ACTION" in
    uninstall)
        uninstall_netreaper
        ;;
    tools)
        install_netreaper
        install_tools
        ;;
    help)
        echo "NETREAPER Installer"
        echo ""
        echo "Usage:"
        echo "  sudo ./install.sh         Install system-wide (recommended)"
        echo "  ./install.sh --user       Install to ~/.local/bin"
        echo ""
        echo "Options:"
        echo "  --user          Install to ~/.local/bin instead of /usr/local/bin"
        echo "  --uninstall, -u Remove NETREAPER"
        echo "  --tools, -t     Install + security tools"
        echo "  --help, -h      Show this help"
        ;;
    *)
        install_netreaper
        ;;
esac
