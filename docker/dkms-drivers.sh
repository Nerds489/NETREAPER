#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Provision the injection-capable Realtek USB Wi-Fi drivers via DKMS (#94).
#
# The three the README recommends for monitor mode + injection:
#   rtl8812au  rtl8814au  rtl8821au
#
# DKMS rebuilds them automatically on each kernel update, which is the point:
# out-of-tree Realtek drivers otherwise break on every `apt upgrade` that bumps
# the kernel. Runs on the HOST, not in a container: a driver is kernel-space and
# must match the running kernel.
#
# This CANNOT be verified without the matching kernel headers and, ideally, the
# hardware, so treat a clean run as "queued for DKMS", not "confirmed working".
# Verify with `dkms status` and `ip link` after a reboot.
set -euo pipefail

DRIVERS=(rtl8812au rtl8814au rtl8821au)
# The morrownr trees are the maintained source for all three chipsets.
declare -A REPOS=(
    [rtl8812au]="https://github.com/morrownr/8812au-20210820"
    [rtl8814au]="https://github.com/morrownr/8814au"
    [rtl8821au]="https://github.com/morrownr/8821au-20210708"
)

need_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "This installs kernel modules and must run as root (sudo)." >&2
        exit 1
    fi
}

prereqs() {
    echo "[*] Installing build prerequisites (dkms, headers, git)..."
    if command -v apt-get >/dev/null; then
        apt-get update
        apt-get install -y --no-install-recommends \
            dkms git build-essential "linux-headers-$(uname -r)"
    elif command -v dnf >/dev/null; then
        dnf install -y dkms git "kernel-devel-$(uname -r)" || dnf install -y dkms git kernel-devel
    elif command -v pacman >/dev/null; then
        pacman -Sy --noconfirm dkms git linux-headers
    else
        echo "No known package manager (apt/dnf/pacman); install dkms + kernel headers by hand." >&2
        exit 1
    fi
}

# The Debian/Ubuntu shortcut: one package covers all three chipsets.
try_apt_shortcut() {
    command -v apt-get >/dev/null || return 1
    apt-get install -y realtek-rtl88xxau-dkms 2>/dev/null || return 1
    echo "[ok] realtek-rtl88xxau-dkms installed (covers 8812/8814/8821au)."
    return 0
}

install_driver() {
    local name="$1" repo="${REPOS[$1]}" src="/usr/src/${1}-git"
    if dkms status 2>/dev/null | grep -qi "$name"; then
        echo "[skip] $name already registered with DKMS."
        return 0
    fi
    echo "[*] Fetching $name from $repo ..."
    rm -rf "$src"
    git clone --depth 1 "$repo" "$src"
    # morrownr trees ship a dkms.conf; build against the running kernel.
    local ver
    ver="$(awk -F'"' '/PACKAGE_VERSION/{print $2; exit}' "$src/dkms.conf" 2>/dev/null || echo 1.0)"
    dkms add    "$src" || dkms add "$name/$ver" || true
    dkms build  "$name/$ver"
    dkms install "$name/$ver"
    echo "[ok] $name built and installed."
}

main() {
    need_root
    prereqs
    if try_apt_shortcut; then
        echo "Done. Reboot, then check: dkms status ; ip link"
        exit 0
    fi
    for d in "${DRIVERS[@]}"; do
        install_driver "$d"
    done
    echo "Done. Reboot, then check: dkms status ; ip link"
}

main "$@"
