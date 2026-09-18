"""MAC address spoofing utilities.

Every spawn here goes through :func:`run_host`, the gated seam, with
``host_action=True``: changing our own adapter's MAC has no network target, but
it still needs the seam's exec-only argument arrays, timeout, process-group
teardown and hash-chained audit line. These helpers sit on a live attack path
(``wireless.advanced`` calls :func:`change_mac`), so a direct spawn here would
leave a hole in the trail exactly where it matters most.
"""
import re
import secrets
from pathlib import Path

from netreaper.automation.handlers._host import run_host
from netreaper.core.logging import get_logger

logger = get_logger(__name__)

# OUI prefixes for common vendors (for generating realistic MACs)
VENDOR_OUIS = {
    "apple": ["00:03:93", "00:05:02", "00:0A:27", "00:0A:95", "00:0D:93"],
    "samsung": ["00:00:F0", "00:02:78", "00:09:18", "00:12:47", "00:12:FB"],
    "intel": ["00:02:B3", "00:03:47", "00:04:23", "00:07:E9", "00:0C:F1"],
    "realtek": ["00:0A:CD", "00:0C:E7", "00:E0:4C", "00:E0:66", "52:54:00"],
    "random": [],  # Will generate fully random
}


def generate_mac(vendor: str = "random") -> str:
    """Generate a MAC address."""
    if vendor in VENDOR_OUIS and VENDOR_OUIS[vendor]:
        oui = secrets.choice(VENDOR_OUIS[vendor])
        suffix = ":".join(f"{secrets.randbelow(256):02x}" for _ in range(3))
        return f"{oui}:{suffix}"
    else:
        # Fully random (ensure locally administered bit)
        first_byte = secrets.randbelow(256) | 0x02  # Set locally administered bit
        first_byte &= 0xFE  # Clear multicast bit
        rest = [secrets.randbelow(256) for _ in range(5)]
        return ":".join(f"{b:02x}" for b in [first_byte] + rest)


def validate_mac(mac: str) -> bool:
    """Validate MAC address format.

    fullmatch, not match+$. Python's ``$`` matches at the end of the string OR
    immediately before a single trailing newline, so ``re.match(r"...$", x)``
    accepted "aa:bb:cc:dd:ee:ff\n" as a valid MAC. This function guards
    change_mac(), a destructive host action, so the value it blesses goes on to
    a command line and into logs. core/validation.py already uses fullmatch and
    says why; this is the same fix.
    """
    pattern = r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"
    return bool(re.fullmatch(pattern, mac))


async def get_current_mac(interface: str) -> str | None:
    """Get current MAC address of interface."""
    try:
        address_path = Path(f"/sys/class/net/{interface}/address")
        if address_path.exists():
            return address_path.read_text().strip()
    except Exception as e:
        logger.debug("Failed to read MAC from sysfs for %s: %s", interface, e)

    # Fallback to the ip command, through the gated seam.
    try:
        result = await run_host(["ip", "link", "show", interface])
        if result is None:
            return None

        match = re.search(r"link/ether\s+([0-9a-f:]{17})", result.stdout)
        if match:
            return match.group(1)
    except Exception as e:
        logger.debug("Failed to get MAC via ip command for %s: %s", interface, e)

    return None


async def get_permanent_mac(interface: str) -> str | None:
    """Get permanent (hardware) MAC address."""
    try:
        result = await run_host(["ethtool", "-P", interface])
        if result is None:
            return None

        match = re.search(r"Permanent address:\s+([0-9a-f:]{17})", result.stdout)
        if match:
            return match.group(1)
    except Exception as e:
        logger.debug("Failed to get permanent MAC for %s: %s", interface, e)

    return None


async def change_mac(
    interface: str, new_mac: str | None = None, vendor: str = "random"
) -> str:
    """
    Change MAC address of interface.

    If new_mac is None, generates a random one.
    Returns the new MAC address.
    """
    if new_mac is None:
        new_mac = generate_mac(vendor)

    if not validate_mac(new_mac):
        raise ValueError(f"Invalid MAC address: {new_mac}")

    # Store original MAC
    original_mac = await get_current_mac(interface)

    try:
        # Bring interface down
        await _run_ip_command(["link", "set", interface, "down"])

        # Change MAC
        await _run_ip_command(["link", "set", interface, "address", new_mac])

        # Bring interface up
        await _run_ip_command(["link", "set", interface, "up"])

        logger.info("MAC changed: %s %s -> %s", interface, original_mac, new_mac)
        return new_mac

    except Exception:
        # Try to restore original MAC
        if original_mac:
            try:
                await _run_ip_command(["link", "set", interface, "address", original_mac])
                await _run_ip_command(["link", "set", interface, "up"])
            except Exception as restore_err:
                logger.warning("Failed to restore original MAC on %s: %s", interface, restore_err)
        raise


async def restore_mac(interface: str) -> str | None:
    """Restore permanent MAC address."""
    permanent_mac = await get_permanent_mac(interface)
    if permanent_mac:
        await change_mac(interface, permanent_mac)
        logger.info("MAC restored: %s -> %s", interface, permanent_mac)
        return permanent_mac
    return None


async def _run_ip_command(args: list[str]) -> None:
    """Run an ip command through the gated seam.

    ``destructive=True``: these calls take our own interface down and rewrite its
    hardware address. A scope refusal propagates; a missing tool or a timeout
    comes back as ``None`` and is raised here, because :func:`change_mac` relies
    on a failure to trigger its restore path.
    """
    result = await run_host(["ip", *args], destructive=True)

    if result is None:
        raise RuntimeError(
            f"ip {' '.join(args)} did not run (tool missing or timed out)"
        )
    if not result.ok:
        raise RuntimeError(f"ip command failed: {result.stderr}")
