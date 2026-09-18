"""Linux distribution detection and package manager mapping."""
import platform
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Self


class DistroFamily(Enum):
    """Linux distribution families."""

    DEBIAN = "debian"
    REDHAT = "redhat"
    ARCH = "arch"
    SUSE = "suse"
    ALPINE = "alpine"
    VOID = "void"
    GENTOO = "gentoo"
    NIXOS = "nixos"
    UNKNOWN = "unknown"


class PackageManager(Enum):
    """Package manager identifiers."""

    APT = "apt"
    DNF = "dnf"
    YUM = "yum"
    PACMAN = "pacman"
    ZYPPER = "zypper"
    APK = "apk"
    XBPS = "xbps"
    EMERGE = "emerge"
    NIX = "nix"
    UNKNOWN = "unknown"


# (family, exact ID values, ID_LIKE markers). ORDERED: ID_LIKE overlaps, so a
# Rocky os-release listing both "rhel" and "fedora" must resolve the same way it
# did when this was an if-ladder, and Manjaro listing "arch" likewise.
_FAMILY_MARKERS: tuple[tuple["DistroFamily", frozenset[str], tuple[str, ...]], ...] = (
    (
        DistroFamily.DEBIAN,
        frozenset({"debian", "ubuntu", "kali", "parrot", "mint", "pop", "elementary"}),
        ("debian", "ubuntu"),
    ),
    (
        DistroFamily.REDHAT,
        frozenset({"fedora", "rhel", "centos", "rocky", "alma", "oracle"}),
        ("fedora", "rhel"),
    ),
    (
        DistroFamily.ARCH,
        frozenset({"arch", "manjaro", "endeavouros", "garuda", "blackarch"}),
        ("arch",),
    ),
    (
        DistroFamily.SUSE,
        frozenset({"opensuse", "suse", "opensuse-leap", "opensuse-tumbleweed"}),
        ("suse",),
    ),
    (DistroFamily.ALPINE, frozenset({"alpine"}), ()),
    (DistroFamily.VOID, frozenset({"void"}), ()),
    (DistroFamily.GENTOO, frozenset({"gentoo"}), ()),
    (DistroFamily.NIXOS, frozenset({"nixos"}), ()),
)


@dataclass
class SystemInfo:
    """Detected system information."""

    distro_id: str
    distro_name: str
    distro_version: str
    distro_family: DistroFamily
    package_manager: PackageManager
    is_immutable: bool
    immutable_type: str | None
    is_wsl: bool
    is_container: bool
    is_steamdeck: bool
    architecture: str
    kernel_version: str

    @classmethod
    def detect(cls) -> Self:
        """Detect current system information."""
        # Read os-release
        os_release = cls._read_os_release()

        distro_id = os_release.get("ID", "unknown").lower()
        distro_name = os_release.get("NAME", "Unknown")
        distro_version = os_release.get("VERSION_ID", "")

        # Determine family
        id_like = os_release.get("ID_LIKE", "").lower().split()
        distro_family = cls._determine_family(distro_id, id_like)

        # Determine package manager
        package_manager = cls._determine_package_manager(distro_id, distro_family)

        # Check special system types
        is_immutable, immutable_type = cls._check_immutable()
        is_wsl = cls._check_wsl()
        is_container = cls._check_container()
        is_steamdeck = cls._check_steamdeck()

        return cls(
            distro_id=distro_id,
            distro_name=distro_name,
            distro_version=distro_version,
            distro_family=distro_family,
            package_manager=package_manager,
            is_immutable=is_immutable,
            immutable_type=immutable_type,
            is_wsl=is_wsl,
            is_container=is_container,
            is_steamdeck=is_steamdeck,
            architecture=platform.machine(),
            kernel_version=platform.release(),
        )

    @staticmethod
    def _read_os_release() -> dict[str, str]:
        """Read /etc/os-release file."""
        os_release = {}
        for path in [Path("/etc/os-release"), Path("/usr/lib/os-release")]:
            if path.exists():
                content = path.read_text()
                for line in content.splitlines():
                    if "=" in line:
                        key, _, value = line.partition("=")
                        os_release[key] = value.strip('"\'')
                break
        return os_release

    @staticmethod
    def _determine_family(distro_id: str, id_like: list[str]) -> DistroFamily:
        """Determine distribution family.

        Ordered, because ID_LIKE overlaps: a Rocky os-release lists both "rhel"
        and "fedora", and Manjaro lists "arch". First match wins, as it did
        when this was an if-ladder.
        """
        for family, ids, like_markers in _FAMILY_MARKERS:
            if distro_id in ids or any(m in id_like for m in like_markers):
                return family
        return DistroFamily.UNKNOWN

    @staticmethod
    def _determine_package_manager(
        distro_id: str, family: DistroFamily
    ) -> PackageManager:
        """Determine package manager for distribution."""
        manager_map = {
            DistroFamily.DEBIAN: PackageManager.APT,
            DistroFamily.REDHAT: PackageManager.DNF,
            DistroFamily.ARCH: PackageManager.PACMAN,
            DistroFamily.SUSE: PackageManager.ZYPPER,
            DistroFamily.ALPINE: PackageManager.APK,
            DistroFamily.VOID: PackageManager.XBPS,
            DistroFamily.GENTOO: PackageManager.EMERGE,
            DistroFamily.NIXOS: PackageManager.NIX,
        }
        return manager_map.get(family, PackageManager.UNKNOWN)

    @staticmethod
    def _check_immutable() -> tuple[bool, str | None]:
        """Check if system is immutable."""
        # rpm-ostree (Fedora Silverblue, Kinoite)
        if Path("/run/ostree-booted").exists():
            return True, "ostree"
        # Check for read-only /usr
        if Path("/usr").stat().st_mode & 0o222 == 0:
            return True, "readonly-usr"
        return False, None

    @staticmethod
    def _check_wsl() -> bool:
        """Check if running in WSL."""
        return "microsoft" in platform.release().lower()

    @staticmethod
    def _check_container() -> bool:
        """Check if running in container."""
        return Path("/.dockerenv").exists() or Path("/run/.containerenv").exists()

    @staticmethod
    def _check_steamdeck() -> bool:
        """Check if running on Steam Deck."""
        os_release = SystemInfo._read_os_release()
        return os_release.get("ID") == "steamos"


# Singleton for cached system info
_system_info: SystemInfo | None = None


def get_system_info() -> SystemInfo:
    """Get cached system information."""
    global _system_info
    if _system_info is None:
        _system_info = SystemInfo.detect()
    return _system_info
