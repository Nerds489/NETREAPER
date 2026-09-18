"""Default event handlers for common operations."""
from netreaper.core.logging import get_logger
from netreaper.orchestration.events import Events, event_bus

logger = get_logger(__name__)


async def on_vulnerability_found(data: dict) -> None:
    """Handle vulnerability discovery."""
    severity = data.get("severity", "unknown")
    vuln_id = data.get("id", "unknown")
    title = data.get("title", "Unknown vulnerability")
    target = data.get("target", "")

    logger.warning(
        f"Vulnerability found: [{severity.upper()}] {vuln_id} - {title} on {target}"
    )

    # Store in database
    from netreaper.db.engine import get_db

    db = await get_db()
    await db.execute(
        """
        INSERT INTO audit_log (level, category, message, details)
        VALUES (?, ?, ?, ?)
        """,
        ("warning", "vulnerability", f"{vuln_id}: {title}", str(data)),
    )


async def on_credential_cracked(data: dict) -> None:
    """Handle cracked credential."""
    cred_type = data.get("type", "unknown")
    target = data.get("target", "")

    logger.info(f"Credential cracked: {cred_type} for {target}")

    # Store encrypted in loot table
    from netreaper.loot.storage import loot_storage

    await loot_storage.store(
        loot_type="credential",
        data=data,
        source_tool=data.get("tool", "unknown"),
    )


async def on_handshake_captured(data: dict) -> None:
    """Handle WPA handshake capture."""
    bssid = data.get("bssid", "")
    essid = data.get("essid", "")
    file_path = data.get("file", "")

    logger.info(f"Handshake captured: {essid} ({bssid}) -> {file_path}")

    # Through LootStorage, like on_credential_cracked above. This used to raw
    # INSERT into loot, putting a plain file path straight into the column named
    # encrypted_data. Two writers, one format contract, and only one honoured
    # it: every handshake row was then permanently unreadable, because
    # LootStorage.retrieve() calls Fernet.decrypt() on that column and a plain
    # path raises InvalidToken. The metadata column also got str(dict) rather
    # than the JSON the reader parses.
    from netreaper.loot.storage import loot_storage

    await loot_storage.store(
        loot_type="handshake",
        data={"file": file_path, "bssid": bssid, "essid": essid},
        source_tool="airodump-ng",
        metadata={"bssid": bssid, "essid": essid},
    )


def register_default_handlers() -> None:
    """Register default event handlers."""
    event_bus.on(Events.VULNERABILITY_FOUND, on_vulnerability_found)
    event_bus.on(Events.CREDENTIAL_CRACKED, on_credential_cracked)
    event_bus.on(Events.HANDSHAKE_CAPTURED, on_handshake_captured)

    logger.info("Registered default event handlers")
