"""Command palette commands for NETREAPER."""
from textual.command import DiscoveryHit, Hit, Hits, Provider


class NetreaperCommands(Provider):
    """Command provider for NETREAPER operations."""

    async def search(self, query: str) -> Hits:
        """Search for commands matching the query."""
        matcher = self.matcher(query)

        # Tool commands
        commands = [
            ("scan", "🔍 Start Network Scan", "scan"),
            ("wireless", "📡 Open Wireless Menu", "wireless"),
            ("credentials", "🔑 Open Credentials Menu", "credentials"),
            ("osint", "🌐 Open OSINT Menu", "osint"),
            ("recon", "🎯 Open Recon Menu", "recon"),
            ("traffic", "📊 Open Traffic Menu", "traffic"),
            ("exploit", "💥 Open Exploit Menu", "exploit"),
            ("stress", "⚡ Open Stress Menu", "stress"),
            ("status", "📈 Show System Status", "status"),
            ("settings", "⚙️ Open Settings", "settings"),
            ("help", "❓ Show Help", "help"),
            ("quick-scan", "⚡ Quick Network Scan", "quick-scan"),
            ("wifi-scan", "📡 Quick WiFi Scan", "wifi-scan"),
            ("stop-all", "🛑 Stop All Tools", "stop-all"),
        ]

        for command_id, display, search_terms in commands:
            if match := matcher(search_terms):
                yield Hit(
                    match,
                    matcher.highlight(display),
                    lambda cmd=command_id: self._run_command(cmd),
                    help=f"Execute: {display}"
                )

    async def _run_command(self, command: str) -> None:
        """Execute a command."""
        if command == "scan":
            self.app.action_new_scan()
        elif command == "wireless":
            self.app.action_wireless_menu()
        elif command == "help":
            self.app.action_show_help()
        elif command == "quick-scan":
            # Trigger quick scan button
            pass
        elif command == "wifi-scan":
            self.app.action_wireless_menu()
        elif command == "stop-all":
            # Trigger stop all
            pass
        else:
            # Navigate to screen
            try:
                screen_class_name = f"{command.title().replace('-', '')}Screen"
                module_path = f"netreaper.tui.screens.{command.replace('-', '_')}"
                module = __import__(module_path, fromlist=[screen_class_name])
                screen_class = getattr(module, screen_class_name)
                await self.app.push_screen(screen_class())
            except (ImportError, AttributeError):
                self.app.bell()

    async def discover(self) -> Hits:
        """Return all available commands for discovery."""
        commands = [
            ("scan", "🔍 Start Network Scan"),
            ("wireless", "📡 Wireless Operations"),
            ("credentials", "🔑 Credential Attacks"),
            ("osint", "🌐 OSINT Gathering"),
            ("recon", "🎯 Reconnaissance"),
            ("traffic", "📊 Traffic Analysis"),
            ("exploit", "💥 Exploitation"),
            ("stress", "⚡ Stress Testing"),
            ("status", "📈 System Status"),
            ("settings", "⚙️ Settings"),
        ]

        for command_id, display in commands:
            yield DiscoveryHit(
                display,
                lambda cmd=command_id: self._run_command(cmd),
                help=f"Open {display}"
            )
