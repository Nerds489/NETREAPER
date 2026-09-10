# NETREAPER Fish Shell Completions
# Install: cp netreaper.fish ~/.config/fish/completions/

# Disable file completion by default
complete -c netreaper -f

# Global flags
complete -c netreaper -s h -l help -d "Show help message"
complete -c netreaper -l version -d "Show version"
complete -c netreaper -l dry-run -d "Preview commands without executing"
complete -c netreaper -s v -l verbose -d "Enable verbose output"
complete -c netreaper -s q -l quiet -d "Suppress non-essential output"
complete -c netreaper -l no-color -d "Disable colored output"
complete -c netreaper -l debug -d "Enable debug mode"

# Top-level commands
complete -c netreaper -n "__fish_use_subcommand" -a "menu" -d "Interactive menu"
complete -c netreaper -n "__fish_use_subcommand" -a "wizard" -d "Guided wizard"
complete -c netreaper -n "__fish_use_subcommand" -a "scan" -d "Network scanning"
complete -c netreaper -n "__fish_use_subcommand" -a "discover" -d "Host discovery"
complete -c netreaper -n "__fish_use_subcommand" -a "wifi" -d "Wireless operations"
complete -c netreaper -n "__fish_use_subcommand" -a "crack" -d "Handshake cracking"
complete -c netreaper -n "__fish_use_subcommand" -a "session" -d "Session management"
complete -c netreaper -n "__fish_use_subcommand" -a "history" -d "Target history"
complete -c netreaper -n "__fish_use_subcommand" -a "favorite" -d "Manage favorites"
complete -c netreaper -n "__fish_use_subcommand" -a "alias" -d "Manage aliases"
complete -c netreaper -n "__fish_use_subcommand" -a "profile" -d "Scan presets"
complete -c netreaper -n "__fish_use_subcommand" -a "export" -d "Export results"
complete -c netreaper -n "__fish_use_subcommand" -a "schedule" -d "Scheduled scans"
complete -c netreaper -n "__fish_use_subcommand" -a "diff" -d "Compare scans"
complete -c netreaper -n "__fish_use_subcommand" -a "status" -d "Tool status"
complete -c netreaper -n "__fish_use_subcommand" -a "arsenal" -d "Tool status (alias)"
complete -c netreaper -n "__fish_use_subcommand" -a "install" -d "Install tools"
complete -c netreaper -n "__fish_use_subcommand" -a "install-quick" -d "Install essentials"
complete -c netreaper -n "__fish_use_subcommand" -a "config" -d "Configuration"
complete -c netreaper -n "__fish_use_subcommand" -a "update" -d "Check for updates"
complete -c netreaper -n "__fish_use_subcommand" -a "logs" -d "View logs"
complete -c netreaper -n "__fish_use_subcommand" -a "help" -d "Show help"

# Wizard subcommands
complete -c netreaper -n "__fish_seen_subcommand_from wizard" -a "scan" -d "Guided scan wizard"
complete -c netreaper -n "__fish_seen_subcommand_from wizard" -a "wifi" -d "Guided WiFi wizard"

# Scan options
complete -c netreaper -n "__fish_seen_subcommand_from scan" -l quick -d "Quick scan"
complete -c netreaper -n "__fish_seen_subcommand_from scan" -l full -d "Full port scan"
complete -c netreaper -n "__fish_seen_subcommand_from scan" -l stealth -d "Stealth/SYN scan"
complete -c netreaper -n "__fish_seen_subcommand_from scan" -l vuln -d "Vulnerability scan"
complete -c netreaper -n "__fish_seen_subcommand_from scan" -l udp -d "UDP scan"
complete -c netreaper -n "__fish_seen_subcommand_from scan" -l profile -d "Use saved profile" -r

# WiFi options
complete -c netreaper -n "__fish_seen_subcommand_from wifi" -l monitor -d "Enable monitor mode" -r
complete -c netreaper -n "__fish_seen_subcommand_from wifi" -l managed -d "Return to managed mode" -r
complete -c netreaper -n "__fish_seen_subcommand_from wifi" -l scan -d "Scan for networks" -r

# Crack options
complete -c netreaper -n "__fish_seen_subcommand_from crack" -l aircrack -d "Use aircrack-ng"
complete -c netreaper -n "__fish_seen_subcommand_from crack" -l john -d "Use John the Ripper"
complete -c netreaper -n "__fish_seen_subcommand_from crack" -l cowpatty -d "Use cowpatty"
complete -c netreaper -n "__fish_seen_subcommand_from crack" -l hashcat-rules -d "Use hashcat with rules"
complete -c netreaper -n "__fish_seen_subcommand_from crack" -s w -l wordlist -d "Wordlist file" -r
complete -c netreaper -n "__fish_seen_subcommand_from crack" -l ssid -d "Target SSID" -r
complete -c netreaper -n "__fish_seen_subcommand_from crack" -l rules -d "Rules file" -r

# Config subcommands
complete -c netreaper -n "__fish_seen_subcommand_from config" -a "edit" -d "Edit config file"
complete -c netreaper -n "__fish_seen_subcommand_from config" -a "show" -d "Show config"
complete -c netreaper -n "__fish_seen_subcommand_from config" -a "get" -d "Get config value"
complete -c netreaper -n "__fish_seen_subcommand_from config" -a "set" -d "Set config value"
complete -c netreaper -n "__fish_seen_subcommand_from config" -a "reset" -d "Reset config"
complete -c netreaper -n "__fish_seen_subcommand_from config" -a "path" -d "Show config path"

# Session subcommands
complete -c netreaper -n "__fish_seen_subcommand_from session" -a "start" -d "Start new session"
complete -c netreaper -n "__fish_seen_subcommand_from session" -a "resume" -d "Resume session"
complete -c netreaper -n "__fish_seen_subcommand_from session" -a "status" -d "Session status"
complete -c netreaper -n "__fish_seen_subcommand_from session" -a "list" -d "List sessions"
complete -c netreaper -n "__fish_seen_subcommand_from session" -a "export" -d "Export session"
complete -c netreaper -n "__fish_seen_subcommand_from session" -a "notes" -d "Session notes"

# Status options
complete -c netreaper -n "__fish_seen_subcommand_from status" -s c -l compact -d "Compact view"
complete -c netreaper -n "__fish_seen_subcommand_from status" -s j -l json -d "JSON output"
complete -c netreaper -n "__fish_seen_subcommand_from status" -s C -l category -d "Show category" -r

# Favorite subcommands
complete -c netreaper -n "__fish_seen_subcommand_from favorite" -a "add" -d "Add favorite"
complete -c netreaper -n "__fish_seen_subcommand_from favorite" -a "list" -d "List favorites"
complete -c netreaper -n "__fish_seen_subcommand_from favorite" -a "use" -d "Use favorite"

# Alias subcommands
complete -c netreaper -n "__fish_seen_subcommand_from alias" -a "add" -d "Add alias"
complete -c netreaper -n "__fish_seen_subcommand_from alias" -a "remove" -d "Remove alias"
complete -c netreaper -n "__fish_seen_subcommand_from alias" -a "list" -d "List aliases"

# Profile subcommands
complete -c netreaper -n "__fish_seen_subcommand_from profile" -a "save" -d "Save profile"
complete -c netreaper -n "__fish_seen_subcommand_from profile" -a "load" -d "Load profile"
complete -c netreaper -n "__fish_seen_subcommand_from profile" -a "list" -d "List profiles"

# Help topics
complete -c netreaper -n "__fish_seen_subcommand_from help" -a "scan" -d "Scan help"
complete -c netreaper -n "__fish_seen_subcommand_from help" -a "wifi" -d "WiFi help"
complete -c netreaper -n "__fish_seen_subcommand_from help" -a "config" -d "Config help"

# Install categories
complete -c netreaper -n "__fish_seen_subcommand_from install" -a "all" -d "Install everything"
complete -c netreaper -n "__fish_seen_subcommand_from install" -a "essentials" -d "Essential tools"
complete -c netreaper -n "__fish_seen_subcommand_from install" -a "scanning" -d "Scanning tools"
complete -c netreaper -n "__fish_seen_subcommand_from install" -a "wireless" -d "Wireless tools"
complete -c netreaper -n "__fish_seen_subcommand_from install" -a "exploit" -d "Exploit tools"
complete -c netreaper -n "__fish_seen_subcommand_from install" -a "creds" -d "Credential tools"
complete -c netreaper -n "__fish_seen_subcommand_from install" -a "osint" -d "OSINT tools"
complete -c netreaper -n "__fish_seen_subcommand_from install" -a "traffic" -d "Traffic tools"
complete -c netreaper -n "__fish_seen_subcommand_from install" -a "web" -d "Web tools"
