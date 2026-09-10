# NETREAPER Environment Variables

Complete reference for all environment variables used by NETREAPER.

## Core Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `NETREAPER_HOME` | Path | `~/.netreaper` | Base directory for all data |
| `NETREAPER_CONFIG_DIR` | Path | `~/.netreaper/config` | Configuration file location |
| `NETREAPER_LOG_DIR` | Path | `~/.netreaper/logs` | Log file location |
| `NETREAPER_DATA_DIR` | Path | `~/.netreaper/data` | Data storage location |
| `NETREAPER_LOOT_DIR` | Path | `~/.netreaper/loot` | Captured credentials/handshakes |
| `NETREAPER_SESSION_DIR` | Path | `~/.netreaper/sessions` | Session files location |

## Runtime Behavior

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `NR_NON_INTERACTIVE` | 0/1 | `0` | Skip all interactive prompts |
| `NR_SUPPRESS_OUTPUT` | 0/1 | `0` | Silent mode - suppress non-essential output |
| `NR_DRY_RUN` | 0/1 | `0` | Preview mode - show commands without executing |
| `NR_UNSAFE_MODE` | 0/1 | `0` | Bypass safety checks (DANGEROUS) |
| `DEBUG` | 0/1 | `0` | Enable debug output |
| `NO_COLOR` | 0/1 | `0` | Disable colored output |

## Logging

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `NETREAPER_LOG_LEVEL` | 0-5 | `1` | Minimum log level (0=DEBUG, 5=FATAL) |
| `NETREAPER_FILE_LOGGING` | 0/1 | `1` | Enable logging to files |
| `NETREAPER_LOG_FORMAT` | text/json | `text` | Log output format |

**Log Levels:**
- 0 = DEBUG (verbose debugging info)
- 1 = INFO (general information)
- 2 = SUCCESS (successful operations)
- 3 = WARNING (non-critical issues)
- 4 = ERROR (errors that don't stop execution)
- 5 = FATAL (critical errors)

## API Keys

| Variable | Description |
|----------|-------------|
| `SHODAN_API_KEY` | Shodan.io API key for OSINT reconnaissance |
| `VT_API_KEY` | VirusTotal API key for file/URL analysis |
| `CENSYS_API_KEY` | Censys.io API key for internet-wide scanning |
| `HUNTER_API_KEY` | Hunter.io API key for email discovery |

## Wireless Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `WIRELESS_INTERFACE` | String | auto | Default wireless interface |
| `MONITOR_INTERFACE` | String | - | Currently active monitor interface |
| `CHANNEL` | Integer | - | Wireless channel to use |

## Cracking Settings

| Variable | Type | Description |
|----------|------|-------------|
| `CRACK_USE_GPU` | 0/1 | Enable GPU acceleration for hashcat |
| `HASHCAT_OPTS` | String | Additional hashcat options |
| `JOHN_OPTS` | String | Additional John the Ripper options |

## Examples

### Run in non-interactive CI mode
```bash
NR_NON_INTERACTIVE=1 NR_SUPPRESS_OUTPUT=1 netreaper config show
```

### Dry-run to preview commands
```bash
NR_DRY_RUN=1 netreaper wifi scan
```

### Verbose debug logging
```bash
NETREAPER_LOG_LEVEL=0 DEBUG=1 netreaper status
```

### JSON logging for parsing
```bash
NETREAPER_LOG_FORMAT=json netreaper status 2>&1 | jq .
```

### Use with OSINT features
```bash
export SHODAN_API_KEY="your-api-key"
netreaper osint shodan target.com
```

### Disable colors for piping
```bash
NO_COLOR=1 netreaper status | grep -i interface
```

### Run headless scan
```bash
NR_NON_INTERACTIVE=1 \
WIRELESS_INTERFACE=wlan0 \
netreaper wifi scan --duration 60
```

## Configuration File

Most settings can also be set in the configuration file:

```bash
# View config file path
netreaper config path

# Show current configuration
netreaper config show

# Set a value
netreaper config set log_level DEBUG

# Validate configuration
netreaper config validate
```

Environment variables take precedence over configuration file settings.

## See Also

- [QUICKREF.md](QUICKREF.md) - Quick reference guide
- [HOWTO.md](HOWTO.md) - Common tasks and procedures
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - Problem solving guide
