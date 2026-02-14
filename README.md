```
██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗██████╗  ██████╗  ██████╗
██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║██╔══██╗██╔═══██╗██╔════╝
██║ █╗ ██║███████║   ██║   ██║     ███████║██║  ██║██║   ██║██║  ███╗
██║███╗██║██╔══██║   ██║   ██║     ██╔══██║██║  ██║██║   ██║██║   ██║
╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║██████╔╝╚██████╔╝╚██████╔╝
 ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚═════╝
                              Agent
```
**Lightweight Monitoring Agent for Private Networks**

![Go](https://img.shields.io/badge/Go-1.23-00ADD8?logo=go&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-green)
![Docker](https://img.shields.io/badge/Docker-Scratch--based-2496ED?logo=docker&logoColor=white)
![Binary Size](https://img.shields.io/badge/Image-%3C10MB-brightgreen)

[Installation](#installation) • [Configuration](#configuration) • [Check Types](#check-types) • [Running as a Service](#running-as-a-service)

---

## What is WatchDog Agent?

WatchDog Agent is a lightweight Go binary that runs inside your network and performs health checks against internal and external targets. It connects **outbound** to the [WatchDog Hub](https://github.com/sylvester-francis/watchdog) over WebSocket — no inbound firewall rules required.

**Key Features:**

- **Zero-Config** — Only needs an API key, all monitoring tasks are pushed from the Hub
- **Multi-Protocol Checks** — HTTP, TCP, and Ping monitoring out of the box
- **Auto-Reconnection** — Automatically reconnects and resumes monitoring on connection loss
- **Cross-Platform** — Pre-built binaries for Linux, macOS, and Windows (amd64/arm64)
- **Minimal Footprint** — Scratch-based Docker image under 10 MB, two external dependencies

## How It Works

```
                    Customer Network
                    +-----------------------------------------+
                    |                                         |
                    |  watchdog-agent                         |
                    |  +-----------------------------------+  |
                    |  | HTTP Checker | TCP Checker | Ping |  |
                    |  +-----------------------------------+  |
                    |       |              |            |      |
                    |       v              v            v      |
                    |  [Internal API] [Database:5432] [Host]  |
                    |                                         |
                    +-------|-----|------|---------------------+
                            |     |      |
                      WebSocket (outbound only, port 443)
                            |     |      |
                            v     v      v
                    +---------------------------+
                    |      WatchDog Hub          |
                    |  (cloud / your server)     |
                    +---------------------------+
```

1. Agent connects to the Hub via WebSocket and authenticates with an API key
2. Hub pushes monitoring tasks (targets, intervals, timeouts)
3. Agent runs checks on the configured interval
4. Results (status, latency, errors) are sent back as heartbeats
5. On disconnect, the agent automatically reconnects after 5 seconds

## Installation

### One-Liner Install (Linux)

Downloads the latest release, installs to `/usr/local/bin`, and configures a systemd service:

```bash
curl -sSL https://raw.githubusercontent.com/sylvester-francis/watchdog-agent/main/scripts/install-agent.sh | sudo sh -s -- \
  --api-key YOUR_API_KEY \
  --hub-url wss://your-hub.example.com/ws/agent
```

| Option | Description | Default |
|--------|-------------|---------|
| `--api-key` | Agent API key (required) | — |
| `--hub-url` | Hub WebSocket URL | `ws://localhost:8080/ws/agent` |
| `--repo` | GitHub repository for release download | `sylvester-francis/watchdog-agent` |

### Download Binary

Pre-built binaries are available on the [Releases](https://github.com/sylvester-francis/watchdog-agent/releases) page:

| Platform | Binary |
|----------|--------|
| Linux (x86_64) | `agent-linux-amd64` |
| Linux (ARM64) | `agent-linux-arm64` |
| macOS (x86_64) | `agent-darwin-amd64` |
| macOS (ARM64) | `agent-darwin-arm64` |
| Windows (x86_64) | `agent-windows-amd64.exe` |

```bash
curl -fsSL -o watchdog-agent \
  https://github.com/sylvester-francis/watchdog-agent/releases/latest/download/agent-linux-amd64
chmod +x watchdog-agent
./watchdog-agent --api-key YOUR_API_KEY --hub wss://your-hub.example.com/ws/agent
```

### Docker

```bash
docker run -d \
  --name watchdog-agent \
  --restart always \
  ghcr.io/sylvester-francis/watchdog-agent:latest \
  -hub wss://your-hub.example.com/ws/agent \
  -api-key YOUR_API_KEY
```

### Build from Source

```bash
git clone https://github.com/sylvester-francis/watchdog-agent.git
cd watchdog-agent
go build -o watchdog-agent .
```

Cross-platform release build:

```bash
VERSION=1.0.0 ./scripts/build-agent.sh
# Output: bin/agent-{os}-{arch}
```

## Configuration

### Command-Line Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-hub` | Hub WebSocket URL | `ws://localhost:8080/ws/agent` |
| `-api-key` | Agent API key | — |
| `-debug` | Enable debug logging | `false` |
| `-version` | Print version and exit | — |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `WATCHDOG_API_KEY` | Agent API key (alternative to `-api-key` flag) |

The `-api-key` flag takes precedence over the environment variable.

## Check Types

### HTTP

Performs an HTTP GET request. Follows up to 10 redirects. Reports `up` for 2xx/3xx, `down` for 4xx/5xx, `timeout` if the request exceeds the configured timeout.

```
Target: https://example.com/health
```

### TCP

Opens a TCP connection to the target host and port. Reports `up` if the connection succeeds, `down` if refused, `timeout` if it exceeds the configured timeout.

```
Target: database.internal:5432
```

### Ping

TCP-based reachability check (ICMP requires elevated privileges). Tries port 80 and 443 sequentially. Reports `up` if either port responds.

```
Target: internal-host.example.com
```

## Authentication

1. Agent opens a WebSocket connection to the Hub
2. Sends `auth` message with API key and version
3. Hub validates and responds with `auth_ack` (success) or `auth_error` (failure)
4. On success, Hub pushes `task` messages for each enabled monitor
5. Agent begins executing checks and sending `heartbeat` messages

If authentication fails, the agent logs the error and retries after 5 seconds.

## Reconnection

If the connection drops, the agent:

1. Stops all running monitoring tasks
2. Waits 5 seconds
3. Re-establishes the WebSocket connection
4. Re-authenticates and receives fresh task assignments
5. Resumes monitoring

This cycle repeats indefinitely until the agent process is stopped.

## Running as a Service

### systemd (Linux)

The install script creates this automatically. Manual setup:

```ini
[Unit]
Description=WatchDog Monitoring Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/watchdog-agent -hub "wss://your-hub.example.com/ws/agent" -api-key "YOUR_API_KEY"
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable watchdog-agent
sudo systemctl start watchdog-agent
```

### launchd (macOS)

Create `~/Library/LaunchAgents/com.watchdog.agent.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.watchdog.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/watchdog-agent</string>
        <string>-hub</string>
        <string>wss://your-hub.example.com/ws/agent</string>
        <string>-api-key</string>
        <string>YOUR_API_KEY</string>
    </array>
    <key>KeepAlive</key>
    <true/>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
```

```bash
launchctl load ~/Library/LaunchAgents/com.watchdog.agent.plist
```

## Project Structure

```
watchdog-agent/
    main.go              # Entrypoint, agent lifecycle, reconnection loop
    connection.go        # WebSocket connection management, auth handshake
    checker.go           # HTTP, TCP, and ping check implementations
    Dockerfile           # Multi-stage build (scratch-based, <10 MB)
    scripts/
        build-agent.sh       # Cross-platform release build
        install-agent.sh     # One-liner installer with systemd setup
```

## Dependencies

| Package | Purpose |
|---------|---------|
| [gorilla/websocket](https://github.com/gorilla/websocket) | WebSocket client |
| [watchdog-proto](https://github.com/sylvester-francis/watchdog-proto) | Shared message protocol |

No other external dependencies. The agent uses only the Go standard library for HTTP, TCP, logging, and signal handling.

## Related Repositories

| Repository | Description |
|------------|-------------|
| [watchdog](https://github.com/sylvester-francis/watchdog) | Hub server — dashboard, API, alerting, data storage |
| [watchdog-proto](https://github.com/sylvester-francis/watchdog-proto) | Shared WebSocket message protocol |

## License

MIT License. See [LICENSE](LICENSE) for details.
