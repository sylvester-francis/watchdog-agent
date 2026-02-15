# watchdog-agent

The monitoring agent for the [WatchDog](https://github.com/sylvester-francis/watchdog) infrastructure monitoring system.

WatchDog Agent is a lightweight Go binary that runs inside customer networks (behind firewalls, in private labs, on-premise environments) and performs health checks against internal and external targets. It connects outbound to the WatchDog Hub over WebSocket, receives monitoring tasks, and reports results back as heartbeats. No inbound firewall rules are required.

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

1. The agent connects to the Hub via WebSocket and authenticates with an API key
2. The Hub pushes monitoring tasks (which targets to check, at what interval)
3. The agent runs checks (HTTP, TCP, ping) on the configured interval
4. Results (status, latency, errors) are sent back to the Hub as heartbeats
5. If the connection drops, the agent automatically reconnects with a 5-second delay

## Installation

### One-Liner Install (Linux)

Downloads the latest release from GitHub, installs to `/usr/local/bin`, and configures a systemd service:

```bash
curl -sSL https://raw.githubusercontent.com/sylvester-francis/watchdog-agent/main/scripts/install-agent.sh | sudo sh -s -- \
  --api-key YOUR_API_KEY \
  --hub-url wss://your-hub.example.com/ws/agent
```

The installer supports the following options:

| Option       | Description                            | Default                          |
|--------------|----------------------------------------|----------------------------------|
| `--api-key`  | Agent API key (required)               | --                               |
| `--hub-url`  | Hub WebSocket URL                      | `ws://localhost:8080/ws/agent`   |
| `--repo`     | GitHub repository for release download | `sylvester-francis/watchdog-agent` |

On systems with systemd, the installer creates and starts a `watchdog-agent` service automatically.

### Download Binary

Pre-built binaries are available on the [Releases](https://github.com/sylvester-francis/watchdog-agent/releases) page for:

| Platform        | Binary Name              |
|-----------------|--------------------------|
| Linux (x86_64)  | `agent-linux-amd64`      |
| Linux (ARM64)   | `agent-linux-arm64`      |
| macOS (x86_64)  | `agent-darwin-amd64`     |
| macOS (ARM64)   | `agent-darwin-arm64`     |
| Windows (x86_64)| `agent-windows-amd64.exe`|

```bash
# Example: download and run on Linux x86_64
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

The Docker image is built from scratch (no OS layer) and includes only the agent binary and CA certificates. Final image size is under 10 MB.

### Build from Source

Requires Go 1.23 or later.

```bash
git clone https://github.com/sylvester-francis/watchdog-agent.git
cd watchdog-agent
go build -o watchdog-agent .
```

To build release binaries for all supported platforms:

```bash
VERSION=1.0.0 ./scripts/build-agent.sh
```

This produces binaries in the `bin/` directory with version and build time embedded via ldflags.

## Configuration

The agent follows a zero-configuration principle. All monitoring tasks (what to check, how often, timeouts) are pushed from the Hub after authentication. The agent itself only needs two things: where the Hub is, and how to authenticate.

### Command-Line Flags

| Flag         | Description              | Default                          |
|--------------|--------------------------|----------------------------------|
| `-hub`       | Hub WebSocket URL        | `ws://localhost:8080/ws/agent`   |
| `-api-key`   | Agent API key            | --                               |
| `-version`   | Print version and exit   | --                               |
| `-debug`     | Enable debug logging     | `false`                          |

### Environment Variables

| Variable           | Description       |
|--------------------|-------------------|
| `WATCHDOG_API_KEY` | Agent API key (alternative to `-api-key` flag) |

The `-api-key` flag takes precedence over the environment variable.

## Check Types

The agent supports the following monitoring check types:

### HTTP

Performs an HTTP GET request against the target URL. Follows up to 10 redirects. Reports `up` for 2xx and 3xx status codes, `down` for 4xx/5xx, and `timeout` if the request exceeds the configured timeout.

```
Target format: https://example.com/health
```

### TCP

Opens a TCP connection to the target host and port. Reports `up` if the connection succeeds, `down` if refused, and `timeout` if the connection exceeds the configured timeout.

```
Target format: database.internal:5432
```

### Ping

Performs a TCP-based reachability check (ICMP requires elevated privileges on most systems). Tries port 80 and 443 sequentially. Reports `up` if either port responds.

```
Target format: internal-host.example.com
```

## Authentication Flow

1. Agent opens a WebSocket connection to the Hub
2. Agent sends an `auth` message containing the API key and agent version
3. Hub validates the API key and responds with either:
   - `auth_ack` containing the agent ID and name (success)
   - `auth_error` with an error message (failure)
4. On success, the Hub pushes `task` messages for each enabled monitor assigned to this agent
5. The agent begins executing checks and sending `heartbeat` messages

If authentication fails, the agent logs the error and retries after 5 seconds.

## Reconnection

The agent maintains a persistent connection to the Hub. If the connection drops (network issues, Hub restart, etc.), the agent:

1. Stops all running monitoring tasks
2. Waits 5 seconds
3. Re-establishes the WebSocket connection
4. Re-authenticates
5. Receives fresh task assignments from the Hub
6. Resumes monitoring

This cycle repeats indefinitely until the agent process is stopped.

## Running as a Service

### systemd (Linux)

The install script creates this automatically, but you can also create it manually:

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
sudo systemctl status watchdog-agent
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
    main.go          # Entrypoint, agent lifecycle, reconnection loop
    connection.go    # WebSocket connection management, auth handshake
    checker.go       # HTTP, TCP, and ping check implementations
    Dockerfile       # Multi-stage build (scratch-based, <10 MB)
    scripts/
        build-agent.sh     # Cross-platform release build script
        install-agent.sh   # One-liner installer with systemd setup
```

## Dependencies

| Package | Purpose |
|---------|---------|
| [gorilla/websocket](https://github.com/gorilla/websocket) | WebSocket client |
| [watchdog-proto](https://github.com/sylvester-francis/watchdog-proto) | Shared message protocol |

No other external dependencies. The agent uses only the Go standard library for HTTP checks, TCP connections, logging, and signal handling.

## Related Repositories

| Repository | Description |
|------------|-------------|
| [watchdog](https://github.com/sylvester-francis/watchdog) | Hub server -- dashboard, API, alerting, and data storage |
| [watchdog-proto](https://github.com/sylvester-francis/watchdog-proto) | Shared WebSocket message protocol |

## License

MIT License. See [LICENSE](LICENSE) for details.
