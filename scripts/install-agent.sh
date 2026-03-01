#!/bin/sh
# WatchDog Agent Installer
#
# SECURITY NOTE: Piping curl output to sh (curl | sh) means you trust the server
# to deliver safe content at download time. For production environments, we recommend:
#   1. Download the script first:  curl -sSL <url> -o install-agent.sh
#   2. Inspect the script:         less install-agent.sh
#   3. Run it:                     sh install-agent.sh --api-key YOUR_KEY --hub-url wss://...
#
# Usage: curl -sSL https://raw.githubusercontent.com/sylvester-francis/watchdog-agent/main/scripts/install-agent.sh | sh -s -- \
#   --hub-url wss://your-app.railway.app/ws/agent --api-key YOUR_KEY

set -e

INSTALL_DIR="/usr/local/bin"
BINARY_NAME="watchdog-agent"
SERVICE_USER="_watchdog-agent"
CONFIG_DIR="/etc/watchdog-agent"
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
GITHUB_REPO="sylvester-francis/watchdog-agent"

# Map architecture names
case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# Parse arguments
API_KEY=""
HUB_URL="ws://localhost:8080/ws/agent"
ENABLE_DOCKER=""

while [ $# -gt 0 ]; do
    case "$1" in
        --api-key) API_KEY="$2"; shift 2 ;;
        --hub|--hub-url) HUB_URL="$2"; shift 2 ;;
        --repo) GITHUB_REPO="$2"; shift 2 ;;
        --enable-docker) ENABLE_DOCKER="1"; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [ -z "$API_KEY" ]; then
    echo "Error: --api-key is required"
    echo "Usage: install-agent.sh --api-key YOUR_KEY [--hub-url wss://hub:8080/ws/agent] [--repo owner/repo] [--enable-docker]"
    exit 1
fi

echo "WatchDog Agent Installer"
echo "========================"
echo "OS:   $OS"
echo "Arch: $ARCH"
echo "Hub:  $HUB_URL"
echo ""

# Download binary from GitHub Releases
DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/latest/download/agent-${OS}-${ARCH}"
CHECKSUM_URL="https://github.com/${GITHUB_REPO}/releases/latest/download/agent-${OS}-${ARCH}.sha256"
TMP_BINARY=$(mktemp)
TMP_CHECKSUM=$(mktemp)

echo "Downloading from GitHub Releases..."
if ! curl -fsSL -o "$TMP_BINARY" "$DOWNLOAD_URL"; then
    echo "Error: Failed to download from $DOWNLOAD_URL"
    rm -f "$TMP_BINARY" "$TMP_CHECKSUM"
    exit 1
fi

# SHA-256 checksum verification
# NOTE: Checksums must be published alongside release binaries.
# Generate with: sha256sum agent-${OS}-${ARCH} > agent-${OS}-${ARCH}.sha256
echo "Verifying SHA-256 checksum..."
if curl -fsSL -o "$TMP_CHECKSUM" "$CHECKSUM_URL" 2>/dev/null; then
    EXPECTED=$(awk '{print $1}' "$TMP_CHECKSUM")
    if command -v sha256sum > /dev/null 2>&1; then
        ACTUAL=$(sha256sum "$TMP_BINARY" | awk '{print $1}')
    elif command -v shasum > /dev/null 2>&1; then
        ACTUAL=$(shasum -a 256 "$TMP_BINARY" | awk '{print $1}')
    else
        echo "WARNING: No sha256sum or shasum available, skipping checksum verification"
        ACTUAL="$EXPECTED"
    fi

    if [ "$EXPECTED" != "$ACTUAL" ]; then
        echo "ERROR: Checksum verification failed!"
        echo "  Expected: $EXPECTED"
        echo "  Got:      $ACTUAL"
        echo "The binary may have been tampered with. Aborting."
        rm -f "$TMP_BINARY" "$TMP_CHECKSUM"
        exit 1
    fi
    echo "Checksum verified OK"
else
    echo "WARNING: Checksum file not found at $CHECKSUM_URL"
    echo "  Skipping verification. Publish .sha256 files with releases for integrity checks."
fi
rm -f "$TMP_CHECKSUM"

# Install binary
mv "$TMP_BINARY" "${INSTALL_DIR}/${BINARY_NAME}"
chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
echo "Installed to ${INSTALL_DIR}/${BINARY_NAME}"

# Create dedicated system user (A-008: avoid running as root)
if command -v systemctl > /dev/null 2>&1; then
    if ! id "$SERVICE_USER" > /dev/null 2>&1; then
        echo "Creating system user $SERVICE_USER..."
        useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    fi

    # Add to docker group if Docker monitoring is enabled
    if [ -n "$ENABLE_DOCKER" ]; then
        if getent group docker > /dev/null 2>&1; then
            usermod -aG docker "$SERVICE_USER"
            echo "Added $SERVICE_USER to docker group for container monitoring"
        else
            echo "WARNING: docker group not found. Docker monitoring may not work."
        fi
    fi

    # Create config directory and store API key in file (not in process args)
    mkdir -p "$CONFIG_DIR"
    echo "$API_KEY" > "${CONFIG_DIR}/api-key"
    chmod 600 "${CONFIG_DIR}/api-key"
    chown "$SERVICE_USER":"$SERVICE_USER" "${CONFIG_DIR}/api-key" 2>/dev/null || true

    echo "Creating systemd service..."
    cat > /etc/systemd/system/watchdog-agent.service << EOF
[Unit]
Description=WatchDog Monitoring Agent
After=network.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
ExecStart=${INSTALL_DIR}/${BINARY_NAME} -hub "${HUB_URL}" -api-key-file "${CONFIG_DIR}/api-key"
Restart=always
RestartSec=5

# Systemd hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
ReadOnlyPaths=/
ReadWritePaths=/tmp

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable watchdog-agent
    systemctl start watchdog-agent

    # A-011: Verify the agent actually started successfully.
    echo "Waiting for agent to start..."
    sleep 3

    if systemctl is-active --quiet watchdog-agent; then
        AGENT_PID=$(systemctl show --property=MainPID --value watchdog-agent)
        echo "Agent started successfully as systemd service (running as $SERVICE_USER, PID $AGENT_PID)"
    else
        echo ""
        echo "WARNING: Agent does not appear to be running!"
        echo "Recent journal output:"
        journalctl -u watchdog-agent -n 10 --no-pager 2>/dev/null || true
        echo ""
        echo "Check the configuration and logs with:"
        echo "  systemctl status watchdog-agent"
        echo "  journalctl -u watchdog-agent -f"
    fi
else
    echo ""
    echo "Run manually:"
    echo "  ${BINARY_NAME} -hub \"${HUB_URL}\" -api-key-file /path/to/api-key"
fi

echo ""
echo "Done!"
