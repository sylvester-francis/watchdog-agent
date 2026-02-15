#!/bin/sh
# WatchDog Agent Installer
# Usage: curl -sSL https://raw.githubusercontent.com/sylvester-francis/watchdog-agent/main/scripts/install-agent.sh | sh -s -- \
#   --hub-url wss://your-app.railway.app/ws/agent --api-key YOUR_KEY

set -e

INSTALL_DIR="/usr/local/bin"
BINARY_NAME="watchdog-agent"
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

while [ $# -gt 0 ]; do
    case "$1" in
        --api-key) API_KEY="$2"; shift 2 ;;
        --hub|--hub-url) HUB_URL="$2"; shift 2 ;;
        --repo) GITHUB_REPO="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [ -z "$API_KEY" ]; then
    echo "Error: --api-key is required"
    echo "Usage: install-agent.sh --api-key YOUR_KEY [--hub-url wss://hub:8080/ws/agent] [--repo owner/repo]"
    exit 1
fi

echo "WatchDog Agent Installer"
echo "========================"
echo "OS:   $OS"
echo "Arch: $ARCH"
echo "Hub:  $HUB_URL"
echo ""

# Download from GitHub Releases
DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/latest/download/agent-${OS}-${ARCH}"
echo "Downloading from GitHub Releases..."
if curl -fsSL -o "${INSTALL_DIR}/${BINARY_NAME}" "$DOWNLOAD_URL"; then
    chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
    echo "Downloaded and installed to ${INSTALL_DIR}/${BINARY_NAME}"
else
    echo "Error: Failed to download from $DOWNLOAD_URL"
    exit 1
fi

# Create systemd service if available
if command -v systemctl > /dev/null 2>&1; then
    echo "Creating systemd service..."
    cat > /etc/systemd/system/watchdog-agent.service << EOF
[Unit]
Description=WatchDog Monitoring Agent
After=network.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/${BINARY_NAME} -hub "${HUB_URL}" -api-key "${API_KEY}"
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable watchdog-agent
    systemctl start watchdog-agent
    echo "Agent started as systemd service"
else
    echo ""
    echo "Run manually:"
    echo "  ${BINARY_NAME} -hub \"${HUB_URL}\" -api-key \"${API_KEY}\""
fi

echo ""
echo "Done!"
