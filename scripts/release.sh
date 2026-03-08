#!/usr/bin/env bash
set -euo pipefail

# release.sh — Cross-compile, sign, and optionally upload the WatchDog agent.
#
# Usage:
#   ./scripts/release.sh v1.2.0
#   ./scripts/release.sh v1.2.0 --private-key /path/to/key.hex
#   ./scripts/release.sh v1.2.0 --private-key /path/to/key.hex --upload

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_DIR="$PROJECT_ROOT/dist"
GITHUB_REPO="sylvester-francis/watchdog-agent"

# Target platforms
PLATFORMS=(
  "linux/amd64"
  "linux/arm64"
  "darwin/amd64"
  "darwin/arm64"
)

# --- Argument parsing ---

VERSION=""
PRIVATE_KEY_FILE=""
UPLOAD=false

usage() {
  echo "Usage: $0 <version> [--private-key /path/to/key.hex] [--upload]"
  echo ""
  echo "  <version>       Semver tag, e.g. v1.2.0"
  echo "  --private-key   Path to hex-encoded ed25519 private key (128 hex chars = 64 bytes)"
  echo "  --upload        Upload artifacts to GitHub Releases via 'gh' CLI"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --private-key)
      [[ $# -lt 2 ]] && { echo "Error: --private-key requires a path argument"; exit 1; }
      PRIVATE_KEY_FILE="$2"
      shift 2
      ;;
    --upload)
      UPLOAD=true
      shift
      ;;
    -h|--help)
      usage
      ;;
    -*)
      echo "Error: Unknown flag '$1'"
      usage
      ;;
    *)
      if [[ -z "$VERSION" ]]; then
        VERSION="$1"
        shift
      else
        echo "Error: Unexpected argument '$1'"
        usage
      fi
      ;;
  esac
done

if [[ -z "$VERSION" ]]; then
  echo "Error: Version argument is required"
  usage
fi

# Validate version format
if [[ ! "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
  echo "Error: Version must match vX.Y.Z (got '$VERSION')"
  exit 1
fi

# Strip leading 'v' for manifest
VERSION_BARE="${VERSION#v}"
BUILD_TIME="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# Validate private key file if provided
PRIVATE_KEY_HEX=""
if [[ -n "$PRIVATE_KEY_FILE" ]]; then
  if [[ ! -f "$PRIVATE_KEY_FILE" ]]; then
    echo "Error: Private key file not found: $PRIVATE_KEY_FILE"
    exit 1
  fi
  PRIVATE_KEY_HEX="$(tr -d '[:space:]' < "$PRIVATE_KEY_FILE")"
  if [[ ${#PRIVATE_KEY_HEX} -ne 128 ]]; then
    echo "Error: Private key must be 128 hex characters (64 bytes), got ${#PRIVATE_KEY_HEX}"
    exit 1
  fi
  if [[ ! "$PRIVATE_KEY_HEX" =~ ^[0-9a-fA-F]+$ ]]; then
    echo "Error: Private key contains non-hex characters"
    exit 1
  fi
fi

# Check for upload prerequisites
if [[ "$UPLOAD" == true ]]; then
  if ! command -v gh &>/dev/null; then
    echo "Error: 'gh' CLI is required for --upload (install from https://cli.github.com)"
    exit 1
  fi
  if ! gh auth status &>/dev/null; then
    echo "Error: 'gh' CLI is not authenticated — run 'gh auth login' first"
    exit 1
  fi
fi

echo "==> Building watchdog-agent $VERSION ($BUILD_TIME)"
echo "    Signing: $(if [[ -n "$PRIVATE_KEY_HEX" ]]; then echo "enabled"; else echo "disabled (no --private-key)"; fi)"
echo "    Upload:  $UPLOAD"
echo ""

# --- Build the ed25519 signing tool (if signing is enabled) ---

SIGNER_BIN=""
SIGNER_TMPDIR=""

if [[ -n "$PRIVATE_KEY_HEX" ]]; then
  SIGNER_TMPDIR="$(mktemp -d)"
  SIGNER_BIN="$SIGNER_TMPDIR/ed25519sign"

  cat > "$SIGNER_TMPDIR/main.go" <<'SIGNEREOF'
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

func main() {
	keyHex := os.Getenv("ED25519_PRIVATE_KEY")
	if keyHex == "" {
		fmt.Fprintln(os.Stderr, "ED25519_PRIVATE_KEY env var not set")
		os.Exit(1)
	}
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bad hex key: %v\n", err)
		os.Exit(1)
	}
	if len(keyBytes) != ed25519.PrivateKeySize {
		fmt.Fprintf(os.Stderr, "key must be %d bytes, got %d\n", ed25519.PrivateKeySize, len(keyBytes))
		os.Exit(1)
	}
	// Read the raw hash bytes from stdin
	hash, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read stdin: %v\n", err)
		os.Exit(1)
	}
	sig := ed25519.Sign(ed25519.PrivateKey(keyBytes), hash)
	fmt.Print(hex.EncodeToString(sig))
}
SIGNEREOF

  echo "==> Building ed25519 signing helper..."
  (cd "$SIGNER_TMPDIR" && go build -o ed25519sign main.go)
  echo "    Signer ready: $SIGNER_BIN"
  echo ""

  cleanup_signer() {
    rm -rf "$SIGNER_TMPDIR"
  }
  trap cleanup_signer EXIT
fi

# --- Prepare dist directory ---

rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

# --- Cross-compile ---

LDFLAGS="-s -w -X main.Version=${VERSION_BARE} -X main.BuildTime=${BUILD_TIME}"

echo "==> Cross-compiling for ${#PLATFORMS[@]} platforms..."
for platform in "${PLATFORMS[@]}"; do
  GOOS="${platform%/*}"
  GOARCH="${platform#*/}"
  BINARY_NAME="watchdog-agent-${GOOS}-${GOARCH}"
  OUTPUT="$DIST_DIR/$BINARY_NAME"

  echo "    $platform -> $BINARY_NAME"
  CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" \
    go build -ldflags "$LDFLAGS" -o "$OUTPUT" "$PROJECT_ROOT"
done

echo ""
echo "==> Computing checksums and signatures..."

# --- Checksums and signatures ---

# We build the manifest JSON incrementally
MANIFEST_BINARIES=""

for platform in "${PLATFORMS[@]}"; do
  GOOS="${platform%/*}"
  GOARCH="${platform#*/}"
  BINARY_NAME="watchdog-agent-${GOOS}-${GOARCH}"
  BINARY_PATH="$DIST_DIR/$BINARY_NAME"

  # SHA256 — get the hex digest
  SHA256_HEX="$(shasum -a 256 "$BINARY_PATH" | awk '{print $1}')"

  # Sign the raw SHA256 hash bytes (not the hex string)
  SIGNATURE_HEX=""
  if [[ -n "$PRIVATE_KEY_HEX" ]]; then
    # Convert hex digest to raw bytes and pipe to signer
    SIGNATURE_HEX="$(echo -n "$SHA256_HEX" | xxd -r -p | ED25519_PRIVATE_KEY="$PRIVATE_KEY_HEX" "$SIGNER_BIN")"
  fi

  DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/${BINARY_NAME}"

  echo "    $BINARY_NAME  sha256=$SHA256_HEX"
  if [[ -n "$SIGNATURE_HEX" ]]; then
    echo "                     sig=${SIGNATURE_HEX:0:16}..."
  fi

  # Build JSON entry (using printf to avoid jq dependency)
  ENTRY="\"${platform}\": {"
  ENTRY+="\"url\": \"${DOWNLOAD_URL}\","
  ENTRY+="\"sha256\": \"${SHA256_HEX}\""
  if [[ -n "$SIGNATURE_HEX" ]]; then
    ENTRY+=",\"signature\": \"${SIGNATURE_HEX}\""
  fi
  ENTRY+="}"

  if [[ -n "$MANIFEST_BINARIES" ]]; then
    MANIFEST_BINARIES+=","
  fi
  MANIFEST_BINARIES+="$ENTRY"
done

# --- Write manifest.json ---

MANIFEST_PATH="$DIST_DIR/manifest.json"

# Use python for pretty-printing if available, otherwise write raw
MANIFEST_RAW="{\"version\":\"${VERSION_BARE}\",\"binaries\":{${MANIFEST_BINARIES}}}"

if command -v python3 &>/dev/null; then
  echo "$MANIFEST_RAW" | python3 -m json.tool > "$MANIFEST_PATH"
elif command -v jq &>/dev/null; then
  echo "$MANIFEST_RAW" | jq '.' > "$MANIFEST_PATH"
else
  echo "$MANIFEST_RAW" > "$MANIFEST_PATH"
fi

echo ""
echo "==> Manifest written to $MANIFEST_PATH"

# --- Print summary ---

echo ""
echo "==> Artifacts:"
ls -lh "$DIST_DIR/"

echo ""
echo "==> manifest.json:"
cat "$MANIFEST_PATH"

# --- Upload to GitHub Releases ---

if [[ "$UPLOAD" == true ]]; then
  echo ""
  echo "==> Uploading to GitHub Releases ($GITHUB_REPO @ $VERSION)..."

  # Collect all artifact paths
  ARTIFACTS=()
  for platform in "${PLATFORMS[@]}"; do
    GOOS="${platform%/*}"
    GOARCH="${platform#*/}"
    ARTIFACTS+=("$DIST_DIR/watchdog-agent-${GOOS}-${GOARCH}")
  done
  ARTIFACTS+=("$MANIFEST_PATH")

  gh release create "$VERSION" \
    --repo "$GITHUB_REPO" \
    --title "watchdog-agent $VERSION" \
    --notes "Release $VERSION" \
    --draft \
    "${ARTIFACTS[@]}"

  echo ""
  echo "==> Draft release created. Review and publish at:"
  echo "    https://github.com/${GITHUB_REPO}/releases/tag/${VERSION}"
else
  echo ""
  echo "==> Dry run complete. To upload, re-run with --upload:"
  echo "    $0 $VERSION$(if [[ -n "$PRIVATE_KEY_FILE" ]]; then echo " --private-key $PRIVATE_KEY_FILE"; fi) --upload"
fi
