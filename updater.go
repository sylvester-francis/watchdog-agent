package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/sylvester-francis/watchdog-proto/protocol"
)

// maxUpdateSize limits update binary downloads to 100 MB.
const maxUpdateSize = 100 * 1024 * 1024

// handleUpdateAvailable processes an update_available message from the hub.
// It downloads the new binary, verifies its SHA-256 checksum, atomically
// replaces the running binary, and re-execs the process.
func (a *Agent) handleUpdateAvailable(msg *protocol.Message) {
	var payload protocol.UpdateAvailablePayload
	if err := msg.ParsePayload(&payload); err != nil {
		a.logger.Error("failed to parse update payload", slog.String("error", err.Error()))
		return
	}

	if payload.Version == "" || payload.DownloadURL == "" || payload.SHA256 == "" {
		a.logger.Warn("incomplete update payload, ignoring")
		return
	}

	// Skip if already on this version.
	if payload.Version == a.config.Version {
		a.logger.Debug("already on latest version", slog.String("version", payload.Version))
		return
	}

	a.logger.Info("update available",
		slog.String("current", a.config.Version),
		slog.String("new", payload.Version),
	)

	if err := applyUpdate(payload, a.logger); err != nil {
		a.logger.Error("update failed", slog.String("error", err.Error()))
		return
	}

	a.logger.Info("update applied, restarting...")

	// Trigger a graceful restart by closing the stop channel.
	// The process supervisor (systemd) will restart us with the new binary.
	close(a.stopCh)
}

// applyUpdate downloads, verifies, and atomically replaces the current binary.
func applyUpdate(payload protocol.UpdateAvailablePayload, logger *slog.Logger) error {
	// Windows doesn't support atomic rename of running binaries.
	if runtime.GOOS == "windows" {
		return fmt.Errorf("auto-update not supported on Windows")
	}

	// Get path to current executable.
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return fmt.Errorf("failed to resolve symlinks: %w", err)
	}

	// Download the new binary to a temp file in the same directory
	// (same filesystem guarantees atomic rename).
	dir := filepath.Dir(execPath)
	tmpFile, err := os.CreateTemp(dir, ".watchdog-update-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer func() {
		// Clean up temp file on any error.
		tmpFile.Close()
		os.Remove(tmpPath)
	}()

	logger.Info("downloading update", slog.String("url", payload.DownloadURL))

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(payload.DownloadURL) //nolint:gosec // URL comes from trusted hub
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned status %d", resp.StatusCode)
	}

	// Hash while downloading.
	hasher := sha256.New()
	reader := io.LimitReader(resp.Body, maxUpdateSize+1)
	n, err := io.Copy(io.MultiWriter(tmpFile, hasher), reader)
	if err != nil {
		return fmt.Errorf("download write failed: %w", err)
	}
	if n > maxUpdateSize {
		return fmt.Errorf("update binary exceeds %d MB size limit", maxUpdateSize/(1024*1024))
	}
	if n == 0 {
		return fmt.Errorf("downloaded empty file")
	}

	// Verify checksum.
	actualHash := hex.EncodeToString(hasher.Sum(nil))
	if actualHash != payload.SHA256 {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", payload.SHA256, actualHash)
	}
	logger.Info("checksum verified", slog.String("sha256", actualHash))

	// Verify ed25519 signature of the SHA256 hash.
	if err := verifySignature(hasher.Sum(nil), payload.Signature, logger); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	// Close temp file before chmod/rename.
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	// Preserve permissions from original binary.
	origInfo, err := os.Stat(execPath)
	if err != nil {
		return fmt.Errorf("failed to stat original binary: %w", err)
	}
	if err := os.Chmod(tmpPath, origInfo.Mode()); err != nil {
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	// Atomic replace: rename new binary over old one.
	if err := os.Rename(tmpPath, execPath); err != nil {
		return fmt.Errorf("failed to replace binary: %w", err)
	}

	logger.Info("binary replaced successfully", slog.String("path", execPath))
	return nil
}

// verifySignature checks the ed25519 signature of the SHA256 hash bytes.
// If ReleaseSigningPublicKey is the all-zeros placeholder, verification is
// skipped with a warning. Otherwise the signature must be present and valid.
func verifySignature(sha256Hash []byte, signatureHex string, logger *slog.Logger) error {
	// Check if the public key is the placeholder (all zeros).
	if strings.Trim(ReleaseSigningPublicKey, "0") == "" {
		logger.Warn("release signing public key not set, skipping signature verification")
		return nil
	}

	pubKeyBytes, err := hex.DecodeString(ReleaseSigningPublicKey)
	if err != nil {
		return fmt.Errorf("invalid public key hex: %w", err)
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key length: got %d, want %d", len(pubKeyBytes), ed25519.PublicKeySize)
	}

	if signatureHex == "" {
		return fmt.Errorf("update payload missing signature")
	}

	sigBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		return fmt.Errorf("invalid signature hex: %w", err)
	}
	if len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature length: got %d, want %d", len(sigBytes), ed25519.SignatureSize)
	}

	if !ed25519.Verify(ed25519.PublicKey(pubKeyBytes), sha256Hash, sigBytes) {
		return fmt.Errorf("ed25519 signature does not match")
	}

	logger.Info("signature verified")
	return nil
}
