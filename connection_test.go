package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// --- BuildTLSConfig ---

func TestBuildTLSConfig_Defaults(t *testing.T) {
	cfg, err := BuildTLSConfig("wss://hub.example.com:443/ws", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify must be false")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want TLS 1.2 (%d)", cfg.MinVersion, tls.VersionTLS12)
	}
	if cfg.ServerName != "hub.example.com" {
		t.Errorf("ServerName = %q, want %q", cfg.ServerName, "hub.example.com")
	}
	if cfg.RootCAs != nil {
		t.Error("RootCAs should be nil when no CA cert provided")
	}
}

func TestBuildTLSConfig_ServerNameExtraction(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		wantServer string
	}{
		{"with port", "wss://hub.example.com:8443/ws", "hub.example.com"},
		{"without port", "wss://hub.example.com/ws", "hub.example.com"},
		{"ip address", "wss://192.168.1.1:443/ws", "192.168.1.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := BuildTLSConfig(tt.url, "")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.ServerName != tt.wantServer {
				t.Errorf("ServerName = %q, want %q", cfg.ServerName, tt.wantServer)
			}
		})
	}
}

func TestBuildTLSConfig_InvalidURL(t *testing.T) {
	_, err := BuildTLSConfig("://invalid", "")
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestBuildTLSConfig_CustomCA(t *testing.T) {
	// Generate a self-signed CA cert for testing.
	tmpDir := t.TempDir()
	caPath := filepath.Join(tmpDir, "ca.pem")

	// Create a self-signed cert using crypto stdlib.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(caPath, certPEM, 0600); err != nil {
		t.Fatalf("failed to write test CA: %v", err)
	}

	cfg, err := BuildTLSConfig("wss://hub.example.com/ws", caPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.RootCAs == nil {
		t.Error("RootCAs should be set when CA cert is provided")
	}
}

func TestBuildTLSConfig_MissingCAFile(t *testing.T) {
	_, err := BuildTLSConfig("wss://hub.example.com/ws", "/nonexistent/ca.pem")
	if err == nil {
		t.Error("expected error for missing CA file")
	}
	if !strings.Contains(err.Error(), "failed to read CA cert") {
		t.Errorf("error should mention CA cert read failure, got: %v", err)
	}
}

func TestBuildTLSConfig_InvalidCAPEM(t *testing.T) {
	tmpDir := t.TempDir()
	caPath := filepath.Join(tmpDir, "bad.pem")
	if err := os.WriteFile(caPath, []byte("not a real PEM"), 0600); err != nil {
		t.Fatalf("failed to write bad PEM: %v", err)
	}

	_, err := BuildTLSConfig("wss://hub.example.com/ws", caPath)
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
	if !strings.Contains(err.Error(), "failed to parse CA cert") {
		t.Errorf("error should mention PEM parse failure, got: %v", err)
	}
}

// --- collectFingerprint ---

func TestCollectFingerprint_Fields(t *testing.T) {
	fp := collectFingerprint()

	// Must have all four keys.
	required := []string{"hostname", "os", "arch", "go"}
	for _, key := range required {
		if _, ok := fp[key]; !ok {
			t.Errorf("missing key %q in fingerprint", key)
		}
	}

	// OS and arch must match runtime.
	if fp["os"] != runtime.GOOS {
		t.Errorf("os = %q, want %q", fp["os"], runtime.GOOS)
	}
	if fp["arch"] != runtime.GOARCH {
		t.Errorf("arch = %q, want %q", fp["arch"], runtime.GOARCH)
	}
}

func TestCollectFingerprint_HostnameRedacted(t *testing.T) {
	fp := collectFingerprint()

	hostname := fp["hostname"]
	// Must be a hex string of exactly 12 characters (SHA-256 prefix).
	if len(hostname) != 12 {
		t.Errorf("hashed hostname length = %d, want 12", len(hostname))
	}
	for _, c := range hostname {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("hashed hostname contains non-hex char: %c", c)
		}
	}
}

func TestCollectFingerprint_GoVersionTruncated(t *testing.T) {
	fp := collectFingerprint()

	goVer := fp["go"]
	// Should be "goX.Y" format (no patch version).
	parts := strings.SplitN(goVer, ".", 3)
	if len(parts) > 2 {
		t.Errorf("Go version should be truncated to major.minor, got %q", goVer)
	}
	if !strings.HasPrefix(goVer, "go") {
		t.Errorf("Go version should start with 'go', got %q", goVer)
	}
}
