package main

import (
	"strings"
	"testing"
)

// --- identifyService ---

func TestIdentifyService_SSH(t *testing.T) {
	banner := []byte("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13")
	svc, ver := identifyService(22, banner)
	if svc != "ssh" {
		t.Errorf("service = %q, want ssh", svc)
	}
	if ver == "" {
		t.Error("expected version to be extracted")
	}
	if !strings.Contains(ver, "OpenSSH") {
		t.Errorf("version = %q, expected to contain OpenSSH", ver)
	}
}

func TestIdentifyService_HTTP(t *testing.T) {
	banner := []byte("HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n")
	svc, _ := identifyService(80, banner)
	if svc != "http" {
		t.Errorf("service = %q, want http", svc)
	}
}

func TestIdentifyService_SMTP(t *testing.T) {
	banner := []byte("220 mail.example.com ESMTP Postfix")
	svc, _ := identifyService(25, banner)
	if svc != "smtp" {
		t.Errorf("service = %q, want smtp", svc)
	}
}

func TestIdentifyService_FTP(t *testing.T) {
	banner := []byte("220 Welcome to FTP service")
	svc, _ := identifyService(21, banner)
	if svc != "ftp" {
		t.Errorf("service = %q, want ftp", svc)
	}
}

func TestIdentifyService_Redis(t *testing.T) {
	tests := []struct {
		name   string
		banner []byte
	}{
		{"PONG", []byte("+PONG\r\n")},
		{"ERR", []byte("-ERR operation not permitted\r\n")},
		{"NOAUTH", []byte("-NOAUTH Authentication required\r\n")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, _ := identifyService(6379, tt.banner)
			if svc != "redis" {
				t.Errorf("service = %q, want redis", svc)
			}
		})
	}
}

func TestIdentifyService_POP3(t *testing.T) {
	banner := []byte("+OK POP3 server ready")
	svc, _ := identifyService(110, banner)
	if svc != "pop3" {
		t.Errorf("service = %q, want pop3", svc)
	}
}

func TestIdentifyService_IMAP(t *testing.T) {
	banner := []byte("* OK [CAPABILITY IMAP4rev1] Dovecot ready.")
	svc, _ := identifyService(143, banner)
	if svc != "imap" {
		t.Errorf("service = %q, want imap", svc)
	}
}

func TestIdentifyService_NginxVersion(t *testing.T) {
	// When HTTP status line is present, the ^HTTP pattern matches first (no version).
	banner := []byte("HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n")
	svc, _ := identifyService(80, banner)
	if svc != "http" {
		t.Errorf("service = %q, want http", svc)
	}

	// Without HTTP status line, nginx server header extracts version.
	banner2 := []byte("Server: nginx/1.24.0\r\n\r\n")
	svc2, ver2 := identifyService(80, banner2)
	if svc2 != "http" {
		t.Errorf("service = %q, want http", svc2)
	}
	if !strings.Contains(ver2, "nginx") {
		t.Errorf("version = %q, expected to contain nginx", ver2)
	}
}

func TestIdentifyService_ApacheVersion(t *testing.T) {
	// Without HTTP status line, apache server header extracts version.
	banner := []byte("Server: Apache/2.4.57\r\n\r\n")
	svc, ver := identifyService(80, banner)
	if svc != "http" {
		t.Errorf("service = %q, want http", svc)
	}
	if !strings.Contains(ver, "Apache") {
		t.Errorf("version = %q, expected to contain Apache", ver)
	}
}

func TestIdentifyService_UnknownBanner(t *testing.T) {
	banner := []byte("PROPRIETARY PROTOCOL v3.0\r\n")
	svc, _ := identifyService(12345, banner)
	if svc != "" {
		t.Errorf("service = %q, want empty for unknown banner on unknown port", svc)
	}
}

func TestIdentifyService_WellKnownPortFallback(t *testing.T) {
	// Unknown banner but well-known port should fall back.
	banner := []byte("PROPRIETARY PROTOCOL v3.0\r\n")
	svc, _ := identifyService(22, banner)
	if svc != "ssh" {
		t.Errorf("service = %q, want ssh (well-known port fallback)", svc)
	}
}

// --- sanitizeBanner ---

func TestSanitizeBanner_PrintableOnly(t *testing.T) {
	raw := []byte("SSH-2.0-OpenSSH\x00\x01\x02\x7f_9.6")
	got := sanitizeBanner(raw)
	// Should strip non-printable bytes.
	if strings.ContainsAny(got, "\x00\x01\x02\x7f") {
		t.Errorf("banner contains non-printable chars: %q", got)
	}
	if !strings.Contains(got, "SSH-2.0-OpenSSH") {
		t.Errorf("banner should contain printable prefix, got %q", got)
	}
}

func TestSanitizeBanner_Truncation(t *testing.T) {
	// Banner should be truncated to bannerMaxLineLen (256).
	raw := make([]byte, 500)
	for i := range raw {
		raw[i] = 'A'
	}
	got := sanitizeBanner(raw)
	if len(got) != bannerMaxLineLen {
		t.Errorf("banner length = %d, want %d (truncated)", len(got), bannerMaxLineLen)
	}
}

func TestSanitizeBanner_Empty(t *testing.T) {
	got := sanitizeBanner(nil)
	if got != "" {
		t.Errorf("expected empty string for nil input, got %q", got)
	}
}

func TestSanitizeBanner_ControlCharsStripped(t *testing.T) {
	// Tab, newline, carriage return, bell — all should be stripped.
	raw := []byte("Hello\tWorld\nFoo\rBar\x07Baz")
	got := sanitizeBanner(raw)
	if got != "HelloWorldFooBarBaz" {
		t.Errorf("expected control chars stripped, got %q", got)
	}
}

// --- encodePortDetails ---

func TestEncodePortDetails_Normal(t *testing.T) {
	details := []PortDetail{
		{Port: 22, State: "open", Service: "ssh", Banner: "SSH-2.0-OpenSSH"},
		{Port: 80, State: "open", Service: "http"},
	}
	result := encodePortDetails(details)
	if result == "" {
		t.Error("expected non-empty JSON")
	}
	if !strings.Contains(result, `"port":22`) {
		t.Errorf("result should contain port 22, got %q", result)
	}
}

func TestEncodePortDetails_Empty(t *testing.T) {
	result := encodePortDetails(nil)
	if result != "null" && result != "[]" && result != "" {
		// json.Marshal(nil slice) returns "null"
		t.Logf("empty details encoded as: %q", result)
	}
}

func TestEncodePortDetails_OverSizeStripsBanners(t *testing.T) {
	// Create details that exceed 64KB with banners.
	details := make([]PortDetail, 500)
	longBanner := strings.Repeat("A", 200)
	for i := range details {
		details[i] = PortDetail{
			Port:    i + 1,
			State:   "open",
			Service: "http",
			Banner:  longBanner,
			Version: "1.0",
		}
	}
	result := encodePortDetails(details)
	if result == "" {
		t.Log("result empty — details too large even after stripping banners")
		return
	}
	// If we got a result, banners should have been stripped.
	if strings.Contains(result, longBanner) {
		t.Error("oversize result should have banners stripped")
	}
}
