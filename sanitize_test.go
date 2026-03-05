package main

import (
	"strings"
	"testing"
)

// --- containsShellMeta ---

func TestContainsShellMeta(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"clean string", "example.com", false},
		{"backtick", "example`id`", true},
		{"dollar paren", "$(whoami)", true},
		{"pipe", "foo|bar", true},
		{"semicolon", "foo;bar", true},
		{"double amp", "foo&&bar", true},
		{"double pipe", "foo||bar", true},
		{"redirect out", "foo>bar", true},
		{"redirect in", "foo<bar", true},
		{"newline", "foo\nbar", true},
		{"carriage return", "foo\rbar", true},
		{"single amp is fine", "foo&bar", false},  // only && is blocked
		{"single pipe blocked", "a|b", true},       // single pipe IS blocked
		{"empty string", "", false},
		{"dollar without paren", "$HOME", false},
		{"url with query", "https://example.com?a=1&b=2", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsShellMeta(tt.input)
			if got != tt.want {
				t.Errorf("containsShellMeta(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// --- scrubCredentials ---

func TestScrubCredentials(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			"postgres with creds",
			"postgres://admin:s3cret@localhost:5432/db",
			"postgres://***:***@localhost:5432/db",
		},
		{
			"mysql with creds",
			"mysql://root:password123@db.host:3306/mydb",
			"mysql://***:***@db.host:3306/mydb",
		},
		{
			"no credentials",
			"postgres://localhost:5432/db",
			"postgres://localhost:5432/db",
		},
		{
			"empty string",
			"",
			"",
		},
		{
			"plain error message",
			"connection refused",
			"connection refused",
		},
		{
			"multiple URIs",
			"failed: postgres://u:p@h1/db and redis://x:y@h2/0",
			"failed: postgres://***:***@h1/db and redis://***:***@h2/0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scrubCredentials(tt.input)
			if got != tt.want {
				t.Errorf("scrubCredentials(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// --- sanitizeTarget ---

func TestSanitizeTarget_Universal(t *testing.T) {
	tests := []struct {
		name      string
		checkType string
		target    string
		wantErr   bool
		errSubstr string
	}{
		{"empty target", "http", "", true, "target is required"},
		{"too long", "http", "https://" + strings.Repeat("a", 2050), true, "target too long"},
		{"shell meta backtick", "http", "https://`whoami`.com", true, "prohibited characters"},
		{"shell meta pipe", "tcp", "host|evil:443", true, "prohibited characters"},
		{"shell meta dollar", "dns", "$(cat /etc/passwd)", true, "prohibited characters"},
		{"shell meta semicolon", "ping", "host;rm -rf /", true, "prohibited characters"},
		{"shell meta newline", "tcp", "host\n:443", true, "prohibited characters"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeTarget(tt.checkType, tt.target)
			if tt.wantErr {
				if got == "" {
					t.Error("expected error, got empty string")
				}
				if tt.errSubstr != "" && !strings.Contains(got, tt.errSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.errSubstr, got)
				}
			} else {
				if got != "" {
					t.Errorf("expected no error, got %q", got)
				}
			}
		})
	}
}

func TestSanitizeTarget_HTTP(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{"valid https", "https://example.com", false},
		{"valid http", "http://example.com/path?q=1", false},
		{"missing scheme", "example.com", true},
		{"ftp scheme", "ftp://example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeTarget("http", tt.target)
			if tt.wantErr && got == "" {
				t.Error("expected error, got empty string")
			}
			if !tt.wantErr && got != "" {
				t.Errorf("expected no error, got %q", got)
			}
		})
	}
}

func TestSanitizeTarget_TCP(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{"host:port", "example.com:443", false},
		{"ip:port", "192.168.1.1:8080", false},
		{"bare hostname", "example.com", true},
		{"bare ip", "192.168.1.1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeTarget("tcp", tt.target)
			if tt.wantErr && got == "" {
				t.Error("expected error, got empty string")
			}
			if !tt.wantErr && got != "" {
				t.Errorf("expected no error, got %q", got)
			}
		})
	}
}

func TestSanitizeTarget_TLS(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{"host:port", "example.com:443", false},
		{"bare hostname OK for TLS", "example.com", false},
		{"bare IP OK for TLS", "192.168.1.1", false},
		{"ip:port", "10.0.0.1:8443", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeTarget("tls", tt.target)
			if tt.wantErr && got == "" {
				t.Error("expected error, got empty string")
			}
			if !tt.wantErr && got != "" {
				t.Errorf("expected no error, got %q", got)
			}
		})
	}
}

func TestSanitizeTarget_DNS(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{"valid hostname", "example.com", false},
		{"subdomain", "sub.example.com", false},
		{"with port", "example.com:53", true},
		{"ip address matches hostname regex", "192.168.1.1", false}, // hostname regex accepts IP-like patterns
		{"underscore", "_dmarc.example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeTarget("dns", tt.target)
			if tt.wantErr && got == "" {
				t.Error("expected error, got empty string")
			}
			if !tt.wantErr && got != "" {
				t.Errorf("expected no error, got %q", got)
			}
		})
	}
}

func TestSanitizeTarget_Ping(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{"hostname", "example.com", false},
		{"ip", "192.168.1.1", false},
		{"host:port", "example.com:80", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeTarget("ping", tt.target)
			if tt.wantErr && got == "" {
				t.Error("expected error, got empty string")
			}
			if !tt.wantErr && got != "" {
				t.Errorf("expected no error, got %q", got)
			}
		})
	}
}

func TestSanitizeTarget_Docker(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{"simple name", "nginx", false},
		{"with dots", "my.container", false},
		{"with underscores", "my_container", false},
		{"with hyphens", "my-container", false},
		{"slash path traversal", "../../../etc/passwd", true},
		{"spaces", "my container", true},
		{"too long", strings.Repeat("a", 256), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeTarget("docker", tt.target)
			if tt.wantErr && got == "" {
				t.Error("expected error, got empty string")
			}
			if !tt.wantErr && got != "" {
				t.Errorf("expected no error, got %q", got)
			}
		})
	}
}

func TestSanitizeTarget_Database(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{"host:port", "db.example.com:5432", false},
		{"bare hostname", "db.example.com", false},
		{"bare IP", "10.0.0.5", false},
		{"ip:port", "10.0.0.5:3306", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeTarget("database", tt.target)
			if tt.wantErr && got == "" {
				t.Error("expected error, got empty string")
			}
			if !tt.wantErr && got != "" {
				t.Errorf("expected no error, got %q", got)
			}
		})
	}
}

func TestSanitizeTarget_System(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{"cpu threshold", "cpu:90", false},
		{"memory threshold", "memory:80", false},
		{"disk threshold", "disk:90:/", false},
		{"disk with path", "disk:85:/var/log", false},
		{"cpu decimal", "cpu:90.5", false},
		{"invalid metric", "network:90", true},
		{"missing threshold", "cpu:", true},
		{"bare string", "foobar", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeTarget("system", tt.target)
			if tt.wantErr && got == "" {
				t.Error("expected error, got empty string")
			}
			if !tt.wantErr && got != "" {
				t.Errorf("expected no error, got %q", got)
			}
		})
	}
}

func TestSanitizeTarget_Service(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{"simple service", "nginx", false},
		{"service with dot", "nginx.service", false},
		{"service with at", "getty@tty1", false},
		{"service with hyphen", "docker-engine", false},
		{"starts with hyphen", "-bad", true},
		{"spaces", "my service", true},
		{"too long", strings.Repeat("a", 256), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeTarget("service", tt.target)
			if tt.wantErr && got == "" {
				t.Error("expected error, got empty string")
			}
			if !tt.wantErr && got != "" {
				t.Errorf("expected no error, got %q", got)
			}
		})
	}
}

func TestSanitizeTarget_PortScan(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{"hostname", "example.com", false},
		{"ip", "192.168.1.1", false},
		{"host:port rejected", "example.com:80", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeTarget("port_scan", tt.target)
			if tt.wantErr && got == "" {
				t.Error("expected error, got empty string")
			}
			if !tt.wantErr && got != "" {
				t.Errorf("expected no error, got %q", got)
			}
		})
	}
}

// --- sanitizeConnectionString ---

func TestSanitizeConnectionString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"empty string", "", false},
		{"normal conn string", "postgres://user:pass@localhost:5432/db", false},
		{"with pipe", "postgres://user:pass@host|evil/db", true},
		{"with backtick", "host=`cmd`", true},
		{"with semicolon", "host=foo;DROP TABLE users", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeConnectionString(tt.input)
			if tt.wantErr && got == "" {
				t.Error("expected error, got empty string")
			}
			if !tt.wantErr && got != "" {
				t.Errorf("expected no error, got %q", got)
			}
		})
	}
}
