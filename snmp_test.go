package main

import (
	"strings"
	"testing"

	"github.com/gosnmp/gosnmp"
)

// --- sanitizeTarget for SNMP ---

func TestSanitizeTarget_SNMP(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{"hostname", "switch.local", false},
		{"ip", "192.168.1.1", false},
		{"ip octets", "10.0.0.1", false},
		{"host:port rejected", "192.168.1.1:161", true},
		{"path traversal", "../etc/passwd", true},
		{"spaces", "192.168.1 .1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeTarget("snmp", tt.target)
			if tt.wantErr && got == "" {
				t.Error("expected error, got empty string")
			}
			if !tt.wantErr && got != "" {
				t.Errorf("expected no error, got %q", got)
			}
		})
	}
}

// --- OID validation ---

func TestValidOIDPattern(t *testing.T) {
	tests := []struct {
		name  string
		oid   string
		valid bool
	}{
		{"sysUpTime", "1.3.6.1.2.1.1.3.0", true},
		{"sysDescr", "1.3.6.1.2.1.1.1.0", true},
		{"ifTable", "1.3.6.1.2.1.2.2", true},
		{"simple", "1.3", true},
		{"empty", "", false},
		{"no dot", "12345", false},
		{"leading dot", ".1.3.6", false},
		{"trailing dot", "1.3.6.", false},
		{"double dot", "1.3..6", false},
		{"letters", "1.3.abc.6", false},
		{"spaces", "1.3.6 .1", false},
		{"too long", "1." + strings.Repeat("3.", 128) + "0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validOIDPattern(tt.oid)
			if got != tt.valid {
				t.Errorf("validOIDPattern(%q) = %v, want %v", tt.oid, got, tt.valid)
			}
		})
	}
}

// --- parseSNMPOIDs ---

func TestParseSNMPOIDs(t *testing.T) {
	tests := []struct {
		name    string
		single  string
		csv     string
		wantLen int
		wantErr bool
	}{
		{"single OID", "1.3.6.1.2.1.1.3.0", "", 1, false},
		{"csv OIDs", "", "1.3.6.1.2.1.1.1.0,1.3.6.1.2.1.1.3.0", 2, false},
		{"both", "1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0,1.3.6.1.2.1.1.5.0", 3, false},
		{"dedup", "1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.1.0", 1, false},
		{"empty both", "", "", 0, false},
		{"invalid single", "not-an-oid", "", 0, true},
		{"invalid in csv", "", "1.3.6,invalid", 0, true},
		{"whitespace trimmed", " 1.3.6.1.2.1.1.1.0 ", " 1.3.6.1.2.1.1.3.0 ", 2, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oids, err := parseSNMPOIDs(tt.single, tt.csv)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(oids) != tt.wantLen {
				t.Errorf("got %d OIDs, want %d", len(oids), tt.wantLen)
			}
		})
	}
}

func TestParseSNMPOIDs_MaxLimit(t *testing.T) {
	// Build 65 OIDs (exceeds max of 64)
	var oids []string
	for i := 0; i < 65; i++ {
		oids = append(oids, "1.3.6.1.2.1.1."+strings.Repeat("0.", i)+"0")
	}
	// Use unique OIDs to avoid dedup
	csv := strings.Join(oids, ",")
	_, err := parseSNMPOIDs("", csv)
	if err == nil {
		t.Error("expected error for too many OIDs")
	}
	if err != nil && !strings.Contains(err.Error(), "too many OIDs") {
		t.Errorf("expected 'too many OIDs' error, got: %v", err)
	}
}

// --- formatSNMPValue ---

func TestFormatSNMPValue(t *testing.T) {
	tests := []struct {
		name string
		pdu  gosnmp.SnmpPDU
		want string
	}{
		{
			"octet string printable",
			gosnmp.SnmpPDU{Type: gosnmp.OctetString, Value: []byte("Linux router 5.10")},
			"Linux router 5.10",
		},
		{
			"octet string hex (MAC addr)",
			gosnmp.SnmpPDU{Type: gosnmp.OctetString, Value: []byte{0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}},
			"00:1A:2B:3C:4D:5E",
		},
		{
			"integer",
			gosnmp.SnmpPDU{Type: gosnmp.Integer, Value: 42},
			"42",
		},
		{
			"counter32",
			gosnmp.SnmpPDU{Type: gosnmp.Counter32, Value: uint(12345)},
			"12345",
		},
		{
			"timeticks",
			gosnmp.SnmpPDU{Type: gosnmp.TimeTicks, Value: uint32(8640000)}, // 1 day in centiseconds
			"1d 0h 0m 0s",
		},
		{
			"timeticks partial",
			gosnmp.SnmpPDU{Type: gosnmp.TimeTicks, Value: uint32(9000)}, // 90 seconds
			"0d 0h 1m 30s",
		},
		{
			"ip address",
			gosnmp.SnmpPDU{Type: gosnmp.IPAddress, Value: "192.168.1.1"},
			"192.168.1.1",
		},
		{
			"null",
			gosnmp.SnmpPDU{Type: gosnmp.Null},
			"",
		},
		{
			"no such object",
			gosnmp.SnmpPDU{Type: gosnmp.NoSuchObject},
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatSNMPValue(tt.pdu)
			if got != tt.want {
				t.Errorf("formatSNMPValue() = %q, want %q", got, tt.want)
			}
		})
	}
}

// --- isPrintableASCII ---

func TestIsPrintableASCII(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{"empty", []byte{}, true},
		{"ascii text", []byte("Hello World"), true},
		{"with tab", []byte("col1\tcol2"), true},
		{"binary", []byte{0x00, 0x01, 0x02}, false},
		{"mac address bytes", []byte{0xAA, 0xBB, 0xCC}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isPrintableASCII(tt.input)
			if got != tt.want {
				t.Errorf("isPrintableASCII(%v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// --- formatHexString ---

func TestFormatHexString(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{"mac address", []byte{0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}, "00:1A:2B:3C:4D:5E"},
		{"single byte", []byte{0xFF}, "FF"},
		{"empty", []byte{}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatHexString(tt.input)
			if got != tt.want {
				t.Errorf("formatHexString() = %q, want %q", got, tt.want)
			}
		})
	}
}

// --- SNMPv3 configuration ---

func TestParseSNMPAuthProtocol(t *testing.T) {
	tests := []struct {
		input string
		want  gosnmp.SnmpV3AuthProtocol
		err   bool
	}{
		{"MD5", gosnmp.MD5, false},
		{"SHA", gosnmp.SHA, false},
		{"SHA256", gosnmp.SHA256, false},
		{"sha512", gosnmp.SHA512, false}, // case insensitive
		{"", gosnmp.MD5, false},          // default
		{"INVALID", gosnmp.NoAuth, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseSNMPAuthProtocol(tt.input)
			if tt.err && err == nil {
				t.Error("expected error")
			}
			if !tt.err && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !tt.err && got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseSNMPPrivProtocol(t *testing.T) {
	tests := []struct {
		input string
		want  gosnmp.SnmpV3PrivProtocol
		err   bool
	}{
		{"DES", gosnmp.DES, false},
		{"AES", gosnmp.AES, false},
		{"AES256", gosnmp.AES256, false},
		{"aes192c", gosnmp.AES192C, false}, // case insensitive
		{"", gosnmp.DES, false},            // default
		{"INVALID", gosnmp.NoPriv, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseSNMPPrivProtocol(tt.input)
			if tt.err && err == nil {
				t.Error("expected error")
			}
			if !tt.err && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !tt.err && got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfigureSNMPv3_Validation(t *testing.T) {
	tests := []struct {
		name string
		meta map[string]string
		err  string
	}{
		{
			"missing username",
			map[string]string{"security_level": "noAuthNoPriv"},
			"requires 'username'",
		},
		{
			"noAuthNoPriv valid",
			map[string]string{"username": "user1", "security_level": "noAuthNoPriv"},
			"",
		},
		{
			"authNoPriv missing password",
			map[string]string{"username": "user1", "security_level": "authNoPriv", "auth_protocol": "SHA"},
			"requires 'auth_password'",
		},
		{
			"authNoPriv valid",
			map[string]string{"username": "user1", "security_level": "authNoPriv", "auth_protocol": "SHA", "auth_password": "secret123"},
			"",
		},
		{
			"authPriv missing privacy password",
			map[string]string{
				"username": "user1", "security_level": "authPriv",
				"auth_protocol": "SHA", "auth_password": "secret123",
				"privacy_protocol": "AES",
			},
			"requires 'privacy_password'",
		},
		{
			"authPriv valid",
			map[string]string{
				"username": "user1", "security_level": "authPriv",
				"auth_protocol": "SHA256", "auth_password": "authpass",
				"privacy_protocol": "AES256", "privacy_password": "privpass",
			},
			"",
		},
		{
			"invalid security level",
			map[string]string{"username": "user1", "security_level": "invalid"},
			"unsupported security_level",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &gosnmp.GoSNMP{}
			err := configureSNMPv3(client, tt.meta)
			if tt.err == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Error("expected error, got nil")
				} else if !strings.Contains(err.Error(), tt.err) {
					t.Errorf("expected error containing %q, got %q", tt.err, err.Error())
				}
			}
		})
	}
}
