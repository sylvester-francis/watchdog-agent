package main

import (
	"strings"
	"testing"
)

// --- parsePortSpec ---

func TestParsePortSpec_CSV(t *testing.T) {
	ports, err := parsePortSpec("22,80,443", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should be sorted.
	want := []int{22, 80, 443}
	if len(ports) != len(want) {
		t.Fatalf("got %d ports, want %d", len(ports), len(want))
	}
	for i, p := range ports {
		if p != want[i] {
			t.Errorf("port[%d] = %d, want %d", i, p, want[i])
		}
	}
}

func TestParsePortSpec_Range(t *testing.T) {
	ports, err := parsePortSpec("", "8000-8005")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []int{8000, 8001, 8002, 8003, 8004, 8005}
	if len(ports) != len(want) {
		t.Fatalf("got %d ports, want %d", len(ports), len(want))
	}
	for i, p := range ports {
		if p != want[i] {
			t.Errorf("port[%d] = %d, want %d", i, p, want[i])
		}
	}
}

func TestParsePortSpec_Combined(t *testing.T) {
	ports, err := parsePortSpec("22,80,8000-8002", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []int{22, 80, 8000, 8001, 8002}
	if len(ports) != len(want) {
		t.Fatalf("got %d ports, want %d", len(ports), len(want))
	}
	for i, p := range ports {
		if p != want[i] {
			t.Errorf("port[%d] = %d, want %d", i, p, want[i])
		}
	}
}

func TestParsePortSpec_Deduplication(t *testing.T) {
	ports, err := parsePortSpec("80,80,80,443", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 2 {
		t.Errorf("got %d ports, want 2 (deduped)", len(ports))
	}
}

func TestParsePortSpec_InvalidPort(t *testing.T) {
	tests := []struct {
		name      string
		csv       string
		rng       string
		errSubstr string
	}{
		{"port 0", "0", "", "invalid port"},
		{"port 65536", "65536", "", "invalid port"},
		{"negative port", "-1", "", "invalid range"},
		{"non-numeric", "abc", "", "invalid port"},
		{"range start > end", "", "443-80", "start"},
		{"range too large", "", "1-60000", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parsePortSpec(tt.csv, tt.rng)
			if err == nil {
				t.Error("expected error")
			}
			if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
				t.Errorf("error %q should contain %q", err.Error(), tt.errSubstr)
			}
		})
	}
}

func TestParsePortSpec_MaxPortsExceeded(t *testing.T) {
	// Build a CSV with >10000 unique ports.
	// Use range to exceed the limit.
	_, err := parsePortSpec("", "1-10001")
	if err == nil {
		t.Error("expected error for exceeding max ports")
	}
}

func TestParsePortSpec_EmptyInputs(t *testing.T) {
	ports, err := parsePortSpec("", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 0 {
		t.Errorf("got %d ports for empty input, want 0", len(ports))
	}
}

func TestParsePortSpec_WhitespaceHandling(t *testing.T) {
	ports, err := parsePortSpec(" 22 , 80 , 443 ", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 3 {
		t.Errorf("got %d ports, want 3", len(ports))
	}
}

// --- parseRange ---

func TestParseRange_Valid(t *testing.T) {
	ports, err := parseRange("100-105")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 6 {
		t.Errorf("got %d ports, want 6", len(ports))
	}
	if ports[0] != 100 || ports[5] != 105 {
		t.Errorf("range bounds wrong: first=%d, last=%d", ports[0], ports[len(ports)-1])
	}
}

func TestParseRange_SinglePort(t *testing.T) {
	ports, err := parseRange("80-80")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 1 || ports[0] != 80 {
		t.Errorf("got %v, want [80]", ports)
	}
}

func TestParseRange_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"no dash", "80"},
		{"reversed", "443-80"},
		{"zero start", "0-100"},
		{"over 65535", "65535-65536"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseRange(tt.input)
			if err == nil {
				t.Error("expected error")
			}
		})
	}
}

// --- intSliceToCSV ---

func TestIntSliceToCSV(t *testing.T) {
	tests := []struct {
		name  string
		input []int
		want  string
	}{
		{"empty", nil, ""},
		{"single", []int{80}, "80"},
		{"multiple", []int{22, 80, 443}, "22,80,443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := intSliceToCSV(tt.input)
			if got != tt.want {
				t.Errorf("intSliceToCSV(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// --- parseCSVInts ---

func TestParseCSVInts(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []int
	}{
		{"empty", "", nil},
		{"single", "80", []int{80}},
		{"multiple", "22,80,443", []int{22, 80, 443}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseCSVInts(tt.input)
			if len(got) != len(tt.want) {
				t.Fatalf("got %d ints, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("parseCSVInts[%d] = %d, want %d", i, got[i], tt.want[i])
				}
			}
		})
	}
}
