package main

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxPortsPerScan     = 10000
	portScanConcurrency = 50
	portDialTimeout     = 2 * time.Second
)

// checkPortScan scans multiple TCP ports on the target host.
// Metadata fields read:
//   - "ports": comma-separated ports and/or ranges (e.g. "22,80,443,8000-9000")
//   - "port_range": alternative range format (e.g. "1-1024")
//   - "expected_open": comma-separated ports expected to be open (enables alerting)
//
// Returns metadata with open_ports, closed_ports, open_count, scanned_count,
// and optionally missing_ports/unexpected_ports for change-detection alerting.
func (t *Task) checkPortScan(ctx context.Context) (status, errMsg string, metadata map[string]string) {
	target := t.payload.Target

	// Parse ports to scan
	ports, err := parsePortSpec(t.payload.Metadata["ports"], t.payload.Metadata["port_range"])
	if err != nil {
		return StatusError, fmt.Sprintf("invalid port spec: %s", err.Error()), nil
	}
	if len(ports) == 0 {
		return StatusError, "no ports specified: set 'ports' or 'port_range' in metadata", nil
	}

	// Scan ports concurrently with semaphore
	type portResult struct {
		port int
		open bool
	}

	results := make([]portResult, len(ports))
	sem := make(chan struct{}, portScanConcurrency)
	var wg sync.WaitGroup

	for i, port := range ports {
		wg.Add(1)
		go func(idx, p int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			addr := net.JoinHostPort(target, strconv.Itoa(p))
			conn, dialErr := net.DialTimeout("tcp", addr, portDialTimeout)
			if dialErr == nil {
				conn.Close()
				results[idx] = portResult{port: p, open: true}
			} else {
				results[idx] = portResult{port: p, open: false}
			}
		}(i, port)
	}
	wg.Wait()

	// Collect results
	var openPorts, closedPorts []int
	for _, r := range results {
		if r.open {
			openPorts = append(openPorts, r.port)
		} else {
			closedPorts = append(closedPorts, r.port)
		}
	}
	sort.Ints(openPorts)
	sort.Ints(closedPorts)

	metadata = map[string]string{
		"open_ports":    intSliceToCSV(openPorts),
		"closed_ports":  intSliceToCSV(closedPorts),
		"open_count":    strconv.Itoa(len(openPorts)),
		"scanned_count": strconv.Itoa(len(ports)),
	}

	// Change-detection alerting against expected_open
	expectedStr := t.payload.Metadata["expected_open"]
	if expectedStr != "" {
		expected := parseCSVInts(expectedStr)
		expectedSet := make(map[int]bool, len(expected))
		for _, p := range expected {
			expectedSet[p] = true
		}
		openSet := make(map[int]bool, len(openPorts))
		for _, p := range openPorts {
			openSet[p] = true
		}

		var missing, unexpected []int
		for _, p := range expected {
			if !openSet[p] {
				missing = append(missing, p)
			}
		}
		for _, p := range openPorts {
			if !expectedSet[p] {
				unexpected = append(unexpected, p)
			}
		}
		sort.Ints(missing)
		sort.Ints(unexpected)

		if len(missing) > 0 {
			metadata["missing_ports"] = intSliceToCSV(missing)
		}
		if len(unexpected) > 0 {
			metadata["unexpected_ports"] = intSliceToCSV(unexpected)
		}

		if len(missing) > 0 || len(unexpected) > 0 {
			var parts []string
			if len(missing) > 0 {
				parts = append(parts, fmt.Sprintf("expected ports not open: %s", intSliceToCSV(missing)))
			}
			if len(unexpected) > 0 {
				parts = append(parts, fmt.Sprintf("unexpected ports open: %s", intSliceToCSV(unexpected)))
			}
			return StatusDown, strings.Join(parts, "; "), metadata
		}
	}

	return StatusUp, "", metadata
}

// parsePortSpec parses ports from CSV and/or range strings.
// Supports formats: "22,80,443", "8000-9000", "22,80,8000-8100".
// Enforces maxPortsPerScan limit.
func parsePortSpec(portsCSV, portRange string) ([]int, error) {
	seen := make(map[int]bool)

	// Parse CSV ports (may include inline ranges)
	if portsCSV != "" {
		for _, part := range strings.Split(portsCSV, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if strings.Contains(part, "-") {
				rangePorts, err := parseRange(part)
				if err != nil {
					return nil, err
				}
				for _, p := range rangePorts {
					seen[p] = true
				}
			} else {
				p, err := strconv.Atoi(part)
				if err != nil || p < 1 || p > 65535 {
					return nil, fmt.Errorf("invalid port: %s", part)
				}
				seen[p] = true
			}
		}
	}

	// Parse port range
	if portRange != "" {
		rangePorts, err := parseRange(portRange)
		if err != nil {
			return nil, err
		}
		for _, p := range rangePorts {
			seen[p] = true
		}
	}

	if len(seen) > maxPortsPerScan {
		return nil, fmt.Errorf("too many ports: %d (max %d)", len(seen), maxPortsPerScan)
	}

	ports := make([]int, 0, len(seen))
	for p := range seen {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports, nil
}

// parseRange parses a "start-end" range string into a slice of port numbers.
func parseRange(s string) ([]int, error) {
	parts := strings.SplitN(strings.TrimSpace(s), "-", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid range: %s", s)
	}
	start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || start < 1 || start > 65535 {
		return nil, fmt.Errorf("invalid range start: %s", parts[0])
	}
	end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil || end < 1 || end > 65535 {
		return nil, fmt.Errorf("invalid range end: %s", parts[1])
	}
	if start > end {
		return nil, fmt.Errorf("invalid range: start %d > end %d", start, end)
	}
	if end-start+1 > maxPortsPerScan {
		return nil, fmt.Errorf("range too large: %d ports (max %d)", end-start+1, maxPortsPerScan)
	}

	ports := make([]int, 0, end-start+1)
	for p := start; p <= end; p++ {
		ports = append(ports, p)
	}
	return ports, nil
}

// intSliceToCSV converts a slice of ints to a comma-separated string.
func intSliceToCSV(nums []int) string {
	if len(nums) == 0 {
		return ""
	}
	strs := make([]string, len(nums))
	for i, n := range nums {
		strs[i] = strconv.Itoa(n)
	}
	return strings.Join(strs, ",")
}

// parseCSVInts parses a comma-separated string of integers.
func parseCSVInts(s string) []int {
	if s == "" {
		return nil
	}
	var result []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if n, err := strconv.Atoi(part); err == nil && n >= 1 && n <= 65535 {
			result = append(result, n)
		}
	}
	return result
}
