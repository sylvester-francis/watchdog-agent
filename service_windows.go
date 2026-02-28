//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"strings"
)

// checkServiceStatus checks if a Windows service is running via sc query.
// Returns "up" if running, "down" otherwise.
func checkServiceStatus(serviceName string) (status, errMsg string) {
	// Validate service name to prevent command injection.
	for _, c := range serviceName {
		if !isValidServiceNameChar(c) {
			return StatusError, fmt.Sprintf("invalid service name character: %c", c)
		}
	}
	if serviceName == "" {
		return StatusError, "service name is empty"
	}

	// Use sc query to check service status.
	// #nosec G204 — serviceName is validated above
	cmd := exec.Command("sc", "query", serviceName)
	out, err := cmd.Output()
	if err != nil {
		return StatusDown, fmt.Sprintf("service %s not found or access denied", serviceName)
	}

	output := string(out)

	// Parse STATE line: "        STATE              : 4  RUNNING"
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "STATE") {
			upper := strings.ToUpper(trimmed)
			if strings.Contains(upper, "RUNNING") {
				return StatusUp, ""
			}
			if strings.Contains(upper, "STOPPED") {
				return StatusDown, fmt.Sprintf("service %s is stopped", serviceName)
			}
			if strings.Contains(upper, "PAUSED") {
				return StatusDown, fmt.Sprintf("service %s is paused", serviceName)
			}
			if strings.Contains(upper, "START_PENDING") {
				return StatusDown, fmt.Sprintf("service %s is starting", serviceName)
			}
			if strings.Contains(upper, "STOP_PENDING") {
				return StatusDown, fmt.Sprintf("service %s is stopping", serviceName)
			}
			return StatusDown, fmt.Sprintf("service %s state: %s", serviceName, trimmed)
		}
	}

	return StatusDown, fmt.Sprintf("service %s: unable to parse state", serviceName)
}

// isValidServiceNameChar returns true for characters allowed in Windows service names.
func isValidServiceNameChar(c rune) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '_' || c == '.' || c == ' '
}
