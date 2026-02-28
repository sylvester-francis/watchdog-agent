//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// checkServiceStatus checks if a systemd service is active.
// Returns "up" if active, "down" otherwise.
func checkServiceStatus(serviceName string) (status, errMsg string) {
	// Validate service name to prevent command injection.
	// systemd unit names: alphanumeric, dash, underscore, dot, @.
	for _, c := range serviceName {
		if !isValidServiceNameChar(c) {
			return StatusError, fmt.Sprintf("invalid service name character: %c", c)
		}
	}
	if serviceName == "" {
		return StatusError, "service name is empty"
	}

	// Check if systemctl exists
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return StatusError, "systemctl not found — is this a systemd system?"
	}

	// Use "is-active" which returns a single word: active, inactive, failed, etc.
	// #nosec G204 — serviceName is validated above
	cmd := exec.Command(systemctl, "is-active", "--quiet", serviceName)
	cmd.Env = minimalEnv()
	err = cmd.Run()

	if err == nil {
		return StatusUp, fmt.Sprintf("service %s is active (running)", serviceName)
	}

	// Get the actual status text for the error message
	// #nosec G204 — serviceName is validated above
	out, _ := exec.Command(systemctl, "is-active", serviceName).Output()
	state := strings.TrimSpace(string(out))

	switch state {
	case "inactive":
		return StatusDown, fmt.Sprintf("service %s is inactive (stopped)", serviceName)
	case "failed":
		return StatusDown, fmt.Sprintf("service %s has failed", serviceName)
	case "activating":
		return StatusDown, fmt.Sprintf("service %s is still starting", serviceName)
	case "deactivating":
		return StatusDown, fmt.Sprintf("service %s is stopping", serviceName)
	default:
		// Check if the service unit exists at all
		// #nosec G204 — serviceName is validated above
		listCmd := exec.Command(systemctl, "list-unit-files", serviceName+".service", "--no-legend")
		listOut, _ := listCmd.Output()
		if strings.TrimSpace(string(listOut)) == "" {
			return StatusDown, fmt.Sprintf("service %s not found", serviceName)
		}
		return StatusDown, fmt.Sprintf("service %s status: %s", serviceName, state)
	}
}

// isValidServiceNameChar returns true for characters allowed in systemd unit names.
func isValidServiceNameChar(c rune) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '_' || c == '.' || c == '@'
}

// minimalEnv returns a minimal environment to avoid leaking secrets to subprocesses.
func minimalEnv() []string {
	env := []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	if lang := os.Getenv("LANG"); lang != "" {
		env = append(env, "LANG="+lang)
	}
	return env
}
