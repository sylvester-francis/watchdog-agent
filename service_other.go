//go:build !linux && !windows

package main

import "fmt"

// checkServiceStatus is not supported on this platform.
func checkServiceStatus(serviceName string) (status, errMsg string) {
	return StatusError, fmt.Sprintf("service monitoring not supported on this platform")
}
