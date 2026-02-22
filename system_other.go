//go:build !linux

package main

import "fmt"

func getCPUUsage() (float64, error) {
	return 0, fmt.Errorf("system metrics not supported on this platform")
}

func getMemoryUsage() (float64, error) {
	return 0, fmt.Errorf("system metrics not supported on this platform")
}

func getDiskUsage(path string) (float64, error) {
	return 0, fmt.Errorf("system metrics not supported on this platform")
}
