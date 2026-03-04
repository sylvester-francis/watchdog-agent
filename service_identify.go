package main

import (
	"encoding/json"
	"io"
	"net"
	"regexp"
	"strings"
	"time"
)

const (
	bannerReadTimeout = 3 * time.Second
	bannerMaxBytes    = 1024
	bannerMaxLineLen  = 256
	portDetailsMaxLen = 64 * 1024 // 64KB cap on port_details JSON
)

// PortDetail captures service information for a single port.
type PortDetail struct {
	Port    int    `json:"port"`
	State   string `json:"state"`
	Service string `json:"service,omitempty"`
	Banner  string `json:"banner,omitempty"`
	Version string `json:"version,omitempty"`
}

// servicePattern defines a regex-based service identifier.
type servicePattern struct {
	pattern *regexp.Regexp
	service string
	// versionGroup is the regex submatch index for the version string.
	// 0 means no version extraction.
	versionGroup int
}

var servicePatterns = []servicePattern{
	{regexp.MustCompile(`^SSH-[\d.]+-(.*)`), "ssh", 1},
	{regexp.MustCompile(`^HTTP/\d\.\d`), "http", 0},
	{regexp.MustCompile(`^220[ -].*\b(?:ESMTP|SMTP)\b`), "smtp", 0},
	{regexp.MustCompile(`^220[ -].*\bFTP\b`), "ftp", 0},
	{regexp.MustCompile(`^\+OK`), "pop3", 0},
	{regexp.MustCompile(`^\* OK.*IMAP`), "imap", 0},
	{regexp.MustCompile(`^.{4}\x0a([\d.]+)`), "mysql", 1},
	{regexp.MustCompile(`^\+PONG`), "redis", 0},
	{regexp.MustCompile(`^-ERR`), "redis", 0},
	{regexp.MustCompile(`^-NOAUTH`), "redis", 0},
	{regexp.MustCompile(`(?i)server:\s*(nginx[/\s][\d.]+)`), "http", 1},
	{regexp.MustCompile(`(?i)server:\s*(apache[/\s][\d.]+)`), "http", 1},
}

// wellKnownPorts maps port numbers to service names as a fallback.
var wellKnownPorts = map[int]string{
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	53:    "dns",
	80:    "http",
	110:   "pop3",
	143:   "imap",
	443:   "https",
	465:   "smtps",
	587:   "smtp",
	993:   "imaps",
	995:   "pop3s",
	3306:  "mysql",
	5432:  "postgresql",
	6379:  "redis",
	27017: "mongodb",
}

// serviceProbes are sent to ports that don't speak first.
var serviceProbes = map[int][]byte{
	80:    []byte("\r\n"),
	443:   []byte("\r\n"),
	8080:  []byte("\r\n"),
	8443:  []byte("\r\n"),
	6379:  []byte("PING\r\n"),
	27017: {0x00},
	5432:  {0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00},
}

// grabBanner reads a banner from an open connection and identifies the service.
func grabBanner(conn net.Conn, port int, timeout time.Duration) *PortDetail {
	detail := &PortDetail{
		Port:  port,
		State: "open",
	}

	// Phase 1: passive read — many services send a banner on connect.
	passiveTimeout := timeout / 2
	if passiveTimeout < 500*time.Millisecond {
		passiveTimeout = 500 * time.Millisecond
	}

	_ = conn.SetReadDeadline(time.Now().Add(passiveTimeout))
	buf := make([]byte, bannerMaxBytes)
	n, _ := io.LimitReader(conn, bannerMaxBytes).Read(buf)

	if n > 0 {
		detail.Service, detail.Version = identifyService(port, buf[:n])
		detail.Banner = sanitizeBanner(buf[:n])
		return detail
	}

	// Phase 2: active probe — send a small probe to elicit a response.
	probe, hasProbe := serviceProbes[port]
	if !hasProbe {
		// Try HTTP probe on unknown ports as a common fallback.
		probe = []byte("\r\n")
	}

	remainingTimeout := timeout - passiveTimeout
	if remainingTimeout < 500*time.Millisecond {
		remainingTimeout = 500 * time.Millisecond
	}

	_ = conn.SetWriteDeadline(time.Now().Add(remainingTimeout))
	_, writeErr := conn.Write(probe)
	if writeErr != nil {
		// Can't probe — fall back to well-known port hint.
		if svc, ok := wellKnownPorts[port]; ok {
			detail.Service = svc
		}
		return detail
	}

	_ = conn.SetReadDeadline(time.Now().Add(remainingTimeout))
	n, _ = io.LimitReader(conn, bannerMaxBytes).Read(buf)

	if n > 0 {
		detail.Service, detail.Version = identifyService(port, buf[:n])
		detail.Banner = sanitizeBanner(buf[:n])
		return detail
	}

	// No response — use well-known port as hint.
	if svc, ok := wellKnownPorts[port]; ok {
		detail.Service = svc
	}
	return detail
}

// identifyService matches a banner against known service patterns.
func identifyService(port int, banner []byte) (service, version string) {
	bannerStr := string(banner)
	firstLine := bannerStr
	if idx := strings.IndexAny(bannerStr, "\r\n"); idx >= 0 {
		firstLine = bannerStr[:idx]
	}

	for _, sp := range servicePatterns {
		matches := sp.pattern.FindStringSubmatch(firstLine)
		if matches == nil {
			// Try full banner (multi-line responses like HTTP).
			matches = sp.pattern.FindStringSubmatch(bannerStr)
		}
		if matches != nil {
			service = sp.service
			if sp.versionGroup > 0 && sp.versionGroup < len(matches) {
				version = strings.TrimSpace(matches[sp.versionGroup])
				if len(version) > 100 {
					version = version[:100]
				}
			}
			return service, version
		}
	}

	// Fallback: well-known port number hint.
	if svc, ok := wellKnownPorts[port]; ok {
		return svc, ""
	}
	return "", ""
}

// sanitizeBanner strips non-printable characters and truncates.
func sanitizeBanner(raw []byte) string {
	var sb strings.Builder
	sb.Grow(bannerMaxLineLen)

	for _, b := range raw {
		if sb.Len() >= bannerMaxLineLen {
			break
		}
		// Only printable ASCII (0x20-0x7E).
		if b >= 0x20 && b <= 0x7E {
			sb.WriteByte(b)
		}
	}
	return sb.String()
}

// encodePortDetails encodes port details to JSON, respecting the size cap.
// If the full encoding exceeds portDetailsMaxLen, it strips banners.
func encodePortDetails(details []PortDetail) string {
	data, err := json.Marshal(details)
	if err != nil {
		return ""
	}
	if len(data) <= portDetailsMaxLen {
		return string(data)
	}

	// Over size limit — strip banners and retry.
	stripped := make([]PortDetail, len(details))
	for i, d := range details {
		stripped[i] = PortDetail{
			Port:    d.Port,
			State:   d.State,
			Service: d.Service,
			Version: d.Version,
		}
	}
	data, err = json.Marshal(stripped)
	if err != nil {
		return ""
	}
	if len(data) <= portDetailsMaxLen {
		return string(data)
	}
	return ""
}
