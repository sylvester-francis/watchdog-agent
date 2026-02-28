package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/sylvester-francis/watchdog-proto/protocol"
)

// credentialPattern matches user:password in connection strings (e.g. ://user:pass@host).
var credentialPattern = regexp.MustCompile(`://[^:]+:[^@]+@`)

// scrubCredentials removes usernames and passwords from connection strings in error messages.
func scrubCredentials(msg string) string {
	return credentialPattern.ReplaceAllString(msg, "://***:***@")
}

// shellMetachars contains patterns that could enable shell injection if a value
// is ever interpolated into a shell command. We reject these defensively even
// though the current code does not invoke a shell, to prevent future regressions.
var shellMetachars = []string{"`", "$(", "|", ";", "&&", "||", ">", "<", "\n", "\r"}

// containsShellMeta returns true if s contains any shell metacharacter sequence.
func containsShellMeta(s string) bool {
	for _, mc := range shellMetachars {
		if strings.Contains(s, mc) {
			return true
		}
	}
	return false
}

// validHostnameRe matches valid DNS hostnames: labels of alphanumeric + hyphens, separated by dots.
var validHostnameRe = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// validIPv4Re matches dotted-quad IPv4 addresses (not full validation, but sufficient to reject metacharacters).
var validIPv4Re = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)

// validHostPortRe matches host:port where host is a hostname or IPv4 and port is numeric.
var validHostPortRe = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d{1,5}$`)

// validServiceNameRe matches systemd unit names: alphanumeric, hyphens, underscores, dots, @.
var validServiceNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.@-]*$`)

// validSystemTargetRe matches system metric targets like "cpu:90", "memory:80", "disk:90:/path".
var validSystemTargetRe = regexp.MustCompile(`^(cpu|memory):\d+(\.\d+)?$|^disk:\d+(\.\d+)?:/[a-zA-Z0-9/_.-]*$`)

// sanitizeTarget validates the target string for a given check type.
// Returns an error message if the target is invalid, or empty string if valid.
// This is a defense-in-depth measure: even though current checkers use safe APIs
// (net.Dial, http.NewRequest, etc.), we reject dangerous input to prevent future
// regressions if a code path ever passes targets to exec or string interpolation.
func sanitizeTarget(checkType, target string) string {
	if target == "" {
		return "target is required"
	}
	// Cap target length to prevent abuse.
	if utf8.RuneCountInString(target) > 2048 {
		return "target too long (max 2048 characters)"
	}
	// Universal rejection of shell metacharacters in any target.
	if containsShellMeta(target) {
		return "target contains prohibited characters"
	}

	switch checkType {
	case "http":
		// Must be a valid HTTP(S) URL.
		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			return "http target must start with http:// or https://"
		}
	case "tcp", "tls":
		// Must be host:port or just a hostname (tls defaults to :443).
		if _, _, err := net.SplitHostPort(target); err != nil {
			// For TLS, bare hostname is OK (port defaults to 443).
			if checkType == "tls" && validHostnameRe.MatchString(target) {
				break
			}
			if checkType == "tls" && validIPv4Re.MatchString(target) {
				break
			}
			return "tcp/tls target must be host:port format"
		}
	case "dns":
		// Must be a valid hostname — no ports, no paths.
		if !validHostnameRe.MatchString(target) {
			return "dns target must be a valid hostname (alphanumeric, dots, hyphens)"
		}
	case "ping":
		// Must be a hostname or IP, optionally with port.
		if _, _, err := net.SplitHostPort(target); err == nil {
			break // host:port is fine
		}
		if validHostnameRe.MatchString(target) || validIPv4Re.MatchString(target) {
			break
		}
		return "ping target must be a valid hostname or IP address"
	case "docker":
		// Already validated by validContainerName regex in checkDocker, but validate here too for defense-in-depth.
		if !validContainerName.MatchString(target) || len(target) > 255 {
			return "invalid docker container name"
		}
	case "database":
		// For database, target is typically host:port — validate format.
		if _, _, err := net.SplitHostPort(target); err != nil {
			// Bare hostname is also acceptable.
			if !validHostnameRe.MatchString(target) && !validIPv4Re.MatchString(target) {
				return "database target must be host:port or a valid hostname"
			}
		}
	case "system":
		// Must match metric:threshold or disk:threshold:/path format.
		if !validSystemTargetRe.MatchString(target) {
			return "system target must be metric:threshold (e.g. cpu:90, disk:90:/)"
		}
	case "service":
		// Must be a valid systemd service name.
		if !validServiceNameRe.MatchString(target) || len(target) > 255 {
			return "invalid service name: must match [a-zA-Z0-9][a-zA-Z0-9_.@-]*"
		}
	}
	return ""
}

// sanitizeConnectionString rejects connection strings that contain shell metacharacters.
// This is defense-in-depth: connection strings are passed to sql.Open (not a shell),
// but we reject dangerous patterns to prevent future regressions.
func sanitizeConnectionString(connStr string) string {
	if connStr == "" {
		return ""
	}
	if containsShellMeta(connStr) {
		return "connection string contains prohibited characters (shell metacharacters)"
	}
	return ""
}

// Check result statuses.
const (
	StatusUp      = "up"
	StatusDown    = "down"
	StatusTimeout = "timeout"
	StatusError   = "error"
)

// Task represents a monitoring task running on the agent.
type Task struct {
	payload protocol.TaskPayload
	conn    *Connection
	logger  *slog.Logger
	stopCh  chan struct{}
	stopped bool
	mu      sync.Mutex
}

// NewTask creates a new monitoring task.
func NewTask(payload protocol.TaskPayload, conn *Connection, logger *slog.Logger) *Task {
	return &Task{
		payload: payload,
		conn:    conn,
		logger:  logger,
		stopCh:  make(chan struct{}),
	}
}

// Run starts the monitoring loop.
func (t *Task) Run() {
	ticker := time.NewTicker(time.Duration(t.payload.Interval) * time.Second)
	defer ticker.Stop()

	// Run initial check immediately
	t.runCheck()

	for {
		select {
		case <-t.stopCh:
			return
		case <-ticker.C:
			t.runCheck()
		}
	}
}

// Stop stops the monitoring task.
func (t *Task) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.stopped {
		t.stopped = true
		close(t.stopCh)
	}
}

// IsStopped returns true if the task has been stopped.
func (t *Task) IsStopped() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.stopped
}

func (t *Task) runCheck() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(t.payload.Timeout)*time.Second)
	defer cancel()

	var status string
	var latencyMs int
	var errMsg string
	var certExpiryDays *int
	var certIssuer string
	var certMeta map[string]string

	// A-009: Validate target before dispatching to any checker.
	if reason := sanitizeTarget(t.payload.Type, t.payload.Target); reason != "" {
		status = StatusError
		errMsg = fmt.Sprintf("invalid target: %s", reason)
		t.sendHeartbeat(status, 0, errMsg, nil, "", nil)
		return
	}

	// A-009: Validate connection string metadata if present.
	if connStr := t.payload.Metadata["connection_string"]; connStr != "" {
		if reason := sanitizeConnectionString(connStr); reason != "" {
			status = StatusError
			errMsg = fmt.Sprintf("invalid connection_string: %s", reason)
			t.sendHeartbeat(status, 0, errMsg, nil, "", nil)
			return
		}
	}

	start := time.Now()

	switch t.payload.Type {
	case "http":
		status, errMsg = t.checkHTTP(ctx)
	case "tcp":
		status, errMsg = t.checkTCP(ctx)
	case "ping":
		status, errMsg = t.checkPing(ctx)
	case "dns":
		status, errMsg = t.checkDNS(ctx)
	case "tls":
		status, errMsg, certExpiryDays, certIssuer, certMeta = t.checkTLS(ctx)
	case "docker":
		status, errMsg = t.checkDocker(ctx)
	case "database":
		status, errMsg = t.checkDatabase(ctx)
	case "system":
		status, errMsg = t.checkSystem(ctx)
	case "service":
		status, errMsg = t.checkService()
	default:
		status = StatusError
		errMsg = fmt.Sprintf("unknown check type: %s", t.payload.Type)
	}

	// Only report latency for network-based checks
	switch t.payload.Type {
	case "system", "docker", "service":
		latencyMs = 0
	default:
		latencyMs = int(time.Since(start).Milliseconds())
		if latencyMs == 0 {
			latencyMs = 1 // sub-millisecond checks report as 1ms
		}
	}

	t.sendHeartbeat(status, latencyMs, errMsg, certExpiryDays, certIssuer, certMeta)
}

// sendHeartbeat sends a heartbeat message to the hub and logs the check result.
func (t *Task) sendHeartbeat(status string, latencyMs int, errMsg string, certExpiryDays *int, certIssuer string, metadata map[string]string) {
	hb := protocol.HeartbeatPayload{
		MonitorID:      t.payload.MonitorID,
		Status:         status,
		LatencyMs:      latencyMs,
		ErrorMessage:   errMsg,
		CertExpiryDays: certExpiryDays,
		CertIssuer:     certIssuer,
		Metadata:       metadata,
	}
	msg := protocol.MustNewMessage(protocol.MsgTypeHeartbeat, hb)
	if err := t.conn.Send(msg); err != nil {
		t.logger.Error("failed to send heartbeat",
			slog.String("monitor_id", t.payload.MonitorID),
			slog.String("error", err.Error()),
		)
	}

	t.logger.Debug("check completed",
		slog.String("monitor_id", t.payload.MonitorID),
		slog.String("status", status),
		slog.Int("latency_ms", latencyMs),
	)
}

// checkHTTP performs an HTTP check.
func (t *Task) checkHTTP(ctx context.Context) (status, errMsg string) {
	client := &http.Client{
		Timeout: time.Duration(t.payload.Timeout) * time.Second,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.payload.Target, http.NoBody)
	if err != nil {
		return StatusError, fmt.Sprintf("invalid URL: %s", err.Error())
	}

	req.Header.Set("User-Agent", "WatchDog-Agent/1.0")

	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return StatusTimeout, "request timed out"
		}
		return StatusDown, err.Error()
	}
	defer resp.Body.Close()

	// Consider 2xx and 3xx as success
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		// Check for expected content if configured
		if expected := t.payload.Metadata["expected_content"]; expected != "" {
			body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB cap
			if err != nil {
				return StatusDown, fmt.Sprintf("failed to read body: %s", err.Error())
			}
			if !strings.Contains(string(body), expected) {
				return StatusDown, "expected content not found"
			}
		}
		return StatusUp, ""
	}

	return StatusDown, fmt.Sprintf("HTTP %d", resp.StatusCode)
}

// checkTCP performs a TCP connection check.
func (t *Task) checkTCP(ctx context.Context) (status, errMsg string) {
	dialer := net.Dialer{
		Timeout: time.Duration(t.payload.Timeout) * time.Second,
	}

	conn, err := dialer.DialContext(ctx, "tcp", t.payload.Target)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return StatusTimeout, "connection timed out"
		}
		return StatusDown, err.Error()
	}
	conn.Close()

	return StatusUp, ""
}

// checkPing performs a ping check.
// Note: ICMP requires elevated privileges on most systems.
// Falls back to TCP connect on port 80 or 443 for HTTP targets.
func (t *Task) checkPing(ctx context.Context) (status, errMsg string) {
	// For simplicity, use TCP connect as ping alternative
	// Real ICMP ping requires raw sockets and elevated privileges
	target := t.payload.Target

	// Try common ports if just a host is provided
	ports := []string{":80", ":443"}

	for _, port := range ports {
		addr := target + port
		if _, _, err := net.SplitHostPort(target); err == nil {
			addr = target // Already has port
		}

		dialer := net.Dialer{
			Timeout: time.Duration(t.payload.Timeout) * time.Second,
		}

		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			conn.Close()
			return StatusUp, ""
		}
	}

	return StatusDown, "host unreachable"
}

// checkDNS performs a DNS lookup check.
func (t *Task) checkDNS(ctx context.Context) (status, errMsg string) {
	resolver := net.Resolver{}
	addrs, err := resolver.LookupHost(ctx, t.payload.Target)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return StatusTimeout, "DNS lookup timed out"
		}
		return StatusDown, fmt.Sprintf("DNS lookup failed: %s", err.Error())
	}
	if len(addrs) == 0 {
		return StatusDown, "DNS lookup returned no addresses"
	}
	return StatusUp, ""
}

// checkTLS performs a TLS certificate check and extracts certificate metadata.
func (t *Task) checkTLS(ctx context.Context) (status, errMsg string, certExpiryDays *int, certIssuer string, certMeta map[string]string) {
	target := t.payload.Target

	// Default to port 443 if no port specified
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = target + ":443"
	}

	host, _, _ := net.SplitHostPort(target)

	dialer := &net.Dialer{Timeout: time.Duration(t.payload.Timeout) * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", target, &tls.Config{
		ServerName: host,
	})
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return StatusTimeout, "TLS handshake timed out", nil, "", nil
		}
		return StatusDown, fmt.Sprintf("TLS connection failed: %s", err.Error()), nil, "", nil
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return StatusDown, "no certificates presented", nil, "", nil
	}

	leaf := certs[0]
	daysUntilExpiry := int(time.Until(leaf.NotAfter).Hours() / 24)
	issuer := leaf.Issuer.CommonName

	certExpiryDays = &daysUntilExpiry
	certIssuer = issuer

	// Build extended cert metadata
	certMeta = make(map[string]string)
	if len(leaf.DNSNames) > 0 {
		certMeta["cert_sans"] = strings.Join(leaf.DNSNames, ",")
	}
	certMeta["cert_algorithm"] = leaf.SignatureAlgorithm.String()
	certMeta["cert_serial"] = leaf.SerialNumber.String()

	// Extract key size from public key
	switch pub := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		certMeta["cert_key_size"] = strconv.Itoa(pub.N.BitLen())
	case *ecdsa.PublicKey:
		certMeta["cert_key_size"] = strconv.Itoa(pub.Curve.Params().BitSize)
	}

	// Verify certificate chain
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	_, verifyErr := leaf.Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		DNSName:       host,
	})
	if verifyErr == nil {
		certMeta["cert_chain_valid"] = "true"
	} else {
		certMeta["cert_chain_valid"] = "false"
	}

	if daysUntilExpiry < 0 {
		return StatusDown, fmt.Sprintf("certificate expired %d days ago", -daysUntilExpiry), certExpiryDays, certIssuer, certMeta
	}
	if daysUntilExpiry < 14 {
		return StatusDown, fmt.Sprintf("certificate expires in %d days", daysUntilExpiry), certExpiryDays, certIssuer, certMeta
	}

	return StatusUp, "", certExpiryDays, certIssuer, certMeta
}

// validContainerName matches valid Docker container names.
var validContainerName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)

// checkDocker checks if a Docker container is running via the Docker socket.
// Access is restricted to read-only container inspection (GET /containers/{name}/json).
func (t *Task) checkDocker(ctx context.Context) (status, errMsg string) {
	containerName := t.payload.Target

	// Validate container name to prevent path traversal and API abuse
	if !validContainerName.MatchString(containerName) {
		return StatusError, "invalid container name: must match [a-zA-Z0-9][a-zA-Z0-9_.-]*"
	}
	if len(containerName) > 255 {
		return StatusError, "container name too long (max 255 characters)"
	}

	// HTTP client using Unix socket
	client := &http.Client{
		Timeout: time.Duration(t.payload.Timeout) * time.Second,
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", "/var/run/docker.sock")
			},
		},
	}

	// Only allow the container inspect endpoint (read-only)
	apiURL := "http://localhost/containers/" + containerName + "/json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return StatusError, fmt.Sprintf("invalid request: %s", err.Error())
	}

	resp, err := client.Do(req)
	if err != nil {
		return StatusDown, fmt.Sprintf("docker socket error: %s", err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return StatusDown, "container not found"
	}
	if resp.StatusCode != 200 {
		return StatusDown, fmt.Sprintf("docker API returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return StatusDown, fmt.Sprintf("failed to read response: %s", err.Error())
	}

	bodyStr := string(body)
	// Check if container is running (simple string check to avoid json dependency overhead)
	if !strings.Contains(bodyStr, `"Running":true`) {
		return StatusDown, "container not running"
	}

	// Check health status if present
	if strings.Contains(bodyStr, `"Health"`) {
		if strings.Contains(bodyStr, `"Status":"unhealthy"`) {
			return StatusDown, "container unhealthy"
		}
	}

	return StatusUp, fmt.Sprintf("container %s is running", containerName)
}

// checkDatabase routes to the appropriate DB check based on metadata["db_type"].
func (t *Task) checkDatabase(ctx context.Context) (status, errMsg string) {
	dbType := t.payload.Metadata["db_type"]
	switch dbType {
	case "postgres":
		return t.checkPostgres(ctx)
	case "mysql":
		return t.checkMySQL(ctx)
	case "redis":
		return t.checkRedis(ctx)
	default:
		return StatusError, fmt.Sprintf("unsupported database type: %s", dbType)
	}
}

func (t *Task) checkPostgres(ctx context.Context) (status, errMsg string) {
	connStr := t.payload.Metadata["connection_string"]
	if connStr == "" {
		connStr = fmt.Sprintf("postgres://%s/postgres?sslmode=disable", t.payload.Target)
	}

	db, err := sql.Open("pgx", connStr)
	if err != nil {
		return StatusDown, scrubCredentials(fmt.Sprintf("postgres open: %s", err.Error()))
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		return StatusDown, scrubCredentials(fmt.Sprintf("postgres ping: %s", err.Error()))
	}
	return StatusUp, ""
}

func (t *Task) checkMySQL(ctx context.Context) (status, errMsg string) {
	connStr := t.payload.Metadata["connection_string"]
	if connStr == "" {
		connStr = fmt.Sprintf("tcp(%s)/", t.payload.Target)
	}

	db, err := sql.Open("mysql", connStr)
	if err != nil {
		return StatusDown, scrubCredentials(fmt.Sprintf("mysql open: %s", err.Error()))
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		return StatusDown, scrubCredentials(fmt.Sprintf("mysql ping: %s", err.Error()))
	}
	return StatusUp, ""
}

func (t *Task) checkRedis(ctx context.Context) (status, errMsg string) {
	target := t.payload.Target
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = target + ":6379"
	}

	dialer := net.Dialer{Timeout: time.Duration(t.payload.Timeout) * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return StatusDown, fmt.Sprintf("redis connect: %s", err.Error())
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(time.Duration(t.payload.Timeout) * time.Second)); err != nil {
		return StatusDown, fmt.Sprintf("redis set deadline: %s", err.Error())
	}

	// AUTH if password is set
	if pw := t.payload.Metadata["password"]; pw != "" {
		authCmd := fmt.Sprintf("*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n", len(pw), pw)
		if _, err := conn.Write([]byte(authCmd)); err != nil {
			return StatusDown, fmt.Sprintf("redis auth write: %s", err.Error())
		}
		reader := bufio.NewReader(conn)
		line, err := reader.ReadString('\n')
		if err != nil {
			return StatusDown, fmt.Sprintf("redis auth read: %s", err.Error())
		}
		if !strings.HasPrefix(line, "+OK") {
			return StatusDown, fmt.Sprintf("redis auth failed: %s", strings.TrimSpace(line))
		}
	}

	// PING
	if _, err := conn.Write([]byte("*1\r\n$4\r\nPING\r\n")); err != nil {
		return StatusDown, fmt.Sprintf("redis ping write: %s", err.Error())
	}
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return StatusDown, fmt.Sprintf("redis ping read: %s", err.Error())
	}
	if !strings.HasPrefix(line, "+PONG") {
		return StatusDown, fmt.Sprintf("redis unexpected response: %s", strings.TrimSpace(line))
	}

	return StatusUp, ""
}

// checkService checks if a named OS service (systemd/Windows) is running.
// Target is the service name (e.g., "nginx", "postgresql").
func (t *Task) checkService() (status, errMsg string) {
	serviceName := t.payload.Target
	if serviceName == "" {
		return StatusError, "service name is required as target"
	}
	return checkServiceStatus(serviceName)
}

// checkSystem checks system metrics (CPU/memory/disk) against thresholds.
func (t *Task) checkSystem(ctx context.Context) (status, errMsg string) {
	target := t.payload.Target
	parts := strings.SplitN(target, ":", 2)
	if len(parts) < 2 {
		return StatusError, "system target format: metric:threshold (e.g. cpu:90)"
	}

	metric := parts[0]
	rest := parts[1]

	var threshold float64
	var path string
	if metric == "disk" {
		// format: disk:90:/path
		diskParts := strings.SplitN(rest, ":", 2)
		if len(diskParts) < 2 {
			return StatusError, "disk target format: disk:threshold:/path (e.g. disk:90:/)"
		}
		if _, err := fmt.Sscanf(diskParts[0], "%f", &threshold); err != nil {
			return StatusError, fmt.Sprintf("invalid threshold: %s", diskParts[0])
		}
		path = diskParts[1]
	} else {
		if _, err := fmt.Sscanf(rest, "%f", &threshold); err != nil {
			return StatusError, fmt.Sprintf("invalid threshold: %s", rest)
		}
	}

	var usage float64
	var metricErr error

	switch metric {
	case "cpu":
		usage, metricErr = getCPUUsage()
	case "memory":
		usage, metricErr = getMemoryUsage()
	case "disk":
		usage, metricErr = getDiskUsage(path)
	default:
		return StatusError, fmt.Sprintf("unsupported metric: %s", metric)
	}

	if metricErr != nil {
		return StatusError, metricErr.Error()
	}

	if usage > threshold {
		return StatusDown, fmt.Sprintf("%s usage %.1f%% exceeds threshold %.0f%%", metric, usage, threshold)
	}
	return StatusUp, fmt.Sprintf("%s usage %.1f%%", metric, usage)
}

// Checker provides check functions for different monitor types.
type Checker interface {
	Check(ctx context.Context, target string, timeout time.Duration) (status string, latencyMs int, errMsg string)
}

// HTTPChecker performs HTTP checks.
type HTTPChecker struct{}

// Check performs an HTTP GET request.
func (c *HTTPChecker) Check(ctx context.Context, target string, timeout time.Duration) (status string, latencyMs int, errMsg string) {
	start := time.Now()

	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, http.NoBody)
	if err != nil {
		return StatusError, 0, err.Error()
	}

	resp, err := client.Do(req)
	latencyMs = int(time.Since(start).Milliseconds())

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return StatusTimeout, latencyMs, "timeout"
		}
		return StatusDown, latencyMs, err.Error()
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return StatusUp, latencyMs, ""
	}

	return StatusDown, latencyMs, fmt.Sprintf("HTTP %d", resp.StatusCode)
}

// TCPChecker performs TCP connection checks.
type TCPChecker struct{}

// Check performs a TCP connection attempt.
func (c *TCPChecker) Check(ctx context.Context, target string, timeout time.Duration) (status string, latencyMs int, errMsg string) {
	start := time.Now()

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	latencyMs = int(time.Since(start).Milliseconds())

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return StatusTimeout, latencyMs, "timeout"
		}
		return StatusDown, latencyMs, err.Error()
	}
	defer conn.Close()

	return StatusUp, latencyMs, ""
}
