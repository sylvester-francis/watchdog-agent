package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"math"
	"math/rand/v2"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"

	"github.com/sylvester-francis/watchdog-proto/protocol"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
)

func main() {
	// Flags
	hubURL := flag.String("hub", "ws://localhost:8080/ws/agent", "Hub WebSocket URL")
	apiKey := flag.String("api-key", "", "Agent API key (prefer -api-key-file or env var to avoid process list exposure)")
	apiKeyFile := flag.String("api-key-file", "", "Path to file containing API key (default: "+BrandDefaultKeyFile()+")")
	caCert := flag.String("ca-cert", "", "Path to custom CA certificate bundle for TLS verification")
	version := flag.Bool("version", false, "Print version and exit")
	debug := flag.Bool("debug", false, "Enable debug logging")
	flag.Parse()

	if *version {
		fmt.Printf("%s Agent %s (built %s)\n", BrandName, Version, BuildTime)
		os.Exit(0)
	}

	// Setup logger
	logLevel := slog.LevelInfo
	if *debug {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))

	// API key resolution order: file > env var > flag
	key := resolveAPIKey(*apiKey, *apiKeyFile, logger)
	if key == "" {
		logger.Error("API key required. Use -api-key-file, " + BrandEnvAPIKey() + " env var, or -api-key flag")
		os.Exit(1)
	}

	wsURL := normalizeHubURL(*hubURL)

	// Warn if using unencrypted WebSocket
	if strings.HasPrefix(wsURL, "ws://") {
		logger.Warn("WARNING: using unencrypted ws:// connection. API key will be sent in cleartext. Use wss:// in production")
	}

	// Build TLS config for secure connections
	var tlsCfg *tls.Config
	if strings.HasPrefix(wsURL, "wss://") {
		var err error
		tlsCfg, err = BuildTLSConfig(wsURL, *caCert)
		if err != nil {
			logger.Error("failed to build TLS config", slog.String("error", err.Error()))
			os.Exit(1)
		}
	}

	logger.Info(BrandName+" Agent starting",
		slog.String("version", Version),
		slog.String("hub_url", wsURL),
	)

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// OpenTelemetry SDK init. Both providers no-op when
	// WATCHDOG_OTEL_ENABLED=false or when no OTLP endpoint is configured.
	// Setting the global TracerProvider lets any code that calls
	// otel.Tracer("...") participate in the same provider; the W3C
	// TraceContext propagator stitches outbound HTTP probes to upstream
	// traces. The slog tee wraps `logger` BEFORE NewAgent captures it,
	// so subsystems hold the wrapped handler from the start.
	tracerProvider, traceShutdown, err := newTracerProvider(ctx)
	if err != nil {
		logger.Error("initialize tracer provider", slog.String("error", err.Error()))
		os.Exit(1)
	}
	otel.SetTracerProvider(tracerProvider)
	otel.SetTextMapPropagator(propagation.TraceContext{})

	loggerProvider, logShutdown, err := newLoggerProvider(ctx)
	if err != nil {
		logger.Error("initialize logger provider", slog.String("error", err.Error()))
		os.Exit(1)
	}
	serviceName := os.Getenv("WATCHDOG_OTEL_SERVICE_NAME")
	if serviceName == "" {
		serviceName = "watchdog-agent"
	}
	logger = slog.New(newSlogHandler(logger.Handler(), loggerProvider, serviceName))
	slog.SetDefault(logger)

	telemetryShutdown := func(ctx context.Context) error {
		traceErr := traceShutdown(ctx)
		logErr := logShutdown(ctx)
		if traceErr != nil {
			return traceErr
		}
		return logErr
	}

	// Create and start agent
	agent := NewAgent(AgentConfig{
		HubURL:    wsURL,
		APIKey:    key,
		Version:   Version,
		Logger:    logger,
		TLSConfig: tlsCfg,
	})

	// Start agent in background
	go func() {
		if err := agent.Run(ctx); err != nil {
			logger.Error("agent error", slog.String("error", err.Error()))
		}
	}()

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("shutting down agent...")

	// Give agent time to clean up
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	// Flush any batched telemetry before the process exits. Best-effort:
	// errors are logged but don't block the shutdown sequence.
	if err := telemetryShutdown(shutdownCtx); err != nil {
		logger.Warn("telemetry shutdown failed", slog.String("error", err.Error()))
	}

	cancel() // Cancel the main context

	// Wait for shutdown or timeout
	select {
	case <-shutdownCtx.Done():
		logger.Warn("shutdown timed out")
	case <-time.After(2 * time.Second):
		logger.Info("agent stopped gracefully")
	}
}

// normalizeHubURL converts user-friendly URLs to the WebSocket endpoint.
// e.g. "https://example.com" -> "wss://example.com/ws/agent"
func normalizeHubURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}

	// Upgrade scheme: https -> wss, http -> ws
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	}

	// Append /ws/agent if not already present
	if !strings.HasSuffix(u.Path, "/ws/agent") {
		u.Path = strings.TrimRight(u.Path, "/") + "/ws/agent"
	}

	return u.String()
}

// AgentConfig holds agent configuration.
type AgentConfig struct {
	HubURL    string
	APIKey    string
	Version   string
	Logger    *slog.Logger
	TLSConfig *tls.Config
}

// Reconnection backoff constants.
const (
	reconnectBase = 1 * time.Second  // initial delay
	reconnectMax  = 60 * time.Second // cap
)

// Agent represents the monitoring agent.
type Agent struct {
	config          AgentConfig
	conn            *Connection
	reconnectCount  int
	tasks  map[string]*Task
	logger *slog.Logger
	stopCh chan struct{}
}

// NewAgent creates a new agent instance.
func NewAgent(config AgentConfig) *Agent {
	return &Agent{
		config: config,
		tasks:  make(map[string]*Task),
		logger: config.Logger,
		stopCh: make(chan struct{}),
	}
}

// Run starts the agent and maintains connection to the hub.
func (a *Agent) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			a.stopAllTasks()
			return ctx.Err()
		default:
			if err := a.connectAndRun(ctx); err != nil {
				a.logger.Error("connection error", slog.String("error", err.Error()))
				a.reconnectCount++
			}

			// Stop all tasks before reconnecting so stale goroutines
			// don't send heartbeats on the dead connection.
			a.stopAllTasks()

			// Wait before reconnecting with exponential backoff + jitter.
			delay := a.getReconnectDelay()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
				a.logger.Info("reconnecting to hub...", slog.Duration("backoff", delay))
			}
		}
	}
}

func (a *Agent) connectAndRun(ctx context.Context) error {
	conn, err := NewConnection(a.config.HubURL, a.config.APIKey, a.config.Version, a.logger, a.config.TLSConfig)
	if err != nil {
		return fmt.Errorf("failed to create connection: %w", err)
	}
	defer conn.Close()
	a.conn = conn

	// Authenticate
	if err := conn.Authenticate(ctx); err != nil {
		conn.Close()
		return fmt.Errorf("authentication failed: %w", err)
	}

	a.logger.Info("connected and authenticated")
	a.reconnectCount = 0 // reset backoff on successful connection

	// Run message loop
	return conn.Run(ctx, a.handleMessage)
}

func (a *Agent) handleMessage(msg *protocol.Message) {
	switch msg.Type {
	case protocol.MsgTypeTask:
		a.handleTask(msg)
	case protocol.MsgTypeTaskCancel:
		a.handleTaskCancel(msg)
	case protocol.MsgTypeUpdateAvailable:
		a.handleUpdateAvailable(msg)
	case protocol.MsgTypePing:
		if err := a.conn.Send(protocol.NewPongMessage()); err != nil {
			a.logger.Error("failed to send pong", slog.String("error", err.Error()))
		}
	default:
		a.logger.Debug("received message", slog.String("type", msg.Type))
	}
}

// maxTasks is the maximum number of concurrent monitoring tasks.
const maxTasks = 100

func (a *Agent) handleTask(msg *protocol.Message) {
	var payload protocol.TaskPayload
	if err := msg.ParsePayload(&payload); err != nil {
		a.logger.Error("failed to parse task", slog.String("error", err.Error()))
		return
	}

	// Stop existing task for this monitor if running
	if existing, ok := a.tasks[payload.MonitorID]; ok {
		existing.Stop()
		delete(a.tasks, payload.MonitorID)
	}

	// Enforce task limit to prevent unbounded goroutine creation
	if len(a.tasks) >= maxTasks {
		a.logger.Warn("task limit reached, rejecting new task",
			slog.Int("max_tasks", maxTasks),
			slog.String("monitor_id", payload.MonitorID),
		)
		return
	}

	// Create and start new task
	task := NewTask(payload, a.conn, a.logger)
	a.tasks[payload.MonitorID] = task
	go task.Run()

	a.logger.Info("task started",
		slog.String("monitor_id", payload.MonitorID),
		slog.String("type", payload.Type),
		slog.String("target", payload.Target),
	)
}

func (a *Agent) handleTaskCancel(msg *protocol.Message) {
	var payload protocol.TaskCancelPayload
	if err := msg.ParsePayload(&payload); err != nil {
		a.logger.Error("failed to parse task cancel", slog.String("error", err.Error()))
		return
	}

	if existing, ok := a.tasks[payload.MonitorID]; ok {
		existing.Stop()
		delete(a.tasks, payload.MonitorID)
		a.logger.Info("task cancelled",
			slog.String("monitor_id", payload.MonitorID),
		)
	}
}

func (a *Agent) stopAllTasks() {
	for _, task := range a.tasks {
		task.Stop()
	}
	a.tasks = make(map[string]*Task)
}

func (a *Agent) getReconnectDelay() time.Duration {
	// Exponential backoff: base * 2^attempt, capped at reconnectMax.
	exp := math.Pow(2, float64(a.reconnectCount))
	delay := time.Duration(float64(reconnectBase) * exp)
	if delay > reconnectMax {
		delay = reconnectMax
	}
	// Add jitter: ±50% of delay to prevent thundering herd.
	jitter := time.Duration(rand.Int64N(int64(delay)))
	return delay/2 + jitter
}

// resolveAPIKey reads the API key using the priority: file > env var > flag.
// This avoids exposing the key in the process argument list.
func resolveAPIKey(flagValue, filePath string, logger *slog.Logger) string {
	// 1. Try explicit file path
	if filePath != "" {
		key, err := readKeyFile(filePath)
		if err != nil {
			logger.Error("failed to read API key file", slog.String("path", filePath), slog.String("error", err.Error()))
			os.Exit(1)
		}
		return key
	}

	// 2. Try default file path
	defaultKeyFile := BrandDefaultKeyFile()
	if key, err := readKeyFile(defaultKeyFile); err == nil && key != "" {
		logger.Debug("loaded API key from default file", slog.String("path", defaultKeyFile))
		return key
	}

	// 3. Environment variable
	if key := os.Getenv(BrandEnvAPIKey()); key != "" {
		return key
	}

	// 4. CLI flag (least preferred — visible in process list)
	if flagValue != "" {
		logger.Warn("API key passed via CLI flag is visible in process list. Use -api-key-file or " + BrandEnvAPIKey() + " env var instead")
	}
	return flagValue
}

// readKeyFile reads and trims whitespace from a key file.
func readKeyFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
