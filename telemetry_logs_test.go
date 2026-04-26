package main

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	lognoop "go.opentelemetry.io/otel/log/noop"
	sdklog "go.opentelemetry.io/otel/sdk/log"
)

func TestNewLoggerProvider_DisabledReturnsNoop(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://does-not-matter.example.com")
	t.Setenv("WATCHDOG_OTEL_ENABLED", "false")

	lp, shutdown, err := newLoggerProvider(context.Background())
	require.NoError(t, err)
	require.NotNil(t, lp)
	require.NotNil(t, shutdown)

	_, isSDK := lp.(*sdklog.LoggerProvider)
	assert.False(t, isSDK, "WATCHDOG_OTEL_ENABLED=false must return no-op LoggerProvider even with endpoint set")

	require.NoError(t, shutdown(context.Background()))
}

func TestNewLoggerProvider_EnabledWithoutEndpointReturnsNoop(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "")
	t.Setenv("WATCHDOG_OTEL_ENABLED", "")

	lp, shutdown, err := newLoggerProvider(context.Background())
	require.NoError(t, err)
	require.NotNil(t, lp)
	t.Cleanup(func() { _ = shutdown(context.Background()) })

	_, isSDK := lp.(*sdklog.LoggerProvider)
	assert.False(t, isSDK, "default-on with no endpoint must return no-op (no log spam)")
}

func TestNewLoggerProvider_EnabledWithEndpointReturnsSDKProvider(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://otlp.example.com")
	t.Setenv("WATCHDOG_OTEL_ENABLED", "")

	lp, shutdown, err := newLoggerProvider(context.Background())
	require.NoError(t, err)
	require.NotNil(t, lp)
	t.Cleanup(func() { _ = shutdown(context.Background()) })

	_, isSDK := lp.(*sdklog.LoggerProvider)
	require.True(t, isSDK, "endpoint set must produce real SDK LoggerProvider")
}

func TestNewSlogHandler_NoopProviderReturnsBaseUnwrapped(t *testing.T) {
	base := slog.NewTextHandler(io.Discard, nil)

	got := newSlogHandler(base, lognoop.NewLoggerProvider(), "test-svc")
	assert.Same(t, base, got, "no-op provider must return base handler unchanged (zero-cost disabled path)")
}

func TestNewSlogHandler_RealProviderWrapsBase(t *testing.T) {
	base := slog.NewTextHandler(io.Discard, nil)
	lp := sdklog.NewLoggerProvider()
	t.Cleanup(func() { _ = lp.Shutdown(context.Background()) })

	got := newSlogHandler(base, lp, "test-svc")
	assert.NotSame(t, base, got, "real provider must wrap base handler")
}

// recordingHandler captures records for assertion.
type recordingHandler struct {
	records []slog.Record
}

func (h *recordingHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.records = append(h.records, r)
	return nil
}

func (h *recordingHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }

func (h *recordingHandler) WithGroup(_ string) slog.Handler { return h }

func TestSlogHandler_TeeStillEmitsToPrimary(t *testing.T) {
	primary := &recordingHandler{}
	lp := sdklog.NewLoggerProvider()
	t.Cleanup(func() { _ = lp.Shutdown(context.Background()) })

	tee := newSlogHandler(primary, lp, "test-svc")
	slog.New(tee).Info("hello", "key", "value")

	require.Len(t, primary.records, 1, "primary handler must still receive every record after the tee wraps it")
	assert.Equal(t, "hello", primary.records[0].Message)
}
