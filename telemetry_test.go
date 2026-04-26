package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

func TestNewTracerProvider_DisabledReturnsNoop(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://does-not-matter.example.com")
	t.Setenv("WATCHDOG_OTEL_ENABLED", "false")

	tp, shutdown, err := newTracerProvider(context.Background())
	require.NoError(t, err)
	require.NotNil(t, tp)
	require.NotNil(t, shutdown)

	// Force-disable wins over a configured endpoint.
	_, isSDK := tp.(*sdktrace.TracerProvider)
	assert.False(t, isSDK, "WATCHDOG_OTEL_ENABLED=false must return no-op even with endpoint set")

	require.NoError(t, shutdown(context.Background()))

	// Tracer must satisfy the interface contract.
	var _ trace.TracerProvider = tp
	_, span := tp.Tracer("test").Start(context.Background(), "test-span")
	span.End()
}

func TestNewTracerProvider_EnabledWithoutEndpointReturnsNoop(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
	t.Setenv("WATCHDOG_OTEL_ENABLED", "")

	tp, shutdown, err := newTracerProvider(context.Background())
	require.NoError(t, err)
	require.NotNil(t, tp)
	t.Cleanup(func() { _ = shutdown(context.Background()) })

	_, isSDK := tp.(*sdktrace.TracerProvider)
	assert.False(t, isSDK, "default-on with no endpoint must return no-op (no log spam)")
}

func TestNewTracerProvider_EnabledWithEndpointReturnsSDKProvider(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://otlp.example.com")
	t.Setenv("WATCHDOG_OTEL_ENABLED", "")

	tp, shutdown, err := newTracerProvider(context.Background())
	require.NoError(t, err)
	require.NotNil(t, tp)
	t.Cleanup(func() { _ = shutdown(context.Background()) })

	_, isSDK := tp.(*sdktrace.TracerProvider)
	require.True(t, isSDK, "endpoint set must produce real SDK TracerProvider")
}

func TestTelemetryEnabled_RecognizedOffValues(t *testing.T) {
	cases := []struct {
		val      string
		expected bool
	}{
		{"", true},
		{"true", true},
		{"1", true},
		{"yes", true},
		{"false", false},
		{"FALSE", false},
		{" false ", false},
		{"0", false},
		{"no", false},
		{"NO", false},
	}
	for _, tc := range cases {
		t.Run(tc.val, func(t *testing.T) {
			t.Setenv("WATCHDOG_OTEL_ENABLED", tc.val)
			assert.Equal(t, tc.expected, telemetryEnabled())
		})
	}
}
