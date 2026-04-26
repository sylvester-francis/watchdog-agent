package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

// newTracerProvider returns an OpenTelemetry TracerProvider plus a shutdown
// function. Mirrors the hub-side pattern in internal/adapters/telemetry on
// the Watchdog repo — same gate semantics:
//
//   - WATCHDOG_OTEL_ENABLED is not "false" (default unset = enabled), AND
//   - an OTLP traces endpoint is configured via OTEL_EXPORTER_OTLP_ENDPOINT
//     or OTEL_EXPORTER_OTLP_TRACES_ENDPOINT
//
// otherwise a no-op TracerProvider is returned with a no-op shutdown — no
// exporter is created, no network egress, no log spam from failed export
// retries against the SDK's localhost:4318 fallback.
//
// Endpoint, headers, sampler, and other transport details flow through
// standard OTEL_* env vars read by the SDK directly.
func newTracerProvider(ctx context.Context) (trace.TracerProvider, func(context.Context) error, error) {
	if !telemetryEnabled() || !hasOTLPTracesEndpoint() {
		return tracenoop.NewTracerProvider(), noopShutdown, nil
	}

	serviceName := os.Getenv("WATCHDOG_OTEL_SERVICE_NAME")
	if serviceName == "" {
		serviceName = "watchdog-agent"
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(semconv.ServiceName(serviceName)),
		resource.WithFromEnv(),
		resource.WithProcess(),
		resource.WithTelemetrySDK(),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("build telemetry resource: %w", err)
	}

	exporter, err := otlptracehttp.New(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("build OTLP HTTP trace exporter: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	return tp, tp.Shutdown, nil
}

// telemetryEnabled reports whether the user has explicitly disabled
// telemetry. Default (env var unset) is enabled. Recognized "off" values:
// "false", "0", "no" (case-insensitive). Anything else is enabled.
func telemetryEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("WATCHDOG_OTEL_ENABLED")))
	return v != "false" && v != "0" && v != "no"
}

// hasOTLPTracesEndpoint reports whether the OTel SDK will find a configured
// OTLP traces endpoint via the standard env vars.
func hasOTLPTracesEndpoint() bool {
	return os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != "" ||
		os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") != ""
}

func noopShutdown(context.Context) error { return nil }
