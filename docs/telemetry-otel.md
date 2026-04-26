# OpenTelemetry Traces and Logs (Agent)

The agent emits OTLP traces and structured logs alongside the hub. Same gate semantics as the hub, same standard `OTEL_*` env vars — see the hub's `docs/telemetry-otel.md` for the full configuration reference.

## Enable

```sh
OTEL_EXPORTER_OTLP_ENDPOINT=https://otel.example.com
```

That's the only required env var. The SDK is auto-initialized when an endpoint is configured. With no endpoint set, a no-op tracer is installed — no exporter, no network egress.

## Force-disable

```sh
WATCHDOG_OTEL_ENABLED=false
```

Recognized "off" values: `false`, `0`, `no` (case-insensitive). Anything else (or unset) is enabled.

## Service name

```sh
WATCHDOG_OTEL_SERVICE_NAME=my-agent-name   # optional; default "watchdog-agent"
```

Sets the `service.name` resource attribute on every emitted span.

## What's instrumented

- **HTTP probes** (`checkHTTP`): the probe client is wired with `otelhttp.NewTransport`, so every outbound HTTP check becomes an OTel client span. W3C trace context is propagated via headers — if the target is OTel-instrumented, the probe stitches into the upstream service's trace.
- **Structured logs**: every `slog` log record (Info, Warn, Error, Debug) is emitted to both stdout (Docker-friendly) AND the OTel logs exporter when an endpoint is configured. The bridge captures structured attributes (`slog.String`, `slog.Int`, etc.) as OTel log attributes.

## What's not instrumented yet (planned)

- TCP, ICMP, DNS, TLS, SNMP, port-scan, service-identify check types
- WebSocket connection lifecycle (connect, reconnect, message send/recv)

## Verifying the pipeline

```sh
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318 \
OTEL_EXPORTER_OTLP_TRACES_INSECURE=true \
OTEL_EXPORTER_OTLP_LOGS_INSECURE=true \
./watchdog-agent -api-key=...
```

Trigger an HTTP check from the hub, then look for spans and log records tagged `service.name=watchdog-agent` in the receiver UI. Stdout logs continue to flow as before — the OTel side is additive.
