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

- **Per-check parent span**: every check runs inside an INTERNAL span named `monitor.check` with attributes set up-front (`monitor.id`, `monitor.type`, `monitor.target`) and added after execution (`monitor.status` — `up` / `down` / `timeout` / etc., and `monitor.latency_ms`). Failed checks call `span.SetStatus(codes.Error, errMsg)` so errors-only filters in trace explorers work out of the box.
- **HTTP probes** nest an `otelhttp` CLIENT child span named `HTTP GET` under the parent `monitor.check`. A single HTTP check therefore produces a 2-span trace: parent (INTERNAL `monitor.check`) → child (CLIENT `HTTP GET`). W3C trace context is propagated via headers — if the target is OTel-instrumented, the probe stitches into the upstream service's trace.
- **Structured logs**: every `slog` log record (Info, Warn, Error, Debug) is emitted to both stdout (Docker-friendly) AND the OTel logs exporter when an endpoint is configured. The `otelslog` bridge captures structured attributes (`slog.String`, `slog.Int`, etc.) as OTel log attributes AND inherits the active span's `trace_id`/`span_id` from `ctx` automatically. Explorers like the WatchDog hub's `/traces/<id>` page show heartbeat logs under "Logs in this trace" without a manual correlation step.

## What's not instrumented yet (planned)

- Per-runner finer-grained spans inside the agent (TCP, ICMP, DNS, TLS, Docker, Database, System, Service, SNMP, port-scan). The parent `monitor.check` span exists for every check type today; nested child spans inside each runner are still planned.
- WebSocket connection lifecycle (connect, reconnect, message send/recv)

## Verifying the pipeline

```sh
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318 \
OTEL_EXPORTER_OTLP_TRACES_INSECURE=true \
OTEL_EXPORTER_OTLP_LOGS_INSECURE=true \
./watchdog-agent -api-key=...
```

Trigger an HTTP check from the hub, then look for spans and log records tagged `service.name=watchdog-agent` in the receiver UI. Stdout logs continue to flow as before — the OTel side is additive.
