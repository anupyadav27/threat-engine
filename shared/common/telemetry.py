"""
OpenTelemetry SDK bootstrap for all threat-engine services.

Call ``configure_telemetry(service_name, fastapi_app)`` once at startup.
It auto-instruments FastAPI, outgoing httpx calls, psycopg2, and Python
logging.  Traces and metrics are exported via OTLP to the OpenTelemetry
Collector (``otel-collector.threat-engine-engines.svc.cluster.local:4317``).

If any OTel package is missing the function logs a warning and returns — all
engines continue to work without instrumentation.

Environment variables
---------------------
OTEL_ENABLED                  "true" / "false"  (default "true")
OTEL_SERVICE_NAME             Overrides the *service_name* argument
OTEL_EXPORTER_OTLP_ENDPOINT   OTLP gRPC endpoint  (default: see below)
OTEL_EXPORTER_OTLP_INSECURE   "true" to disable TLS  (default "true" in-cluster)
OTEL_TRACES_SAMPLER           "always_on" / "always_off" / "traceidratio"
OTEL_TRACES_SAMPLER_ARG       Sampling ratio (0.0–1.0) when using traceidratio

Usage::

    from engine_common.telemetry import configure_telemetry, get_tracer, get_meter

    # In api_server.py, after app = FastAPI(...)
    configure_telemetry("engine-threat", app)

    # Optional: create custom spans in business logic
    tracer = get_tracer(__name__)
    with tracer.start_as_current_span("process_finding") as span:
        span.set_attribute("finding.rule_id", rule_id)

    # Optional: custom metrics
    meter = get_meter(__name__)
    findings_counter = meter.create_counter("findings_total")
    findings_counter.add(1, {"engine": "threat", "severity": "HIGH"})
"""
from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from fastapi import FastAPI

logger = logging.getLogger(__name__)

# ── Internal state ────────────────────────────────────────────────────────────

_tracer_provider = None
_meter_provider = None
_configured = False

# ── Default collector endpoint (K8s DNS within threat-engine-engines ns) ─────

_DEFAULT_OTLP_ENDPOINT = os.getenv(
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "http://otel-collector.threat-engine-engines.svc.cluster.local:4317",
)


# ── Public API ────────────────────────────────────────────────────────────────


def configure_telemetry(
    service_name: str,
    app: "Optional[FastAPI]" = None,
) -> bool:
    """Bootstrap OTel SDK.  Returns True if instrumentation succeeded.

    Safe to call multiple times — only the first call has effect.

    Args:
        service_name: Logical service name (e.g. ``"engine-threat"``).
                      Overridden by ``OTEL_SERVICE_NAME`` env var when set.
        app: FastAPI application instance.  When supplied, FastAPI
             auto-instrumentation is enabled for HTTP server spans.

    Returns:
        ``True`` if OTel was configured, ``False`` if disabled or packages
        unavailable.
    """
    global _tracer_provider, _meter_provider, _configured

    if _configured:
        return True

    if os.getenv("OTEL_ENABLED", "true").lower() in ("false", "0", "no"):
        logger.info("OpenTelemetry disabled (OTEL_ENABLED=false)")
        return False

    service_name = os.getenv("OTEL_SERVICE_NAME", service_name)

    try:
        _setup_traces(service_name)
        _setup_metrics(service_name)
        _instrument_libraries(app)
        _configured = True
        logger.info("OpenTelemetry configured service=%s endpoint=%s",
                    service_name, _DEFAULT_OTLP_ENDPOINT)
        return True

    except ImportError as exc:
        logger.warning(
            "OpenTelemetry packages not installed — telemetry disabled. "
            "Add opentelemetry-* packages to requirements.txt. Error: %s", exc
        )
        return False
    except Exception as exc:
        logger.warning("OpenTelemetry setup failed — telemetry disabled: %s", exc)
        return False


def get_tracer(name: str = __name__):
    """Return an OTel Tracer (no-op tracer when OTel not configured)."""
    try:
        from opentelemetry import trace  # type: ignore[import]
        return trace.get_tracer(name)
    except ImportError:
        return _NoopTracer()


def get_meter(name: str = __name__):
    """Return an OTel Meter (no-op meter when OTel not configured)."""
    try:
        from opentelemetry import metrics  # type: ignore[import]
        return metrics.get_meter(name)
    except ImportError:
        return _NoopMeter()


# ── Internal setup helpers ────────────────────────────────────────────────────


def _setup_traces(service_name: str) -> None:
    """Configure TracerProvider with OTLP gRPC exporter."""
    from opentelemetry import trace  # type: ignore[import]
    from opentelemetry.sdk.resources import Resource  # type: ignore[import]
    from opentelemetry.sdk.trace import TracerProvider  # type: ignore[import]
    from opentelemetry.sdk.trace.export import BatchSpanProcessor  # type: ignore[import]
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (  # type: ignore[import]
        OTLPSpanExporter,
    )

    resource = Resource.create({"service.name": service_name})

    sampler = _build_sampler()
    provider = TracerProvider(resource=resource, sampler=sampler)

    insecure = os.getenv("OTEL_EXPORTER_OTLP_INSECURE", "true").lower() == "true"
    exporter = OTLPSpanExporter(
        endpoint=_DEFAULT_OTLP_ENDPOINT,
        insecure=insecure,
    )
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)

    global _tracer_provider
    _tracer_provider = provider


def _setup_metrics(service_name: str) -> None:
    """Configure MeterProvider with OTLP gRPC exporter."""
    from opentelemetry import metrics  # type: ignore[import]
    from opentelemetry.sdk.metrics import MeterProvider  # type: ignore[import]
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader  # type: ignore[import]
    from opentelemetry.sdk.resources import Resource  # type: ignore[import]
    from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (  # type: ignore[import]
        OTLPMetricExporter,
    )

    resource = Resource.create({"service.name": service_name})

    insecure = os.getenv("OTEL_EXPORTER_OTLP_INSECURE", "true").lower() == "true"
    exporter = OTLPMetricExporter(
        endpoint=_DEFAULT_OTLP_ENDPOINT,
        insecure=insecure,
    )
    reader = PeriodicExportingMetricReader(exporter, export_interval_millis=30_000)
    provider = MeterProvider(resource=resource, metric_readers=[reader])
    metrics.set_meter_provider(provider)

    global _meter_provider
    _meter_provider = provider


def _instrument_libraries(app: "Optional[FastAPI]") -> None:
    """Auto-instrument FastAPI, httpx, psycopg2, and logging."""

    # FastAPI — server-side request spans
    if app is not None:
        try:
            from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor  # type: ignore[import]
            FastAPIInstrumentor.instrument_app(
                app,
                excluded_urls=",".join([
                    "/health",
                    "/api/v1/health",
                    "/api/v1/health/live",
                    "/api/v1/health/ready",
                    "/metrics",
                    "/openapi.json",
                    "/docs",
                    "/redoc",
                ]),
            )
        except ImportError:
            logger.debug("opentelemetry-instrumentation-fastapi not installed — skipping")

    # httpx — outgoing HTTP client spans (orchestrator calls to engines)
    try:
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor  # type: ignore[import]
        HTTPXClientInstrumentor().instrument()
    except ImportError:
        logger.debug("opentelemetry-instrumentation-httpx not installed — skipping")

    # psycopg2 — DB query spans
    try:
        from opentelemetry.instrumentation.psycopg2 import Psycopg2Instrumentor  # type: ignore[import]
        Psycopg2Instrumentor().instrument()
    except ImportError:
        logger.debug("opentelemetry-instrumentation-psycopg2 not installed — skipping")

    # Logging — inject trace_id / span_id into log records
    try:
        from opentelemetry.instrumentation.logging import LoggingInstrumentor  # type: ignore[import]
        LoggingInstrumentor().instrument(set_logging_format=True)
    except ImportError:
        logger.debug("opentelemetry-instrumentation-logging not installed — skipping")


def _build_sampler():
    """Build sampler from OTEL_TRACES_SAMPLER env var."""
    try:
        from opentelemetry.sdk.trace.sampling import (  # type: ignore[import]
            ALWAYS_ON, ALWAYS_OFF, TraceIdRatioBased, ParentBased,
        )
        sampler_name = os.getenv("OTEL_TRACES_SAMPLER", "always_on").lower()
        if sampler_name == "always_off":
            return ALWAYS_OFF
        if sampler_name == "traceidratio":
            ratio = float(os.getenv("OTEL_TRACES_SAMPLER_ARG", "0.1"))
            return ParentBased(root=TraceIdRatioBased(ratio))
        return ALWAYS_ON  # default
    except ImportError:
        return None


# ── No-op fallbacks (when OTel packages not installed) ───────────────────────


class _NoopSpan:
    def set_attribute(self, key: str, value) -> None: pass
    def set_status(self, *a, **kw) -> None: pass
    def record_exception(self, *a, **kw) -> None: pass
    def __enter__(self): return self
    def __exit__(self, *a): pass


class _NoopTracer:
    def start_as_current_span(self, name: str, **kw):
        return _NoopSpan()
    def start_span(self, name: str, **kw):
        return _NoopSpan()


class _NoopCounter:
    def add(self, amount, attributes=None) -> None: pass


class _NoopMeter:
    def create_counter(self, name: str, **kw): return _NoopCounter()
    def create_histogram(self, name: str, **kw): return _NoopCounter()
    def create_gauge(self, name: str, **kw): return _NoopCounter()
