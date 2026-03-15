"""
Prometheus metrics shared across all threat-engine services.

Each engine imports this module and calls ``setup_metrics(app)`` once at
startup.  The ``/api/v1/metrics`` endpoint is auto-registered on the FastAPI
app.

Usage::

    from shared.common.metrics import setup_metrics, record_scan, record_etl

    # In api_server.py, after app = FastAPI(...)
    setup_metrics(app, service_name="engine-threat")

    # In scan handler
    with record_scan("threat"):
        ...  # run scan

    # In ETL
    with record_etl("threat"):
        ...  # transform data
"""
from __future__ import annotations

import logging
import time
from contextlib import contextmanager
from typing import TYPE_CHECKING, Optional

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from fastapi import FastAPI

# ── Lazy imports (prometheus_client may not be installed) ─────────────────────

_METRICS_READY = False


def _ensure_metrics():
    """Lazily import and create all Prometheus metrics objects."""
    global _METRICS_READY
    if _METRICS_READY:
        return

    try:
        from prometheus_client import (  # type: ignore[import]
            Counter, Gauge, Histogram, Info,
        )

        global scan_duration_seconds, findings_count, scan_errors_total
        global cache_age_seconds, cache_row_count
        global api_request_duration_seconds, database_query_duration_seconds
        global etl_duration_seconds, evaluation_duration_seconds
        global report_duration_seconds, service_info
        global database_query_errors_total

        # ── Scan lifecycle metrics ──────────────────────────────────────
        scan_duration_seconds = Histogram(
            "engine_scan_duration_seconds",
            "Total duration of a scan run",
            labelnames=["engine", "status"],
            buckets=(10, 30, 60, 120, 300, 600, 1800),
        )

        findings_count = Gauge(
            "engine_findings_count",
            "Number of findings from the most recent scan",
            labelnames=["engine", "severity"],
        )

        scan_errors_total = Counter(
            "engine_scan_errors_total",
            "Total number of scan errors",
            labelnames=["engine", "error_type"],
        )

        # ── Stage-level metrics ─────────────────────────────────────────
        etl_duration_seconds = Histogram(
            "engine_etl_duration_seconds",
            "Duration of the ETL (transform) stage",
            labelnames=["engine"],
            buckets=(5, 10, 30, 60, 120, 300),
        )

        evaluation_duration_seconds = Histogram(
            "engine_evaluation_duration_seconds",
            "Duration of the rule evaluation stage",
            labelnames=["engine", "stage"],
            buckets=(5, 10, 30, 60, 120, 300),
        )

        report_duration_seconds = Histogram(
            "engine_report_duration_seconds",
            "Duration of the report aggregation stage",
            labelnames=["engine"],
            buckets=(1, 5, 10, 30, 60),
        )

        # ── Cache metrics ───────────────────────────────────────────────
        cache_age_seconds = Gauge(
            "external_collector_cache_age_seconds",
            "Age of the external data cache in seconds",
            labelnames=["cache_name"],
        )

        cache_row_count = Gauge(
            "external_collector_cache_row_count",
            "Number of rows in the external data cache",
            labelnames=["cache_name"],
        )

        # ── API / DB metrics ────────────────────────────────────────────
        api_request_duration_seconds = Histogram(
            "engine_api_request_duration_seconds",
            "Duration of API requests",
            labelnames=["engine", "method", "endpoint", "status_code"],
            buckets=(0.01, 0.05, 0.1, 0.5, 1, 2, 5),
        )

        database_query_duration_seconds = Histogram(
            "engine_database_query_duration_seconds",
            "Duration of database queries",
            labelnames=["engine", "operation"],
            buckets=(0.01, 0.05, 0.1, 0.5, 1, 2, 5, 10),
        )

        database_query_errors_total = Counter(
            "engine_database_query_errors_total",
            "Total number of database query errors",
            labelnames=["engine", "error_type"],
        )

        # ── Service info ────────────────────────────────────────────────
        service_info = Info(
            "engine_service",
            "Service metadata",
        )

        _METRICS_READY = True
        logger.info("Prometheus metrics initialized")

    except ImportError:
        logger.warning(
            "prometheus_client not installed — metrics disabled. "
            "Add prometheus-client to requirements.txt."
        )


# ── Public API ────────────────────────────────────────────────────────────────


def setup_metrics(app: "FastAPI", service_name: str = "unknown") -> None:
    """Register /api/v1/metrics endpoint and initialize all metric objects.

    Args:
        app: FastAPI application instance.
        service_name: Logical service name for the ``engine_service_info`` metric.
    """
    _ensure_metrics()

    if not _METRICS_READY:
        return

    try:
        from prometheus_client import generate_latest, CONTENT_TYPE_LATEST  # type: ignore[import]
        from fastapi import Response

        service_info.info({"service": service_name})

        @app.get("/api/v1/metrics", include_in_schema=False)
        async def metrics_endpoint():
            return Response(
                content=generate_latest(),
                media_type=CONTENT_TYPE_LATEST,
            )

        logger.info("Prometheus /api/v1/metrics endpoint registered for %s", service_name)
    except ImportError:
        logger.warning("Could not register metrics endpoint — prometheus_client not installed")


@contextmanager
def record_scan(engine: str):
    """Context manager to record scan duration and errors.

    Usage::

        with record_scan("threat"):
            run_scan(...)
    """
    _ensure_metrics()
    start = time.monotonic()
    status = "success"
    try:
        yield
    except Exception as exc:
        status = "error"
        if _METRICS_READY:
            scan_errors_total.labels(engine=engine, error_type=type(exc).__name__).inc()
        raise
    finally:
        elapsed = time.monotonic() - start
        if _METRICS_READY:
            scan_duration_seconds.labels(engine=engine, status=status).observe(elapsed)


@contextmanager
def record_etl(engine: str):
    """Context manager to record ETL stage duration."""
    _ensure_metrics()
    start = time.monotonic()
    try:
        yield
    finally:
        elapsed = time.monotonic() - start
        if _METRICS_READY:
            etl_duration_seconds.labels(engine=engine).observe(elapsed)


@contextmanager
def record_evaluation(engine: str, stage: str = "evaluate"):
    """Context manager to record evaluation stage duration."""
    _ensure_metrics()
    start = time.monotonic()
    try:
        yield
    finally:
        elapsed = time.monotonic() - start
        if _METRICS_READY:
            evaluation_duration_seconds.labels(engine=engine, stage=stage).observe(elapsed)


@contextmanager
def record_report(engine: str):
    """Context manager to record report stage duration."""
    _ensure_metrics()
    start = time.monotonic()
    try:
        yield
    finally:
        elapsed = time.monotonic() - start
        if _METRICS_READY:
            report_duration_seconds.labels(engine=engine).observe(elapsed)


def set_findings_count(engine: str, severity: str, count: int) -> None:
    """Update the findings gauge for a given engine/severity."""
    _ensure_metrics()
    if _METRICS_READY:
        findings_count.labels(engine=engine, severity=severity).set(count)


def set_cache_age(cache_name: str, age_seconds: float) -> None:
    """Update the cache age gauge."""
    _ensure_metrics()
    if _METRICS_READY:
        cache_age_seconds.labels(cache_name=cache_name).set(age_seconds)


def set_cache_row_count(cache_name: str, count: int) -> None:
    """Update the cache row count gauge."""
    _ensure_metrics()
    if _METRICS_READY:
        cache_row_count.labels(cache_name=cache_name).set(count)


def record_db_error(engine: str, error_type: str = "connection") -> None:
    """Increment the DB error counter."""
    _ensure_metrics()
    if _METRICS_READY:
        database_query_errors_total.labels(engine=engine, error_type=error_type).inc()
