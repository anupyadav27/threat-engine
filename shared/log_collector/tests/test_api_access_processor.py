"""
Unit Tests — API Access Log Processor
Task 0.2.12 [Seq 24 | QA]

Tests: parse API GW JSON format, ALB CLF format, error rate, p99 latency.
"""

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from shared.log_collector.processors.api_access_processor import (
    APIAccessProcessor,
    parse_apigw_log,
    parse_alb_log,
    _truncate_to_5min,
    _is_error_status,
)


# ---------------------------------------------------------------------------
# parse_apigw_log tests
# ---------------------------------------------------------------------------
class TestParseApigwLog:
    def test_parse_valid_json(self):
        msg = json.dumps({
            "requestId": "abc-123",
            "ip": "203.0.113.50",
            "httpMethod": "GET",
            "resourcePath": "/api/v1/users",
            "status": 200,
            "protocol": "HTTP/1.1",
            "responseLength": 1024,
            "integrationLatency": 45.5,
        })
        result = parse_apigw_log(msg)
        assert result is not None
        assert result["source_ip"] == "203.0.113.50"
        assert result["method"] == "GET"
        assert result["path"] == "/api/v1/users"
        assert result["status"] == 200
        assert result["latency_ms"] == 45.5
        assert result["bytes_sent"] == 1024

    def test_parse_error_status(self):
        msg = json.dumps({
            "ip": "10.0.0.1",
            "httpMethod": "POST",
            "resourcePath": "/api/v1/orders",
            "status": 500,
            "integrationLatency": 1200,
        })
        result = parse_apigw_log(msg)
        assert result is not None
        assert result["status"] == 500

    def test_parse_missing_fields(self):
        msg = json.dumps({"httpMethod": "GET"})
        result = parse_apigw_log(msg)
        assert result is not None
        assert result["source_ip"] is None
        assert result["status"] == 0

    def test_parse_invalid_json(self):
        result = parse_apigw_log("not json {{{")
        assert result is None


# ---------------------------------------------------------------------------
# parse_alb_log tests
# ---------------------------------------------------------------------------
class TestParseAlbLog:
    def test_parse_valid_clf(self):
        line = (
            'h2 2024-01-15T10:30:00.000000Z app/my-alb/abc123 '
            '203.0.113.50:49152 10.0.0.5:8080 '
            '0.001 0.050 0.000 '
            '200 200 '
            '256 1024 '
            '"GET /api/v1/health HTTP/2.0" '
            '"python-requests/2.31.0" '
            'ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2'
        )
        result = parse_alb_log(line)
        assert result is not None
        assert result["source_ip"] == "203.0.113.50"
        assert result["method"] == "GET"
        assert result["path"] == "/api/v1/health"
        assert result["status"] == 200
        assert result["latency_ms"] == 50.0  # 0.050 sec → 50ms
        assert result["bytes_sent"] == 1024

    def test_parse_error_response(self):
        line = (
            'h2 2024-01-15T10:30:00.000000Z app/my-alb/abc123 '
            '10.0.0.1:12345 10.0.0.5:8080 '
            '0.001 0.500 0.000 '
            '502 502 '
            '100 50 '
            '"POST /api/v1/process HTTP/2.0" '
            '"curl/7.88.1" '
            'ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2'
        )
        result = parse_alb_log(line)
        assert result is not None
        assert result["status"] == 502

    def test_parse_invalid_format(self):
        result = parse_alb_log("this is not a valid log line")
        assert result is None


# ---------------------------------------------------------------------------
# Utility function tests
# ---------------------------------------------------------------------------
class TestUtilities:
    def test_is_error_status(self):
        assert _is_error_status(200) is False
        assert _is_error_status(301) is False
        assert _is_error_status(400) is True
        assert _is_error_status(404) is True
        assert _is_error_status(500) is True
        assert _is_error_status(503) is True

    def test_truncate_to_5min(self):
        dt = datetime(2024, 1, 15, 10, 37, 45, tzinfo=timezone.utc)
        result = _truncate_to_5min(dt)
        assert result.minute == 35
        assert result.second == 0


# ---------------------------------------------------------------------------
# APIAccessProcessor integration tests
# ---------------------------------------------------------------------------
class TestAPIAccessProcessor:
    @pytest.fixture
    def mock_pool(self):
        pool = AsyncMock()
        conn = AsyncMock()
        pool.acquire.return_value.__aenter__ = AsyncMock(return_value=conn)
        pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)
        return pool

    @pytest.fixture
    def mock_logs_client(self):
        logs = MagicMock()
        logs.filter_log_events.return_value = {
            "events": [
                {
                    "timestamp": 1705312200000,  # 2024-01-15T10:30:00Z
                    "message": json.dumps({
                        "ip": "10.0.0.1",
                        "httpMethod": "GET",
                        "resourcePath": "/api/v1/health",
                        "status": 200,
                        "integrationLatency": 5.0,
                        "responseLength": 32,
                    }),
                },
                {
                    "timestamp": 1705312260000,
                    "message": json.dumps({
                        "ip": "10.0.0.2",
                        "httpMethod": "POST",
                        "resourcePath": "/api/v1/data",
                        "status": 500,
                        "integrationLatency": 2000.0,
                        "responseLength": 128,
                    }),
                },
            ],
        }
        return logs

    @pytest.mark.asyncio
    async def test_process_api_logs(self, mock_pool, mock_logs_client):
        processor = APIAccessProcessor(pool=mock_pool, logs_client=mock_logs_client)
        result = await processor.process(
            log_group_name="/aws/apigateway/test-api",
            lookback_hours=24,
        )

        assert result["rows_inserted"] == 2
        assert result["rows_skipped"] == 0
        assert result["aggregation_rows"] > 0

    @pytest.mark.asyncio
    async def test_process_no_events(self, mock_pool):
        logs = MagicMock()
        logs.filter_log_events.return_value = {"events": []}

        processor = APIAccessProcessor(pool=mock_pool, logs_client=logs)
        result = await processor.process(log_group_name="/aws/apigateway/empty")

        assert result["rows_inserted"] == 0
