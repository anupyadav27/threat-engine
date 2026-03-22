"""
Unit Tests — VPC Flow Log Processor
Task 0.2.12 [Seq 24 | QA]

Tests: parse valid/invalid records, aggregation logic, edge cases.
"""

import gzip
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shared.log_collector.processors.vpc_flow_processor import (
    VPCFlowProcessor,
    parse_flow_log_line,
    _truncate_to_5min,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
SAMPLE_FLOW_LOG = """version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status
2 123456789012 eni-abc123 10.0.1.5 10.0.2.10 49152 443 6 20 4096 1609459200 1609459260 ACCEPT OK
2 123456789012 eni-abc123 10.0.2.10 10.0.1.5 443 49152 6 15 3072 1609459200 1609459260 ACCEPT OK
2 123456789012 eni-abc123 192.168.1.1 10.0.1.5 12345 22 6 5 512 1609459200 1609459260 REJECT OK
"""


# ---------------------------------------------------------------------------
# parse_flow_log_line tests
# ---------------------------------------------------------------------------
class TestParseFlowLogLine:
    def test_parse_valid_record(self):
        line = "2 123456789012 eni-abc123 10.0.1.5 10.0.2.10 49152 443 6 20 4096 1609459200 1609459260 ACCEPT OK"
        result = parse_flow_log_line(line)

        assert result is not None
        assert result["srcaddr"] == "10.0.1.5"
        assert result["dstaddr"] == "10.0.2.10"
        assert result["srcport"] == 49152
        assert result["dstport"] == 443
        assert result["protocol_name"] == "TCP"
        assert result["packets"] == 20
        assert result["bytes"] == 4096
        assert result["action"] == "ACCEPT"
        assert result["log_status"] == "OK"

    def test_parse_header_line(self):
        line = "version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status"
        result = parse_flow_log_line(line)
        assert result is None

    def test_parse_empty_line(self):
        assert parse_flow_log_line("") is None
        assert parse_flow_log_line("   ") is None

    def test_parse_malformed_line_too_few_fields(self):
        result = parse_flow_log_line("2 123456789012 eni-abc123")
        assert result is None

    def test_parse_reject_action(self):
        line = "2 123456789012 eni-abc123 192.168.1.1 10.0.1.5 12345 22 6 5 512 1609459200 1609459260 REJECT OK"
        result = parse_flow_log_line(line)
        assert result is not None
        assert result["action"] == "REJECT"

    def test_parse_dash_values(self):
        """Dash values should be parsed as None."""
        line = "2 123456789012 eni-abc123 - - - - 6 0 0 1609459200 1609459260 - OK"
        result = parse_flow_log_line(line)
        assert result is not None
        assert result["srcaddr"] is None
        assert result["dstaddr"] is None
        assert result["srcport"] is None
        assert result["action"] is None

    def test_parse_udp_protocol(self):
        line = "2 123456789012 eni-abc123 10.0.1.5 10.0.2.10 49152 53 17 3 256 1609459200 1609459260 ACCEPT OK"
        result = parse_flow_log_line(line)
        assert result is not None
        assert result["protocol_name"] == "UDP"

    def test_parse_zero_packets(self):
        """Zero packets edge case — valid record."""
        line = "2 123456789012 eni-abc123 10.0.1.5 10.0.2.10 49152 443 6 0 0 1609459200 1609459260 ACCEPT OK"
        result = parse_flow_log_line(line)
        assert result is not None
        assert result["packets"] == 0
        assert result["bytes"] == 0

    def test_parse_invalid_action(self):
        """Invalid action value should return None."""
        line = "2 123456789012 eni-abc123 10.0.1.5 10.0.2.10 49152 443 6 20 4096 1609459200 1609459260 INVALID OK"
        result = parse_flow_log_line(line)
        assert result is None


# ---------------------------------------------------------------------------
# _truncate_to_5min tests
# ---------------------------------------------------------------------------
class TestTruncateTo5Min:
    def test_exact_boundary(self):
        result = _truncate_to_5min(1609459200)  # 2021-01-01 00:00:00 UTC
        assert result.minute == 0
        assert result.second == 0

    def test_mid_window(self):
        result = _truncate_to_5min(1609459380)  # 2021-01-01 00:03:00 UTC
        assert result.minute == 0  # Truncated to 00:00

    def test_near_boundary(self):
        result = _truncate_to_5min(1609459500)  # 2021-01-01 00:05:00 UTC
        assert result.minute == 5


# ---------------------------------------------------------------------------
# VPCFlowProcessor integration tests (with mocked S3 and DB)
# ---------------------------------------------------------------------------
class TestVPCFlowProcessor:
    @pytest.fixture
    def mock_pool(self):
        pool = AsyncMock()
        conn = AsyncMock()
        pool.acquire.return_value.__aenter__ = AsyncMock(return_value=conn)
        pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)
        return pool

    @pytest.fixture
    def mock_s3(self):
        s3 = MagicMock()
        compressed = gzip.compress(SAMPLE_FLOW_LOG.encode("utf-8"))
        s3.get_object.return_value = {"Body": MagicMock(read=MagicMock(return_value=compressed))}
        return s3

    @pytest.mark.asyncio
    async def test_process_valid_file(self, mock_pool, mock_s3):
        processor = VPCFlowProcessor(pool=mock_pool, s3_client=mock_s3)
        result = await processor.process(
            bucket="test-bucket",
            key="AWSLogs/123/VPCFlowLogs/us-east-1/2024/flow.log.gz",
            customer_id="cust-1",
            tenant_id="tenant-1",
        )

        assert result["rows_inserted"] == 3
        assert result["rows_skipped"] == 1  # Header line
        assert result["aggregation_rows"] > 0

    @pytest.mark.asyncio
    async def test_process_empty_file(self, mock_pool):
        s3 = MagicMock()
        compressed = gzip.compress(b"")
        s3.get_object.return_value = {"Body": MagicMock(read=MagicMock(return_value=compressed))}

        processor = VPCFlowProcessor(pool=mock_pool, s3_client=s3)
        result = await processor.process(bucket="b", key="k.gz")

        assert result["rows_inserted"] == 0
