"""
Unit Tests — Threat Intel Adapter
Task 0.3.17 [Seq 41 | QA]

Tests: IOC feed parsing, deduplication, IP check.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shared.external_collector.adapters.threat_intel_adapter import (
    AbuseIPDBAdapter,
    OTXAdapter,
    ThreatIntelCollector,
)


class TestAbuseIPDBAdapter:
    def test_check_ip_malicious(self):
        adapter = AbuseIPDBAdapter(api_key="test-key")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "ipAddress": "1.2.3.4",
                "abuseConfidenceScore": 95,
                "countryCode": "CN",
                "isp": "China Telecom",
                "domain": "chinanet.cn",
                "totalReports": 42,
                "isTor": False,
                "lastReportedAt": "2024-01-15T10:00:00Z",
                "reports": [
                    {"categories": [14, 15]},
                ],
            }
        }

        with patch.object(adapter._session, "get", return_value=mock_resp):
            result = adapter.check_ip("1.2.3.4")
            assert result is not None
            assert result["indicator_value"] == "1.2.3.4"
            assert result["confidence"] == 95

    def test_check_ip_benign(self):
        adapter = AbuseIPDBAdapter(api_key="test-key")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "ipAddress": "8.8.8.8",
                "abuseConfidenceScore": 0,
                "reports": [],
            }
        }

        with patch.object(adapter._session, "get", return_value=mock_resp):
            result = adapter.check_ip("8.8.8.8")
            assert result is None

    def test_check_ip_rate_limited(self):
        adapter = AbuseIPDBAdapter(api_key="test-key")
        mock_resp = MagicMock()
        mock_resp.status_code = 429

        with patch.object(adapter._session, "get", return_value=mock_resp):
            result = adapter.check_ip("1.2.3.4")
            assert result is None


class TestOTXAdapter:
    def test_extract_iocs_from_pulses(self):
        adapter = OTXAdapter(api_key="test-key")
        pulses = [
            {
                "id": "pulse-1",
                "name": "Test Pulse",
                "tags": ["malware", "botnet"],
                "indicators": [
                    {"type": "IPv4", "indicator": "10.0.0.1", "created": "2024-01-15"},
                    {"type": "domain", "indicator": "evil.com", "created": "2024-01-15"},
                    {"type": "FileHash-SHA256", "indicator": "abc123def456", "created": "2024-01-15"},
                    {"type": "UnknownType", "indicator": "skip-me"},  # Should be filtered
                ],
            }
        ]

        iocs = adapter.extract_iocs_from_pulses(pulses)
        assert len(iocs) == 3  # UnknownType filtered
        assert iocs[0]["indicator_type"] == "ipv4"
        assert iocs[1]["indicator_type"] == "domain"
        assert iocs[2]["indicator_type"] == "hash_sha256"

    def test_extract_empty_pulses(self):
        adapter = OTXAdapter(api_key="test-key")
        iocs = adapter.extract_iocs_from_pulses([])
        assert iocs == []


class TestThreatIntelCollector:
    @pytest.fixture
    def mock_pool(self):
        pool = AsyncMock()
        conn = AsyncMock()
        pool.acquire.return_value.__aenter__ = AsyncMock(return_value=conn)
        pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)
        conn.fetchrow.return_value = None
        return pool

    @pytest.mark.asyncio
    async def test_refresh_no_adapters(self, mock_pool):
        collector = ThreatIntelCollector(pool=mock_pool)
        result = await collector.refresh()
        assert result["total_stored"] == 0

    @pytest.mark.asyncio
    async def test_check_ip_cache_miss_no_adapter(self, mock_pool):
        collector = ThreatIntelCollector(pool=mock_pool)
        result = await collector.check_ip("1.2.3.4")
        assert result is None
