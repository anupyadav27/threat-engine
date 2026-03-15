"""
Unit Tests — NVD Adapter
Task 0.3.17 [Seq 41 | QA]

Tests: NVD API response parsing, bulk download, CPE matching.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shared.external_collector.adapters.nvd_adapter import NVDAdapter

SAMPLE_NVD_RESPONSE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2024-1234",
                "published": "2024-01-15T10:00:00.000",
                "lastModified": "2024-01-16T12:00:00.000",
                "descriptions": [
                    {"lang": "en", "value": "A buffer overflow in OpenSSL allows remote code execution."}
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "type": "Primary",
                            "cvssData": {
                                "baseScore": 9.8,
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseSeverity": "CRITICAL",
                            },
                        }
                    ]
                },
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {"vulnerable": True, "criteria": "cpe:2.3:a:openssl:openssl:3.0.11:*:*:*:*:*:*:*"},
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {"url": "https://openssl.org/patch", "tags": ["Patch"]},
                ],
            }
        }
    ],
    "totalResults": 1,
}


class TestNVDAdapter:
    @pytest.fixture
    def mock_pool(self):
        pool = AsyncMock()
        conn = AsyncMock()
        pool.acquire.return_value.__aenter__ = AsyncMock(return_value=conn)
        pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)
        return pool

    def test_parse_cve(self, mock_pool):
        adapter = NVDAdapter(pool=mock_pool, api_key="test-key")
        cve = SAMPLE_NVD_RESPONSE["vulnerabilities"][0]["cve"]
        result = adapter._parse_cve(cve)

        assert result["cve_id"] == "CVE-2024-1234"
        assert result["cvss_v3_score"] == 9.8
        assert result["severity"] == "CRITICAL"
        assert "buffer overflow" in result["description"]
        assert len(result["affected_cpe"]) == 1
        assert "openssl" in result["affected_cpe"][0]
        assert len(result["fix_references"]) == 1

    def test_parse_cve_no_cvss(self, mock_pool):
        adapter = NVDAdapter(pool=mock_pool)
        cve = {"id": "CVE-2024-9999", "descriptions": [], "metrics": {}}
        result = adapter._parse_cve(cve)

        assert result["cve_id"] == "CVE-2024-9999"
        assert result["cvss_v3_score"] == 0.0
        assert result["severity"] == "UNKNOWN"

    def test_parse_cve_empty_id(self, mock_pool):
        adapter = NVDAdapter(pool=mock_pool)
        result = adapter._parse_cve({})
        assert result is None

    def test_fetch_cve_success(self, mock_pool):
        adapter = NVDAdapter(pool=mock_pool, api_key="test-key")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_NVD_RESPONSE

        with patch.object(adapter._session, "get", return_value=mock_resp):
            result = adapter.fetch_cve("CVE-2024-1234")
            assert result is not None
            assert result["cve_id"] == "CVE-2024-1234"

    def test_fetch_cve_not_found(self, mock_pool):
        adapter = NVDAdapter(pool=mock_pool)
        mock_resp = MagicMock()
        mock_resp.status_code = 404

        with patch.object(adapter._session, "get", return_value=mock_resp):
            result = adapter.fetch_cve("CVE-9999-0000")
            assert result is None

    def test_fetch_recent_cves(self, mock_pool):
        adapter = NVDAdapter(pool=mock_pool, api_key="test-key")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_NVD_RESPONSE

        with patch.object(adapter._session, "get", return_value=mock_resp):
            cves = adapter.fetch_recent_cves(lookback_days=1)
            assert len(cves) == 1

    @pytest.mark.asyncio
    async def test_store_cves(self, mock_pool):
        adapter = NVDAdapter(pool=mock_pool, api_key="test-key")
        cves = [adapter._parse_cve(SAMPLE_NVD_RESPONSE["vulnerabilities"][0]["cve"])]

        conn = mock_pool.acquire.return_value.__aenter__.return_value
        stored = await adapter.store_cves(cves)
        assert stored == 1
        conn.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_store_cves_empty(self, mock_pool):
        adapter = NVDAdapter(pool=mock_pool)
        stored = await adapter.store_cves([])
        assert stored == 0
