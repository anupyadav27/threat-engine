"""
Unit Tests — Trivy Scanner
Task 0.3.17 [Seq 41 | QA]

Tests: subprocess execution, JSON parsing, SBOM extraction, timeout handling.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shared.external_collector.scanners.trivy_scanner import TrivyScanner


SAMPLE_TRIVY_OUTPUT = {
    "Results": [
        {
            "Target": "nginx:latest (debian 12.4)",
            "Type": "os",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-1234",
                    "PkgName": "openssl",
                    "InstalledVersion": "3.0.11",
                    "Severity": "HIGH",
                    "FixedVersion": "3.0.13",
                    "Title": "OpenSSL buffer overflow",
                    "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
                },
                {
                    "VulnerabilityID": "CVE-2024-5678",
                    "PkgName": "curl",
                    "InstalledVersion": "7.88.1",
                    "Severity": "MEDIUM",
                    "FixedVersion": "",
                    "Title": "curl header injection",
                    "PrimaryURL": "",
                },
            ],
            "Packages": [
                {"Name": "openssl", "Version": "3.0.11", "Identifier": {"PURL": "pkg:deb/debian/openssl@3.0.11"}},
                {"Name": "curl", "Version": "7.88.1", "Identifier": {"PURL": "pkg:deb/debian/curl@7.88.1"}},
            ],
        }
    ]
}


class TestTrivyScanner:
    @pytest.fixture
    def mock_pool(self):
        pool = AsyncMock()
        conn = AsyncMock()
        pool.acquire.return_value.__aenter__ = AsyncMock(return_value=conn)
        pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)
        return pool

    def test_extract_cves(self, mock_pool):
        scanner = TrivyScanner(pool=mock_pool)
        cves = scanner._extract_cves(SAMPLE_TRIVY_OUTPUT)

        assert len(cves) == 2
        assert cves[0]["cve_id"] == "CVE-2024-1234"
        assert cves[0]["severity"] == "HIGH"
        assert cves[0]["package_name"] == "openssl"
        assert cves[0]["fixed_version"] == "3.0.13"
        assert cves[1]["cve_id"] == "CVE-2024-5678"
        assert cves[1]["severity"] == "MEDIUM"

    def test_extract_cves_no_results(self, mock_pool):
        scanner = TrivyScanner(pool=mock_pool)
        cves = scanner._extract_cves({"Results": []})
        assert cves == []

    def test_extract_sbom(self, mock_pool):
        scanner = TrivyScanner(pool=mock_pool)
        sbom = scanner._extract_sbom(SAMPLE_TRIVY_OUTPUT)

        assert sbom["bomFormat"] == "CycloneDX"
        assert sbom["specVersion"] == "1.4"
        assert len(sbom["components"]) == 2
        assert sbom["components"][0]["name"] == "openssl"
        assert sbom["components"][0]["purl"] == "pkg:deb/debian/openssl@3.0.11"

    def test_extract_sbom_empty(self, mock_pool):
        scanner = TrivyScanner(pool=mock_pool)
        sbom = scanner._extract_sbom({"Results": []})
        assert sbom["components"] == []

    def test_execute_trivy_success(self, mock_pool):
        scanner = TrivyScanner(pool=mock_pool, trivy_bin="/usr/local/bin/trivy")
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(SAMPLE_TRIVY_OUTPUT)
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            result = scanner._execute_trivy("nginx:latest")
            assert result["returncode"] == 0
            assert "Results" in result["stdout"]

    def test_execute_trivy_timeout(self, mock_pool):
        scanner = TrivyScanner(pool=mock_pool)

        import subprocess
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="trivy", timeout=300)):
            result = scanner._execute_trivy("nginx:latest")
            assert result["returncode"] == -1
            assert "timed out" in result["stderr"]

    @pytest.mark.asyncio
    async def test_scan_image_success(self, mock_pool):
        scanner = TrivyScanner(pool=mock_pool)
        mock_result = {
            "returncode": 0,
            "stdout": json.dumps(SAMPLE_TRIVY_OUTPUT),
            "stderr": "",
        }

        with patch.object(scanner, "_execute_trivy", return_value=mock_result):
            result = await scanner.scan_image("nginx:latest")
            assert result["scan_status"] == "completed"
            assert len(result["cve_list"]) == 2
            assert result["error"] is None

    @pytest.mark.asyncio
    async def test_scan_image_failure(self, mock_pool):
        scanner = TrivyScanner(pool=mock_pool)
        mock_result = {
            "returncode": 1,
            "stdout": "",
            "stderr": "image not found",
        }

        with patch.object(scanner, "_execute_trivy", return_value=mock_result):
            result = await scanner.scan_image("nonexistent:latest")
            assert result["scan_status"] == "failed"
            assert "image not found" in result["error"]
