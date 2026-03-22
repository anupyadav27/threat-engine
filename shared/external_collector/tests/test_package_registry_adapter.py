"""
Unit Tests — Package Registry Adapter
Task 0.3.17 [Seq 41 | QA]

Tests: npm, PyPI, Maven API parsing.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shared.external_collector.adapters.package_registry_adapter import (
    CratesRegistry,
    MavenRegistry,
    NpmRegistry,
    PackageRegistryCollector,
    PyPIRegistry,
)


class TestNpmRegistry:
    def test_lookup_success(self):
        registry = NpmRegistry()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "name": "lodash",
            "dist-tags": {"latest": "4.17.21"},
            "versions": {"4.17.21": {"license": "MIT"}},
            "maintainers": [{"name": "jdalton"}],
            "time": {"4.17.21": "2021-02-20T15:00:00.000Z"},
            "description": "Lodash modular utilities.",
        }

        with patch.object(registry._session, "get", return_value=mock_resp):
            result = registry.lookup("lodash")
            assert result["package_name"] == "lodash"
            assert result["latest_version"] == "4.17.21"
            assert result["maintainer_count"] == 1

    def test_lookup_not_found(self):
        registry = NpmRegistry()
        mock_resp = MagicMock()
        mock_resp.status_code = 404

        with patch.object(registry._session, "get", return_value=mock_resp):
            result = registry.lookup("nonexistent-pkg-xyz")
            assert result is None


class TestPyPIRegistry:
    def test_lookup_success(self):
        registry = PyPIRegistry()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "info": {
                "version": "2.31.0",
                "license": "Apache 2.0",
                "maintainer": "Kenneth Reitz",
                "summary": "Python HTTP for Humans.",
            }
        }

        with patch.object(registry._session, "get", return_value=mock_resp):
            result = registry.lookup("requests")
            assert result["latest_version"] == "2.31.0"
            assert result["registry"] == "pypi"


class TestMavenRegistry:
    def test_lookup_success(self):
        registry = MavenRegistry()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "response": {
                "docs": [{"latestVersion": "2.15.3", "timestamp": 1705312200000}]
            }
        }

        with patch.object(registry._session, "get", return_value=mock_resp):
            result = registry.lookup("com.fasterxml.jackson.core:jackson-databind")
            assert result["latest_version"] == "2.15.3"

    def test_lookup_invalid_name(self):
        registry = MavenRegistry()
        result = registry.lookup("no-colon-here")
        assert result is None


class TestCratesRegistry:
    def test_lookup_success(self):
        registry = CratesRegistry()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "crate": {
                "name": "serde",
                "max_version": "1.0.195",
                "downloads": 150000000,
                "description": "A serialization framework.",
            }
        }

        with patch.object(registry._session, "get", return_value=mock_resp):
            result = registry.lookup("serde")
            assert result["latest_version"] == "1.0.195"
            assert result["downloads"] == 150000000


class TestPackageRegistryCollector:
    @pytest.fixture
    def mock_pool(self):
        pool = AsyncMock()
        conn = AsyncMock()
        pool.acquire.return_value.__aenter__ = AsyncMock(return_value=conn)
        pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)
        return pool

    @pytest.mark.asyncio
    async def test_lookup_unknown_registry(self, mock_pool):
        collector = PackageRegistryCollector(pool=mock_pool)
        result = await collector.lookup_package("pkg", "unknown_registry")
        assert result is None
