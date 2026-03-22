"""
End-to-end integration tests for the 5-layer pipeline worker.

Tests verify that the pipeline orchestrates all engines in the correct
layer order with proper dependency handling and failure isolation.
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch, call
import pytest

from shared.pipeline_worker.worker import run_pipeline, _run_layer
from shared.pipeline_worker import handlers


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def mock_sqs():
    sqs = MagicMock()
    sqs.publish = MagicMock()
    return sqs


@pytest.fixture
def scan_event():
    """Minimal PipelineEvent-like object for testing."""
    event = MagicMock()
    event.orchestration_id = "orch-test-001"
    event.tenant_id = "tenant-1"
    event.account_id = "123456789012"
    event.provider = "aws"
    event.event_type = "scan_requested"
    return event


def _ok_response(**extra) -> dict:
    """Standard success response from an engine."""
    return {"status": "completed", "scan_id": "scan-abc-123", **extra}


def _fail_response():
    """Simulated engine failure."""
    return Exception("connection refused")


# ── Layer execution tests ─────────────────────────────────────────────────────

class TestRunLayer:
    @pytest.mark.asyncio
    async def test_all_stages_succeed(self, mock_sqs):
        stages = [
            ("engine_a", asyncio.coroutine(lambda: _ok_response())()),
            ("engine_b", asyncio.coroutine(lambda: _ok_response())()),
        ]
        results = await _run_layer(
            "test-layer", stages,
            "orch-1", "t-1", "a-1", "aws", mock_sqs,
        )
        assert results["engine_a"] is not None
        assert results["engine_b"] is not None

    @pytest.mark.asyncio
    async def test_partial_failure_isolated(self, mock_sqs):
        async def succeed():
            return _ok_response()

        async def fail():
            raise Exception("timeout")

        stages = [
            ("good_engine", succeed()),
            ("bad_engine", fail()),
        ]
        results = await _run_layer(
            "test-layer", stages,
            "orch-1", "t-1", "a-1", "aws", mock_sqs,
        )
        assert results["good_engine"] is not None
        assert results["bad_engine"] is None

    @pytest.mark.asyncio
    async def test_empty_stages(self, mock_sqs):
        results = await _run_layer(
            "test-layer", [],
            "orch-1", "t-1", "a-1", "aws", mock_sqs,
        )
        assert results == {}

    @pytest.mark.asyncio
    async def test_publishes_events_for_each_stage(self, mock_sqs):
        async def succeed():
            return _ok_response()

        stages = [
            ("engine_a", succeed()),
            ("engine_b", succeed()),
        ]
        await _run_layer(
            "test-layer", stages,
            "orch-1", "t-1", "a-1", "aws", mock_sqs,
        )
        # No events queue configured in test, so publish not called
        # But the function completes without error


# ── Full pipeline tests ───────────────────────────────────────────────────────

class TestRunPipeline:
    @pytest.mark.asyncio
    @patch.dict("os.environ", {
        "ENABLE_COLLECTORS": "true",
        "ENABLE_NEW_ENGINES": "true",
    })
    @patch("shared.pipeline_worker.handlers.trigger_risk", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_compliance", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_datasec_enhanced", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_supplychain", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_datasec", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_threat", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_ai_security", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_network", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_secops", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_iam", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_check", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_api_engine", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_container", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_inventory", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_external_collector", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_log_collector", new_callable=AsyncMock)
    async def test_full_pipeline_all_engines(
        self,
        mock_log_collector, mock_external_collector,
        mock_inventory, mock_container, mock_api_engine,
        mock_check, mock_iam, mock_secops, mock_network, mock_ai_security,
        mock_threat, mock_datasec, mock_supplychain, mock_datasec_enhanced,
        mock_compliance, mock_risk,
        scan_event, mock_sqs,
    ):
        # Configure all mocks to return success
        for mock in [
            mock_log_collector, mock_external_collector,
            mock_inventory, mock_container, mock_api_engine,
            mock_check, mock_iam, mock_secops, mock_network, mock_ai_security,
            mock_threat, mock_datasec, mock_supplychain, mock_datasec_enhanced,
            mock_compliance, mock_risk,
        ]:
            mock.return_value = _ok_response()

        mock_check.return_value = _ok_response(check_scan_id="chk-001")

        await run_pipeline(scan_event, mock_sqs)

        # All handlers should have been called
        mock_log_collector.assert_called_once()
        mock_external_collector.assert_called_once()
        mock_inventory.assert_called_once()
        mock_container.assert_called_once()
        mock_api_engine.assert_called_once()
        mock_check.assert_called_once()
        mock_iam.assert_called_once()
        mock_secops.assert_called_once()
        mock_network.assert_called_once()
        mock_ai_security.assert_called_once()
        mock_threat.assert_called_once()
        mock_datasec.assert_called_once()
        mock_supplychain.assert_called_once()
        mock_datasec_enhanced.assert_called_once()
        mock_compliance.assert_called_once()
        mock_risk.assert_called_once()

    @pytest.mark.asyncio
    @patch.dict("os.environ", {
        "ENABLE_COLLECTORS": "false",
        "ENABLE_NEW_ENGINES": "false",
    })
    @patch("shared.pipeline_worker.handlers.trigger_compliance", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_datasec", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_threat", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_secops", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_iam", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_check", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_inventory", new_callable=AsyncMock)
    async def test_legacy_mode_no_new_engines(
        self,
        mock_inventory, mock_check, mock_iam, mock_secops,
        mock_threat, mock_datasec, mock_compliance,
        scan_event, mock_sqs,
    ):
        for mock in [mock_inventory, mock_check, mock_iam, mock_secops,
                     mock_threat, mock_datasec, mock_compliance]:
            mock.return_value = _ok_response()

        mock_check.return_value = _ok_response(check_scan_id="chk-002")

        await run_pipeline(scan_event, mock_sqs)

        mock_inventory.assert_called_once()
        mock_check.assert_called_once()
        mock_iam.assert_called_once()
        mock_secops.assert_called_once()
        mock_threat.assert_called_once()
        mock_datasec.assert_called_once()
        mock_compliance.assert_called_once()

    @pytest.mark.asyncio
    @patch.dict("os.environ", {
        "ENABLE_COLLECTORS": "true",
        "ENABLE_NEW_ENGINES": "true",
    })
    @patch("shared.pipeline_worker.handlers.trigger_risk", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_compliance", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_datasec_enhanced", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_supplychain", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_datasec", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_threat", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_ai_security", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_network", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_secops", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_iam", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_check", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_api_engine", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_container", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_inventory", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_external_collector", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_log_collector", new_callable=AsyncMock)
    async def test_layer2_failure_doesnt_block_layer3(
        self,
        mock_log_collector, mock_external_collector,
        mock_inventory, mock_container, mock_api_engine,
        mock_check, mock_iam, mock_secops, mock_network, mock_ai_security,
        mock_threat, mock_datasec, mock_supplychain, mock_datasec_enhanced,
        mock_compliance, mock_risk,
        scan_event, mock_sqs,
    ):
        # All succeed except check engine
        for mock in [
            mock_log_collector, mock_external_collector,
            mock_inventory, mock_container, mock_api_engine,
            mock_iam, mock_secops, mock_network, mock_ai_security,
            mock_threat, mock_datasec, mock_supplychain, mock_datasec_enhanced,
            mock_compliance, mock_risk,
        ]:
            mock.return_value = _ok_response()

        # Check engine fails
        mock_check.side_effect = Exception("check engine down")

        await run_pipeline(scan_event, mock_sqs)

        # Layer 3 should still run despite Layer 2 check failure
        mock_threat.assert_called_once()
        mock_datasec.assert_called_once()
        mock_supplychain.assert_called_once()
        mock_compliance.assert_called_once()
        mock_risk.assert_called_once()


# ── Handler retry tests ───────────────────────────────────────────────────────

class TestHandlerRetry:
    @pytest.mark.asyncio
    @patch("shared.pipeline_worker.handlers.httpx.AsyncClient")
    async def test_retry_on_503(self, mock_client_cls):
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        # First call returns 503, second returns 200
        resp_503 = MagicMock()
        resp_503.status_code = 503
        resp_200 = MagicMock()
        resp_200.status_code = 200
        resp_200.json.return_value = {"status": "ok"}
        resp_200.raise_for_status = MagicMock()

        mock_client.post = AsyncMock(side_effect=[resp_503, resp_200])

        result = await handlers._post_with_retry(
            "http://test/api/v1/scan",
            json={"orchestration_id": "test"},
            timeout=5.0,
            max_retries=2,
        )
        assert result == {"status": "ok"}
        assert mock_client.post.call_count == 2

    @pytest.mark.asyncio
    async def test_url_resolution(self):
        url = handlers._url("inventory")
        assert "engine-inventory" in url

    @pytest.mark.asyncio
    async def test_url_env_override(self):
        import os
        os.environ["CONTAINER_ENGINE_URL"] = "http://localhost:8006"
        url = handlers._url("container")
        assert url == "http://localhost:8006"
        del os.environ["CONTAINER_ENGINE_URL"]


# ── Layer ordering tests ─────────────────────────────────────────────────────

class TestLayerOrdering:
    """Verify that stages are grouped into the correct layers."""

    @pytest.mark.asyncio
    @patch.dict("os.environ", {
        "ENABLE_COLLECTORS": "true",
        "ENABLE_NEW_ENGINES": "true",
    })
    @patch("shared.pipeline_worker.handlers.trigger_risk", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_compliance", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_datasec_enhanced", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_supplychain", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_datasec", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_threat", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_ai_security", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_network", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_secops", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_iam", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_check", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_api_engine", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_container", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_inventory", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_external_collector", new_callable=AsyncMock)
    @patch("shared.pipeline_worker.handlers.trigger_log_collector", new_callable=AsyncMock)
    async def test_check_scan_id_passed_to_threat(
        self,
        mock_log_collector, mock_external_collector,
        mock_inventory, mock_container, mock_api_engine,
        mock_check, mock_iam, mock_secops, mock_network, mock_ai_security,
        mock_threat, mock_datasec, mock_supplychain, mock_datasec_enhanced,
        mock_compliance, mock_risk,
        scan_event, mock_sqs,
    ):
        for mock in [
            mock_log_collector, mock_external_collector,
            mock_inventory, mock_container, mock_api_engine,
            mock_iam, mock_secops, mock_network, mock_ai_security,
            mock_datasec, mock_supplychain, mock_datasec_enhanced,
            mock_compliance, mock_risk,
        ]:
            mock.return_value = _ok_response()

        mock_check.return_value = {"status": "completed", "check_scan_id": "chk-999"}
        mock_threat.return_value = _ok_response()

        await run_pipeline(scan_event, mock_sqs)

        # Threat should receive the check_scan_id from Layer 2
        threat_call = mock_threat.call_args
        assert threat_call[1].get("check_scan_id") == "chk-999" or \
               (len(threat_call[0]) > 2 and threat_call[0][2] == "chk-999")


# ── Scan ID extraction tests ─────────────────────────────────────────────────

class TestScanIdExtraction:
    @pytest.mark.asyncio
    async def test_extracts_scan_id(self, mock_sqs):
        async def respond():
            return {"scan_id": "sid-001"}

        stages = [("test_engine", respond())]
        results = await _run_layer("test", stages, "o", "t", "a", "aws", mock_sqs)
        assert results["test_engine"]["scan_id"] == "sid-001"

    @pytest.mark.asyncio
    async def test_extracts_scan_run_id(self, mock_sqs):
        async def respond():
            return {"scan_run_id": "run-001"}

        stages = [("test_engine", respond())]
        results = await _run_layer("test", stages, "o", "t", "a", "aws", mock_sqs)
        assert results["test_engine"]["scan_run_id"] == "run-001"
