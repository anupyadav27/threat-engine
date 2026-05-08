"""Unit tests for narrative_generator.py.

Mocks LLM calls to verify output validation and failure handling.
"""

import asyncio
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def mock_psycopg2(monkeypatch):
    """Stub out psycopg2 for all tests in this module."""
    mock_module = MagicMock()
    mock_module.OperationalError = Exception
    monkeypatch.setitem(sys.modules, "psycopg2", mock_module)
    yield mock_module


def _make_ctx(resource_uid: str = "arn:aws:s3:::bucket") -> dict:
    """Return a minimal context dict sufficient to pass the sufficiency check."""
    return {
        "detection_id": "det-test",
        "scan_run_id": "scan-test",
        "scenario_type": "data_exfil",
        "attack_chain": [{"description": "Phishing"}, {"description": "Exfil"}],
        "attack_chain_description": "Phishing → Exfil",
        "entry_technique_description": "phishing email",
        "resource_uid": resource_uid,
        "resource_type": "S3 Bucket",
        "resource_name": "prod-bucket",
        "region": "us-east-1",
        "account_id": "123456789012",
        "threat_category": "exfiltration",
        "mitre_techniques": [],
        "risk_score": 80,
        "blast_radius_score": 70,
        "affected_resource_count": 10,
        "estimated_impact": 500000,
        "estimated_impact_display": "~$500,000",
        "estimated_record_count": "1 million",
        "data_classification": "PII",
        "framework_list": "PCI-DSS, HIPAA",
        "ciem_row": None,
        "identity_description": "no identity signal contributing",
        "resource_tags": {},
    }


# ── get_llm_provider ──────────────────────────────────────────────────────────

class TestGetLlmProvider:
    def test_anthropic_when_key_set(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
        monkeypatch.delenv("MISTRAL_API_KEY", raising=False)

        from threat_narrative_engine.narrative_generator import get_llm_provider
        assert get_llm_provider() == "anthropic"

    def test_mistral_when_only_mistral_set(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.setenv("MISTRAL_API_KEY", "mist-key")

        from threat_narrative_engine.narrative_generator import get_llm_provider
        assert get_llm_provider() == "mistral"

    def test_none_when_no_keys(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("MISTRAL_API_KEY", raising=False)

        from threat_narrative_engine.narrative_generator import get_llm_provider
        assert get_llm_provider() is None


# ── generate_for_detection ────────────────────────────────────────────────────

class TestGenerateForDetection:
    @pytest.mark.asyncio
    async def test_skips_when_no_llm_key(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("MISTRAL_API_KEY", raising=False)

        with patch(
            "threat_narrative_engine.db_reader.read_detection_context",
            return_value=_make_ctx(),
        ):
            from threat_narrative_engine.narrative_generator import generate_for_detection
            result = await generate_for_detection("det-1", "scan-1")

        assert result.skipped is True
        assert result.failed is False

    @pytest.mark.asyncio
    async def test_skips_when_no_resource_uid(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        ctx = _make_ctx()
        ctx["resource_uid"] = ""

        with patch(
            "threat_narrative_engine.db_reader.read_detection_context",
            return_value=ctx,
        ):
            from threat_narrative_engine.narrative_generator import generate_for_detection
            result = await generate_for_detection("det-2", "scan-2")

        assert result.skipped is True

    @pytest.mark.asyncio
    async def test_skips_when_no_attack_chain(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        ctx = _make_ctx()
        ctx["attack_chain"] = None

        with patch(
            "threat_narrative_engine.db_reader.read_detection_context",
            return_value=ctx,
        ):
            from threat_narrative_engine.narrative_generator import generate_for_detection
            result = await generate_for_detection("det-3", "scan-3")

        assert result.skipped is True

    @pytest.mark.asyncio
    async def test_success_path(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")

        chain_text = "If this scenario executes, attackers could exfiltrate your data."
        stakes_text = "The organization faces significant regulatory exposure. " * 3

        with (
            patch(
                "threat_narrative_engine.db_reader.read_detection_context",
                return_value=_make_ctx(),
            ),
            patch(
                "threat_narrative_engine.narrative_generator._call_anthropic",
                side_effect=[chain_text, stakes_text],
            ),
            patch("threat_narrative_engine.db_writer.write_narrative") as mock_write,
        ):
            from threat_narrative_engine.narrative_generator import generate_for_detection
            result = await generate_for_detection("det-ok", "scan-ok")

        assert result.skipped is False
        assert result.failed is False
        assert result.chain_of_consequence == chain_text
        assert result.stakes_narrative is not None
        assert result.model == "claude-sonnet-4-6"
        mock_write.assert_called_once()

    @pytest.mark.asyncio
    async def test_llm_timeout_marks_failed(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")

        with (
            patch(
                "threat_narrative_engine.db_reader.read_detection_context",
                return_value=_make_ctx(),
            ),
            patch(
                "threat_narrative_engine.narrative_generator._call_anthropic",
                side_effect=asyncio.TimeoutError(),
            ),
        ):
            from threat_narrative_engine.narrative_generator import generate_for_detection
            result = await generate_for_detection("det-timeout", "scan-t")

        assert result.failed is True
        assert result.skipped is False

    @pytest.mark.asyncio
    async def test_short_stakes_leaves_null(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")

        with (
            patch(
                "threat_narrative_engine.db_reader.read_detection_context",
                return_value=_make_ctx(),
            ),
            patch(
                "threat_narrative_engine.narrative_generator._call_anthropic",
                side_effect=[
                    "If this executes, attackers could breach your data.",
                    "Too short.",  # < 50 chars
                ],
            ),
            patch("threat_narrative_engine.db_writer.write_narrative") as mock_write,
        ):
            from threat_narrative_engine.narrative_generator import generate_for_detection
            result = await generate_for_detection("det-short", "scan-s")

        # Chain was valid — should succeed, stakes NULL
        assert result.failed is False
        assert result.stakes_narrative is None
        mock_write.assert_called_once()

    @pytest.mark.asyncio
    async def test_chain_truncated_to_500_chars(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        long_text = "A" * 600
        stakes_text = "B" * 200

        with (
            patch(
                "threat_narrative_engine.db_reader.read_detection_context",
                return_value=_make_ctx(),
            ),
            patch(
                "threat_narrative_engine.narrative_generator._call_anthropic",
                side_effect=[long_text, stakes_text],
            ),
            patch("threat_narrative_engine.db_writer.write_narrative") as mock_write,
        ):
            from threat_narrative_engine.narrative_generator import generate_for_detection
            result = await generate_for_detection("det-long", "scan-l")

        assert result.chain_of_consequence is not None
        assert len(result.chain_of_consequence) <= 500

    @pytest.mark.asyncio
    async def test_service_continues_after_llm_exception(self, monkeypatch):
        """LLM exception must not crash the service — returns NarrativeResult(failed=True)."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")

        with (
            patch(
                "threat_narrative_engine.db_reader.read_detection_context",
                return_value=_make_ctx(),
            ),
            patch(
                "threat_narrative_engine.narrative_generator._call_anthropic",
                side_effect=Exception("API error"),
            ),
        ):
            from threat_narrative_engine.narrative_generator import generate_for_detection
            # Should NOT raise
            result = await generate_for_detection("det-err", "scan-err")

        assert result.failed is True
