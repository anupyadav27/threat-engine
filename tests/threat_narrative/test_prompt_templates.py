"""Unit tests for prompt_templates.py.

Verifies template rendering with typical and edge-case context dicts.
"""

import pytest

from threat_narrative_engine.prompt_templates import (
    build_attack_chain_description,
    build_estimated_impact_display,
    build_identity_description,
    build_chain_user_prompt,
    build_stakes_user_prompt,
)


# ── build_attack_chain_description ────────────────────────────────────────────

class TestBuildAttackChainDescription:
    def test_list_of_dicts(self):
        steps = [
            {"technique_id": "T1078", "description": "Initial Access"},
            {"technique_id": "T1552", "description": "Credential Theft"},
        ]
        result = build_attack_chain_description(steps)
        assert "Initial Access" in result
        assert "Credential Theft" in result
        assert "→" in result

    def test_list_of_strings(self):
        steps = ["Recon", "Exploit", "Persist"]
        result = build_attack_chain_description(steps)
        assert result == "Recon → Exploit → Persist"

    def test_dict_with_steps_key(self):
        chain = {"steps": [{"description": "Phishing"}, {"description": "Exfil"}]}
        result = build_attack_chain_description(chain)
        assert "Phishing" in result
        assert "Exfil" in result

    def test_dict_with_chain_key(self):
        chain = {"chain": [{"action": "Lateral Move"}, {"action": "Data Collection"}]}
        result = build_attack_chain_description(chain)
        assert "Lateral Move" in result

    def test_empty_list(self):
        result = build_attack_chain_description([])
        assert result == "multi-stage attack path"

    def test_none(self):
        result = build_attack_chain_description(None)
        assert result == "multi-stage attack path"

    def test_plain_string(self):
        result = build_attack_chain_description("Direct access")
        assert result == "Direct access"

    def test_caps_at_four_steps(self):
        steps = [{"description": f"Step {i}"} for i in range(10)]
        result = build_attack_chain_description(steps)
        parts = result.split(" → ")
        assert len(parts) <= 4

    def test_unknown_type(self):
        result = build_attack_chain_description(12345)
        assert result == "unknown attack path"


# ── build_estimated_impact_display ────────────────────────────────────────────

class TestBuildEstimatedImpactDisplay:
    def test_positive_number(self):
        result = build_estimated_impact_display(1250000)
        assert result == "~$1,250,000"

    def test_zero(self):
        result = build_estimated_impact_display(0)
        assert result == "unknown financial impact"

    def test_none(self):
        result = build_estimated_impact_display(None)
        assert result == "unknown financial impact"

    def test_negative(self):
        result = build_estimated_impact_display(-500)
        assert result == "unknown financial impact"

    def test_float(self):
        result = build_estimated_impact_display(99999.99)
        assert result == "~$100,000"

    def test_non_numeric_string(self):
        result = build_estimated_impact_display("N/A")
        assert result == "unknown financial impact"


# ── build_identity_description ────────────────────────────────────────────────

class TestBuildIdentityDescription:
    def test_full_ciem_row(self):
        row = {
            "privilege_level": "admin",
            "identity_type": "IAM role",
            "principal_name": "data-processor-role",
        }
        result = build_identity_description(row)
        assert "admin" in result
        assert "IAM role" in result
        assert "data-processor-role" in result

    def test_missing_principal_name(self):
        row = {"privilege_level": "read-only", "identity_type": "user", "principal_name": ""}
        result = build_identity_description(row)
        assert "read-only" in result
        assert "user" in result
        assert "(" not in result

    def test_none_row(self):
        result = build_identity_description(None)
        assert result == "no identity signal contributing"

    def test_empty_dict(self):
        result = build_identity_description({})
        assert result == "no identity signal contributing"


# ── build_chain_user_prompt ───────────────────────────────────────────────────

class TestBuildChainUserPrompt:
    def _make_ctx(self, **overrides) -> dict:
        base = {
            "scenario_type": "data exfiltration",
            "attack_chain_description": "Initial Access → Exfiltration",
            "entry_technique_description": "phishing",
            "resource_name": "prod-s3-bucket",
            "resource_type": "S3 Bucket",
            "data_classification": "PII",
            "blast_radius_score": 72,
            "affected_resource_count": 15,
            "estimated_impact_display": "~$500,000",
            "framework_list": "PCI-DSS, HIPAA",
        }
        base.update(overrides)
        return base

    def test_renders_all_fields(self):
        ctx = self._make_ctx()
        prompt = build_chain_user_prompt(ctx)
        assert "data exfiltration" in prompt
        assert "prod-s3-bucket" in prompt
        assert "PCI-DSS" in prompt
        assert "72/100" in prompt

    def test_missing_fields_use_fallbacks(self):
        # Empty context should not raise KeyError
        prompt = build_chain_user_prompt({})
        assert "threat scenario" in prompt
        assert "cloud resource" in prompt


# ── build_stakes_user_prompt ──────────────────────────────────────────────────

class TestBuildStakesUserPrompt:
    def _make_ctx(self, **overrides) -> dict:
        base = {
            "resource_name": "prod-rds",
            "resource_type": "RDS Instance",
            "region": "us-east-1",
            "attack_chain_description": "SQL Injection → Data Dump",
            "data_classification": "PHI",
            "estimated_record_count": "2 million",
            "blast_radius_score": 85,
            "affected_resource_count": 30,
            "framework_list": "HIPAA, SOC 2",
            "identity_description": "admin IAM role (db-admin)",
        }
        base.update(overrides)
        return base

    def test_renders_chain_as_opening(self):
        ctx = self._make_ctx()
        chain = "If this scenario executes, attackers could breach your database."
        prompt = build_stakes_user_prompt(ctx, chain)
        assert chain in prompt

    def test_renders_region(self):
        ctx = self._make_ctx()
        prompt = build_stakes_user_prompt(ctx, "chain sentence")
        assert "us-east-1" in prompt

    def test_missing_fields_fallback(self):
        prompt = build_stakes_user_prompt({}, "chain")
        assert "cloud resource" in prompt
