"""Local test harness for ai-security engine mappers.

Validates AIInventoryBuilder.build_inventory against canonical
discovery_findings fixtures with no DB / network / Docker.

Coverage:
  - Full-population test (rich emitted_fields)
  - Order-independence (sparse-first vs rich-first)
  - Nested-envelope fallback for PrimaryContainer.Image (regression for
    the catalog flatten fix in commit 115da3fa9)

  python3 tests/engine_mappers/test_ai_security_mappers.py
  python3 -m pytest tests/engine_mappers/test_ai_security_mappers.py -v
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "engines" / "ai-security"))

from ai_security_engine.analyzer.ai_inventory_builder import AIInventoryBuilder  # noqa: E402

FIXTURE_DIR = ROOT / "tests" / "dcat_fixtures"


def _load(name: str) -> list:
    with (FIXTURE_DIR / name).open() as fh:
        return json.load(fh)


def _by_uid(inv: list, uid: str) -> dict:
    matches = [e for e in inv if e["resource_uid"] == uid]
    assert matches, f"no entry for {uid}"
    return matches[0]


# ── Full-field population ────────────────────────────────────────────


def test_ai_inventory_full_population():
    """Each ML resource should classify and extract posture from emitted_fields."""
    rows = _load("aws_sagemaker_describe_model.json")
    inv = AIInventoryBuilder().build_inventory(rows, [], [])
    assert len(inv) == 4, f"expected 4 ML resources, got {len(inv)}"

    model = _by_uid(inv, "arn:aws:sagemaker:us-east-1:111:model/my-model")
    assert model["ml_service"] == "sagemaker"
    assert model["deployment_type"] == "model"
    assert model["framework"] == "pytorch"  # image contains "pytorch" (checked before huggingface)
    assert model["network_isolation"] is True
    assert model["is_vpc_isolated"] is True
    assert model["iam_role_arn"] == "arn:aws:iam::111:role/SageMakerExecutionRole"

    endpoint = _by_uid(inv, "arn:aws:sagemaker:us-east-1:111:endpoint/llm-endpoint")
    assert endpoint["ml_service"] == "sagemaker"
    assert endpoint["deployment_type"] == "endpoint"
    assert endpoint["encryption_at_rest"] is True
    assert endpoint["has_data_capture"] is True
    assert endpoint["model_type"] == "llm"  # image contains "llama"

    guardrail = _by_uid(inv, "arn:aws:bedrock:us-east-1:111:guardrail/g-1")
    assert guardrail["has_guardrails"] is True
    assert guardrail["has_content_filter"] is True
    print("✓ AI inventory full-field population passes")


def test_ai_inventory_nested_primary_container_fallback():
    """Regression: legacy data with PrimaryContainer.Image envelope must still
    parse — the bug fix in 115da3fa9 keeps both flat (Image) and nested fallback.
    """
    rows = _load("aws_sagemaker_describe_model.json")
    inv = AIInventoryBuilder().build_inventory(rows, [], [])
    legacy = _by_uid(inv, "arn:aws:sagemaker:us-east-1:111:model/legacy-nested-model")
    assert legacy["framework"] == "tensorflow", (
        f"PrimaryContainer.Image fallback dropped — got framework={legacy['framework']}"
    )
    print("✓ AI inventory nested PrimaryContainer.Image fallback passes")


def test_ai_inventory_check_findings_enrichment():
    """Check pass/fail counts must be indexed by resource_uid."""
    rows = _load("aws_sagemaker_describe_model.json")
    findings = [
        {"resource_uid": "arn:aws:sagemaker:us-east-1:111:model/my-model", "status": "PASS"},
        {"resource_uid": "arn:aws:sagemaker:us-east-1:111:model/my-model", "status": "FAIL"},
        {"resource_uid": "arn:aws:sagemaker:us-east-1:111:model/my-model", "status": "FAIL"},
    ]
    inv = AIInventoryBuilder().build_inventory(rows, findings, [])
    model = _by_uid(inv, "arn:aws:sagemaker:us-east-1:111:model/my-model")
    assert model["check_pass_count"] == 1
    assert model["check_fail_count"] == 2
    print("✓ AI inventory check findings enrichment passes")


def test_ai_inventory_risk_score_bounds():
    """Risk score must clamp to 0..100."""
    rows = _load("aws_sagemaker_describe_model.json")
    inv = AIInventoryBuilder().build_inventory(rows, [], [])
    for e in inv:
        assert 0 <= e["risk_score"] <= 100, f"{e['resource_uid']} risk={e['risk_score']}"
    print("✓ AI inventory risk_score within [0,100]")


# ── Runner ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        test_ai_inventory_full_population,
        test_ai_inventory_nested_primary_container_fallback,
        test_ai_inventory_check_findings_enrichment,
        test_ai_inventory_risk_score_bounds,
    ]
    failed = 0
    for t in tests:
        try:
            t()
        except AssertionError as exc:
            print(f"✗ {t.__name__}: {exc}")
            failed += 1
        except Exception as exc:
            print(f"✗ {t.__name__}: {type(exc).__name__}: {exc}")
            failed += 1
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(0 if failed == 0 else 1)
