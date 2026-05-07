"""Local test harness for container-security engine mappers.

Validates build_container_inventory across EKS / ECS / ECR / Lambda
fixtures with no DB / network.

  python3 tests/engine_mappers/test_container_security_mappers.py
  python3 -m pytest tests/engine_mappers/test_container_security_mappers.py -v
"""
from __future__ import annotations

import json
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "engines" / "container-security"))

if "engine_common" not in sys.modules:
    fake = types.ModuleType("engine_common")
    sys.modules["engine_common"] = fake
    sys.modules["engine_common.category_loader"] = types.ModuleType("engine_common.category_loader")
    sys.modules["engine_common.db_connections"] = types.ModuleType("engine_common.db_connections")

from container_security_engine.analyzer.inventory_builder import build_container_inventory  # noqa: E402

FIXTURE_DIR = ROOT / "tests" / "dcat_fixtures"


def _load(name):
    with (FIXTURE_DIR / name).open() as fh:
        return json.load(fh)


def _by_uid(inv, uid):
    matches = [e for e in inv if e["resource_uid"] == uid]
    assert matches, f"no entry for {uid}"
    return matches[0]


def test_container_inventory_full_population():
    rows = _load("aws_eks_describe_cluster.json")
    inv = build_container_inventory(rows, [])
    assert len(inv) == 4, f"expected 4 container resources, got {len(inv)}"

    eks = _by_uid(inv, "arn:aws:eks:us-east-1:111:cluster/prod-eks")
    assert eks["container_service"] == "eks"
    assert eks["k8s_version"] == "1.28"
    assert eks["platform_version"] == "eks.5"
    assert eks["endpoint_public"] is False
    assert eks["encryption_enabled"] is True
    assert eks["logging_enabled"] is True
    assert eks["vpc_id"] == "vpc-1"
    assert eks["security_groups"] == ["sg-1"]

    ecs = _by_uid(inv, "arn:aws:ecs:us-east-1:111:cluster/web-cluster")
    assert ecs["container_service"] == "ecs"
    assert ecs["logging_enabled"] is True  # containerInsights enabled
    assert "FARGATE" in ecs["capacity_providers"]

    ecr = _by_uid(inv, "arn:aws:ecr:us-east-1:111:repository/app-images")
    assert ecr["container_service"] == "ecr"
    assert ecr["image_scan_on_push"] is True
    assert ecr["image_tag_mutability"] == "IMMUTABLE"

    lam = _by_uid(inv, "arn:aws:lambda:us-east-1:111:function:my-fn")
    assert lam["container_service"] == "lambda"
    assert lam["runtime"] == "python3.11"
    assert lam["memory_size"] == 512
    assert lam["encryption_enabled"] is True
    assert lam["tracing_enabled"] is True
    assert lam["endpoint_public"] is False
    print("✓ container inventory full-population passes")


def test_container_inventory_check_findings_skipped_when_not_db_rule():
    """Findings whose rule_id isn't recognized must not crash; with empty
    findings the rule_categorizer lazy import path stays cold."""
    rows = _load("aws_eks_describe_cluster.json")
    inv = build_container_inventory(rows, [])
    for e in inv:
        assert e["check_pass_count"] == 0
        assert e["check_fail_count"] == 0
        assert e["check_total"] == 0
    print("✓ container inventory zero-finding default counters")


def test_container_inventory_arrival_order_independence():
    rows = _load("aws_eks_describe_cluster.json")
    a = build_container_inventory(rows, [])
    b = build_container_inventory(list(reversed(rows)), [])
    set_a = {(e["resource_uid"], e["container_service"]) for e in a}
    set_b = {(e["resource_uid"], e["container_service"]) for e in b}
    assert set_a == set_b
    print("✓ container inventory order-independent")


if __name__ == "__main__":
    tests = [
        test_container_inventory_full_population,
        test_container_inventory_check_findings_skipped_when_not_db_rule,
        test_container_inventory_arrival_order_independence,
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
