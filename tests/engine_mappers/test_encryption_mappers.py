"""Local test harness for encryption engine mappers.

Validates that key/cert/secret inventory builders produce expected output
shapes from canonical discovery_findings fixtures — without K8s, RDS, or
any deploy. Run before pushing engine code changes.

  python3 -m pytest tests/engine_mappers/test_encryption_mappers.py -v

Or as a plain script:
  python3 tests/engine_mappers/test_encryption_mappers.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "engines" / "encryption-security"))

from encryption_security_engine.analyzer.key_inventory_builder import build_key_inventory  # noqa: E402
from encryption_security_engine.analyzer.cert_inventory_builder import build_cert_inventory  # noqa: E402
from encryption_security_engine.analyzer.secrets_inventory_builder import build_secrets_inventory  # noqa: E402

FIXTURE_DIR = ROOT / "tests" / "dcat_fixtures"


def _load(name: str) -> list:
    with (FIXTURE_DIR / name).open() as fh:
        return json.load(fh)


# ── KMS ──────────────────────────────────────────────────────────────


def test_kms_inventory_full_field_population():
    """Every detail field from describe_key + rotation must reach the entry,
    regardless of source-row arrival order. Regression for Bug 5."""
    rows = _load("aws_kms_describe_key.json")
    inv = build_key_inventory(rows, [])
    assert len(inv) == 1, f"expected 1 deduped key, got {len(inv)}"
    entry = inv[0]
    assert entry["key_arn"] == "arn:aws:kms:us-east-1:111:key/key-1"
    assert entry["key_id"] == "key-1"
    assert entry["key_state"] == "Enabled"
    assert entry["key_spec"] == "SYMMETRIC_DEFAULT"
    assert entry["key_usage"] == "ENCRYPT_DECRYPT"
    assert entry["origin"] == "AWS_KMS"
    assert entry["enabled"] is True
    assert entry["multi_region"] is False
    assert entry["key_manager"] == "CUSTOMER"
    assert entry["encryption_algorithms"] == ["SYMMETRIC_DEFAULT"]
    assert entry["rotation_enabled"] is True
    assert entry["rotation_interval_days"] == 365
    assert entry["creation_date"] is not None
    # policy was provided — principals should be extracted
    assert isinstance(entry.get("key_policy_principals"), list)
    print("✓ KMS full-field population passes")


def test_kms_inventory_sparse_first_then_rich():
    """Reverse order: list_keys (sparse) lands first in cert_map, describe_key
    (rich) merges later. Without the Bug 5 fix, KeySpec/KeyUsage stay None."""
    rows = _load("aws_kms_describe_key.json")
    # Force sparse-first ordering
    rows.sort(key=lambda r: 0 if r["discovery_id"] == "aws.kms.list_keys" else 1)
    inv = build_key_inventory(rows, [])
    assert len(inv) == 1
    e = inv[0]
    assert e["key_spec"] == "SYMMETRIC_DEFAULT", f"key_spec dropped — got {e['key_spec']}"
    assert e["key_usage"] == "ENCRYPT_DECRYPT", f"key_usage dropped — got {e['key_usage']}"
    print("✓ KMS sparse-first merge order passes")


def test_kms_inventory_rich_first_then_sparse():
    """Opposite order: describe_key first, list_keys later — the merge must not
    overwrite rich fields with None."""
    rows = _load("aws_kms_describe_key.json")
    rows.sort(key=lambda r: 0 if r["discovery_id"] == "aws.kms.describe_key" else 1)
    inv = build_key_inventory(rows, [])
    assert len(inv) == 1
    e = inv[0]
    assert e["key_spec"] == "SYMMETRIC_DEFAULT"
    assert e["key_state"] == "Enabled"
    print("✓ KMS rich-first merge order passes")


# ── ACM ──────────────────────────────────────────────────────────────


def test_acm_filters_account_configuration():
    """Bug from this session: get_account_configuration rows leaked into
    cert_inventory. Must be filtered out by resource_type or by the
    arn:aws:acm: prefix guard."""
    rows = _load("aws_acm_describe_certificate.json")
    inv = build_cert_inventory(rows, [])
    assert len(inv) == 1, (
        f"account_configuration rows leaking into certs — got {len(inv)} "
        f"entries with arns: {[c.get('cert_arn') for c in inv]}"
    )
    e = inv[0]
    assert e["cert_arn"] == "arn:aws:acm:us-east-1:111:certificate/cert-1"
    assert e["domain_name"] == "example.com"
    assert e["cert_status"] == "ISSUED"
    assert e["cert_type"] == "AMAZON_ISSUED"
    assert e["key_algorithm"] == "RSA-2048"
    assert e["issuer"] == "Amazon"
    assert e["serial_number"] == "0a:0b:0c"
    assert e["not_before"] is not None
    assert e["not_after"] is not None
    print("✓ ACM filters account_configuration + full field merge")


def test_acm_sparse_first_then_rich():
    """list_certificates (sparse) first → describe_certificate (rich) second:
    rich fields must reach the entry via _merge_cert_emitted."""
    rows = _load("aws_acm_describe_certificate.json")
    rows.sort(key=lambda r: 0 if r["discovery_id"] == "aws.acm.list_certificates" else 1)
    inv = build_cert_inventory(rows, [])
    assert len(inv) == 1
    e = inv[0]
    assert e["cert_type"] == "AMAZON_ISSUED", f"cert_type dropped — {e['cert_type']}"
    assert e["key_algorithm"] == "RSA-2048", f"key_algorithm dropped — {e['key_algorithm']}"
    assert e["not_after"] is not None, "not_after dropped"
    print("✓ ACM sparse-first merge order passes")


# ── Secrets Manager ──────────────────────────────────────────────────


def test_secretsmanager_full_population():
    rows = _load("aws_secretsmanager_list_secrets.json")
    inv = build_secrets_inventory(rows)
    assert len(inv) == 1
    e = inv[0]
    assert e["secret_arn"] == "arn:aws:secretsmanager:us-east-1:111:secret:foo-AbCdEf"
    assert e["secret_name"] == "foo"
    assert e["kms_key_id"] == "alias/aws/secretsmanager"
    assert e["rotation_enabled"] is True
    assert e["rotation_interval_days"] == 30
    print("✓ Secrets Manager full-field merge passes")


# ── Runner ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        test_kms_inventory_full_field_population,
        test_kms_inventory_sparse_first_then_rich,
        test_kms_inventory_rich_first_then_sparse,
        test_acm_filters_account_configuration,
        test_acm_sparse_first_then_rich,
        test_secretsmanager_full_population,
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
