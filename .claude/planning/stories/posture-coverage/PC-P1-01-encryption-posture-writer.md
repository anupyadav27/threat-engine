# Story PC-P1-01: Encryption Engine — Write Posture Signals to resource_security_posture

## Status: done

## Metadata
- **Phase**: P1 — Tier A (immediately implementable, data available)
- **Sprint**: Posture Coverage Enhancement
- **Points**: 3
- **Priority**: P1
- **Depends on**: AP-P0-01 (posture table exists), AP-P0-02 (posture_writer utility)
- **Blocks**: PC-P1-07 (composite flags need encryption signals), PC-P3-02 (risk Monte Carlo needs cert_days_remaining)
- **RACI**: R=DEV A=DL C=SA I=PO,QA
- **Security Gate**: bmad-security-reviewer — new cross-DB write path from encryption engine to inventory DB

## Gap Being Closed

**Current state:** The `resource_security_posture` table has 6 encryption-owned columns (`is_encrypted_at_rest`, `is_encrypted_in_transit`, `has_kms_managed_key`, `has_valid_certificate`, `cert_days_remaining`, `tls_version`) — but the encryption engine has NO `posture_signals.py` writer. These columns are always `FALSE`/`0` for every resource.

**Impact of gap:** The risk engine's +10 exposure boost for `cert_days_remaining < 30` never fires. The attack-path engine cannot identify unencrypted resources as preferred traversal targets. Crown jewel classifier cannot check `is_encrypted_at_rest` to flag unprotected data stores.

**Why Tier A:** All required data is in `encryption_findings` table today. No new external API calls needed.

## Data Sources (what the writer queries)

```
threat_engine_encryption DB → encryption_findings table
  Fields used:
    rule_id         → pattern match for encryption type (at_rest / in_transit / kms / tls / cert)
    status          → PASS/FAIL
    resource_uid    → join key
    resource_type   → passed through
    finding_data    → JSONB: {cert_days_remaining, tls_version, key_id}
```

## Signals to Write (column ownership)

| Column | Source Logic |
|--------|-------------|
| `is_encrypted_at_rest` | `status=PASS` for rules matching `at_rest\|sse\|encryption_enabled\|encrypted` |
| `is_encrypted_in_transit` | `status=PASS` for rules matching `in_transit\|tls\|https\|ssl` |
| `has_kms_managed_key` | `status=PASS` for rules matching `kms\|cmk\|customer_managed` |
| `has_valid_certificate` | `status=PASS` for rules matching `certificate\|acm\|cert` AND cert not expired |
| `cert_days_remaining` | `finding_data->>'cert_days_remaining'` cast to INT; default 0 |
| `tls_version` | `finding_data->>'tls_version'`; e.g. `"TLSv1.3"` |

**Aggregation rule:** Per `resource_uid`, take `bool_or()` for boolean signals (any PASS = True for positive signals; any FAIL = True for negative detection). Take `MAX()` for `cert_days_remaining`. Take `MAX()` for `tls_version` (TLSv1.3 > TLSv1.2 > TLSv1.0).

## Implementation

**New file:** `engines/encryption-security/encryption_security_engine/posture_signals.py`

Follow the exact pattern of `engines/iam/iam_engine/posture_signals.py`:
- Function: `write_encryption_posture_signals(scan_run_id, tenant_id, account_id, provider) -> int`
- Inner: `_aggregate_encryption_signals()` → queries encryption DB
- Inner: `_batch_upsert()` → calls `upsert_posture_signals()` in batches of 500
- Non-fatal: wrap in `try/except`, log warning, return 0 on error

**Wire into scan:** At the end of `engines/encryption-security/run_scan.py`, after findings are committed:
```python
from encryption_security_engine.posture_signals import write_encryption_posture_signals
write_encryption_posture_signals(scan_run_id, tenant_id, account_id, provider)
```

**DB connection:** Use `get_encryption_conn()` from `engine_common.db_connections`. Write to inventory DB via `get_inventory_conn()`.

## Acceptance Criteria

- [ ] AC-1: After encryption engine scan, `resource_security_posture` rows exist for every resource in `encryption_findings` for the same `scan_run_id`
- [ ] AC-2: `is_encrypted_at_rest=TRUE` for S3 buckets with SSE-KMS enabled (verify against known test resource)
- [ ] AC-3: `cert_days_remaining` is a non-zero integer for ACM certificate resources
- [ ] AC-4: `has_valid_certificate=FALSE` and `cert_days_remaining=0` for expired certificates (status=FAIL)
- [ ] AC-5: Writer does NOT overwrite IAM, network, datasec, or CDR columns — verify via `SELECT is_internet_exposed, is_encrypted_at_rest FROM resource_security_posture` after both engines run
- [ ] AC-6: posture write is non-fatal — if inventory DB is unreachable, encryption engine scan still completes and logs a WARNING
- [ ] AC-7: New image built: `yadavanup84/engine-encryption:v-encryption-posture1`

## MITRE ATT&CK
| Technique | How addressed |
|-----------|--------------|
| T1552.005 | Cloud Instance Metadata API — `is_encrypted_at_rest=FALSE` flags unprotected secrets storage |
| T1485 | Data Destruction — `has_kms_managed_key` tracks whether backup encryption key is customer-controlled |

## Definition of Done
- [ ] `posture_signals.py` written and unit tested
- [ ] `run_scan.py` wired to call writer after findings commit
- [ ] Integration test: scan → posture rows populated for encryption columns
- [ ] New image built and deployed to EKS
- [ ] Post-deploy: `SELECT COUNT(*) FROM resource_security_posture WHERE is_encrypted_at_rest=TRUE` returns > 0 for a real scan
