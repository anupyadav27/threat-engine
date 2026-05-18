# Story SF-P0-02: Shared security_findings_writer Utility

## Status: done

## Metadata
- **Phase**: P0 — Foundation
- **Epic**: Security Findings Unified Layer (sub-project of Attack Path Engine Epic)
- **Points**: 3
- **Priority**: P0
- **Depends on**: SF-P0-01 (table must exist)
- **Blocks**: SF-P1-01, SF-P1-02 (engine writers import this utility)
- **RACI**: R=DEV A=DL C=SA,SR I=PO,QA
- **Security Gate**: bmad-security-reviewer mandatory — this utility is called by 7 engines; any bug here affects all of them.

## User Story

As an engine developer, I want a shared `security_findings_writer.py` utility in `engine_common` so that I can upsert findings into `security_findings` with a single function call, without re-implementing batch logic or ON CONFLICT handling in every engine.

## Context

This is the same pattern as `posture_writer.py` introduced in AP-P0-02. The two utilities are intentionally separate because:
- `posture_writer` is called once per resource per scan (aggregate signals — 1 row per resource)
- `security_findings_writer` is called once per individual finding (violation rows — N per resource)

Different calling patterns, different ON CONFLICT semantics, different column sets.

The utility is placed in `shared/common/engine_common/` so that all engine Docker images include it automatically via `COPY shared/common /app/engine_common`.

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance  [ ] Design  [x] Implementation  [x] Verification  [ ] Operations

**NIST CSF 2.0 Function(s)**
- [ ] GV  [x] ID  [x] PR  [ ] DE  [ ] RS  [ ] RC
PR.DS-1 (data integrity: batch + transaction), PR.DS-2 (parameterized queries — no string interpolation)

**CSA CCM v4 Domain(s)**
- DSP-07, IVS-01, SEF-01

## Threat Model

### STRIDE
| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Tampering | upsert | Engine writes rows with tenant_id from resource metadata instead of scan auth parameter | tenant_id passed explicitly by caller from scan auth context — utility never infers it from row content |
| Injection | detail JSONB | Engine builds detail with user-controlled values in f-string SQL | All values passed via %s parameterized placeholders — no f-string interpolation in any query |
| DoS | no batching | Engine calls upsert 100K times individually | Utility enforces batching: executemany in chunks of batch_size (default 500) |

## Acceptance Criteria

### Functional
- [ ] AC-1: File `shared/common/engine_common/security_findings_writer.py` created
- [ ] AC-2: `FindingRow` TypedDict defined with all non-auto-filled columns: `source_engine`, `source_finding_id`, `resource_uid`, `account_id`, `provider`, `resource_type`, `finding_type`, `severity`, `rule_id`, `title`, `description`, `epss_score`, `cvss_score`, `in_kev`, `mitre_technique_id`, `mitre_tactic`, `detail`, `status`, `first_seen_at`
- [ ] AC-3: `upsert_findings(conn, findings, source_engine, tenant_id, scan_run_id, batch_size=500)` function implemented
- [ ] AC-4: Upsert uses `ON CONFLICT (source_engine, source_finding_id, tenant_id) DO UPDATE SET last_seen_at=NOW(), scan_run_id=EXCLUDED.scan_run_id, severity=EXCLUDED.severity, status=EXCLUDED.status, detail=EXCLUDED.detail, updated_at=NOW()` — never updates `first_seen_at`
- [ ] AC-5: Batching: splits `findings` into chunks of `batch_size` and calls `executemany` per chunk; commits per chunk
- [ ] AC-6: Returns total count of rows upserted
- [ ] AC-7: `tenant_id` and `scan_run_id` are injected by the caller — never read from individual FindingRow (prevents engine accidentally writing wrong tenant)
- [ ] AC-8: `source_engine` validated against allowed values: `{'check', 'iam', 'network', 'datasec', 'vuln', 'cdr', 'container'}` — raises ValueError if unknown. `'container'` covers K8s RBAC violations, privileged workload findings, and image vulnerabilities from the container-security engine (all CSPs: EKS/AKS/GKE/OKE + self-managed K8s)
- [ ] AC-9: All SQL queries use `%s` parameterized placeholders — no f-string or `.format()` interpolation anywhere in the file
- [ ] AC-10: `detail` JSONB serialized via `json.dumps()` before passing to psycopg2 (psycopg2 does not auto-serialize Python dicts to JSONB in executemany)

### Security (must pass bmad-security-reviewer)
- [ ] AC-11: No DEV_BYPASS_AUTH or environment-variable-based auth skipping in utility
- [ ] AC-12: No logging of `detail` field contents (may contain security-sensitive raw payloads)
- [ ] AC-13: `source_engine` allowlist enforced (AC-8) — prevents an engine accidentally tagging rows as a different engine

### Testing
- [ ] AC-14: Unit test: `test_upsert_findings_batches_correctly` — 1100 rows → 3 executemany calls (500+500+100)
- [ ] AC-15: Unit test: `test_upsert_findings_never_updates_first_seen_at` — ON CONFLICT row retains original first_seen_at
- [ ] AC-16: Unit test: `test_upsert_findings_rejects_unknown_engine` — raises ValueError for source_engine='unknown'

## Technical Notes

```python
from typing import TypedDict, Optional
import json
import logging

logger = logging.getLogger(__name__)

_ALLOWED_ENGINES = frozenset({'check', 'iam', 'network', 'datasec', 'vuln', 'cdr', 'container'})

class FindingRow(TypedDict, total=False):
    source_finding_id: str        # required
    resource_uid: str             # required
    finding_type: str             # required: misconfig|cve|iam_violation|cdr_event|data_risk|network_exposure|k8s_violation|container_risk
    severity: str                 # required: critical|high|medium|low
    title: str                    # required
    account_id: Optional[str]
    provider: Optional[str]
    resource_type: Optional[str]
    rule_id: Optional[str]
    description: Optional[str]
    epss_score: Optional[float]
    cvss_score: Optional[float]
    in_kev: bool                  # default False
    mitre_technique_id: Optional[str]
    mitre_tactic: Optional[str]
    detail: Optional[dict]        # engine-specific payload
    status: str                   # default 'open'
    first_seen_at: Optional[str]  # ISO timestamp; None = NOW()

_UPSERT_SQL = """
INSERT INTO security_findings (
    source_engine, source_finding_id, resource_uid, scan_run_id, tenant_id,
    account_id, provider, resource_type,
    finding_type, severity, rule_id, title, description,
    epss_score, cvss_score, in_kev, mitre_technique_id, mitre_tactic,
    detail, status, first_seen_at
) VALUES (
    %s, %s, %s, %s, %s,
    %s, %s, %s,
    %s, %s, %s, %s, %s,
    %s, %s, %s, %s, %s,
    %s, %s, %s
)
ON CONFLICT (source_engine, source_finding_id, tenant_id) DO UPDATE SET
    last_seen_at  = NOW(),
    scan_run_id   = EXCLUDED.scan_run_id,
    severity      = EXCLUDED.severity,
    status        = EXCLUDED.status,
    detail        = EXCLUDED.detail,
    updated_at    = NOW()
"""
```

**Note on `first_seen_at`**: ON CONFLICT never overwrites it. The INSERT sets it to NOW() on first write; subsequent upserts only update `last_seen_at`.

## Key Files
- `/Users/apple/Desktop/threat-engine/shared/common/engine_common/security_findings_writer.py` (create new)
- `/Users/apple/Desktop/threat-engine/tests/unit/test_security_findings_writer.py` (create new)

## Definition of Done
- [ ] `security_findings_writer.py` committed to `shared/common/engine_common/`
- [ ] Unit tests pass (3 tests from AC-14/15/16)
- [ ] `python3 -c "from engine_common.security_findings_writer import upsert_findings, FindingRow; print('OK')"` runs without error inside any engine pod
- [ ] bmad-security-reviewer: no BLOCKERS
