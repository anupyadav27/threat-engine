# Story SF-P1-01: Wire Check + IAM Engines → security_findings

## Status: done

## Metadata
- **Phase**: P1 — Engine Writers
- **Epic**: Security Findings Unified Layer (sub-project of Attack Path Engine Epic)
- **Points**: 5
- **Priority**: P0
- **Depends on**: SF-P0-01 (table exists), SF-P0-02 (writer utility exists)
- **Blocks**: SF-P2-01 (BFF needs data), SF-P3-01 (attack-path integration needs check+iam rows)
- **Runs alongside**: AP-P0-03 (which wires same engines for posture signals) — same scan hook point, additional write
- **RACI**: R=DEV A=DL C=SA,SR I=PO,QA
- **Security Gate**: bmad-security-reviewer mandatory — touches 2 engine codebases and their DB write paths.

## User Story

As the security_findings layer, I want the check engine to write every FAIL finding as a `misconfig` row and the IAM engine to write every violation as an `iam_violation` row into `security_findings` after their scan steps complete, so that cross-engine queries have misconfig and IAM data available by pipeline stage 5.

## Context

The check engine runs at pipeline stage 3 — earliest source of findings. The IAM engine runs at stage 5. Both write to security_findings at the END of their existing scan completion handler, AFTER writing to their own tables. This is the same hook point used in AP-P0-03 for posture signals.

**Critical distinction from AP-P0-03**: AP-P0-03 writes aggregate signals per resource (is_admin_role=true for IAM). This story writes individual violation rows (one row per rule that fired). The two writes are independent — both happen in the same scan handler, neither blocks the other.

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance  [ ] Design  [x] Implementation  [x] Verification  [ ] Operations

**NIST CSF 2.0 Function(s)**
- [ ] GV  [x] ID  [x] PR  [x] DE  [ ] RS  [ ] RC
DE.CM-1 (misconfig detections recorded), PR.AC-4 (IAM violations recorded)

**CSA CCM v4 Domain(s)**
- IVS-01 (check findings), IAM-09 (IAM findings), GRC-05 (audit trail)

## Threat Model

### STRIDE
| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Info Disclosure | check findings write | check engine writes tenant_id from resource metadata instead of scan auth | tenant_id passed from scan's auth parameter; AC-16 verifies this |
| DoS | bulk check findings | Large tenant has 50K FAIL findings; individual upserts blow DB | security_findings_writer batches in 500-row chunks (SF-P0-02 AC-5) |
| Tampering | IAM detail JSONB | IAM engine logs iam_detail (policy document) containing policy content | detail field sanitized: only rule_id, resource_uid, policy summary — no raw policy document in detail |

## Acceptance Criteria

### Functional — engine-check
- [ ] AC-1: At the end of the check engine's scan completion handler (`engines/check/*/run_scan.py` or equivalent), `upsert_findings()` is called for all FAIL findings from the current `scan_run_id`
- [ ] AC-2: Each FAIL finding maps to one FindingRow: `source_engine='check'`, `source_finding_id=check_findings.finding_id`, `finding_type='misconfig'`, `severity` from check_findings, `rule_id` from check_findings, `title` from rule_metadata.title, `detail={'resource_type': ..., 'region': ..., 'remediation': rule_metadata.remediation}`
- [ ] AC-3: PASS findings are NOT written to security_findings (only FAILs)
- [ ] AC-4: Write call is appended AFTER existing check_findings inserts — does not change existing check engine behavior
- [ ] AC-5: engine-check builds new image tagged `v-check-sf1`

### Functional — engine-iam
- [ ] AC-6: At the end of the IAM engine's scan completion handler, `upsert_findings()` is called for all IAM violations from the current `scan_run_id`
- [ ] AC-7: Each IAM violation maps to one FindingRow: `source_engine='iam'`, `source_finding_id=iam_findings.finding_id`, `finding_type='iam_violation'`, `severity` from iam_findings, `rule_id` from iam_findings.rule_id, `title` from iam_findings.title or rule_metadata, `mitre_technique_id` if available, `detail={'resource_uid': ..., 'account_id': ..., 'region': ...}` (NO raw policy document in detail)
- [ ] AC-8: Write call is appended AFTER existing iam_findings inserts — does not change existing IAM engine behavior
- [ ] AC-9: engine-iam builds new image tagged `v-iam-sf1`

### Integration
- [ ] AC-10: After a full pipeline scan, `SELECT COUNT(*) FROM security_findings WHERE source_engine='check' AND scan_run_id='<current>'` returns > 0
- [ ] AC-11: After a full pipeline scan, `SELECT COUNT(*) FROM security_findings WHERE source_engine='iam' AND scan_run_id='<current>'` returns > 0
- [ ] AC-12: `SELECT DISTINCT source_engine FROM security_findings WHERE tenant_id='<tenant>'` includes both 'check' and 'iam'
- [ ] AC-13: No existing engine findings tables altered — all changes additive

### Security (must pass bmad-security-reviewer)
- [ ] AC-14: `upsert_findings()` called with `tenant_id` from scan auth context — never from resource metadata
- [ ] AC-15: No DEV_BYPASS_AUTH in either engine change
- [ ] AC-16: IAM detail JSONB does NOT contain raw policy document or role ARN (those stay in iam_findings.finding_data — never copied to the shared security_findings table)
- [ ] AC-17: Check engine does NOT call `json.loads()` on JSONB fields from rule_metadata when building detail dict

## Technical Notes

**Import pattern** (engine_common available in all engine Docker images):
```python
from engine_common.security_findings_writer import upsert_findings, FindingRow
```

**Check engine — building FindingRow list:**
```python
# After check_findings inserts complete:
rows: list[FindingRow] = []
for f in fail_findings:
    rows.append(FindingRow(
        source_finding_id=f["finding_id"],
        resource_uid=f["resource_uid"],
        finding_type="misconfig",
        severity=f["severity"],
        rule_id=f["rule_id"],
        title=f.get("title") or rule_meta.get("title", f["rule_id"]),
        account_id=f.get("account_id"),
        provider=f.get("provider"),
        resource_type=f.get("resource_type"),
        detail={"region": f.get("region"), "remediation": rule_meta.get("remediation")},
    ))
upsert_findings(conn=inventory_conn, findings=rows,
                source_engine="check", tenant_id=tenant_id,
                scan_run_id=scan_run_id)
```

**Inventory DB connection**: check and IAM engines will need a connection to `threat_engine_inventory` DB. Add `INVENTORY_DB_HOST` / `INVENTORY_DB_USER` / `INVENTORY_DB_PASSWORD` / `INVENTORY_DB_NAME` to their K8s env from the existing `threat-engine-db-config` ConfigMap and `threat-engine-db-passwords` secret (these are already in the config — no new secrets needed).

**New image tags**:
- engine-check: `yadavanup84/engine-check-aws:v-check-sf1`
- engine-iam: `yadavanup84/engine-iam:v-iam-sf1`

## Key Files
- `/Users/apple/Desktop/threat-engine/engines/check/common/database/rule_reader.py` (check how findings are collected — read only)
- Check engine `run_scan.py` (modify — add security_findings write at end)
- IAM engine `run_scan.py` (modify — add security_findings write at end)
- `/Users/apple/Desktop/threat-engine/deployment/aws/eks/engines/engine-check.yaml` (update image tag)
- `/Users/apple/Desktop/threat-engine/deployment/aws/eks/engines/engine-iam.yaml` (update image tag — note: AP-P0-03 will have already set this to v-iam-posture1; this story bumps to v-iam-sf1)

## Definition of Done
- [ ] Both engine files modified and committed
- [ ] Both Docker images built and pushed (`v-check-sf1`, `v-iam-sf1`)
- [ ] Both K8s manifests updated
- [ ] kubectl rollout status clean for both
- [ ] kubectl logs show no ERROR in first 50 lines for both
- [ ] After scan: security_findings contains check + iam rows for current scan_run_id
- [ ] MEMORY.md production table updated for both changed image tags
- [ ] bmad-security-reviewer: no BLOCKERS