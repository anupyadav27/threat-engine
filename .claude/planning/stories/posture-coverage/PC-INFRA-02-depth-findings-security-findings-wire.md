# Story PC-INFRA-02: Wire PC-DEPTH New Finding Types to security_findings Table

## Status: done

## Metadata
- **Phase**: Infrastructure Track
- **Sprint**: Posture Coverage Enhancement
- **Points**: 2
- **Priority**: P2 — depth gap findings (escalation paths, cross-account S3, ECR, CDR sequences) must flow to security_findings so the UI findings page shows them
- **Depends on**: SF-P0-02 (shared findings writer exists), SF-P1-01 (IAM→security_findings pattern established), PC-DEPTH-01/04/05/06 (new finding types produced)
- **RACI**: R=DEV A=DL C=SA I=PO,QA
- **Security Gate**: bmad-security-reviewer

## User Story

As a security analyst, I want the new depth-analysis findings (IAM privilege escalation paths, DataSec cross-account S3 access, Container ECR cross-account pulls, CDR exfiltration sequences) to appear in the unified security findings feed (`security_findings` table) so that the Findings page and asset investigation panels surface them without requiring analysts to know which engine produced each finding.

## Context

### Existing Wiring (do NOT duplicate)

| Engine | Story | Finding types already wired |
|--------|-------|---------------------------|
| check + IAM | SF-P1-01 | `misconfig` (check FAIL rules), `iam_violation` (IAM direct admin/MFA/stale) |
| vuln + CDR + datasec | SF-P1-02 | `cve` (vuln engine), `cdr_event` (CDR correlation rules), `data_risk` (datasec classification) |
| container | SF-P1-03 | `misconfig` (container check rules + pod security context) |

### New finding types from PC-DEPTH stories (not yet wired)

| PC-DEPTH story | New rule_id prefix | Target `finding_type` | Source engine table |
|---------------|-------------------|----------------------|-------------------|
| PC-DEPTH-01 | `aws.iam.role.privilege_escalation_*` | `iam_violation` | `iam_findings` |
| PC-DEPTH-04 | `aws.s3.bucket.no_cross_account_write_access`, `aws.lakeformation.*` | `data_risk` | `datasec_findings` |
| PC-DEPTH-05 | `aws.ecr.repository.*`, `aws.eks.node_group.*`, `azure.aks.cluster.*` | `misconfig` | `container_sec_findings` |
| PC-DEPTH-06 | `aws.cdr.sequence.*` | `cdr_event` | `cdr_findings` |

### Why new stories are needed

SF-P1-01/02/03 wire findings by **rule_id prefix ranges** (e.g. `aws.iam.role.*`). The new PC-DEPTH finding rule_ids are new prefixes not covered by those ranges. The `security_findings` write-path in each engine's `run_scan.py` must be extended to include these new rule_id patterns.

---

## Implementation — Per Engine

### IAM Engine — extend `run_scan.py` security_findings write

PC-DEPTH-01 produces `iam_findings` rows with `rule_id LIKE 'aws.iam.role.privilege_escalation%'`. These are currently NOT written to `security_findings`.

**Extend** `engines/iam/run_scan.py` after the escalation detector runs:

```python
# Write escalation findings to security_findings (cross-engine table)
for finding in escalation_findings:
    security_finding = {
        "source_engine": "iam",
        "source_finding_id": finding["finding_id"],
        "tenant_id": tenant_id,
        "account_id": account_id,
        "resource_uid": finding["resource_uid"],
        "resource_type": finding["resource_type"],
        "finding_type": "iam_violation",
        "severity": finding["severity"],
        "title": f"Privilege escalation path: {finding['finding_data']['escalation_action']}",
        "description": finding["finding_data"].get("description", ""),
        "mitre_technique_id": "T1078.004",
        "detail": finding["finding_data"],
        "scan_run_id": scan_run_id,
        "first_seen_at": finding["first_seen_at"],
        "last_seen_at": finding["last_seen_at"],
    }
    write_to_security_findings(inv_conn, security_finding)
```

### DataSec Engine — extend `run_scan.py` security_findings write

PC-DEPTH-04 produces `datasec_findings` with `rule_id LIKE 'aws.s3.bucket.%cross_account%'` and `aws.lakeformation.*`. These are `data_risk` type.

**Extend** `engines/datasec/run_scan.py` to include these rule_ids in the existing security_findings write loop. Filter:
```python
CROSS_ACCOUNT_RULE_PREFIXES = [
    "aws.s3.bucket.no_cross_account",
    "aws.s3.bucket.cross_account",
    "aws.lakeformation.database.",
]
if any(finding["rule_id"].startswith(p) for p in CROSS_ACCOUNT_RULE_PREFIXES):
    write_to_security_findings(inv_conn, {..., "finding_type": "data_risk", ...})
```

### Container Engine — extend `run_scan.py` security_findings write

PC-DEPTH-05 produces `container_sec_findings` with `rule_id LIKE 'aws.ecr.%'`, `aws.eks.node_group.%`, and `azure.aks.cluster.%`. These are `misconfig` type.

**Extend** `engines/container-security/run_scan.py` to include ECR/EKS/AKS rule_ids in the security_findings write loop:
```python
DEPTH_CONTAINER_RULE_PREFIXES = [
    "aws.ecr.repository.",
    "aws.eks.node_group.",
    "azure.aks.cluster.",
]
```

### CDR Engine — extend `run_scan.py` security_findings write

PC-DEPTH-06 produces `cdr_findings` with `rule_id LIKE 'aws.cdr.sequence.%'`. These are `cdr_event` type but with higher severity than standard correlation rules.

**Extend** `engines/cdr/run_scan.py` after `SequenceDetector.detect()` to write sequence findings to `security_findings`. The existing CDR→security_findings write loop already handles `cdr_event` type; just ensure `rule_id LIKE 'aws.cdr.sequence.%'` is included in the query that feeds it.

---

## security_findings Table — No Schema Changes Required

Migration 025 created `security_findings` with:
- `finding_type` enum: `'misconfig'`, `'cve'`, `'iam_violation'`, `'cdr_event'`, `'data_risk'`, `'network_exposure'`
- `detail JSONB` — stores all engine-specific extra fields
- `mitre_technique_id VARCHAR` — directly set per finding
- UNIQUE constraint: `(source_engine, source_finding_id, tenant_id)` — prevents duplicates on re-scan

All new depth gap findings fit the existing enum values. **No DDL changes needed.**

---

## Acceptance Criteria

- [ ] AC-1: After IAM scan with escalation findings, `SELECT COUNT(*) FROM security_findings WHERE finding_type='iam_violation' AND source_engine='iam' AND title LIKE '%privilege_escalation%'` > 0
- [ ] AC-2: After DataSec scan with cross-account S3 findings, `SELECT COUNT(*) FROM security_findings WHERE finding_type='data_risk' AND source_engine='datasec'` > 0 (increment from pre-PC-DEPTH-04 baseline)
- [ ] AC-3: After Container scan with ECR findings, `SELECT COUNT(*) FROM security_findings WHERE source_engine='container' AND title LIKE '%ecr%'` > 0
- [ ] AC-4: After CDR scan with sequence findings, `SELECT COUNT(*) FROM security_findings WHERE finding_type='cdr_event' AND title LIKE '%sequence%'` > 0
- [ ] AC-5: `UNIQUE (source_engine, source_finding_id, tenant_id)` constraint prevents duplicates on re-scan — second scan of same account updates `last_seen_at` not creates duplicate row
- [ ] AC-6: Cross-tenant isolation: `SELECT DISTINCT tenant_id FROM security_findings` never shows findings from tenant B appearing under tenant A's session

## Definition of Done
- [ ] IAM `run_scan.py` writes escalation findings to `security_findings`
- [ ] DataSec `run_scan.py` writes cross-account S3 + LakeFormation findings to `security_findings`
- [ ] Container `run_scan.py` writes ECR/EKS/AKS depth findings to `security_findings`
- [ ] CDR `run_scan.py` writes sequence detection findings to `security_findings`
- [ ] Integration test: trigger a scan, verify all 4 new finding categories appear in `security_findings`