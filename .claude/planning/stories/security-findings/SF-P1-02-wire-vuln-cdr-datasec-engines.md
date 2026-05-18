# Story SF-P1-02: Wire Vuln + CDR + DataSec Engines → security_findings

## Status: done

## Metadata
- **Phase**: P1 — Engine Writers
- **Epic**: Security Findings Unified Layer (sub-project of Attack Path Engine Epic)
- **Points**: 5
- **Priority**: P0
- **Depends on**: SF-P0-01 (table exists), SF-P0-02 (writer utility exists)
- **Runs alongside**: AP-P0-03 (posture writes for same engines — same hook point, additional write)
- **Blocks**: SF-P2-01 (BFF needs CVE + CDR data), SF-P3-01 (attack-path node evidence needs CVE rows)
- **RACI**: R=DEV A=DL C=SA,SR I=PO,QA
- **Security Gate**: bmad-security-reviewer mandatory — CVE data contains EPSS/KEV signals; CDR events contain actor data (hash only — CP1-02).

## User Story

As the security_findings layer, I want the vulnerability, CDR, and datasec engines to each write their findings as normalized rows into `security_findings` after their scan steps complete, so that cross-engine CVE + behavioral + data risk queries are available from a single table by pipeline stage 6.5 (when attack-path runs).

## Context

These three engines run at pipeline stage 5 (parallel). Each writes to `security_findings` at the end of its existing scan handler, after writing to its own table.

**CDR-specific note**: CDR runs on an independent cron schedule, not tied to a main scan_run_id. For CDR security_findings writes, use the most recent `scan_run_id` from `scan_orchestration` for the matching tenant_id/account_id — same pattern as AP-P0-03 AC-10/AC-11. If no scan_run_id found, skip the write for that cron run.

**CP1-02 enforcement for CDR**: actor_principal is PII — NEVER write raw actor_principal to `security_findings.detail`. Only `actor_hash = sha256(actor_principal)` is allowed.

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance  [ ] Design  [x] Implementation  [x] Verification  [ ] Operations

**NIST CSF 2.0 Function(s)**
- [ ] GV  [x] ID  [x] PR  [x] DE  [ ] RS  [ ] RC
DE.CM-6 (CVE/KEV signals), DE.CM-1 (CDR behavioral detections), PR.DS-7 (data risk findings)

**CSA CCM v4 Domain(s)**
- IVS-01, DSP-07 (datasec), SEF-01 (CDR), TVM-09 (vulnerability)

## Threat Model

### STRIDE
| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Info Disclosure | CDR detail JSONB | Raw actor_principal (email/ARN) written to shared security_findings.detail | CP1-02 enforced: only actor_hash written; AC-16 verifies |
| Info Disclosure | CVE detail | EPSS/KEV signals could reveal exploitability intel | detail JSONB stripped for viewer role by BFF strip_sensitive_fields() |
| Tampering | CDR scan_run_id lookup | CDR cron picks wrong scan_run_id — writes to wrong scan context | lookup uses MAX(created_at) for matching tenant_id + account_id from scan_orchestration |
| DoS | vuln findings | Agent scan finds 10K CVEs across 500 resources | Batch upsert 500-row chunks (enforced by writer utility) |

## Acceptance Criteria

### Functional — engine-vuln
- [ ] AC-1: After vuln engine scan completes, `upsert_findings()` called for all CVE findings from current scan_run_id
- [ ] AC-2: Each CVE maps to one FindingRow: `source_engine='vuln'`, `source_finding_id=sha256(cve_id+"|"+resource_uid)[:32]`, `finding_type='cve'`, `severity` from CVSS/EPSS bucket, `title=f"{cve_id} — {cve_description[:100]}"`, `epss_score`, `cvss_score`, `in_kev`, `mitre_technique_id` if available, `detail={'package': ..., 'fixed_version': ..., 'affected_version': ...}`
- [ ] AC-3: Only exploitable CVEs written — filter where `cvss_score >= 4.0 OR epss_score >= 0.1 OR in_kev = true` (low-noise filter: informational CVEs skipped)
- [ ] AC-4: Write appended AFTER existing vuln table writes — no change to existing vuln behavior
- [ ] AC-5: engine-vuln builds new image tagged `v-vuln-sf1`

### Functional — engine-cdr
- [ ] AC-6: After each CDR cron detection batch completes, `upsert_findings()` called for resources where a CDR actor was observed
- [ ] AC-7: Each CDR event maps to one FindingRow: `source_engine='cdr'`, `source_finding_id=cdr_findings.detection_id`, `finding_type='cdr_event'`, `severity` from cdr_findings.severity, `title` from detection description, `mitre_technique_id`, `mitre_tactic`, `detail={'actor_hash': sha256(actor_principal), 'event_time': ..., 'event_type': ...}` — NO raw actor_principal in detail (CP1-02)
- [ ] AC-8: CDR engine resolves `scan_run_id` as: `SELECT scan_run_id FROM scan_orchestration WHERE tenant_id=$tid AND account_id=$aid ORDER BY created_at DESC LIMIT 1`. If no row found, skip security_findings write for this cron run.
- [ ] AC-9: engine-cdr builds new image tagged `v-cdr-sf1`

### Functional — engine-datasec
- [ ] AC-10: After datasec scan completes, `upsert_findings()` called for data risk findings
- [ ] AC-11: Each data risk maps to one FindingRow: `source_engine='datasec'`, `source_finding_id=datasec_findings.finding_id`, `finding_type='data_risk'`, `severity`, `title`, `rule_id`, `detail={'data_classification': ..., 'resource_type': ..., 'bucket_public': ...}` — NO raw data content
- [ ] AC-12: engine-datasec builds new image tagged `v-datasec-sf1`

### Integration
- [ ] AC-13: After full pipeline scan: `SELECT DISTINCT source_engine FROM security_findings WHERE tenant_id='<tenant>'` includes 'vuln', 'cdr', 'datasec'
- [ ] AC-14: `SELECT * FROM security_findings WHERE source_engine='vuln' AND in_kev=true AND tenant_id='<tenant>'` returns KEV CVEs
- [ ] AC-15: A CDR-observed resource has security_findings rows with finding_type='cdr_event' and detail NOT containing actor_principal

### Security (must pass bmad-security-reviewer)
- [ ] AC-16: CDR detail JSONB does NOT contain raw actor_principal — only actor_hash (CP1-02)
- [ ] AC-17: Vuln detail JSONB does NOT contain raw exploit code or PoC URLs
- [ ] AC-18: DataSec detail JSONB does NOT contain raw data samples or classified content
- [ ] AC-19: No DEV_BYPASS_AUTH in any of the 3 engine changes
- [ ] AC-20: CDR does NOT call `json.loads()` on JSONB fields from cdr_findings when reading actor data (JSONB is auto-deserialized by psycopg2)

## Technical Notes

**Vuln engine source_finding_id:**
```python
import hashlib
source_finding_id = hashlib.sha256(
    f"{cve_id}|{resource_uid}".encode()
).hexdigest()[:32]
```

**CDR scan_run_id lookup:**
```python
cur.execute("""
    SELECT scan_run_id FROM scan_orchestration
    WHERE tenant_id = %s AND account_id = %s
    ORDER BY created_at DESC LIMIT 1
""", (tenant_id, account_id))
row = cur.fetchone()
if not row:
    logger.info("No scan_run_id found for CDR posture write — skipping")
    return
scan_run_id = row[0]
```

**New image tags**:
- engine-vuln: `yadavanup84/engine-vulnerability:v-vuln-sf1`
- engine-cdr: `yadavanup84/engine-cdr:v-cdr-sf1`
- engine-datasec: `yadavanup84/engine-datasec:v-datasec-sf1`

**Inventory DB connection**: Same as SF-P1-01 — each engine needs `INVENTORY_DB_*` env vars added to K8s manifest (already in ConfigMap/secret).

## Key Files
- Vuln engine `run_scan.py` (modify — add security_findings write at end)
- CDR engine `cron_handler.py` (modify — add security_findings write after detection batch)
- DataSec engine `run_scan.py` (modify — add security_findings write at end)
- `deployment/aws/eks/engines/engine-vulnerability.yaml` (update image tag)
- `deployment/aws/eks/engines/engine-cdr.yaml` (update image tag)
- `deployment/aws/eks/engines/engine-datasec.yaml` (update image tag)

## Definition of Done
- [ ] All 3 engine files modified and committed
- [ ] All 3 Docker images built and pushed
- [ ] All 3 K8s manifests updated
- [ ] kubectl rollout status clean for all 3
- [ ] After scan + CDR cron: security_findings has vuln + cdr + datasec rows
- [ ] CDR rows verified: `SELECT detail FROM security_findings WHERE source_engine='cdr' LIMIT 1` — detail contains actor_hash, NOT actor_principal
- [ ] MEMORY.md updated for all 3 changed image tags
- [ ] bmad-security-reviewer: no BLOCKERS