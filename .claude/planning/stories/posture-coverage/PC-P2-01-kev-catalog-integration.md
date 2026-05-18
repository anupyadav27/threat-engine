# Story PC-P2-01: Vulnerability Engine — CISA KEV Catalog Integration

## Status: done

## Metadata
- **Phase**: P2 — Tier B (external data, freely available public API)
- **Sprint**: Posture Coverage Enhancement
- **Points**: 5
- **Priority**: P2
- **Depends on**: PC-P1-04 (vuln posture writer exists), PC-P0-01 (has_known_exploit column)
- **Blocks**: PC-P1-07 (exploitable_exposed_resource composite flag fires only after this)
- **RACI**: R=DEV A=DL C=SA I=PO,QA
- **Security Gate**: bmad-security-reviewer — new outbound HTTP to CISA API; SSRF risk assessment required

## Gap Being Closed

**Current state:** `has_known_exploit=FALSE` for all resources because the vuln engine has no way to distinguish CVEs in the CISA Known Exploited Vulnerabilities (KEV) catalog from regular CVEs. A CVE with `epss_score=0.97` that is actively used by ransomware groups is scored the same as a theoretical vulnerability.

**External data source:** CISA KEV catalog — `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- Free, public, no auth required
- Updated daily by CISA
- JSON array of CVE IDs with vendor, product, date added, and required action

## Implementation Plan

### 1. KEV Sync Job (new CronJob in K8s)

**New file:** `engines/vulnerability/kev_sync/sync_kev.py`

```python
# Fetches KEV JSON, upserts into kev_catalog table
# Runs daily at 02:00 UTC via K8s CronJob
```

**New migration:** `shared/database/migrations/025_kev_catalog.sql`
```sql
-- In threat_engine_vulnerability DB
CREATE TABLE IF NOT EXISTS kev_catalog (
    cve_id          VARCHAR(50)  PRIMARY KEY,
    vendor_project  VARCHAR(255),
    product         VARCHAR(255),
    vulnerability_name VARCHAR(512),
    date_added      DATE,
    required_action TEXT,
    due_date        DATE,
    known_ransomware BOOLEAN DEFAULT FALSE,
    synced_at       TIMESTAMPTZ DEFAULT NOW()
);
```

### 2. CVE Matching (update scan_vulnerabilities table)

**New migration column:** `ADD COLUMN IF NOT EXISTS kev_listed BOOLEAN NOT NULL DEFAULT FALSE`

During vulnerability scan, after SBOM/CVE matching, run:
```sql
UPDATE scan_vulnerabilities sv
SET kev_listed = TRUE
FROM kev_catalog kev
WHERE sv.cve_id = kev.cve_id
  AND sv.scan_run_id = %s;
```

### 3. Posture Writer Update (PC-P1-04 extension)

Update `write_vulnerability_posture_signals()` to use `kev_listed`:
```python
"has_known_exploit": bool(row.get("has_kev") or False)
# where has_kev = bool_or(kev_listed) in the GROUP BY query
```

### 4. K8s CronJob

**New file:** `deployment/aws/eks/engines/kev-sync-cronjob.yaml`
```yaml
schedule: "0 2 * * *"   # 02:00 UTC daily
```

## Security Considerations

- **SSRF risk:** The sync job fetches from a hardcoded CISA URL, not user-provided input. No SSRF vector. URL must be a constant, not configurable from environment or DB.
- **Network egress:** Requires outbound internet from the EKS pod. Verify security group allows outbound 443 to `www.cisa.gov`.
- **Data validation:** Validate the JSON response structure before upsert. Reject responses > 10MB (DoS protection).
- **Failure mode:** If CISA API is unreachable, keep existing `kev_catalog` data. Do NOT clear the table on fetch failure. Log WARNING and continue.

## Acceptance Criteria

- [ ] AC-1: `kev_catalog` table is populated after CronJob runs — verify `SELECT COUNT(*) FROM kev_catalog` > 1000 (current KEV has ~1200 entries)
- [ ] AC-2: `scan_vulnerabilities.kev_listed=TRUE` for CVEs that appear in `kev_catalog` (verify with a known KEV entry e.g. CVE-2021-44228 / Log4Shell)
- [ ] AC-3: `has_known_exploit=TRUE` in `resource_security_posture` for resources with KEV-listed CVEs
- [ ] AC-4: KEV sync failure (CISA unreachable) does NOT affect vulnerability scan — existing `kev_catalog` data is preserved
- [ ] AC-5: CISA URL is a hardcoded constant, not env-var configurable (SSRF prevention)
- [ ] AC-6: `known_ransomware=TRUE` rows are stored correctly for KEV entries flagged as ransomware vectors
- [ ] AC-7: CronJob deployed and running in `threat-engine-engines` namespace

## MITRE ATT&CK
| Technique | How addressed |
|-----------|--------------|
| T1190 | Exploit Public-Facing Application — KEV-listed exploits on internet-exposed resources now trigger `exploitable_exposed_resource=TRUE` composite flag |
| T1588.006 | Obtain Capabilities: Vulnerabilities — KEV entries represent capabilities already in threat actor toolkits |

## Definition of Done
- [ ] Migration 025 applied to vuln DB
- [ ] `sync_kev.py` implemented and tested with CISA endpoint
- [ ] CronJob deployed, runs successfully (kubectl logs confirm sync)
- [ ] `has_known_exploit` correctly populated in posture table after next scan