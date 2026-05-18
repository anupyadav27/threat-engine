# Story RF-P1-01: Risk Engine — Unified Data Model Integration

## Status: done

## Metadata
- **Phase**: P1 — Risk Engine Upgrade
- **Epic**: Security Findings Unified Layer (sub-project of Attack Path Engine Epic)
- **Points**: 8
- **Priority**: P1
- **Depends on**: SF-P0-01 (security_findings table), SF-P1-01, SF-P1-02 (data populated), AP-P0-01 (posture table), AP-P2-07 (attack-path writes posture signals), AP-P3-01 (attack_paths table), AP-P3-02 (posture signals in risk scoring)
- **Runs alongside**: SF-P3-01 (attack-path reads security_findings; this story makes risk do the same)
- **Blocks**: nothing (terminal story; improves risk score quality across all downstream consumers)
- **RACI**: R=DEV A=DL C=SA,SR I=PO,QA
- **Security Gate**: bmad-security-reviewer mandatory — risk engine DB read path, cross-engine data join, posture write-back.

## User Story

As the risk engine, I want to replace my 6 cross-engine DB reads with queries to `security_findings` and `resource_security_posture`, and write the computed `posture_score` back to `resource_security_posture`, so that the risk calculation uses a single consistent point-in-time data source and closes the loop on the resource posture lifecycle.

## Context

The current risk engine (FAIR model, 3-stage pipeline) opens connections to 8 separate engine DBs plus Neo4j to assemble per-resource risk inputs. This creates:
1. **Cross-engine coupling** — the risk engine must know the schema of 8 other databases
2. **Stale data risk** — each DB read is a separate query at different points in time; findings may change between reads
3. **Blast radius via Neo4j** — expensive graph traversal to count reachable resources; already pre-computed in `resource_security_posture.blast_radius_count` (by attack-path engine)

After this story:
- `security_findings` replaces 6 per-engine DB reads (check, iam, datasec, network, vuln, cdr findings)
- `resource_security_posture` replaces Neo4j blast radius traversal and provides attack-path signals
- `attack_paths` provides crown_jewel context for FAIR scenario classification
- `threat_scenario_incidents` (threat_v1 DB) is the ONE remaining cross-engine connection (attack-chain severity)
- Risk engine writes `posture_score` back to `resource_security_posture` — closes the data loop

**FAIR Stage pipeline after this story:**
```
Stage 1 (ETL):      security_findings JOIN resource_security_posture JOIN attack_paths
Stage 2 (FAIR):     calculate TEF/LEF/VS/PL/RS per resource using unified inputs
Stage 3 (Financial): dollar-denominated exposure output
Stage 4 (Write-back): posture_score → resource_security_posture
```

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance  [ ] Design  [x] Implementation  [x] Verification  [ ] Operations

**NIST CSF 2.0 Function(s)**
- [ ] GV  [x] ID  [x] PR  [ ] DE  [x] RS  [ ] RC
ID.RA-5 (FAIR quantification), RS.AN-3 (risk-ordered response prioritization)

**CSA CCM v4 Domain(s)**
- GRC-05, IVS-01, TVM-09, SEF-01

## Threat Model

### STRIDE
| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Info Disclosure | cross-tenant join | security_findings JOIN posture without tenant_id filter — leaks another tenant's findings | All queries always WHERE tenant_id = %s from AuthContext; verified by AC-18 |
| Tampering | posture_score write-back | Risk engine writes posture_score to wrong tenant's row | UPDATE WHERE tenant_id = %s AND resource_uid = %s — double-keyed update |
| Info Disclosure | FAIR output | risk_scenarios table contains dollar exposure values | risk_scenarios always scoped by tenant_id; existing RBAC enforced |
| DoS | security_findings scan size | Tenant with 500K findings causes Stage 1 to time out | Read grouped by resource_uid (SELECT resource_uid, COUNT, MAX) — aggregate query, not row-by-row fetch |

## Acceptance Criteria

### Functional — Stage 1 ETL replacement

- [ ] AC-1: In `engines/risk/risk_engine/etl/findings_fetcher.py` (new file), implement `fetch_risk_inputs(inv_conn, tenant_id, scan_run_id)` that returns a `dict[str, RiskInputRow]` keyed by resource_uid
- [ ] AC-2: `fetch_risk_inputs()` queries security_findings with aggregate SQL:
  ```sql
  SELECT
      resource_uid,
      COUNT(*) FILTER (WHERE severity = 'critical')       AS critical_count,
      COUNT(*) FILTER (WHERE severity = 'high')           AS high_count,
      COUNT(*) FILTER (WHERE severity = 'medium')         AS medium_count,
      COUNT(*) FILTER (WHERE finding_type = 'iam_violation') AS iam_violation_count,
      COUNT(*) FILTER (WHERE finding_type = 'data_risk')  AS data_risk_count,
      COUNT(*) FILTER (WHERE finding_type = 'cdr_event')  AS cdr_event_count,
      MAX(epss_score) FILTER (WHERE finding_type = 'cve') AS max_epss,
      BOOL_OR(in_kev)                                     AS has_kev_cve,
      COUNT(*) FILTER (WHERE finding_type = 'cve')        AS cve_count
  FROM security_findings
  WHERE tenant_id = %s AND scan_run_id = %s AND status = 'open'
  GROUP BY resource_uid
  ```
- [ ] AC-3: `fetch_risk_inputs()` also queries `resource_security_posture` for the same scan_run_id to attach posture signals per resource:
  ```sql
  SELECT resource_uid, blast_radius_count, is_on_attack_path,
         attack_path_count, is_choke_point, has_active_cdr_actor,
         cert_days_remaining, crown_jewel_type
  FROM resource_security_posture
  WHERE tenant_id = %s AND scan_run_id = %s
  ```
- [ ] AC-4: Result merges both queries: for each resource_uid found in either query, build a `RiskInputRow` TypedDict with fields from both sources; missing fields default to 0/False/None
- [ ] AC-5: If security_findings is empty for this scan_run_id, `fetch_risk_inputs()` returns empty dict and Stage 2 completes without error (graceful degradation — risk score uses posture-only inputs)

### Functional — Stage 2 FAIR scoring changes

- [ ] AC-6: Replace direct per-engine DB reads in Stage 2 (`fair_calculator.py` or equivalent) with `risk_inputs[uid]` from Stage 1 output
- [ ] AC-7: New FAIR scenario type `cdr_confirmed_attack` triggered when BOTH conditions are true:
  ```python
  has_active_cdr_actor and is_on_attack_path
  ```
  This scenario applies the highest primary_loss multiplier in the FAIR formula (configurable, default 2.5×)
- [ ] AC-8: KEV bonus: when `has_kev_cve = true`, Vulnerability Severity (VS) component in FAIR uses `max_epss + 0.20` boost (capped at 1.0) — reflects KEV exploit availability
- [ ] AC-9: blast_radius_count from posture table replaces Neo4j graph traversal for FAIR Loss Magnitude calculation; risk engine no longer opens a Neo4j connection for blast radius
- [ ] AC-10: crown_jewel_type from posture table (set by attack-path CrownJewelClassifier) used to set FAIR Asset Value (AV) tier:
  - `pii_store` → AV tier 5 (highest)
  - `payment_processor` → AV tier 5
  - `secrets_store` → AV tier 4
  - `prod_database` → AV tier 4
  - `admin_console` → AV tier 3
  - null (not a crown jewel) → AV tier derived from resource_type as before

### Functional — Stage 4 overall_posture_score write-back (new stage)

- [ ] AC-11: After Stage 3 completes, for each resource with a computed risk score, write `overall_posture_score` back to `resource_security_posture`:
  ```python
  UPDATE resource_security_posture
  SET overall_posture_score = %s, updated_at = NOW()
  WHERE tenant_id = %s AND resource_uid = %s
  ```
- [ ] AC-12: `overall_posture_score` is the normalized 0–100 integer from the FAIR calculation (same scale as existing risk scores)
- [ ] AC-13: Write-back is batched: use `executemany` in chunks of 500 — no single UPDATE per row
- [ ] AC-14: Write-back is NOT a hard failure: if the UPDATE fails for any resource (e.g., posture row doesn't exist yet), log WARNING and continue — do not fail the whole risk scan
- [ ] AC-15: `overall_posture_score` column in `resource_security_posture` must exist before this runs — confirmed in migration 023 line 119

### Functional — Neo4j dependency removal

- [ ] AC-16: After this story, the risk engine does NOT open a Neo4j connection for blast radius. The only remaining cross-engine connection is to `threat_engine_threat` DB for `threat_scenario_incidents` (attack-chain severity context — not yet in any unified table)
- [ ] AC-17: `THREAT_DB_*` env vars remain in K8s manifest; `NEO4J_*` env vars can be removed from risk engine manifest (but leave as optional/empty to avoid deployment churn — do not fail if present)

### Integration

- [ ] AC-18: All security_findings queries include `tenant_id = %s` — verified by code review (bmad-security-reviewer)
- [ ] AC-19: After a full pipeline scan: `SELECT overall_posture_score FROM resource_security_posture WHERE tenant_id='<tenant>' AND overall_posture_score > 0 LIMIT 5` — returns rows (overall_posture_score populated by risk engine)
- [ ] AC-20: A resource with `has_kev_cve=true` in posture has higher posture_score than equivalent resource without KEV CVEs (same blast_radius, same misconfig count)
- [ ] AC-21: A resource with `is_on_attack_path=true AND has_active_cdr_actor=true` has posture_score ≥ 80 (cdr_confirmed_attack scenario triggers maximum loss multiplier)

### Image & Manifest

- [ ] AC-22: risk engine builds new image: `yadavanup84/engine-risk:v-risk-sf1`
- [ ] AC-23: K8s manifest updated to `v-risk-sf1`; no `latest` tag
- [ ] AC-24: `kubectl rollout status` clean after deploy
- [ ] AC-25: `INVENTORY_DB_*` env vars added to risk engine K8s manifest (for security_findings + posture reads via inv_conn)

### Security (must pass bmad-security-reviewer)

- [ ] AC-26: No DEV_BYPASS_AUTH in any new file
- [ ] AC-27: `fetch_risk_inputs()` never logs individual finding rows (may contain sensitive titles)
- [ ] AC-28: posture_score write-back UPDATE always includes both `tenant_id` AND `resource_uid` in WHERE clause — cannot accidentally update wrong tenant's row
- [ ] AC-29: cdr_confirmed_attack scenario multiplier is a constant, not read from user input or query string

## Technical Notes

**New file**: `engines/risk/risk_engine/etl/findings_fetcher.py`

**Inventory DB connection in risk engine**: The risk engine currently does NOT connect to `threat_engine_inventory`. This story adds `inv_conn` as a new DB connection. Add `INVENTORY_DB_HOST` / `INVENTORY_DB_USER` / `INVENTORY_DB_PASSWORD` / `INVENTORY_DB_NAME` to K8s env from `threat-engine-db-config` ConfigMap (already has these values — no new secrets needed).

**RiskInputRow TypedDict:**
```python
class RiskInputRow(TypedDict, total=False):
    resource_uid: str
    critical_count: int
    high_count: int
    medium_count: int
    iam_violation_count: int
    data_risk_count: int
    cdr_event_count: int
    max_epss: Optional[float]
    has_kev_cve: bool
    cve_count: int
    blast_radius_count: int
    is_on_attack_path: bool
    attack_path_count: int
    is_choke_point: bool
    has_active_cdr_actor: bool
    cert_days_remaining: Optional[int]
    crown_jewel_type: Optional[str]
```

**Stage 1 merge pattern:**
```python
risk_inputs: dict[str, RiskInputRow] = {}
for row in findings_rows:
    risk_inputs[row["resource_uid"]] = RiskInputRow(**row)
for row in posture_rows:
    uid = row["resource_uid"]
    if uid in risk_inputs:
        risk_inputs[uid].update(row)
    else:
        risk_inputs[uid] = RiskInputRow(**row)
```

**cdr_confirmed_attack scenario definition:**
```python
CDR_CONFIRMED_MULTIPLIER = 2.5  # highest primary_loss multiplier

def classify_scenario(r: RiskInputRow) -> str:
    if r.get("has_active_cdr_actor") and r.get("is_on_attack_path"):
        return "cdr_confirmed_attack"
    if r.get("is_on_attack_path") and r.get("attack_path_count", 0) >= 1:
        return "active_attack_path"
    if r.get("has_kev_cve"):
        return "known_exploitable"
    if r.get("critical_count", 0) >= 3:
        return "high_misconfiguration"
    return "baseline"
```

**overall_posture_score write-back batch:**
```python
updates = [(score, tenant_id, uid) for uid, score in scored_resources.items()]
for chunk in [updates[i:i+500] for i in range(0, len(updates), 500)]:
    cur.executemany(
        "UPDATE resource_security_posture SET overall_posture_score=%s, updated_at=NOW() "
        "WHERE tenant_id=%s AND resource_uid=%s",
        chunk
    )
    inv_conn.commit()
```

**New image tag**: `yadavanup84/engine-risk:v-risk-sf1`

## Key Files
- `/Users/apple/Desktop/threat-engine/engines/risk/risk_engine/etl/findings_fetcher.py` (create new)
- `/Users/apple/Desktop/threat-engine/engines/risk/risk_engine/fair_calculator.py` (modify — replace DB reads with risk_inputs dict)
- `/Users/apple/Desktop/threat-engine/engines/risk/risk_engine/run_scan.py` (modify — add Stage 4 write-back step)
- `/Users/apple/Desktop/threat-engine/deployment/aws/eks/engines/engine-risk.yaml` (add INVENTORY_DB_* env, update image tag)

## Definition of Done
- [ ] `findings_fetcher.py` created and committed
- [ ] `fair_calculator.py` modified — no more direct cross-engine DB calls for findings
- [ ] `run_scan.py` modified — Stage 4 posture_score write-back added
- [ ] K8s manifest updated: INVENTORY_DB_* env + image tag `v-risk-sf1`
- [ ] Docker image built and pushed: `v-risk-sf1`
- [ ] kubectl rollout clean
- [ ] AC-19/AC-20/AC-21 verified against live data
- [ ] MEMORY.md production table updated for risk image tag
- [ ] bmad-security-reviewer: no BLOCKERS