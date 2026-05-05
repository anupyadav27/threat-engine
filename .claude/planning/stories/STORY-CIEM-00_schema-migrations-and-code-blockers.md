# STORY-CIEM-00: Schema Migrations + Code Blockers Before UI Sprint

## Track
CIEM Investigation Journey — Pre-Sprint (Must ship before STORY-CIEM-01 through STORY-CWPP-02)

## Priority
P0 — Hard blockers. No UI story can deliver correct data without these.

## Context

A specialist CIEM engine agent audited the schema and code against the finalized UI spec. Three hard blockers were found:

1. **`actor_principal_type` is always written as empty string `""` in L2 and L3 findings** — heatmap renders everything as "unknown"
2. **`contributing_steps` JSONB path does not exist** — Stage 3 attack chain timeline is impossible to render
3. **`effort` field does not exist anywhere** — Stage 5 Kanban cannot bucket findings

Additionally, 6 missing indexes will cause sequential scans at scale, and there is no formal `ciem_schema.sql` DDL file.

---

## Part A — Schema Migrations

### Migration 1: `ciem_ui_gaps_001.sql` (CIEM DB)

**File to create**: `shared/database/migrations/ciem_ui_gaps_001.sql`

```sql
-- Migration: ciem_ui_gaps_001
-- Target DB: threat_engine_ciem
-- Purpose: Indexes required for CIEM investigation journey UI performance

BEGIN;

-- Heatmap Stage 1: GROUP BY (account_id × actor_principal_type × severity)
CREATE INDEX IF NOT EXISTS idx_cf_heatmap
    ON ciem_findings (tenant_id, account_id, actor_principal_type, severity);

-- Stage 1 identity table: COUNT FILTER (WHERE rule_source = 'log_correlation'/'baseline')
CREATE INDEX IF NOT EXISTS idx_cf_rule_source
    ON ciem_findings (tenant_id, rule_source);

CREATE INDEX IF NOT EXISTS idx_cf_actor_source
    ON ciem_findings (tenant_id, actor_principal, rule_source);

-- Stage 2 behavioral timeline: ORDER BY event_time ASC for a single principal
CREATE INDEX IF NOT EXISTS idx_cf_actor_timeline
    ON ciem_findings (tenant_id, actor_principal, event_time ASC);

-- Stage 2 + Stage 3: JSONB path lookups on finding_data (contributing_steps, anomalies)
CREATE INDEX IF NOT EXISTS idx_cf_finding_data_gin
    ON ciem_findings USING GIN (finding_data);

-- Stage 2 time-of-day heatmap: EXTRACT(HOUR) without seq scan
ALTER TABLE ciem_findings
    ADD COLUMN IF NOT EXISTS event_hour SMALLINT
    GENERATED ALWAYS AS (EXTRACT(HOUR FROM event_time)::smallint) STORED;

CREATE INDEX IF NOT EXISTS idx_cf_actor_hour
    ON ciem_findings (tenant_id, actor_principal, event_hour);

COMMIT;
```

### Migration 2: `ciem_ui_gaps_002.sql` (Check DB)

**File to create**: `shared/database/migrations/ciem_ui_gaps_002.sql`

```sql
-- Migration: ciem_ui_gaps_002
-- Target DB: threat_engine_check
-- Purpose: Add remediation_effort to rule_metadata for Stage 5 Kanban bucketing

BEGIN;

ALTER TABLE rule_metadata
    ADD COLUMN IF NOT EXISTS remediation_effort VARCHAR(20) DEFAULT 'medium'
    CONSTRAINT rule_metadata_effort_check
        CHECK (remediation_effort IN ('low', 'medium', 'high'));

COMMENT ON COLUMN rule_metadata.remediation_effort
    IS 'Analyst effort estimate for remediation. Used to bucket findings in the investigation journey Stage 5 Kanban. Default: medium.';

COMMIT;
```

### Apply Order
1. Apply `ciem_ui_gaps_001.sql` to CIEM DB first (standalone table)
2. Apply `ciem_ui_gaps_002.sql` to Check DB (touches `rule_metadata`)
3. Verify via: `\d ciem_findings` (confirm `event_hour` column) and `\d rule_metadata` (confirm `remediation_effort` column)

---

## Part B — Code Fixes (No Schema Change)

### Fix 1: `actor_principal_type` propagation in L2 evaluator

**File**: `engines/ciem/ciem_engine/evaluator/correlation_evaluator.py`

**Current** (line ~334):
```python
"actor_principal_type": "",
```

**Fix**:
```python
"actor_principal_type": (contributing_findings[0].get("actor_principal_type") or "") if contributing_findings else "",
```

The `contributing_findings` list is already time-sorted before `_create_correlation_finding` is called. The first contributing finding's `actor_principal_type` is the correct type for the correlation finding (same actor throughout the chain).

### Fix 2: `actor_principal_type` propagation in L3 evaluator

**File**: `engines/ciem/ciem_engine/evaluator/baseline_evaluator.py`

**Current** (line ~393):
```python
"actor_principal_type": "",
```

**Fix**: Look up the `actor_principal_type` from `ciem_actor_daily_stats` or from a recent L1 finding for the same `entity_key`:
```python
"actor_principal_type": contributing_l1_finding.get("actor_principal_type", "") if contributing_l1_finding else "",
```
If no contributing L1 finding is available at baseline evaluation time, fall back to `""` — this is acceptable since L3 baseline findings are anomaly signals, not primary classification signals.

### Fix 3: Replace `contributing_findings` with self-contained `contributing_steps` in L2

**File**: `engines/ciem/ciem_engine/evaluator/correlation_evaluator.py`

**Location**: `_create_correlation_finding` method, `finding_data` dict construction

**Current**:
```python
finding_data = {
    "contributing_findings": [f["finding_id"] for f in contributing_findings[:50]],
    "contributing_rules": [...],
    "event_count": ...,
    "first_event": ...,
    "last_event": ...,
    ...
}
```

**Fix** (preserve backwards compat, add new structure):
```python
finding_data = {
    # NEW: ordered, self-contained step data (retention-safe, timeline-renderable)
    "contributing_steps": [
        {
            "step_idx":        idx,
            "finding_id":      f["finding_id"],
            "rule_id":         f.get("rule_id", ""),
            "event_time":      f["event_time"].isoformat() if f.get("event_time") else None,
            "operation":       f.get("operation", ""),
            "service":         f.get("service", ""),
            "actor_principal": f.get("actor_principal", ""),
            "resource_uid":    f.get("resource_uid", ""),
            "resource_name":   f.get("resource_name", ""),
            "outcome":         f.get("finding_data", {}).get("event_outcome", "unknown"),
            "actor_ip":        f.get("actor_ip", ""),  # stripped for auth level >= 4
        }
        for idx, f in enumerate(contributing_findings[:50])
        # contributing_findings is already sorted by event_time at call site
    ],
    # KEPT for backwards compatibility — existing code that reads contributing_findings continues to work
    "contributing_findings": [f["finding_id"] for f in contributing_findings[:50]],
    "contributing_rules":    [f["rule_id"] for f in contributing_findings[:50]],
    "event_count":           len(contributing_findings),
    "first_event":           contributing_findings[0]["event_time"].isoformat() if contributing_findings else None,
    "last_event":            contributing_findings[-1]["event_time"].isoformat() if contributing_findings else None,
    # ... preserve all other existing keys unchanged
}
```

### Fix 4: Propagate `remediation_effort` from rule_metadata into ciem_findings.finding_data

**File**: `engines/ciem/ciem_engine/evaluator/rule_evaluator.py`

**After migration ciem_ui_gaps_002 is applied**, the `rule_metadata` table has a `remediation_effort` column. The rule evaluator already joins `rule_metadata` via `LEFT JOIN rule_metadata rm USING (rule_id)` (verify this JOIN exists — add it if not).

**In `_make_finding`**, add to `finding_data` dict:
```python
"remediation_effort": rule_metadata.get("remediation_effort", "medium"),
```

This populates the field at write time so the Stage 5 Kanban query can GROUP BY `finding_data->>'remediation_effort'`.

---

## Part C — Schema DDL File (New)

**File to create**: `shared/database/schemas/ciem_schema.sql`

Create a formal `CREATE TABLE ciem_findings` DDL file so the schema is version-controlled. Derive the authoritative column list from the evaluator INSERT statements:

```sql
CREATE TABLE IF NOT EXISTS ciem_findings (
    finding_id          VARCHAR(16) PRIMARY KEY,
    scan_run_id         VARCHAR(255),
    tenant_id           VARCHAR(255) NOT NULL,
    rule_id             VARCHAR(255),
    rule_source         VARCHAR(50),   -- 'log' | 'log_correlation' | 'baseline'
    severity            VARCHAR(20),
    status              VARCHAR(20) DEFAULT 'open',
    primary_engine      VARCHAR(50),
    engines             JSONB,
    action_category     VARCHAR(100),
    resource_uid        VARCHAR(1024),
    resource_type       VARCHAR(255),
    resource_name       VARCHAR(512),
    account_id          VARCHAR(512),
    region              VARCHAR(100),
    provider            VARCHAR(50),
    actor_principal     TEXT,
    actor_principal_type VARCHAR(50),  -- 'iam_user' | 'iam_role' | 'service_account' | 'root' | 'anonymous'
    actor_ip            VARCHAR(45),
    event_id            VARCHAR(255),
    event_time          TIMESTAMPTZ,
    event_hour          SMALLINT GENERATED ALWAYS AS (EXTRACT(HOUR FROM event_time)::smallint) STORED,
    service             VARCHAR(100),
    operation           VARCHAR(255),
    title               TEXT,
    description         TEXT,
    remediation         TEXT,
    mitre_tactics       JSONB,
    mitre_techniques    JSONB,
    risk_indicators     JSONB,
    compliance_frameworks JSONB,
    finding_data        JSONB,
    credential_ref      VARCHAR(255),
    credential_type     VARCHAR(50),
    first_seen_at       TIMESTAMPTZ DEFAULT NOW(),
    last_seen_at        TIMESTAMPTZ DEFAULT NOW(),
    created_at          TIMESTAMPTZ DEFAULT NOW()
);
```

---

## Acceptance Criteria

- [ ] `ciem_ui_gaps_001.sql` applied to CIEM DB — verify all 6 indexes exist via `\di ciem_findings`
- [ ] `ciem_ui_gaps_002.sql` applied to Check DB — verify `remediation_effort` column exists on `rule_metadata`
- [ ] `event_hour` generated column present on `ciem_findings`
- [ ] New L2 findings written after Fix 3 have `contributing_steps` array in `finding_data` (test: trigger a multi-step CIEM rule, check DB)
- [ ] `contributing_steps[0].actor_ip` is present in DB but stripped from API responses for auth_level >= 4
- [ ] `actor_principal_type` is non-empty for new L2 and L3 findings (not `""`)
- [ ] `finding_data.remediation_effort` is present on new L1/L2/L3 findings (after Fix 4)
- [ ] `ciem_schema.sql` file created in `shared/database/schemas/`
- [ ] Old findings (pre-migration) are NOT broken — old code paths still read `contributing_findings` flat list

## Security Checklist
- [ ] `contributing_steps[].actor_ip` added to `strip_sensitive_fields()` removal list for auth level >= 4
- [ ] Generated column `event_hour` is derived from `event_time` (no injection surface)
- [ ] `remediation_effort` column has a CHECK constraint limiting values to `low|medium|high`

## Definition of Done
- [ ] Both migration files created and applied
- [ ] All 4 code fixes implemented and committed
- [ ] `ciem_schema.sql` created
- [ ] Manual verify: insert a test L2 finding, confirm `contributing_steps` structure in `finding_data` JSONB
- [ ] Run `EXPLAIN ANALYZE` on heatmap GROUP BY query — confirm index scan not seq scan