# CDR-1-S03: Fix Multi-Technique MITRE Indexing in security_findings

## Sprint
CDR-1 — Correctness Sprint

## Priority
P1 — L2 correlation findings commonly map to 3-5 MITRE techniques (Initial Access → Lateral Movement → Exfiltration). Only `techs[0]` is stored in `security_findings.mitre_technique_id`. Attack-path scorer uses this column for technique-based path elevation, so compound attacks are under-scored.

## Story
As the attack-path and risk engines, I need all MITRE techniques from a CDR finding to be queryable from `security_findings`, so that multi-hop attack sequences are scored correctly and MITRE technique heatmaps show full coverage.

## Background / Root Cause

In `engines/cdr/run_scan.py`, the block that writes to `security_findings` via `shared/common/security_findings_writer.py` builds the payload per finding. It currently does:

```python
"mitre_technique_id": techs[0] if techs else None,
```

This means only the primary technique is indexed. The `detail` JSONB already contains the full `mitre_techniques` list from `cdr_findings`, but the indexed column only has one value.

The `security_findings` schema has `mitre_technique_id VARCHAR(20)` (single value). Rather than schema change (which breaks existing indexes and queries), store all techniques in `detail` JSONB under a well-known key `all_mitre_techniques`, and keep `mitre_technique_id` as the primary (first) technique. Add a GIN index on `detail->'all_mitre_techniques'`.

## Files to Read First

- `engines/cdr/run_scan.py` — lines 510-570 (security_findings write block)
- `shared/common/security_findings_writer.py` — `upsert_findings()` signature and payload shape
- `shared/database/schemas/security_findings_schema.sql` — current columns and indexes

## Files to Modify

| File | Change |
|---|---|
| `engines/cdr/run_scan.py` | Store full `mitre_techniques` list in `detail.all_mitre_techniques`; store top technique in `mitre_technique_id`; store top tactic in `mitre_tactic` |
| `shared/database/migrations/cdr_001_security_findings_mitre_gin.sql` | **NEW** — add GIN index on `detail->'all_mitre_techniques'` |

## Exact Implementation

### `engines/cdr/run_scan.py` — security_findings payload build

Change the finding payload construction:

```python
techs = f.get("mitre_techniques") or []
tactics = f.get("mitre_tactics") or []

detail = f.get("finding_data") or {}  # already a dict (JSONB)
detail["all_mitre_techniques"] = techs          # store full list
detail["all_mitre_tactics"] = tactics

payload = {
    ...
    "mitre_technique_id": techs[0] if techs else None,   # primary (unchanged column)
    "mitre_tactic": tactics[0] if tactics else None,      # primary (unchanged column)
    "detail": detail,                                      # enriched JSONB
}
```

### New migration: `shared/database/migrations/cdr_001_security_findings_mitre_gin.sql`

```sql
-- Add GIN index for multi-technique querying on CDR findings
-- Allows: detail->'all_mitre_techniques' @> '["T1078"]'
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE indexname = 'idx_sf_all_mitre_techniques'
    ) THEN
        CREATE INDEX CONCURRENTLY idx_sf_all_mitre_techniques
        ON security_findings USING GIN ((detail -> 'all_mitre_techniques'))
        WHERE source_engine = 'cdr';
    END IF;
END $$;
```

Apply via `kubectl exec` on a pod with access to `threat_engine_inventory` DB:
```bash
kubectl exec -n threat-engine-engines deployment/engine-cdr -- python3 -c "
import psycopg2, os
conn = psycopg2.connect(host=os.environ['INVENTORY_DB_HOST'], ...)
conn.autocommit = True
cur = conn.cursor()
cur.execute(open('/sql/cdr_001_security_findings_mitre_gin.sql').read())
"
```

## Acceptance Criteria

- [ ] After CDR scan, `SELECT detail->'all_mitre_techniques' FROM security_findings WHERE source_engine='cdr' AND tenant_id=:t LIMIT 5` returns arrays with ≥1 element per finding that has techniques
- [ ] For an L2 correlation finding with 3 techniques, `mitre_technique_id` = first technique AND `detail.all_mitre_techniques` = all 3
- [ ] `mitre_technique_id` column still populated as before (no regression for consumers that read that column)
- [ ] GIN index `idx_sf_all_mitre_techniques` exists on `security_findings` table after migration
- [ ] Attack-path engine query `WHERE detail->'all_mitre_techniques' @> '["T1078"]'` returns matching findings
- [ ] `detail` JSONB is never passed through `json.loads()` (it's already a dict from psycopg2)
- [ ] Findings with no MITRE techniques: `all_mitre_techniques = []`, `mitre_technique_id = NULL` — no crash

## Security Checklist

- [ ] All `security_findings` queries scoped by `tenant_id`
- [ ] No raw event payloads stored in `detail.all_mitre_techniques` — only technique IDs
- [ ] `CREATE INDEX CONCURRENTLY` used so migration does not lock the table

## Definition of Done

- [ ] `run_scan.py` updated to enrich `detail` JSONB before upsert
- [ ] Migration SQL created in `shared/database/migrations/`
- [ ] Migration applied to RDS (verify with `\d security_findings` → index present)
- [ ] Manual verify: query `detail->'all_mitre_techniques'` for a fresh CDR scan → full technique arrays present
- [ ] Image tag bumped in `deployment/aws/eks/engines/engine-cdr.yaml`