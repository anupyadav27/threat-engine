# DI-15: Threat Engine — Backfill mitre_tactics from rule_metadata

## Track
Track 3 — DB Schema Alignment

## Priority
P0 — MITRE ATT&CK Coverage page is always empty without this fix

## Story
As a security analyst, I need `threat_detections.mitre_tactics` and `threat_detections.mitre_techniques` to be populated from the rule metadata for all existing threat findings, so that the MITRE ATT&CK Coverage page shows actual technique counts instead of blank grids.

## Root Cause

`threat_detections.mitre_tactics = []` for both `my-tenant` and `00000000-...`. The threat engine writes records but never resolves the MITRE fields from `rule_metadata`. The check engine's `rule_metadata` table has `mitre_techniques` and `mitre_tactics` arrays per rule. The threat engine writes `threat_findings` with a `rule_id` but doesn't JOIN to `rule_metadata` when building the MITRE fields.

## Data Architecture

- `check` DB: `rule_metadata` table — has `rule_id`, `mitre_techniques` (JSONB), `mitre_tactics` (JSONB)
- `threat` DB: `threat_detections` table — has `rule_id` FK, `mitre_tactics` (JSONB, currently always `[]`)

Note: The threat DB and check DB are SEPARATE PostgreSQL databases on the same RDS instance. The threat engine cannot JOIN across them, but it CAN make an HTTP call to the check engine's rule metadata API or read from its own copy.

## Solution

### Part A: One-time backfill script (run now to fix existing data)

```python
#!/usr/bin/env python3
"""
Backfill mitre_tactics and mitre_techniques on threat_detections from check engine rule_metadata.

Run this inside the threat engine pod:
  kubectl exec -n threat-engine-engines deployment/engine-threat -- python3 /tmp/backfill_mitre.py
"""
import os
import psycopg2
import httpx
import json

CHECK_ENGINE_URL = os.getenv("CHECK_ENGINE_URL", "http://engine-check:8002")
THREAT_DB_HOST = os.getenv("THREAT_DB_HOST")
THREAT_DB_NAME = os.getenv("THREAT_DB_NAME")
THREAT_DB_USER = os.getenv("THREAT_DB_USER", "postgres")
THREAT_DB_PASS = os.getenv("THREAT_DB_PASSWORD", "")

def get_rule_mitre_map():
    """Fetch rule_id -> {mitre_tactics, mitre_techniques} from check engine."""
    resp = httpx.get(f"{CHECK_ENGINE_URL}/api/v1/check/rules/metadata", timeout=30)
    resp.raise_for_status()
    rules = resp.json().get("rules", [])
    return {
        r["rule_id"]: {
            "mitre_tactics": r.get("mitre_tactics") or [],
            "mitre_techniques": r.get("mitre_techniques") or [],
        }
        for r in rules if r.get("rule_id")
    }

conn = psycopg2.connect(
    host=THREAT_DB_HOST, dbname=THREAT_DB_NAME,
    user=THREAT_DB_USER, password=THREAT_DB_PASS
)
cur = conn.cursor()

# Get all distinct rule_ids in threat_detections that have empty mitre_tactics
cur.execute("""
    SELECT DISTINCT rule_id FROM threat_detections
    WHERE (mitre_tactics IS NULL OR mitre_tactics = '[]'::jsonb)
      AND rule_id IS NOT NULL
""")
rule_ids = [row[0] for row in cur.fetchall()]
print(f"Found {len(rule_ids)} rules with empty mitre_tactics")

mitre_map = get_rule_mitre_map()
updated = 0

for rule_id in rule_ids:
    mitre = mitre_map.get(rule_id)
    if not mitre:
        continue
    tactics = json.dumps(mitre["mitre_tactics"])
    techniques = json.dumps(mitre["mitre_techniques"])
    cur.execute("""
        UPDATE threat_detections
        SET mitre_tactics = %s::jsonb,
            mitre_techniques = %s::jsonb
        WHERE rule_id = %s
          AND (mitre_tactics IS NULL OR mitre_tactics = '[]'::jsonb)
    """, (tactics, techniques, rule_id))
    updated += cur.rowcount

conn.commit()
print(f"Updated {updated} rows")
cur.close()
conn.close()
```

### Part B: Fix the threat engine writer to populate mitre fields going forward

The threat engine's writer (find the DB writer module) must populate `mitre_tactics` when inserting new threat_detections.

Find the writer: look in `engines/threat/` for the DB write function.

```bash
grep -rn "INSERT INTO threat_detections\|mitre_tactics" /Users/apple/Desktop/threat-engine/engines/threat/ | head -20
```

In the INSERT or UPSERT for threat_detections, add a JOIN or lookup to populate mitre_tactics from the rule_metadata. If the threat engine doesn't have access to rule_metadata (different DB), it should:

1. Call the check engine's rule metadata endpoint at scan time
2. Cache the rule_id → MITRE mapping in memory during the scan run
3. Enrich each detection with the mapping before writing to DB

### Part C: Verify via SQL

After the backfill:
```sql
-- Check count of rows with non-empty mitre_tactics
SELECT COUNT(*) FROM threat_detections WHERE mitre_tactics != '[]'::jsonb;

-- Sample rows
SELECT rule_id, mitre_tactics, mitre_techniques
FROM threat_detections
WHERE mitre_tactics != '[]'::jsonb
LIMIT 5;
```

## Files to Modify

1. New script: `/Users/apple/Desktop/threat-engine/scripts/backfill_mitre_tactics.py`
2. Threat engine DB writer: find and modify in `engines/threat/`

## Acceptance Criteria

- [ ] Backfill script runs without error on staging cluster
- [ ] After backfill: `SELECT COUNT(*) FROM threat_detections WHERE mitre_tactics != '[]'` > 0 for my-tenant
- [ ] MITRE ATT&CK Coverage page (/threats → MITRE tab) shows non-empty tactic columns after next page load
- [ ] Future scan runs populate mitre_tactics without needing backfill
- [ ] BFF `threats.py` MITRE matrix build code (`build_mitre_matrix()`) receives non-empty tactics from engine

## Testing

```bash
# Port-forward threat engine
kubectl port-forward svc/engine-threat 8020:80 -n threat-engine-engines

# Verify MITRE data returned by engine
python3 -c "
import urllib.request, json
req = urllib.request.Request('http://localhost:8020/api/v1/threat/ui-data?tenant_id=my-tenant&limit=10')
with urllib.request.urlopen(req) as r:
    d = json.loads(r.read())
    print('MITRE matrix entries:', len(d.get('mitre_matrix', [])))
    print('Sample tactics:', [t.get('tactics') for t in d.get('mitre_matrix', [])[:3]])
"
```

Expected: `MITRE matrix entries: > 0`

## Definition of Done
- Backfill script run on production cluster
- MITRE tab shows techniques after page reload
- Threat engine writer updated to populate mitre fields on future scans
