# CDR-1-S01: Write OBSERVED_ACCESS Behavioral Edges to asset_relationships

## Sprint
CDR-1 — Correctness Sprint

## Priority
P0 — Attack-path graph only has static structural edges. CDR's runtime evidence of actual actor→resource access is never written to the graph, making paths miss the most valuable behavioral signal.

## Story
As the attack-path engine, I need observed actor→resource access from CDR findings to appear as `OBSERVED_ACCESS` edges in `asset_relationships`, so that graph traversal reflects real runtime behavior rather than only static IAM topology.

## Background / Root Cause

CDR finds that e.g. `arn:aws:iam::123456:user/alice` accessed `arn:aws:s3:::prod-data` (via CloudTrail GetObject). That signal exists in `cdr_findings` and is mirrored to `security_findings`, but never becomes a graph edge. The attack-path engine reads `asset_relationships` via `pg_graph.py` to build traversal paths — without behavioral edges, it cannot construct a path that includes observed runtime access.

The shared writer already exists: `shared/common/relationship_writer.py` → `upsert_asset_relationships()`. CDR just needs to call it after each scan.

## Files to Modify

| File | Change |
|---|---|
| `engines/cdr/run_scan.py` | Add `_write_behavioral_edges()` call after posture signal write |
| `engines/cdr/cdr_engine/behavioral_edges.py` | **NEW FILE** — aggregates actor→resource pairs from cdr_findings and calls upsert_asset_relationships |

## Files to Read First

- `engines/cdr/run_scan.py` lines 480-580 — posture signal + security_findings write pattern to follow
- `shared/common/relationship_writer.py` — `upsert_asset_relationships()` signature
- `shared/database/migrations/di_012_attack_ontology.sql` — `asset_relationships` columns: `relationship_category`, `attack_path_category`, `is_attack_edge`, `confidence`
- `shared/database/migrations/di_013_attack_edge_validation.sql` — `validation_status`, `attack_edge_type`

## Exact Implementation

### New file: `engines/cdr/cdr_engine/behavioral_edges.py`

```python
import logging
from typing import Any

logger = logging.getLogger(__name__)

SEVERITY_IS_ATTACK = {"critical", "high"}

def build_behavioral_edges(cdr_findings: list[dict[str, Any]], scan_run_id: str, tenant_id: str) -> list[dict]:
    """
    Aggregate actor→resource pairs from CDR findings into asset_relationship rows.
    One edge per (actor_principal, resource_uid, relation_type) — deduplicated before upsert.
    """
    seen: set[tuple] = set()
    edges: list[dict] = []

    for f in cdr_findings:
        actor = f.get("actor_principal", "").strip()
        resource = f.get("resource_uid", "").strip()
        if not actor or not resource or actor == resource:
            continue

        severity = (f.get("severity") or "").lower()
        is_attack = severity in SEVERITY_IS_ATTACK

        key = (actor, "OBSERVED_ACCESS", resource)
        if key in seen:
            continue
        seen.add(key)

        techs = f.get("mitre_techniques") or []
        tactics = f.get("mitre_tactics") or []

        edges.append({
            "scan_run_id": scan_run_id,
            "tenant_id": tenant_id,
            "account_id": f.get("account_id"),
            "provider": f.get("provider"),
            "source_uid": actor,
            "source_type": f.get("actor_principal_type") or "iam_identity",
            "target_uid": resource,
            "target_type": f.get("resource_type"),
            "relation_type": "OBSERVED_ACCESS",
            "relationship_category": "behavioral",
            "attack_path_category": "lateral_movement" if is_attack else None,
            "evidence_field_path": "cdr_findings.actor_principal",
            "evidence_value": actor,
            "is_attack_edge": is_attack,
            "attack_edge_type": "observed_access" if is_attack else None,
            "validation_status": "validated",
            "confidence": "high" if is_attack else "medium",
            "relation_metadata": {
                "mitre_techniques": techs[:5],
                "mitre_tactics": tactics[:5],
                "first_seen_at": str(f.get("first_seen_at", "")),
                "severity": severity,
                "rule_id": f.get("rule_id"),
                "action_category": f.get("action_category"),
            },
        })

    return edges
```

### `engines/cdr/run_scan.py` — add after line where `security_findings` write completes

```python
# Write behavioral edges to asset_relationships
from cdr_engine.behavioral_edges import build_behavioral_edges
from engine_common.relationship_writer import upsert_asset_relationships

behavioral_edges = build_behavioral_edges(findings_rows, scan_run_id, tenant_id)
if behavioral_edges:
    upsert_asset_relationships(di_conn, behavioral_edges)
    logger.info("CDR: wrote %d OBSERVED_ACCESS edges for tenant=%s", len(behavioral_edges), tenant_id)
```

Where `di_conn` is a psycopg2 connection to `threat_engine_di` — obtain it the same way posture_signals.py gets its inventory DB connection (read that pattern first).

## DB Connection Pattern

CDR already connects to `threat_engine_inventory` for posture signals. For `asset_relationships` (in `threat_engine_di`), CDR needs a second connection. Read `engines/cdr/run_scan.py` DB setup section to find where `inv_conn` is created and follow the same pattern using `DI_DB_*` env vars (same pattern used by `engines/di/run_scan.py`).

## Acceptance Criteria

- [ ] After a CDR scan, `SELECT COUNT(*) FROM asset_relationships WHERE relation_type='OBSERVED_ACCESS' AND tenant_id=:t AND scan_run_id=:s` returns > 0 for any tenant that had CDR findings
- [ ] Every edge has `source_uid` = actor_principal ARN, `target_uid` = resource_uid from `cdr_findings`
- [ ] Edges with severity in (critical, high) have `is_attack_edge=TRUE`, `validation_status='validated'`
- [ ] Edges with severity (medium, low) have `is_attack_edge=FALSE`, `confidence='medium'`
- [ ] `actor == resource` pairs are skipped (no self-edges)
- [ ] Empty `actor_principal` or empty `resource_uid` rows are skipped
- [ ] Upsert is idempotent — re-running same CDR scan does not create duplicate rows (unique constraint on `scan_run_id, tenant_id, source_uid, relation_type, target_uid`)
- [ ] All DB queries scoped by `tenant_id`
- [ ] No `json.loads()` on JSONB fields
- [ ] CDR scan completes successfully even if DI DB connection fails (log error, don't raise)

## Security Checklist

- [ ] `tenant_id` always comes from `AuthContext` scan context, never from cdr_findings rows
- [ ] `actor_principal` stored as-is (ARN) — no PII hashing needed (resource identifier, not personal data)
- [ ] `relation_metadata` JSONB does not include raw event payloads (avoid log data leakage)
- [ ] DI DB credentials from env vars, not hardcoded

## MITRE ATT&CK Coverage
- TA0008 Lateral Movement — observed access between identity and resource
- TA0010 Exfiltration — OBSERVED_ACCESS edges to S3/storage trigger path elevation in attack-path scorer

## Definition of Done

- [ ] `engines/cdr/cdr_engine/behavioral_edges.py` created
- [ ] `engines/cdr/run_scan.py` calls `_write_behavioral_edges()` after posture write
- [ ] Manual verify: CDR scan on test-tenant-002 → query `asset_relationships` for OBSERVED_ACCESS rows
- [ ] Attack-path engine re-run shows paths now traverse through OBSERVED_ACCESS edges (check `pg_graph.py` picks up `relation_type='OBSERVED_ACCESS'`)
- [ ] No regression in existing CDR scan completion rate
- [ ] Image tag bumped in `deployment/aws/eks/engines/engine-cdr.yaml` (no `latest`)