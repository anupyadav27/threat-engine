# Story AP-P2-06: Choke Point Detector + DB Writer + Posture Updater

## Status: ready

## Metadata
- **Phase**: P2 — Attack Path Engine Core
- **Epic**: Attack Path Engine
- **Points**: 5
- **Priority**: P0
- **Depends on**: AP-P2-01 (attack_paths tables exist), AP-P2-05 (deduplicated paths with group_id and choke_node_uid), AP-P0-02 (posture_writer for posture updates)
- **Blocks**: AP-P2-07 (run_scan.py calls these components), AP-P3-02 (risk engine reads posture signals written here)
- **RACI**: R=DEV A=DL C=SA,SR I=PO,QA
- **Security Gate**: bmad-security-reviewer mandatory (DB write path for findings tables + posture table).

## User Story

As the attack-path engine, I want a choke point detector that identifies the top-10 nodes appearing in the most attack path groups, a DB writer that persists attack paths and per-hop evidence, and a posture updater that writes attack-path signals back to `resource_security_posture`, so that operators can see which resources to fix first and the risk engine receives accurate attack-path context.

## Context

After deduplication, three coordinated write operations must happen:

1. **Choke point detection**: Count how many distinct `group_id` values each `choke_node_uid` appears in. Top 10 get `is_choke_point=true`. This is the "fix one, break many" lever.

2. **DB writer**: Persist deduplicated paths to `attack_paths`, per-hop evidence to `attack_path_nodes`, and a score/composition snapshot to `attack_path_history`. Paths surviving from a previous scan update `last_seen_at`. Paths that disappear get `status='resolved'`.

3. **Posture updater**: After all paths are written, update `resource_security_posture` for each resource that appears on any path. Signals written: `is_on_attack_path`, `attack_path_count`, `is_choke_point`, `choke_point_path_count`, `blast_radius_count`.

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance  [ ] Design  [x] Implementation  [x] Verification  [ ] Operations

**NIST CSF 2.0 Function(s)**
- [ ] GV  [x] ID  [x] PR  [x] DE  [x] RS  [ ] RC
ID.RA-5 (risk prioritized), DE.CM-1 (attack path monitoring), RS.AN-3 (forensics via per-hop evidence)

**CSA CCM v4 Domain(s)**
- IVS-01, SEF-01 (Security Event Analysis), GRC-05 (Risk Assessment)

## Threat Model

### STRIDE
| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Info Disclosure | attack_path_nodes | policy_statement JSONB exposes IAM policy details — cross-tenant leak | All inserts include tenant_id; attack_path_nodes.path_id FK links to tenant-scoped attack_paths |
| Repudiation | attack_path_history | History row deleted → no evidence a path existed | history table has no DELETE in application code; retention is infra-level |
| Tampering | posture updater | concurrent runs for same tenant write conflicting posture signals | posture_writer uses ON CONFLICT DO UPDATE — last writer wins; Argo serializes per-tenant |
| DoS | attack_path_nodes | Writing 500 paths × 7 hops = 3,500 rows in one transaction | Batch inserts in chunks of 500; single BEGIN/COMMIT per batch |

## MITRE ATT&CK Techniques Addressed
| Technique ID | Name | How this story addresses it |
|-------------|------|-----------------------------|
| T1078.004 | Valid Accounts: Cloud Accounts | Choke point detection identifies IAM roles that appear on most paths — highest-value remediation target |

## Acceptance Criteria

### Functional — Choke Point Detector
- [ ] AC-1: File `engines/attack-path/attack_path_engine/core/choke_point_detector.py` created
- [ ] AC-2: `detect_choke_points(deduplicated_paths) -> list[ChokePoint]` function: counts appearances of each `choke_node_uid` across distinct `group_id` values
- [ ] AC-3: Returns top 10 nodes by `paths_blocked_if_fixed` (count of distinct group_ids in which node appears as choke_node)
- [ ] AC-4: `avg_path_score` computed for each choke point (average score of representative paths in groups where this node is choke_node)
- [ ] AC-5: Nodes appearing in only 1 group are included in counting but top-10 limit applies

### Functional — DB Writer
- [ ] AC-6: File `engines/attack-path/attack_path_engine/db/writer.py` created
- [ ] AC-7: `write_paths(conn, paths, tenant_id, scan_run_id)` inserts/updates `attack_paths` rows — uses `path_id` (sha256 of node_uids) as PK; ON CONFLICT updates `last_seen_at`, `path_score`, `group_id`, `absorbed_count`, `choke_node_uid`, `updated_at`
- [ ] AC-8: `first_seen_at` set on first INSERT, never updated on subsequent scans for the same path_id
- [ ] AC-9: `write_path_nodes(conn, paths, tenant_id)` inserts `attack_path_nodes` rows — one row per hop per path. Clears existing nodes for `path_id` before re-inserting (DELETE ... INSERT — nodes may change between scans)
- [ ] AC-10: `write_history(conn, paths, tenant_id, scan_run_id)` inserts one row per surviving path into `attack_path_history` — always INSERT (never UPDATE) for immutable history
- [ ] AC-11: Paths not found in current scan have `status` updated to `'resolved'` in `attack_paths` (via UPDATE ... WHERE path_id NOT IN (current path IDs) AND tenant_id = $tid)
- [ ] AC-12: No JSONB column (node_uids, node_types, edge_types, hop_categories, misconfigs, cves, etc.) is passed as a string — all JSONB values use `psycopg2.extras.Json()`

### Functional — Posture Updater
- [ ] AC-13: File `engines/attack-path/attack_path_engine/db/posture_updater.py` created
- [ ] AC-14: `update_attack_path_signals(conn, paths, choke_points, tenant_id, scan_run_id)` calls `upsert_posture_signals()` (from AP-P0-02) for each resource_uid that appears on any path
- [ ] AC-15: Signals written: `is_on_attack_path=True`, `attack_path_count=<count>`, `blast_radius_count=<count of crown jewels reachable>`
- [ ] AC-16: Choke point signals written: `is_choke_point=True`, `choke_point_path_count=<paths_blocked>` for top-10 choke nodes
- [ ] AC-17: Scoring helpers written: `max_epss`, `critical_misconfig_count`, `high_misconfig_count` per resource

### Security (must pass bmad-security-reviewer)
- [ ] AC-18: All DB writes scoped by `tenant_id` from scan context — no writes without tenant_id
- [ ] AC-19: `scan_run_id` present on every `attack_paths` row — never written without it
- [ ] AC-20: No `json.loads()` on JSONB values — psycopg2 auto-deserializes; use `psycopg2.extras.Json()` for writes
- [ ] AC-21: No DEV_BYPASS_AUTH
- [ ] AC-22: `attack_path_nodes.tenant_id` always matches parent `attack_paths.tenant_id`

## Technical Notes

**choke_point_detector.py**: Iterate over deduplicated paths, collect all (choke_node_uid, group_id) pairs, count distinct group_ids per choke_node_uid, return top 10.

**writer.py JSONB pattern** (critical — see CLAUDE.md anti-pattern):
```python
import psycopg2.extras
# CORRECT:
cursor.execute("INSERT ... VALUES %s", (psycopg2.extras.Json(path.node_uids),))
# WRONG:
cursor.execute("INSERT ... VALUES %s", (json.dumps(path.node_uids),))  # DO NOT DO THIS
```

**first_seen_at preservation**:
```sql
INSERT INTO attack_paths (...) VALUES (...)
ON CONFLICT (path_id) DO UPDATE SET
    last_seen_at = NOW(),
    path_score = EXCLUDED.path_score,
    -- ... other mutable fields
    -- DO NOT update first_seen_at
    updated_at = NOW()
```

**History table**: Always INSERT ONLY. No ON CONFLICT. Every scan that finds a path generates one new history row. Retention managed at infra level.

## Key Files
- `/Users/apple/Desktop/threat-engine/engines/attack-path/attack_path_engine/core/choke_point_detector.py` (create new)
- `/Users/apple/Desktop/threat-engine/engines/attack-path/attack_path_engine/db/writer.py` (create new)
- `/Users/apple/Desktop/threat-engine/engines/attack-path/attack_path_engine/db/posture_updater.py` (create new)

## Definition of Done
- [ ] All 3 files committed
- [ ] choke_point_detector returns top-10 nodes correctly (unit tested with synthetic path list)
- [ ] writer.py inserts attack_paths rows with correct first_seen_at preservation
- [ ] writer.py inserts attack_path_nodes rows (DELETE+INSERT per path)
- [ ] writer.py inserts attack_path_history row (INSERT only, no conflict handling)
- [ ] Resolved paths updated to status='resolved' in attack_paths
- [ ] posture_updater writes is_on_attack_path, is_choke_point signals correctly
- [ ] No json.loads() calls anywhere in these 3 files
- [ ] bmad-security-reviewer: no BLOCKERS