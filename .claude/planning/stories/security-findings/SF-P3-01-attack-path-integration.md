# Story SF-P3-01: Attack-Path Engine Integration with security_findings

## Status: done

## Metadata
- **Phase**: P3 — Integration
- **Epic**: Security Findings Unified Layer (sub-project of Attack Path Engine Epic)
- **Points**: 5
- **Priority**: P1
- **Depends on**: SF-P0-01, SF-P1-01, SF-P1-02 (data in table), AP-P2-06 (attack-path writer exists), AP-P2-07 (run_scan.py exists)
- **Blocks**: nothing (terminal integration story)
- **RACI**: R=DEV A=DL C=SA,SR I=PO,QA
- **Security Gate**: bmad-security-reviewer mandatory — modifies attack-path engine's run_scan.py and writer.

## User Story

As the attack-path engine, I want to load `security_findings` rows per resource at scan time so that `attack_path_nodes.misconfigs`, `attack_path_nodes.cves`, and `attack_path_nodes.threat_detections` are populated from the unified findings table instead of requiring direct connections to check DB and vuln DB, and so that `resource_security_posture` count columns are derived from the same source of truth.

## Context

Currently (per architecture doc section 7.3), `attack_path_nodes.misconfigs JSONB` stores inline evidence blobs. The attack-path writer must fetch this evidence from somewhere — without security_findings, it would need direct DB connections to check DB and vuln DB (violating the clean architecture: attack-path engine should not know check DB schema).

With `security_findings` populated by SF-P1-01/P1-02, the attack-path engine reads ONE table (same DB as posture) to get all finding evidence per node. This eliminates 2 cross-DB connections from the attack-path engine.

**Two changes in this story:**
1. `run_scan.py`: load findings_lookup from security_findings (between posture_lookup load and BFS)
2. `writer.py`: populate `attack_path_nodes.misconfigs/cves/threat_detections` from findings_lookup

**No schema changes** — `attack_path_nodes` columns already exist from AP-P2-01. Only the data source changes (inline JSONB built from security_findings instead of from raw engine tables).

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance  [ ] Design  [x] Implementation  [x] Verification  [ ] Operations

**NIST CSF 2.0 Function(s)**
- [ ] GV  [x] ID  [x] PR  [x] DE  [ ] RS  [ ] RC
DE.CM-1 (finding evidence preserved in attack path nodes), ID.RA-5 (CVE evidence in path story)

**CSA CCM v4 Domain(s)**
- IVS-01, TVM-09, SEF-01

## Threat Model

### STRIDE
| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Info Disclosure | findings_lookup | findings_lookup contains all findings for all resources — large in-memory dict | Scoped by tenant_id + scan_run_id; loaded once per scan; not exposed to any API caller |
| Info Disclosure | attack_path_nodes.misconfigs | JSONB stored in attack_paths DB contains finding content — cross-tenant if query is wrong | attack_path_nodes queries always join on path_id which is scoped to tenant_id in attack_paths table |
| Tampering | posture count derivation | critical_misconfig_count derived from security_findings is stale | Count derived at scan time from same scan_run_id as the rest of the scan — always current |

## Acceptance Criteria

### Functional — run_scan.py findings_lookup
- [ ] AC-1: In `engines/attack-path/attack_path_engine/run_scan.py`, after the posture_lookup load (per AP-P2-07 AC-2), a `findings_lookup` load step is added:
  ```python
  findings_lookup = load_findings_by_resource(
      inv_conn, tenant_id, scan_run_id
  )  # dict: {resource_uid: [FindingRow, ...]}
  ```
- [ ] AC-2: `load_findings_by_resource()` implemented in `engines/attack-path/attack_path_engine/db/findings_loader.py` (new file)
- [ ] AC-3: `load_findings_by_resource()` query:
  ```sql
  SELECT resource_uid, source_engine, finding_type, severity,
         rule_id, title, epss_score, cvss_score, in_kev,
         mitre_technique_id, str(finding_id) AS finding_id
  FROM security_findings
  WHERE tenant_id = %s AND scan_run_id = %s AND status = 'open'
  ```
  Returns `dict[str, list[dict]]` keyed by resource_uid
- [ ] AC-4: `findings_lookup` passed to scorer and writer (added to function signatures in scorer.py and writer.py per architecture doc section 6 flow)
- [ ] AC-5: If security_findings is empty for this scan_run_id (SF engines not yet wired), `findings_lookup` returns `{}` and scan completes normally — no crash

### Functional — writer.py node evidence
- [ ] AC-6: In the attack-path writer, for each node in a path, populate `attack_path_nodes.misconfigs` from findings_lookup:
  ```python
  node_misconfigs = [
      {"rule_id": f["rule_id"], "severity": f["severity"],
       "title": f["title"], "finding_id": f["finding_id"]}
      for f in findings_lookup.get(node_uid, [])
      if f["finding_type"] == "misconfig"
  ][:10]  # cap at 10 per node
  ```
- [ ] AC-7: Similarly populate `attack_path_nodes.cves` from CVE rows:
  ```python
  node_cves = [
      {"cve_id": f["rule_id"], "epss": f["epss_score"],
       "cvss": f["cvss_score"], "in_kev": f["in_kev"],
       "finding_id": f["finding_id"]}
      for f in findings_lookup.get(node_uid, [])
      if f["finding_type"] == "cve"
  ][:10]
  ```
- [ ] AC-8: `attack_path_nodes.threat_detections` populated from CDR rows:
  ```python
  node_cdr = [
      {"technique": f["mitre_technique_id"], "tactic": f["mitre_tactic"],
       "severity": f["severity"], "finding_id": f["finding_id"]}
      for f in findings_lookup.get(node_uid, [])
      if f["finding_type"] == "cdr_event"
  ][:5]
  ```
- [ ] AC-9: Cap enforced on all 3 JSONB arrays (10/10/5) — prevents unbounded JSONB growth for resources with hundreds of findings

### Functional — posture count derivation
- [ ] AC-10: In `engines/attack-path/attack_path_engine/db/posture_updater.py` (per AP-P2-07 AC-2 last step), when updating `resource_security_posture` after scan: derive `critical_misconfig_count` and `high_misconfig_count` from findings_lookup rather than leaving them at engine-written values:
  ```python
  critical_count = sum(
      1 for f in findings_lookup.get(uid, [])
      if f["finding_type"] == "misconfig" and f["severity"] == "critical"
  )
  ```
- [ ] AC-11: `max_epss` in posture table updated from CVE rows in findings_lookup for each resource on an attack path:
  ```python
  max_epss = max(
      (f["epss_score"] for f in findings_lookup.get(uid, [])
       if f["epss_score"] is not None),
      default=None
  )
  ```

### Integration
- [ ] AC-12: After full pipeline scan: `SELECT misconfigs FROM attack_path_nodes WHERE tenant_id='<tenant>' LIMIT 5` — at least 1 row has non-empty misconfigs array
- [ ] AC-13: A path node for an EC2 with known CVEs has non-empty `cves` array in attack_path_nodes
- [ ] AC-14: `resource_security_posture.critical_misconfig_count` for a known resource matches `SELECT COUNT(*) FROM security_findings WHERE resource_uid=$uid AND finding_type='misconfig' AND severity='critical'`

### Security (must pass bmad-security-reviewer)
- [ ] AC-15: `load_findings_by_resource()` query always includes `tenant_id = %s` — cannot be omitted
- [ ] AC-16: findings_lookup is NOT logged (may contain finding titles that reveal internal config)
- [ ] AC-17: No DEV_BYPASS_AUTH in new files
- [ ] AC-18: JSONB cap (AC-9) prevents DoS via bloated attack_path_nodes rows

## Technical Notes

**New file**: `engines/attack-path/attack_path_engine/db/findings_loader.py`

**Inventory DB connection in attack-path engine**: The attack-path engine already connects to `threat_engine_inventory` DB for posture_lookup (per AP-P2-07). `findings_loader.py` reuses the same `inv_conn` connection pool — no new credentials needed.

**Orchestration order in run_scan.py** (updated from AP-P2-07 AC-2):
```
CrownJewelClassifier.classify()
→ fetch posture_lookup from resource_security_posture       [AP-P2-07]
→ fetch findings_lookup from security_findings              [THIS STORY]
→ scorer.probability_score() + impact_score() per path      [uses findings_lookup for epss/cdr signals]
→ deduplicator.deduplicate()
→ choke_point_detector.detect_choke_points()
→ writer.write_paths() + write_path_nodes()                 [uses findings_lookup for node evidence]
→ posture_updater.update_attack_path_signals()              [uses findings_lookup for count derivation]
```

**Scorer integration**: The `probability_score()` function (AP-P2-04) currently checks `posture_lookup[uid].has_active_cdr_actor`. With findings_lookup, it can also check `any(f["in_kev"] for f in findings_lookup.get(uid, []) if f["finding_type"] == "cve")` for a KEV bonus on the probability score — optional enhancement.

**New image tag**: `yadavanup84/engine-attack-path:v-attack-path-sf1` (or next tag in sequence)

## Key Files
- `/Users/apple/Desktop/threat-engine/engines/attack-path/attack_path_engine/run_scan.py` (modify — add findings_lookup load step)
- `/Users/apple/Desktop/threat-engine/engines/attack-path/attack_path_engine/db/findings_loader.py` (create new)
- `/Users/apple/Desktop/threat-engine/engines/attack-path/attack_path_engine/core/writer.py` (modify — populate node evidence from findings_lookup)
- `/Users/apple/Desktop/threat-engine/engines/attack-path/attack_path_engine/db/posture_updater.py` (modify — derive counts from findings_lookup)
- `/Users/apple/Desktop/threat-engine/deployment/aws/eks/engines/engine-attack-path.yaml` (update image tag)

## Definition of Done
- [ ] `findings_loader.py` created and committed
- [ ] `run_scan.py` modified with findings_lookup load step
- [ ] `writer.py` populates misconfigs/cves/threat_detections from findings_lookup
- [ ] `posture_updater.py` derives critical_misconfig_count and max_epss from findings_lookup
- [ ] Docker image built and pushed: `v-attack-path-sf1`
- [ ] K8s manifest updated and rolled out
- [ ] AC-12/AC-13/AC-14 verified against live data
- [ ] MEMORY.md updated with attack-path image tag
- [ ] bmad-security-reviewer: no BLOCKERS
