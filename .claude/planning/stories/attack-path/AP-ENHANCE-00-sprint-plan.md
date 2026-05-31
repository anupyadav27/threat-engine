# Attack Path Enhancement Sprint — AP-ENHANCE

## Objective
Harden attack-path data quality, remove architectural debt, and align with
the agreed resource_security_posture + security_findings unified data layer.

## Decisions Made (2026-05-18)

| Decision | Rationale |
|---|---|
| Remove `confidence_level` field | P×I score already encodes certainty. CDR/MITRE signals fold into P directly |
| CDR detections → P score per hop | `security_findings` `threat_detection` findings boost P ×1.50 + MITRE tactic multiplier |
| MITRE batch enrichment before graph-build | One Argo step JOINs security_findings + rule_metadata to fill mitre_technique_id gaps |
| Crown jewel via threat-v1 | threat-v1 writes is_crown_jewel=true to resource_security_posture for T2/T3 targets |
| Internet entry points via posture | BFS reads is_internet_exposed from resource_security_posture, no :Internet Neo4j node needed |
| Graph-build unified from posture+findings | graph-build reads resource_security_posture + security_findings (not raw engine tables) |
| Canonical resource types in graph-build | graph-build writes canonical short type names to Neo4j (removes _TYPE_ALIASES stopgap) |

---

## Stories

### Phase 0 — Shipped (2026-05-18)
- [x] BFS fix: allow :Internet + :VirtualNode + is_internet_exposed UIDs as entry points
- [x] Type alias normalization in crown jewel classifier (stopgap)
- [x] CDR detections + MITRE tactic signals folded into P score (v-redesign-bff7)
- [x] `_fetch_internet_exposed_uids` from resource_security_posture pre-BFS
- [x] Threat UI consolidation: /threats/* + /threats-v1 routes removed from frontend
- [x] Threats BFF handlers removed from gateway (13 routers: threats, command_room, detail, scenario_detail, attack_paths, blast_radius, graph, toxic_combos, timeline, posture_delta, mitre_heatmap, technique_detail, threat_v1)
- [x] threat-v1 engine made backend-only (incidents/scan-status/feedback API routes removed)
- [x] All /threats nav links redirected to /attack-paths across dashboard, inventory, misconfig
- [x] Images: attack-path:v-redesign-bff7, gateway:v-bff-no-threats1, frontend:v-no-threats2, threat-v1:v-pipeline-only1

---

### AP-ENHANCE-01 — MITRE Batch Enrichment Argo Step
**Stage:** New Argo pipeline step between engines-complete and graph-build
**Owner:** engine + pipeline

**What:**
Add a lightweight Python job (`scripts/mitre_enrichment_job.py`) that runs as an Argo
WorkflowTemplate step. It joins `security_findings` with `rule_metadata` (check DB) and
fills `mitre_technique_id` + `mitre_tactic` where NULL.

```sql
UPDATE security_findings sf
SET  mitre_technique_id = rm.mitre_attack_id,
     mitre_tactic       = rm.mitre_tactic
FROM rule_metadata rm          -- in threat_engine_check DB
WHERE sf.rule_id = rm.rule_id
  AND sf.mitre_technique_id IS NULL
  AND rm.mitre_attack_id IS NOT NULL
```

**AC:**
- [ ] Runs as Argo step `mitre-enrich` after all engine steps, before `graph-build`
- [ ] Only updates rows with NULL mitre_technique_id (CDR rows preserved)
- [ ] Handles cross-DB join (security_findings in inventory DB, rule_metadata in check DB)
- [ ] Logs: rows_updated, tenant_id, scan_run_id
- [ ] Non-fatal: graph-build proceeds even if step fails

**Notes:**
- Cross-DB: script connects to both DBs via separate psycopg2 connections, does JOIN in Python
- OR: copy rule_metadata MITRE columns to check_findings during check scan, then security_findings writer picks them up

---

### AP-ENHANCE-02 — Crown Jewel Flag via Threat-V1
**Stage:** Threat engine (stage 4 in pipeline)
**Owner:** threat-v1 engine

**What:**
threat-v1 already detects T2/T3 patterns and writes `threat_scenario_incidents` with
`involved_resources`. For resources that are T2/T3 targets (the last hop = crown jewel),
write `is_crown_jewel=true` + `crown_jewel_type` to `resource_security_posture`.

**Changes:**
- `engines/threat-v1/threat_v1_engine/run_scan.py` — after T2/T3 pattern detection
- Write to `resource_security_posture`:
  ```python
  UPDATE resource_security_posture
  SET is_crown_jewel = true,
      crown_jewel_type = %s   -- derive from resource_type
  WHERE resource_uid = %s AND tenant_id = %s
  ```

**AC:**
- [ ] threat-v1 writes is_crown_jewel for T2/T3 incident target resources
- [ ] crown_jewel_type derived from resource_type using the canonical classifier dict
- [ ] CrownJewelClassifier in attack-path engine reads posture.is_crown_jewel first (override)
- [ ] No double-classification if posture already has is_crown_jewel=true
- [ ] Unit test: T3 incident target → is_crown_jewel=true in posture

---

### AP-ENHANCE-03 — Graph-Build Node Property Enrichment from Posture (Safe Migration)
**Stage:** Graph-build (stage 6 in pipeline)
**Owner:** threat engine (graph-build step)

**Scope: NODE PROPERTIES ONLY — edges are NOT changed in this story.**

**Why partial scope:**
`security_findings` is per-resource. Neo4j edges are relationships between two resources
(e.g., IAM_ROLE -[CAN_ACCESS]→ S3_BUCKET). Migrating edge creation to security_findings
would require a `resource_relationships` table (engines write source+edge_type+target) —
that is a separate sprint. Changing edge creation without it would break T2/T3 threat
pattern detection which depends on multi-hop graph traversal.

**What (this story):**
Graph-build enriches Neo4j node properties from `resource_security_posture`:
- Sets `is_crown_jewel=true` on Neo4j nodes where posture has it (instead of only from classifier)
- Sets `entry_point_type='internet'` on nodes where `is_internet_exposed=true` in posture
- Writes canonical `resource_type` (short name) alongside existing property
- Edge creation is UNCHANGED — still reads check_findings, IAM findings, etc.

**Future sprint (AP-GRAPH-01) — full migration:**
Add `resource_relationships` table → engines write source+edge_type+target when they
detect relationships → graph-build reads from it → :Internet node creation removed.
Only then is the full migration safe.

**AC:**
- [ ] graph-build reads resource_security_posture.is_crown_jewel → SET neo4j node property
- [ ] graph-build reads resource_security_posture.is_internet_exposed → SET entry_point_type
- [ ] Neo4j nodes gain `resource_type_canonical` property (short name alias)
- [ ] All existing edge creation unchanged — T2/T3 detection not affected
- [ ] Verified: threat-v1 pattern counts unchanged before/after deploy
- [ ] _TYPE_ALIASES in crown_jewel_classifier kept as fallback until AP-GRAPH-01

---

### AP-ENHANCE-04 — Remove confidence_level Column (Cleanup)
**Stage:** DB migration + BFF + frontend
**Owner:** attack-path engine + gateway BFF

**What:**
Remove `confidence_level` as a standalone field. It was a label (confirmed/likely/speculative)
derived from T2/T3 incident overlap. Now P score encodes this directly.

**Changes:**
- DB migration: `DROP COLUMN confidence_level` from `attack_paths` (or mark deprecated)
- BFF: remove confidence_level filter from `/views/attack-paths` query
- Frontend: remove confidence filter pill from attack-paths page
- Scorer: `path_enricher.py` no longer writes confidence_level (T2/T3 overlap still stored in attack_technique_chain for reference)

**AC:**
- [ ] No confidence_level in BFF response
- [ ] Frontend filter pill removed
- [ ] attack_technique_chain + threat_pattern_ids retained (T2/T3 incident references kept)
- [ ] attack_story retained (useful narrative, just not labeled by confidence)
- [ ] Migration is backward compatible (old rows have confidence_level, new rows NULL)

---

### AP-ENHANCE-05 — security_findings MITRE Schema Enforcement
**Stage:** Each engine's security_findings writer
**Owner:** Per engine

**What:**
Ensure every engine that knows the MITRE technique writes it to security_findings.
Currently only CDR writes mitre_technique_id consistently. The MITRE batch enrichment
(AP-ENHANCE-01) handles rule-based findings. This story covers non-rule findings.

**Engines to update:**
| Engine | MITRE source |
|---|---|
| network | rule_metadata.mitre_attack_id on network_exposure findings |
| IAM | rule_metadata.mitre_attack_id on iam_violation findings |
| datasec | rule_metadata (data exfiltration techniques) |
| vuln | CVE→MITRE mapping from NVD (already in vuln tables) |

**AC:**
- [ ] network engine writes mitre_technique_id on network_exposure findings
- [ ] IAM engine writes mitre_technique_id on iam_violation findings
- [ ] vuln engine writes mitre_technique_id from CVE NVD data
- [ ] Verified: SELECT count(*) FROM security_findings WHERE mitre_technique_id IS NOT NULL > 0 per engine

---

---

### AP-GRAPH-01 — resource_relationships Table + Full Graph-Build Migration (Future Sprint)
**Blocked by:** All engines writing to resource_relationships

**What:**
Add `resource_relationships` table to threat_engine_inventory:
```sql
CREATE TABLE resource_relationships (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       VARCHAR(255) NOT NULL,
    scan_run_id     UUID NOT NULL,
    source_uid      VARCHAR(512) NOT NULL,   -- the resource that has the capability
    target_uid      VARCHAR(512) NOT NULL,   -- the resource being accessed/exposed
    edge_type       VARCHAR(64) NOT NULL,    -- EXPOSES | CAN_ACCESS | CAN_ESCALATE_TO | FLOWS_TO | EXECUTES_IN
    source_engine   VARCHAR(64) NOT NULL,    -- check | network | iam | cdr | k8s
    detail          JSONB,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);
```

Engines write to this table:
- network engine → EXPOSES (internet-facing resources)
- IAM engine → CAN_ACCESS (role→resource), CAN_ESCALATE_TO
- CDR engine → CAN_MOVE_TO (lateral movement detections)
- container engine → EXECUTES_IN (workload→cluster)

Graph-build reads `resource_relationships` → creates Neo4j edges from it.
:Internet node creation removed (replaced by EXPOSES edges from network engine).

**Only after this is complete can AP-ENHANCE-03 full migration happen.**

---

## Pipeline Order After This Sprint

```
Onboarding → Discovery → Inventory → Check → Threat-V1 → [Compliance/IAM/Network/CDR/...]
                                                  ↓
                                          MITRE-Enrich (new — AP-ENHANCE-01)
                                                  ↓
                                          Graph-Build (unified from posture+findings)
                                                  ↓
                                          Attack-Path (BFS from Neo4j + posture signals)
                                                  ↓
                                          Risk Engine
```

## Image Tags (start of sprint)

| Component | Current tag |
|---|---|
| engine-attack-path | v-redesign-bff7 (CDR/MITRE in P score) |
| engine-threat-v1 | v-threat-v1-phase25 |
| cspm-pipeline | current |
