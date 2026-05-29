---
title: "Architecture — Security Findings Unified Layer"
type: architecture
status: approved
version: "1.0"
date: "2026-05-15"
author: "Anup Yadave"
sub-project-of: "Attack Path Engine Epic"
---

# Architecture: Security Findings Unified Layer (`security_findings`)

## 1. Purpose & Scope

`security_findings` is a cross-engine unified findings table living in the `threat_engine_inventory` DB. It provides a single, queryable, paginated view of all individual security violations (misconfigs, CVEs, IAM violations, CDR events, data risks) across all scan engines — without replacing any engine's own table.

**This is a sub-project of the Attack Path Engine epic. It ships alongside attack-path stories, not after them.**

**What it is:**
- One row per individual finding (1:N with resources)
- Written by each engine after its scan step via a shared writer utility
- The authoritative source for cross-engine sorted/filtered findings lists
- The source from which `resource_security_posture` count columns are derived
- The source from which `attack_path_nodes.misconfigs / cves / threat_detections` are populated

**What it is NOT:**
- Not a replacement for per-engine raw tables (`check_findings`, `iam_findings`, etc.) — those stay for engine-internal use
- Not a duplicate of `resource_security_posture` (which is 1 row per resource; this is N rows per resource)
- Not the posture/aggregate layer — that is `resource_security_posture`

---

## 2. Why Not Merge With resource_security_posture

These two tables have fundamentally different cardinality:

```
resource_security_posture  →  1 row per resource  (aggregate state)
security_findings          →  N rows per resource  (individual violations)
```

Merging them requires either repeating posture columns on every finding row (update anomalies, wasted storage) or storing findings as a JSONB array (not pageable, not indexable).

**They are complementary:**

| Question | Table |
|----------|-------|
| "Is this resource on an attack path?" | resource_security_posture |
| "What is this resource's posture score?" | resource_security_posture |
| "What specific rules fired on EC2 i-abc123?" | security_findings |
| "Show all CVEs sorted by EPSS for this tenant" | security_findings |
| "How many critical misconfigs does this resource have?" | resource_security_posture (pre-aggregated FROM security_findings) |

`resource_security_posture.critical_misconfig_count` is a cached aggregate computed FROM `security_findings`. The posture table is the materialized summary; `security_findings` is the normalized source.

---

## 3. What Is NOT Duplicated From Existing Plans

| Existing Story | What It Does | security_findings Relation |
|----------------|-------------|--------------------------|
| AP-P0-01 | Creates `resource_security_posture` table | Different table, different purpose |
| AP-P0-02 | Creates `posture_writer.py` shared utility | security_findings creates its own `security_findings_writer.py` (SF-P0-02) |
| AP-P0-03 | Wires IAM/network/datasec/CDR to write posture signals | SF-P1-01/P1-02 wire same engines to ALSO write security_findings — different write, same hook point |
| AP-P2-01 | Creates `attack_paths`, `attack_path_nodes` tables | `attack_path_nodes.misconfigs JSONB` populated FROM security_findings (SF-P3-01) |
| AP-P4-04 | Asset detail posture tabs from resource_security_posture | SF-P2-01 adds a "Findings" tab from security_findings — different tab, not same data |

**Key integration point (SF-P3-01):** `attack_path_nodes.misconfigs` currently stores inline JSONB blobs. After SF ships, the attack-path writer reads security_findings by resource_uid and populates these fields from normalized rows, eliminating duplicate data copying.

---

## 4. Schema

### 4.1 `security_findings` (threat_engine_inventory DB)

```sql
CREATE TABLE IF NOT EXISTS security_findings (
    finding_id          UUID DEFAULT gen_random_uuid() PRIMARY KEY,

    -- Source identity
    source_engine       VARCHAR(50)   NOT NULL,   -- check|iam|vuln|cdr|datasec|network
    source_finding_id   VARCHAR(255)  NOT NULL,   -- engine's native finding_id/key

    -- Standard columns (constitution-mandated)
    resource_uid        VARCHAR(512)  NOT NULL,
    scan_run_id         UUID          NOT NULL,
    tenant_id           VARCHAR(255)  NOT NULL,
    account_id          VARCHAR(512),
    provider            VARCHAR(50),
    resource_type       VARCHAR(255),

    -- Classification
    finding_type        VARCHAR(50)   NOT NULL,
    -- misconfig | cve | iam_violation | cdr_event | data_risk | network_exposure
    severity            VARCHAR(20)   NOT NULL,   -- critical|high|medium|low
    rule_id             VARCHAR(255),             -- NULL for CVEs, CDR events
    title               TEXT          NOT NULL,
    description         TEXT,

    -- Normalized evidence (populated selectively by engine)
    epss_score          FLOAT,                    -- vuln only
    cvss_score          FLOAT,                    -- vuln only
    in_kev              BOOLEAN DEFAULT FALSE,    -- vuln only (CISA KEV)
    mitre_technique_id  VARCHAR(20),              -- cdr|threat findings
    mitre_tactic        VARCHAR(100),

    -- Engine-specific detail
    detail              JSONB,                    -- raw engine payload

    -- Lifecycle
    status              VARCHAR(20) DEFAULT 'open',
    -- open | suppressed | resolved
    first_seen_at       TIMESTAMPTZ DEFAULT NOW(),
    last_seen_at        TIMESTAMPTZ DEFAULT NOW(),
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    updated_at          TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE (source_engine, source_finding_id, tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_sf_tenant_scan
    ON security_findings(tenant_id, scan_run_id);

CREATE INDEX IF NOT EXISTS idx_sf_resource
    ON security_findings(resource_uid, tenant_id);

CREATE INDEX IF NOT EXISTS idx_sf_severity
    ON security_findings(tenant_id, severity);

CREATE INDEX IF NOT EXISTS idx_sf_type
    ON security_findings(tenant_id, finding_type);

CREATE INDEX IF NOT EXISTS idx_sf_engine
    ON security_findings(tenant_id, source_engine);

CREATE INDEX IF NOT EXISTS idx_sf_open
    ON security_findings(tenant_id, severity, last_seen_at DESC)
    WHERE status = 'open';

CREATE INDEX IF NOT EXISTS idx_sf_epss
    ON security_findings(tenant_id, epss_score DESC)
    WHERE epss_score IS NOT NULL;
```

**Migration:** `025_security_findings.sql` in `shared/database/migrations/`
**Target DB:** `threat_engine_inventory` (same DB as `resource_security_posture`)

---

## 5. Pipeline Wiring — Which Engine Writes What

Each engine appends a write to `security_findings` at the end of its existing scan completion handler. Same hook point as AP-P0-03 posture writes — one scan completion handler, two table writes (posture + security_findings).

| Engine | Stage | finding_type | source_finding_id |
|--------|-------|-------------|-------------------|
| check | 3 | `misconfig` | `check_findings.finding_id` (sha256 hash) |
| iam | 5 | `iam_violation` | `iam_findings.finding_id` |
| network-security | 5 | `network_exposure` | `network_findings.finding_id` |
| datasec | 5 | `data_risk` | `datasec_findings.finding_id` |
| vuln | 5 | `cve` | `sha256(cve_id + resource_uid)[:32]` |
| cdr (cron) | independent | `cdr_event` | `cdr_findings.detection_id` |

**Rules:**
- Each engine writes only its own `source_engine` rows — never another engine's rows
- ON CONFLICT (source_engine, source_finding_id, tenant_id) DO UPDATE: update `last_seen_at`, `scan_run_id`, `status`, `severity`, `detail`
- `first_seen_at` is never updated (preserves age of finding)
- Batch upsert in chunks of 500 — same pattern as posture_writer

---

## 6. Shared Writer Utility

`shared/common/engine_common/security_findings_writer.py`

```python
def upsert_findings(
    conn,
    findings: list[dict],   # list of FindingRow dicts
    source_engine: str,
    tenant_id: str,
    scan_run_id: str,
    batch_size: int = 500,
) -> int:
    """
    Idempotent upsert of findings into security_findings.
    Each engine calls this after writing to its own table.
    Returns count of rows upserted.
    """
```

`FindingRow` is a TypedDict with all security_findings columns. Each engine builds its engine-specific rows and passes them to this utility.

---

## 7. BFF Layer

### 7.1 Asset Findings Endpoint (new)

`GET /api/v1/views/inventory/asset/{uid}/findings`

Replaces per-engine API calls in the inventory asset detail page. One query across all engines for a resource.

**Query:**
```sql
SELECT * FROM security_findings
WHERE resource_uid = %s AND tenant_id = %s AND status = 'open'
ORDER BY
    CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                  WHEN 'medium' THEN 3 ELSE 4 END,
    last_seen_at DESC
LIMIT 100
```

**Response:**
```json
{
  "findings": [
    {
      "finding_id": "...",
      "source_engine": "check",
      "finding_type": "misconfig",
      "severity": "critical",
      "rule_id": "aws-sg-ssh-open",
      "title": "SSH open to 0.0.0.0/0",
      "status": "open",
      "last_seen_at": "2026-05-15T14:00:00Z"
    },
    {
      "finding_id": "...",
      "source_engine": "vuln",
      "finding_type": "cve",
      "severity": "critical",
      "title": "CVE-2023-44487 (HTTP/2 Rapid Reset)",
      "epss_score": 0.94,
      "in_kev": true,
      "last_seen_at": "2026-05-15T14:00:00Z"
    }
  ],
  "total": 14,
  "by_engine": {"check": 8, "vuln": 4, "iam": 2},
  "by_severity": {"critical": 3, "high": 6, "medium": 5}
}
```

**Permission:** `discoveries:read` (viewer-accessible)
**Field stripping:** `detail` JSONB stripped for viewer role (bulk data, not needed in list view)

### 7.2 Unified Findings View (new)

`GET /api/v1/views/findings`

Tenant-wide cross-engine findings. Powers a future "All Findings" page.

**Query params:** `severity`, `finding_type`, `source_engine`, `status`, `resource_uid`, `page`, `page_size`
**Permission:** `discoveries:read`

---

## 8. Integration With Attack-Path Engine

### 8.1 Node Evidence Population (SF-P3-01)

`attack_path_nodes.misconfigs JSONB` currently defined as:
```json
[{"rule_id": "...", "severity": "high", "title": "..."}]
```

After SF-P3-01, the attack-path writer (`choke_point_detector_db_writer.py`) queries `security_findings` at write time instead of copying data from cross-engine APIs:

```python
findings_lookup = load_findings_by_resource(
    conn, tenant_id, scan_run_id
)  # {resource_uid: [FindingRow, ...]}

# For each hop node:
node_misconfigs = [
    {"rule_id": f.rule_id, "severity": f.severity,
     "title": f.title, "finding_id": str(f.finding_id)}
    for f in findings_lookup.get(node_uid, [])
    if f.finding_type == "misconfig"
]
node_cves = [
    {"cve_id": f.rule_id, "epss": f.epss_score,
     "cvss": f.cvss_score, "in_kev": f.in_kev,
     "finding_id": str(f.finding_id)}
    for f in findings_lookup.get(node_uid, [])
    if f.finding_type == "cve"
]
```

This eliminates the attack-path engine needing direct connections to check DB and vuln DB at scan time. It reads only from `security_findings` (same DB as `resource_security_posture`).

### 8.2 Posture Count Derivation (SF-P3-01)

`resource_security_posture.critical_misconfig_count` and `high_misconfig_count` are currently written by each engine estimating from its own findings. After SF, the posture_writer utility derives these from security_findings:

```python
counts = conn.execute("""
    SELECT severity, COUNT(*) FROM security_findings
    WHERE resource_uid = %s AND tenant_id = %s
      AND scan_run_id = %s AND finding_type = 'misconfig'
      AND status = 'open'
    GROUP BY severity
""", (resource_uid, tenant_id, scan_run_id))
```

This ensures the posture table counts are always consistent with the actual findings.

### 8.3 Pipeline Order (no change required)

```
Stage 3: check → writes check_findings + security_findings (misconfig)
Stage 5: [IAM|net|datasec|vuln|CDR] → writes own tables + security_findings
Stage 6: threat_v1 graph-build runs (reads check_findings, cdr_findings directly — unchanged)
Stage 6.5: attack-path → reads security_findings for node evidence + posture counts
```

SF writes happen at the same stage as posture writes (AP-P0-03). attack-path (6.5) runs after all SF writes are complete.

---

## 9. Security Architecture

### STRIDE
| Threat | Component | Mitigation |
|--------|-----------|-----------|
| Info Disclosure | Cross-tenant query | All queries: `WHERE tenant_id = $tid` from AuthContext. source_finding_id is engine's hash, not guessable |
| Tampering | Engine writes wrong tenant_id | tenant_id taken from scan's AuthContext parameter, NOT from resource metadata (same rule as posture_writer) |
| DoS | 500K finding upserts | Batch in chunks of 500; single transaction per batch |
| Info Disclosure | detail JSONB contains PII | detail JSONB stripped for viewer role by BFF `strip_sensitive_fields()` |

### RBAC
- `GET /views/findings` and `GET /views/inventory/asset/{uid}/findings`: `discoveries:read` (all roles including viewer)
- viewer: `detail` JSONB stripped from response
- analyst/tenant_admin: full response
- No write endpoints exposed via gateway — writes are internal (engine scan handlers only)

### Multi-Tenancy
- UNIQUE constraint: `(source_engine, source_finding_id, tenant_id)` — cross-tenant collision impossible by design
- All BFF queries: `tenant_id` from `AuthContext.engine_tenant_id` only, never from query params

---

## 10. ADRs

### ADR-SF-001: Same DB as resource_security_posture

**Decision:** `security_findings` lives in `threat_engine_inventory` DB alongside `resource_security_posture`.

**Rationale:** The attack-path engine already connects to `threat_engine_inventory` DB (for posture lookup). Having `security_findings` in the same DB eliminates one additional connection for the attack-path engine's node evidence population. The BFF posture endpoint and findings endpoint also share a single DB connection.

### ADR-SF-002: Separate Writer Utility (not merged with posture_writer)

**Decision:** `security_findings_writer.py` is separate from `posture_writer.py`.

**Rationale:** posture_writer is called once per resource per scan (upsert of aggregate signals). security_findings_writer is called once per individual finding (upsert of violations). Different calling patterns, different batch sizes, different ON CONFLICT semantics. Merging them would create a multi-purpose utility that violates single-responsibility.

### ADR-SF-003: Keep Per-Engine Tables

**Decision:** Per-engine raw tables (`check_findings`, `iam_findings`, etc.) are NOT deprecated.

**Rationale:** Engines need their own tables for: (1) engine-internal joins and queries during scan, (2) audit/replay of raw findings, (3) engine-specific columns not in security_findings (e.g., `check_findings.rule_metadata`, `iam_findings.policy_document`). security_findings is the query-time cross-engine layer, not a replacement for operational engine tables.
