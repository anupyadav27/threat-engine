# Threat UI Master Plan — v2

> **Date**: 2026-03-17
> **Status**: Planning
> **Owner**: Platform Engineering

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Architecture & Data Flow](#2-architecture--data-flow)
3. [Phase 1 — Fix Plumbing](#3-phase-1--fix-plumbing)
4. [Phase 2 — Threat Detail Page Redesign](#4-phase-2--threat-detail-page-redesign)
5. [Phase 3 — Threat List Page Redesign](#5-phase-3--threat-list-page-redesign)
6. [Phase 4 — Threat vs Findings Differentiation](#6-phase-4--threat-vs-findings-differentiation)
7. [Phase 5 — Advanced Workflows](#7-phase-5--advanced-workflows)
8. [User Stories](#8-user-stories)
9. [Agent Definitions & Execution Plan](#9-agent-definitions--execution-plan)

---

## 1. Executive Summary

### Goal
Transform the Threat UI from a flat data table into an **investigation-ready analyst workspace** that clearly differentiates threats from findings, surfaces attack paths and blast radius contextually, and enables seamless pivoting between triage and deep investigation.

### Current State
- 9 threat pages exist (list, detail, analytics, attack-paths, blast-radius, graph, hunting, internet-exposed, toxic-combinations)
- BFF layer (`bff/threats.py`) properly wired with normalization transforms
- Unified UI data endpoint (`/api/v1/threat/ui-data`) returns comprehensive data
- 65+ backend endpoints in threat engine
- **Key gaps**: detail page fetches entire list, missing DB columns, field name mismatches, no supporting findings on detail page

### Target State
- Threat detail page with 11 investigation blocks
- Clear threat vs finding separation with cross-linking
- Working data flow: DB → Engine → BFF → UI for every field
- Hunt integration from threat context
- Exposure/path/blast radius as distinct visual concepts

---

## 2. Architecture & Data Flow

### End-to-End Data Pipeline

```
┌─────────────┐    ┌──────────────┐    ┌──────────────┐    ┌─────────────┐
│  PostgreSQL  │───→│ Threat Engine│───→│  BFF Layer   │───→│   Next.js   │
│  (RDS)       │    │  (Port 8020) │    │  (Gateway)   │    │   Frontend  │
└─────────────┘    └──────────────┘    └──────────────┘    └─────────────┘
  threat_findings     /api/v1/threat/*   /api/v1/views/*     fetchView()
  threat_report       /api/v1/graph/*    normalize_*()       getFromEngine()
  threat_analysis     /api/v1/hunt/*     aggregate()
  threat_detections   /api/v1/intel
  mitre_technique_ref
```

### Data Flow Per Page

| UI Page | API Pattern | BFF Route | Engine Endpoints | DB Tables |
|---------|------------|-----------|-----------------|-----------|
| Threat List | `fetchView('threats')` | `GET /api/v1/views/threats` | `/threat/ui-data` + `/onboarding/ui-data` | threat_findings, threat_report |
| Threat Detail | `getFromEngine('threat', '/api/v1/threat/{id}/detail')` | N/A (direct) | `/threat/{id}/detail` (NEW) | threat_findings + cross-engine joins |
| Analytics | `getFromEngine('threat', '/api/v1/threat/analytics/*')` | N/A (direct) | `/analytics/distribution`, `/analytics/trend`, `/analytics/mitre` | threat_findings aggregations |
| Attack Paths | `getFromEngine('threat', '/api/v1/graph/attack-paths')` | N/A (direct) | `/graph/attack-paths` | Neo4j graph + threat_findings |
| Blast Radius | `getFromEngine('threat', '/api/v1/graph/blast-radius/{uid}')` | N/A (direct) | `/graph/blast-radius/{uid}` | Neo4j graph |
| Graph | `getFromEngine('inventory', '/api/v1/inventory/runs/latest/graph')` | N/A (direct) | inventory graph | inventory_findings + relationships |
| Hunting | `getFromEngine('threat', '/api/v1/hunt/*')` | N/A (direct) | `/hunt/queries`, `/intel` | threat_hunt_queries, threat_intelligence |
| Internet Exposed | `getFromEngine('threat', '/api/v1/graph/internet-exposed')` | N/A (direct) | `/graph/internet-exposed` | Neo4j graph |
| Toxic Combos | `getFromEngine('threat', '/api/v1/graph/toxic-combinations')` | N/A (direct) | `/graph/toxic-combinations` | Neo4j graph + threat_findings |

---

## 3. Phase 1 — Fix Plumbing

### 3.1 Task: Create Threat Detail Endpoint

**Problem**: Detail page fetches entire threat list (1000 items) and filters client-side.

**DB → Engine → BFF → UI flow:**

```
DB: SELECT * FROM threat_findings WHERE finding_id = %s AND tenant_id = %s
    + JOIN mitre_technique_reference ON technique_id
    + SELECT * FROM check_findings WHERE resource_uid = tf.resource_uid (supporting findings)

Engine: GET /api/v1/threat/{threat_id}/detail?tenant_id=X
  Response: {
    threat: { ...full threat_findings row + enrichments },
    supporting_findings: [ ...check_findings rows ],
    mitre_context: { technique_id, name, description, tactics, detection_guidance, remediation_guidance },
    blast_radius_summary: { reachable_count, resources_with_threats },
    attack_path: { exists: bool, path_id, steps_count },
    remediation: { steps: [], auto_remediable: bool, priority: str }
  }

BFF: Not needed — detail page calls engine directly

UI: getFromEngine('threat', `/api/v1/threat/${threatId}/detail`)
```

**Files to change:**
| Layer | File | Change |
|-------|------|--------|
| Engine | `engines/threat/threat_engine/api_server.py` | Add `GET /api/v1/threat/{threat_id}/detail` route |
| Engine | `engines/threat/threat_engine/api/detail_router.py` (NEW) | Detail endpoint logic with cross-DB queries |
| UI | `ui_samples/src/app/threats/[threatId]/page.jsx` | Replace list-fetch with direct detail call |

### 3.2 Task: Add Missing DB Columns

**Schema changes needed:**

```sql
-- Add assignee column to threat_findings
ALTER TABLE threat_findings ADD COLUMN assignee VARCHAR(255);
ALTER TABLE threat_findings ADD COLUMN assigned_at TIMESTAMP;

-- Add status history for timeline
ALTER TABLE threat_findings ADD COLUMN status_history JSONB DEFAULT '[]'::jsonb;
-- Format: [{"status": "open", "timestamp": "...", "actor": "system"}, ...]

-- Add index for assignee queries
CREATE INDEX idx_tf_assignee ON threat_findings(assignee) WHERE assignee IS NOT NULL;
```

**Files to change:**
| Layer | File | Change |
|-------|------|--------|
| DB | `shared/database/schemas/threat_schema.sql` | Add columns |
| DB | `shared/database/alembic/versions/threat/add_assignee_and_timeline.py` (NEW) | Alembic migration |
| Engine | `engines/threat/threat_engine/api_server.py` | PATCH endpoint for assignee + status |
| BFF | `shared/api_gateway/bff/_transforms.py` | `normalize_threat()` already handles assignee |

### 3.3 Task: Add Missing Analytics Endpoints

**`/api/v1/threat/analytics/mitre`** — MITRE heatmap data

```
DB: SELECT mt.technique_id, mt.technique_name, mt.tactics, mt.severity_base,
           COUNT(tf.id) as count
    FROM threat_findings tf
    JOIN mitre_technique_reference mt ON mt.technique_id = ANY(
        SELECT jsonb_array_elements_text(tf.mitre_techniques)
    )
    WHERE tf.tenant_id = %s
    GROUP BY mt.technique_id, mt.technique_name, mt.tactics, mt.severity_base

Engine Response: {
  matrix: [
    { technique_id: "T1078", technique_name: "Valid Accounts",
      tactics: ["Initial Access", "Persistence"], count: 45, severity_base: "high" }
  ]
}

BFF: Already handled in bff/threats.py lines 103-129 — builds mitre_matrix dict from engine response
```

**`/api/v1/threat/analytics/top-services`** — Already available via `/ui-data` as `summary.by_service`

```
DB: SELECT service, COUNT(*) as count,
           SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) as critical,
           SUM(CASE WHEN severity='high' THEN 1 ELSE 0 END) as high,
           SUM(CASE WHEN severity='medium' THEN 1 ELSE 0 END) as medium,
           SUM(CASE WHEN severity='low' THEN 1 ELSE 0 END) as low
    FROM threat_findings WHERE tenant_id = %s
    GROUP BY service ORDER BY count DESC LIMIT 10

Engine Response: { services: [{ service, count, critical, high, medium, low }] }
```

**`/api/v1/graph/toxic-combinations/matrix`** — Co-occurrence matrix

```
DB: Cross-join threat_findings by resource_uid to find resources with multiple threat types
    SELECT tf1.threat_category as cat1, tf2.threat_category as cat2, COUNT(DISTINCT tf1.resource_uid) as count
    FROM threat_findings tf1
    JOIN threat_findings tf2 ON tf1.resource_uid = tf2.resource_uid AND tf1.threat_category < tf2.threat_category
    WHERE tf1.tenant_id = %s
    GROUP BY cat1, cat2

Engine Response: {
  matrix: [
    { category1: "iam_misconfiguration", category2: "data_exposure", co_occurrence_count: 12, example_resources: [...] }
  ]
}
```

**Files to change:**
| Layer | File | Change |
|-------|------|--------|
| Engine | `engines/threat/threat_engine/api_server.py` | Add `/analytics/mitre`, `/analytics/top-services`, `/graph/toxic-combinations/matrix` |
| Engine | `engines/threat/threat_engine/api/analytics_router.py` (NEW) | Analytics query logic |

### 3.4 Task: Fix Field Name Mismatches

| UI Expects | Engine Returns | Where to Fix | Fix |
|-----------|---------------|-------------|-----|
| `t.mitreTactic` | `t.mitre_tactic` | `threats/page.jsx` line 70 | Change UI to read `mitre_tactic` |
| `t.riskScore` | `t.riskScore` AND `t.risk_score` | Already dual-returned by BFF | No fix needed |
| `attackChain.title` | `attackChain.name` | BFF `normalize_attack_chain()` | Already returns `name` — update UI |
| `attackChain.detectionTime` | `attackChain.detectionTime` | BFF already normalizes | No fix needed |

---

## 4. Phase 2 — Threat Detail Page Redesign

### 4.1 Block-Level UI Design

```
┌─────────────────────────────────────────────────────────────────┐
│ ← Back to Threats    Threat ID: tf-a7b3c9    Status: ● Active  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─── ① THREAT HEADER ───────────────────────────────────────┐ │
│  │ [CRITICAL]  S3 Bucket Public with Sensitive Data Exposure  │ │
│  │                                                            │ │
│  │ MITRE: T1530 · Data from Cloud Storage                     │ │
│  │ Risk Score: ████████████░░ 87/100                          │ │
│  │ Provider: AWS  Account: 588989875114  Region: ap-south-1   │ │
│  │ Assignee: [unassigned ▼]  First Seen: 2026-03-14          │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                 │
│  ┌─── ② EXPOSURE CONTEXT ─── [visible if exposure detected] ─┐ │
│  │ 🌐 INTERNET EXPOSED                                        │ │
│  │ ┌──────────┐    ┌──────────┐    ┌──────────┐              │ │
│  │ │ Internet │───→│ ALB/NLB  │───→│ S3 Bucket│              │ │
│  │ │          │    │ public   │    │ public   │              │ │
│  │ └──────────┘    └──────────┘    └──────────┘              │ │
│  │ Exposure Type: Direct Public Access                        │ │
│  │ Public Since: 2026-03-10  Access Pattern: Anonymous Read   │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                 │
│  ┌─── ③ ATTACK PATH ─── [visible if path exists] ────────────┐ │
│  │ Attack Chain: 3 steps · 5 resources affected               │ │
│  │                                                            │ │
│  │ ┌─────────┐  T1078  ┌─────────┐  T1530  ┌─────────┐     │ │
│  │ │IAM Role │───────→│S3 Bucket│───────→│ Sensitive│     │ │
│  │ │overperm │        │ public  │        │  Data   │     │ │
│  │ └─────────┘        └─────────┘        └─────────┘     │ │
│  │                                                            │ │
│  │ [View Full Attack Path →]                                  │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                 │
│  ┌─── ④ AFFECTED RESOURCES ──────────────────────────────────┐ │
│  │ 3 resources involved                                       │ │
│  │ ┌─────────────────────────────────────────────────────┐   │ │
│  │ │ Resource UID        │ Type     │ Account  │ Region  │   │ │
│  │ ├─────────────────────┼──────────┼──────────┼─────────│   │ │
│  │ │ arn:aws:s3:::data-bk│ S3Bucket │ 5889...  │ global  │   │ │
│  │ │ arn:aws:iam::role/.. │ IAMRole  │ 5889...  │ global  │   │ │
│  │ │ arn:aws:ec2::i-0a... │ Instance │ 5889...  │ ap-s-1  │   │ │
│  │ └─────────────────────────────────────────────────────┘   │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                 │
│  ┌─── ⑤ BLAST RADIUS ─── [collapsed by default] ─────────────┐ │
│  │ ▶ Blast Radius: 12 reachable · 3 with threats              │ │
│  │   [Click to expand radial graph]                            │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                 │
│  ┌─── ⑥ SUPPORTING FINDINGS ────────────────────────────────┐ │
│  │ 4 misconfiguration findings contribute to this threat      │ │
│  │ ┌─────────────────────────────────────────────────────┐   │ │
│  │ │ Rule ID           │ Severity │ Resource    │ Status │   │ │
│  │ ├───────────────────┼──────────┼─────────────┼────────│   │ │
│  │ │ s3-public-access  │ CRITICAL │ data-bkt    │ FAIL   │   │ │
│  │ │ s3-encryption-off │ HIGH     │ data-bkt    │ FAIL   │   │ │
│  │ │ iam-overperm-role │ HIGH     │ data-role   │ FAIL   │   │ │
│  │ │ s3-logging-off    │ MEDIUM   │ data-bkt    │ FAIL   │   │ │
│  │ └─────────────────────────────────────────────────────┘   │ │
│  │ [View in Findings →]                                       │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                 │
│  ┌─── ⑦ REMEDIATION ────────────────────────────────────────┐ │
│  │ Priority: IMMEDIATE    Auto-Remediable: ✅ Yes            │ │
│  │                                                            │ │
│  │ 1. Block public access on S3 bucket                        │ │
│  │    aws s3api put-public-access-block --bucket data-bkt ... │ │
│  │ 2. Enable server-side encryption                           │ │
│  │    aws s3api put-bucket-encryption --bucket data-bkt ...   │ │
│  │ 3. Restrict IAM role permissions to least-privilege        │ │
│  │    Review and scope down iam:* to specific actions         │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                 │
│  ┌─── ⑧ EVIDENCE ─── [collapsed] ───────────────────────────┐ │
│  │ ▶ Raw Evidence & Configuration Details                     │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                 │
│  ┌─── ⑨ MITRE CONTEXT ─── [collapsed] ──────────────────────┐ │
│  │ ▶ T1530 — Data from Cloud Storage Object                  │ │
│  │   Tactic: Collection                                       │ │
│  │   Platforms: AWS, Azure, GCP                               │ │
│  │   [Expand for detection guidance & related techniques]     │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                 │
│  ┌─── ⑩ TIMELINE ─── [collapsed] ───────────────────────────┐ │
│  │ ▶ Activity Timeline (3 events)                             │ │
│  │   2026-03-14 09:15  Detected by scan bfed9ebc...          │ │
│  │   2026-03-14 09:16  Status: open                           │ │
│  │   2026-03-15 14:30  Re-detected in scan c4a1b2...         │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                 │
│  ┌─── ⑪ HUNT ACTIONS ─── [collapsed] ───────────────────────┐ │
│  │ ▶ Investigation Actions                                    │ │
│  │   • Find similar threats (same rule_id)                    │ │
│  │   • Find all assets with same exposure pattern             │ │
│  │   • View related identities                                │ │
│  │   • Open in Graph Explorer                                 │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 4.2 Data Contract: Detail Page

**What the UI needs** (full data contract for the detail page):

```javascript
// GET /api/v1/threat/{threat_id}/detail?tenant_id=X
{
  // ① Header
  "threat": {
    "finding_id": "tf-a7b3c9...",
    "title": "S3 Bucket Public with Sensitive Data Exposure",
    "description": "An S3 bucket with public access enabled contains...",
    "severity": "critical",
    "status": "active",
    "risk_score": 87,
    "threat_category": "data_exposure",
    "resource_uid": "arn:aws:s3:::data-bucket",
    "resource_type": "s3.bucket",
    "account_id": "588989875114",
    "region": "ap-south-1",
    "provider": "AWS",
    "assignee": null,
    "assigned_at": null,
    "first_seen_at": "2026-03-14T09:15:00Z",
    "last_seen_at": "2026-03-15T14:30:00Z",
    "rule_id": "s3-public-data-exposure",
    "scan_run_id": "bfed9ebc-68e7-4f9d-83e1-24ce75e21d01",
    "evidence": { /* raw JSONB */ },
    "finding_data": { /* enriched data */ }
  },

  // ② Exposure Context
  "exposure": {
    "is_internet_exposed": true,
    "exposure_type": "direct_public_access",  // direct_public_access | load_balancer | api_gateway | trust_chain
    "public_since": "2026-03-10T00:00:00Z",
    "access_pattern": "anonymous_read",
    "exposure_path": [
      { "type": "internet", "label": "Internet" },
      { "type": "s3.bucket", "uid": "arn:aws:s3:::data-bucket", "label": "data-bucket", "access": "public" }
    ]
  },

  // ③ Attack Path
  "attack_path": {
    "exists": true,
    "path_id": "ap-1234",
    "title": "Public S3 → Sensitive Data",
    "severity": "critical",
    "steps": [
      { "resource_type": "iam.role", "resource_name": "data-access-role", "resource_uid": "arn:...", "technique": "T1078", "risk_score": 75 },
      { "resource_type": "s3.bucket", "resource_name": "data-bucket", "resource_uid": "arn:...", "technique": "T1530", "risk_score": 87 }
    ],
    "affected_resources": 5,
    "detected_at": "2026-03-14T09:15:00Z"
  },

  // ④ Affected Resources
  "affected_resources": [
    { "resource_uid": "arn:aws:s3:::data-bucket", "resource_type": "s3.bucket", "account_id": "588989875114", "region": "global", "role": "target" },
    { "resource_uid": "arn:aws:iam::588989875114:role/data-access-role", "resource_type": "iam.role", "account_id": "588989875114", "region": "global", "role": "entry_point" }
  ],

  // ⑤ Blast Radius Summary
  "blast_radius": {
    "reachable_count": 12,
    "resources_with_threats": 3,
    "max_depth": 3,
    "depth_distribution": { "1": 5, "2": 4, "3": 3 }
  },

  // ⑥ Supporting Findings (from check engine)
  "supporting_findings": [
    {
      "finding_id": "chk-s3-001",
      "rule_id": "s3-public-access",
      "rule_name": "S3 Bucket Public Access Enabled",
      "severity": "critical",
      "resource_uid": "arn:aws:s3:::data-bucket",
      "status": "FAIL",
      "remediation": "Block public access on S3 bucket"
    }
  ],

  // ⑦ Remediation
  "remediation": {
    "priority": "immediate",
    "auto_remediable": true,
    "steps": [
      { "order": 1, "action": "Block public access on S3 bucket", "command": "aws s3api put-public-access-block ..." },
      { "order": 2, "action": "Enable server-side encryption", "command": "aws s3api put-bucket-encryption ..." }
    ]
  },

  // ⑨ MITRE Context
  "mitre_context": {
    "technique_id": "T1530",
    "technique_name": "Data from Cloud Storage Object",
    "tactics": ["Collection"],
    "description": "Adversaries may access data from...",
    "platforms": ["AWS", "Azure", "GCP"],
    "detection_guidance": {
      "cloudtrail_events": ["GetObject", "ListBucket"],
      "guardduty_types": ["UnauthorizedAccess:S3/MaliciousIPCaller"],
      "data_sources": ["Cloud Storage Logs", "CloudTrail"]
    },
    "remediation_guidance": {
      "immediate": ["Block public access", "Enable encryption"],
      "preventive": ["Enable S3 Block Public Access at account level"],
      "detective": ["Enable CloudTrail data event logging"]
    }
  },

  // ⑩ Timeline
  "timeline": [
    { "timestamp": "2026-03-14T09:15:00Z", "event": "detected", "actor": "system", "details": "Detected by scan bfed9ebc..." },
    { "timestamp": "2026-03-14T09:16:00Z", "event": "status_change", "actor": "system", "details": "Status set to open" },
    { "timestamp": "2026-03-15T14:30:00Z", "event": "re_detected", "actor": "system", "details": "Re-detected in scan c4a1b2..." }
  ]
}
```

### 4.3 Data Flow Per Block

| Block | UI Component | Data Source | BFF Transform | Engine Endpoint | DB Query |
|-------|-------------|-------------|---------------|-----------------|----------|
| ① Header | `ThreatHeader` | `threat` object | N/A (direct call) | `GET /threat/{id}/detail` | `SELECT * FROM threat_findings WHERE finding_id = %s` |
| ② Exposure | `ExposureContext` | `exposure` object | N/A | Same endpoint — engine builds from evidence + graph | `evidence` JSONB + Neo4j exposure query |
| ③ Attack Path | `AttackPathRibbon` | `attack_path` object | N/A | Same endpoint — engine checks graph | Neo4j shortest path query |
| ④ Resources | `AffectedResources` table | `affected_resources` array | N/A | Same endpoint — engine resolves | `evidence.affected_assets` + inventory cross-ref |
| ⑤ Blast Radius | `BlastRadiusSummary` | `blast_radius` object | N/A | Same endpoint — summary only | Neo4j BFS from resource_uid |
| ⑥ Findings | `SupportingFindings` table | `supporting_findings` array | N/A | Same endpoint — cross-DB | `SELECT * FROM check_findings WHERE resource_uid = %s` |
| ⑦ Remediation | `RemediationSteps` | `remediation` object | N/A | Same endpoint — from finding_data | `finding_data->'remediation'` JSONB |
| ⑧ Evidence | `EvidencePanel` (collapsed) | `threat.evidence` | N/A | Same endpoint | `evidence` JSONB column |
| ⑨ MITRE | `MitreContext` (collapsed) | `mitre_context` object | N/A | Same endpoint — joins mitre_technique_reference | `SELECT * FROM mitre_technique_reference WHERE technique_id = %s` |
| ⑩ Timeline | `ActivityTimeline` (collapsed) | `timeline` array | N/A | Same endpoint — builds from status_history | `status_history` JSONB + first/last_seen_at |
| ⑪ Hunt | `HuntActions` (collapsed) | Static links with context | N/A | N/A — links to other pages | N/A |

---

## 5. Phase 3 — Threat List Page Redesign

### 5.1 Block-Level Design

```
┌─────────────────────────────────────────────────────────────────┐
│  Threat Detection & Response                                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─── KPI STRIP ────────────────────────────────────────────┐  │
│  │ Total: 347  │  Critical: 23  │  Active: 289  │           │  │
│  │ High: 67    │  Unassigned: 156  │  Avg Risk: 62.4       │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌─── FILTER BAR ───────────────────────────────────────────┐  │
│  │ [Search threats...]  [Severity ▼] [Status ▼] [Tactic ▼] │  │
│  │ [Provider ▼] [Account ▼] [Region ▼] [Category ▼]        │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌─── TABS ─────────────────────────────────────────────────┐  │
│  │ [Threat List]  [MITRE Matrix]  [Trend]  [Attack Chains]  │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌─── THREAT TABLE ─────────────────────────────────────────┐  │
│  │ ┌────────────────────────────────────────────────────────┐│  │
│  │ │Risk│ Title              │MITRE    │Sev │Resources│Sta │││  │
│  │ ├────┼────────────────────┼─────────┼────┼─────────┼────│││  │
│  │ │ 87 │ S3 Public + Data   │T1530    │CRIT│ 3       │ACT │││  │
│  │ │    │ 🌐 Internet Exposed│Collection│   │         │    │││  │
│  │ │ 75 │ IAM Overperm Role  │T1078    │HIGH│ 7       │ACT │││  │
│  │ │    │ ⚡ Has Attack Path │Init.Acc.│    │         │    │││  │
│  │ │ 63 │ SG Wide Open       │T1190    │MED │ 2       │INV │││  │
│  │ │    │                    │Init.Acc.│    │         │    │││  │
│  │ └────────────────────────────────────────────────────────┘│  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌─── SEVERITY DONUT ──┐  ┌─── 30-DAY TREND ──────────────┐  │
│  │      ┌───┐          │  │  ╱╲    ╱╲                      │  │
│  │     ╱     ╲         │  │ ╱  ╲──╱  ╲──                   │  │
│  │    │ 347   │        │  │╱         ╲──╱╲──                │  │
│  │     ╲     ╱         │  │              ╲                  │  │
│  │      └───┘          │  │                                 │  │
│  └─────────────────────┘  └─────────────────────────────────┘  │
│                                                                 │
│  ┌─── THREAT INTEL ─────────────────────────────────────────┐  │
│  │ Recent threat intelligence matches                        │  │
│  │ [Source │ Indicator │ Type │ Relevance │ Matched Assets]  │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 5.2 List View: What Belongs Here vs Detail

| In List View | In Detail View Only |
|-------------|-------------------|
| Risk score (number) | Full risk breakdown |
| Title (1 line) | Full description |
| MITRE technique + tactic (badge) | MITRE detection/remediation guidance |
| Severity badge | Severity history |
| Affected resource count | Full resource table |
| Provider + Account | Full account context |
| Status badge | Status history timeline |
| 🌐 Internet Exposed chip | Exposure path diagram |
| ⚡ Attack Path chip | Full attack path ribbon |
| Assignee name | Assignment history |

### 5.3 Chips / Indicators for List Rows

```
🌐 Internet Exposed  — shown if exposure.is_internet_exposed = true
⚡ Attack Path        — shown if attack_path.exists = true
💥 Blast Radius: 12   — shown if blast_radius.reachable_count > 5
🔐 Sensitive Data     — shown if threat_category contains "data_exposure"
🔑 Identity Risk      — shown if threat_category contains "iam_"
🤖 Auto-Remediable    — shown if remediation.auto_remediable = true
```

### 5.4 Data needed for list chips

The BFF threats view needs to add indicator flags:

```python
# In bff/threats.py — enrich each threat with indicator flags
for t in filtered:
    t["indicators"] = {
        "internet_exposed": bool(t.get("evidence", {}).get("internet_exposed")),
        "has_attack_path": bool(t.get("attack_path_id")),
        "blast_radius_count": t.get("blast_radius_count", 0),
        "auto_remediable": bool(t.get("auto_remediable")),
        "has_sensitive_data": "data_exposure" in (t.get("threat_category") or ""),
        "has_identity_risk": "iam" in (t.get("threat_category") or ""),
    }
```

**DB columns needed for indicators:**
- `evidence` JSONB already has `internet_exposed` (if populated by threat engine)
- Need to add `attack_path_id VARCHAR(255)` to threat_findings (populated when graph build finds paths)
- Need to add `blast_radius_count INT DEFAULT 0` to threat_findings (populated when graph build calculates radius)
- `finding_data->'auto_remediable'` already exists

---

## 6. Phase 4 — Threat vs Findings Differentiation

### 6.1 Visual Language

| Attribute | Findings Page | Threats Page |
|-----------|--------------|-------------|
| **Primary Color** | Blue (`#3b82f6`) | Red/Orange (`#ef4444` / `#f97316`) |
| **Icon** | `ClipboardCheck` | `Shield` |
| **Badge Style** | Rounded pill | Angular with glow |
| **Card Style** | Flat, border-only | Gradient left-border by severity |
| **Row Click** | Shows finding detail inline | Navigates to full detail page |
| **KPI Focus** | Pass/Fail ratio, framework coverage | Risk score, attack paths, exposure |
| **Chart Types** | Framework compliance bars | MITRE matrix heatmap, attack chains |

### 6.2 Cross-Linking

**Finding → Threat link:**
```
On the Findings/Misconfig page, each finding row shows:
  [🔗 View Threat] chip — if threat_findings has a row with matching rule_id + resource_uid
  Click → navigates to /threats/{finding_id}
```

**Threat → Finding link:**
```
On the Threat Detail page, block ⑥ Supporting Findings shows:
  Table of check_findings contributing to this threat
  [View in Findings →] link at bottom → navigates to /misconfig?rule_id=X
```

**Asset → Threat link:**
```
On the Asset Detail page (/inventory/assets/{uid}):
  Threats tab already exists (via ThreatDBReader enrichment)
  Each threat row → navigates to /threats/{finding_id}
```

### 6.3 Data Flow for Cross-Links

```
-- Finding page: check if threat exists for this finding
SELECT tf.finding_id FROM threat_findings tf
WHERE tf.rule_id = %s AND tf.resource_uid = %s AND tf.tenant_id = %s
LIMIT 1

-- Threat detail: get supporting check findings
SELECT cf.* FROM check_findings cf
WHERE cf.resource_uid = %s AND cf.tenant_id = %s AND cf.status = 'FAIL'
ORDER BY cf.severity DESC
```

---

## 7. Phase 5 — Advanced Workflows

### 7.1 Hunt Integration Points

| Entry Point | Location | Pre-filled Context | Target |
|------------|----------|-------------------|--------|
| "Find similar threats" | Detail page ⑪ | `rule_id` from current threat | `/threats/hunting?query=rule_id:${ruleId}` |
| "All assets same exposure" | Detail page ⑪ | `exposure_type` + `resource_type` | `/threats/hunting?query=exposed:${type}` |
| "Related identities" | Detail page ⑪ | `account_id` + trust relationships | `/threats/hunting?query=identity:${account}` |
| "Open in Graph" | Detail page ⑪ | `resource_uid` | `/threats/graph?focus=${resourceUid}` |
| "View Blast Radius" | Detail page ⑤ expand | `resource_uid` | `/threats/blast-radius?resource=${resourceUid}` |

### 7.2 Navigation Model

```
Top Nav:  Dashboard | Findings | Threats | Assets | Compliance | IAM | DataSec | Risk

Threats Sub-Nav (tabs or sidebar):
  • Overview (main list + KPIs)
  • Analytics
  • Attack Paths
  • Blast Radius
  • Internet Exposed
  • Toxic Combinations
  • Graph Explorer (advanced)
  • Threat Hunting (advanced)
```

---

## 8. User Stories

### Phase 1 — Fix Plumbing

#### US-1.1: Threat Detail API Endpoint
**As a** frontend developer,
**I want** a single `GET /api/v1/threat/{id}/detail` endpoint that returns all data for the detail page,
**So that** the detail page doesn't need to fetch the entire threat list.

**Acceptance Criteria:**
- Returns threat object with all fields from threat_findings
- Returns supporting_findings from check engine DB
- Returns mitre_context from mitre_technique_reference table
- Returns blast_radius_summary from Neo4j (or empty if no graph)
- Returns attack_path from Neo4j (or `exists: false`)
- Returns timeline from status_history + first/last_seen_at
- Returns remediation from finding_data JSONB
- Response time < 500ms for single threat lookup

**Dependencies:** None — all DB tables exist

**Files:**
- `engines/threat/threat_engine/api/detail_router.py` (NEW)
- `engines/threat/threat_engine/api_server.py` (mount router)

---

#### US-1.2: Add Missing DB Columns
**As a** platform engineer,
**I want** `assignee`, `assigned_at`, `status_history`, `attack_path_id`, `blast_radius_count` columns on threat_findings,
**So that** the UI can display assignment, timeline, and indicator data.

**Acceptance Criteria:**
- Alembic migration adds all 5 columns
- Migration is backward-compatible (all columns nullable or have defaults)
- PATCH `/api/v1/threat/{id}` endpoint updates assignee + status_history
- Status changes auto-append to status_history JSONB array

**Dependencies:** None

**Files:**
- `shared/database/schemas/threat_schema.sql` (update)
- `shared/database/alembic/versions/threat/xxx_add_assignee_timeline.py` (NEW)
- `engines/threat/threat_engine/api_server.py` (update PATCH handler)

---

#### US-1.3: MITRE Analytics Endpoint
**As a** security analyst viewing the MITRE matrix,
**I want** a `GET /api/v1/threat/analytics/mitre` endpoint,
**So that** the MITRE heatmap shows real technique counts grouped by tactic.

**Acceptance Criteria:**
- Returns `{matrix: [{technique_id, technique_name, tactics: [], count, severity_base}]}`
- Joins threat_findings.mitre_techniques with mitre_technique_reference
- Filters by tenant_id (required), scan_run_id (optional)
- Response time < 1s

**Dependencies:** mitre_technique_reference table must be populated

**Files:**
- `engines/threat/threat_engine/api/analytics_router.py` (NEW)
- `engines/threat/threat_engine/api_server.py` (mount router)

---

#### US-1.4: Fix Field Name Mismatches
**As a** frontend developer,
**I want** consistent field names between BFF response and UI components,
**So that** filters, sorting, and display work correctly.

**Acceptance Criteria:**
- UI reads `mitre_tactic` (not `mitreTactic`) from BFF response
- UI reads `name` for attack chains (not `title`)
- All field references verified against `_transforms.py` normalizer output

**Dependencies:** None

**Files:**
- `ui_samples/src/app/threats/page.jsx` (fix field references)

---

### Phase 2 — Threat Detail Page

#### US-2.1: Threat Header Block
**As a** security analyst viewing a threat,
**I want** a clear header showing severity, title, MITRE code, risk score, and assignment,
**So that** I can immediately assess the threat's importance.

**Acceptance Criteria:**
- Severity badge with color coding (critical=red, high=orange, medium=yellow, low=blue)
- Risk score progress bar (0-100)
- MITRE technique code as clickable badge
- Assignee dropdown (unassigned / team members)
- Status toggle (active / investigating / resolved / false-positive)
- Provider, Account, Region metadata row

**Data needed:** `threat` object from detail endpoint
**Component:** `ThreatHeader.jsx` (NEW)

---

#### US-2.2: Exposure Context Block
**As a** security analyst,
**I want** to see whether a threat involves internet exposure and what the exposure path is,
**So that** I can understand the external attack surface.

**Acceptance Criteria:**
- Shown only when `exposure.is_internet_exposed = true`
- Visual path: Internet → Intermediary → Target resource
- Exposure type badge: Direct / Load Balancer / API Gateway / Trust Chain
- Public since date + access pattern

**Data needed:** `exposure` object from detail endpoint
**Component:** `ExposureContext.jsx` (NEW)

---

#### US-2.3: Attack Path Block
**As a** security analyst,
**I want** to see the attack chain steps if one exists,
**So that** I can understand how an attacker could exploit this threat.

**Acceptance Criteria:**
- Shown only when `attack_path.exists = true`
- Horizontal ribbon showing: Resource → (Technique) → Resource → (Technique) → Resource
- Each step shows resource type icon, name, and MITRE technique
- "View Full Attack Path" link navigates to `/threats/attack-paths?path_id=X`

**Data needed:** `attack_path` object from detail endpoint
**Component:** `AttackPathRibbon.jsx` (NEW)

---

#### US-2.4: Supporting Findings Block
**As a** security analyst,
**I want** to see which misconfiguration findings contribute to this threat,
**So that** I understand the root cause and can prioritize fixes.

**Acceptance Criteria:**
- Table showing: Rule ID, Rule Name, Severity, Resource, Status
- "View in Findings" link navigates to `/misconfig?rule_id=X`
- Shows count: "4 misconfiguration findings contribute to this threat"

**Data needed:** `supporting_findings` array from detail endpoint
**Component:** `SupportingFindings.jsx` (NEW)

---

#### US-2.5: Blast Radius Block
**As a** security analyst,
**I want** a summary of blast radius and the ability to expand into a full graph,
**So that** I can assess downstream impact without leaving the detail page.

**Acceptance Criteria:**
- Collapsed by default showing: "Blast Radius: 12 reachable · 3 with threats"
- Expand shows mini radial graph (reuse existing blast-radius graph component)
- "Open Full Blast Radius" link navigates to `/threats/blast-radius?resource=X`

**Data needed:** `blast_radius` object (summary from detail endpoint, full graph on expand via separate call)
**Component:** `BlastRadiusSummary.jsx` (NEW)

---

#### US-2.6: Remediation Block
**As a** security analyst,
**I want** prioritized remediation steps with commands I can copy,
**So that** I can quickly fix the threat.

**Acceptance Criteria:**
- Ordered steps with copy-to-clipboard for commands
- Auto-remediable badge if available
- Priority indicator (immediate / high / medium / low)

**Data needed:** `remediation` object from detail endpoint
**Component:** `RemediationSteps.jsx` (NEW)

---

#### US-2.7: MITRE Context Block
**As a** security analyst,
**I want** to see MITRE ATT&CK context for the detected technique,
**So that** I can understand the threat taxonomy and detection guidance.

**Acceptance Criteria:**
- Collapsed by default
- Shows technique ID, name, tactic, description
- Expand shows: detection guidance (CloudTrail events, GuardDuty types), remediation guidance, related techniques
- Links to MITRE ATT&CK website

**Data needed:** `mitre_context` object from detail endpoint
**Component:** `MitreContextPanel.jsx` (NEW)

---

#### US-2.8: Timeline Block
**As a** security analyst,
**I want** to see the history of this threat (when detected, status changes, re-detections),
**So that** I can track investigation progress.

**Acceptance Criteria:**
- Collapsed by default
- Vertical timeline with timestamp, event type, actor
- Events: detected, status_change, re_detected, assigned, resolved

**Data needed:** `timeline` array from detail endpoint
**Component:** `ActivityTimeline.jsx` (NEW)

---

### Phase 3 — Threat List Page

#### US-3.1: Indicator Chips on List Rows
**As a** security analyst scanning the threat list,
**I want** visual indicators (chips) showing internet exposure, attack path existence, blast radius, etc.,
**So that** I can quickly triage which threats need attention.

**Acceptance Criteria:**
- 🌐 Internet Exposed chip (if applicable)
- ⚡ Attack Path chip (if applicable)
- 💥 Blast Radius: N chip (if reachable > 5)
- 🤖 Auto-Remediable chip
- Chips are compact and don't clutter the table

**Data needed:** `indicators` object on each threat (enriched by BFF)
**DB needed:** `attack_path_id`, `blast_radius_count` columns on threat_findings

---

#### US-3.2: Enhanced Filter Model
**As a** security analyst,
**I want** to filter threats by severity, status, MITRE tactic, provider, account, region, and threat category,
**So that** I can focus on specific threat types.

**Acceptance Criteria:**
- All filter options derived from actual data (not hardcoded)
- Multi-select for provider, account, region
- Single-select for severity, status
- Search-as-you-type for MITRE tactic/technique
- Filter state persisted in URL params

---

### Phase 4 — Cross-Linking

#### US-4.1: Finding → Threat Link
**As a** security analyst viewing a misconfiguration finding,
**I want** to see if this finding contributes to a larger threat,
**So that** I can understand the broader context.

**Acceptance Criteria:**
- "View Threat" chip on finding rows that have a matching threat_findings entry
- Chip links to `/threats/{finding_id}`
- BFF misconfig view enriches findings with `has_threat: bool, threat_id: str`

---

### Phase 5 — Hunt Integration

#### US-5.1: Hunt Actions on Detail Page
**As a** security analyst investigating a threat,
**I want** quick-action links to hunt for similar threats, related assets, and identities,
**So that** I can expand my investigation without manual searching.

**Acceptance Criteria:**
- "Find similar" link pre-fills hunt query with `rule_id`
- "All exposed assets" link pre-fills with exposure type
- "Open in Graph" link navigates to graph explorer focused on resource_uid
- Links work via URL parameters (no additional API calls)

---

## 9. Agent Definitions & Execution Plan

### 9.1 Agent Skillset Definitions

Each agent is designed to be invoked via the Claude Agent SDK with enough context to complete its task autonomously.

---

#### Agent 1: `schema-migrator`
**Purpose:** Add missing columns to threat_findings and create Alembic migration.
**Covers:** US-1.2

**Skills/Tools needed:** `Read`, `Write`, `Edit`, `Bash`, `Grep`, `Glob`

**System Prompt:**
```
You are a database migration specialist for a PostgreSQL-based CSPM platform.

Your task: Add the following columns to the threat_findings table in the threat engine database:
1. assignee VARCHAR(255) — Who is assigned to investigate this threat
2. assigned_at TIMESTAMP — When the assignment was made
3. status_history JSONB DEFAULT '[]'::jsonb — Array of {status, timestamp, actor} objects
4. attack_path_id VARCHAR(255) — ID of the attack path this threat belongs to (populated by graph build)
5. blast_radius_count INT DEFAULT 0 — Number of reachable resources (populated by graph build)

Steps:
1. Read the current schema: /Users/apple/Desktop/threat-engine/shared/database/schemas/threat_schema.sql
2. Update the schema file to add the new columns after the existing columns
3. Read existing Alembic migrations for reference: /Users/apple/Desktop/threat-engine/shared/database/alembic/versions/threat/
4. Create a new Alembic migration file with upgrade() and downgrade() functions
5. Add appropriate indexes (idx_tf_assignee, idx_tf_attack_path_id)

Rules:
- All columns must be nullable or have defaults (backward-compatible)
- Use alembic.op.add_column() and alembic.op.create_index()
- Follow the naming convention of existing migrations
- The RDS connection details are in environment variables (don't hardcode)
```

---

#### Agent 2: `threat-detail-endpoint`
**Purpose:** Create the `/api/v1/threat/{id}/detail` endpoint in the threat engine.
**Covers:** US-1.1

**Skills/Tools needed:** `Read`, `Write`, `Edit`, `Bash`, `Grep`, `Glob`

**System Prompt:**
```
You are a Python/FastAPI backend developer building a threat detail endpoint for a CSPM platform.

Your task: Create GET /api/v1/threat/{threat_id}/detail that returns all data needed for the threat detail page.

Context:
- Threat engine: /Users/apple/Desktop/threat-engine/engines/threat/threat_engine/
- API server: /Users/apple/Desktop/threat-engine/engines/threat/threat_engine/api_server.py
- DB schema: /Users/apple/Desktop/threat-engine/shared/database/schemas/threat_schema.sql
- Existing ui-data router: /Users/apple/Desktop/threat-engine/engines/threat/threat_engine/api/ui_data_router.py (reference for DB connection pattern)

The endpoint must return:
1. threat: Full threat_findings row (SELECT * WHERE finding_id = %s AND tenant_id = %s)
2. supporting_findings: Cross-DB query to check_findings (resource_uid match, status = FAIL)
3. mitre_context: JOIN mitre_technique_reference on technique_id extracted from mitre_techniques JSONB
4. blast_radius: Summary from Neo4j graph (reachable_count, resources_with_threats) — fallback to empty if no graph
5. attack_path: Check if attack path exists from Neo4j — fallback to {exists: false}
6. affected_resources: Parse from evidence JSONB + any related resources
7. remediation: Extract from finding_data JSONB
8. timeline: Build from first_seen_at, last_seen_at, status_history JSONB
9. exposure: Build from evidence JSONB (check for internet_exposed, public_access flags)

Implementation:
1. Create /Users/apple/Desktop/threat-engine/engines/threat/threat_engine/api/detail_router.py
2. Use FastAPI APIRouter with prefix /api/v1/threat
3. Use async psycopg2 for DB queries (follow pattern from ui_data_router.py)
4. Mount the router in api_server.py
5. Handle cross-DB queries by connecting to check DB (threat_engine_check) for supporting findings

Error handling:
- 404 if threat not found
- 500 with logging if DB query fails
- Graceful degradation: if Neo4j unavailable, return blast_radius/attack_path as empty
```

---

#### Agent 3: `analytics-endpoints`
**Purpose:** Add missing analytics endpoints (mitre, top-services, toxic-matrix).
**Covers:** US-1.3

**Skills/Tools needed:** `Read`, `Write`, `Edit`, `Bash`, `Grep`, `Glob`

**System Prompt:**
```
You are a Python/FastAPI backend developer adding analytics endpoints to the threat engine.

Your task: Create 3 new analytics endpoints:

1. GET /api/v1/threat/analytics/mitre
   - Query: tenant_id (required), scan_run_id (optional)
   - Response: {matrix: [{technique_id, technique_name, tactics: [], count, severity_base}]}
   - SQL: Join threat_findings.mitre_techniques (JSONB array) with mitre_technique_reference table
   - Use jsonb_array_elements_text() to unnest the JSONB array

2. GET /api/v1/threat/analytics/top-services
   - Query: tenant_id (required), limit (optional, default 10)
   - Response: {services: [{service, count, critical, high, medium, low}]}
   - SQL: GROUP BY service from threat_findings, count by severity

3. GET /api/v1/graph/toxic-combinations/matrix
   - Query: tenant_id (required)
   - Response: {matrix: [{category1, category2, co_occurrence_count, example_resources: []}]}
   - SQL: Self-join threat_findings by resource_uid to find resources with multiple threat categories

Context:
- API server: /Users/apple/Desktop/threat-engine/engines/threat/threat_engine/api_server.py
- Existing analytics in ui_data_router.py for reference patterns
- DB connection pattern: use psycopg2 with RDS connection from env vars

Create: /Users/apple/Desktop/threat-engine/engines/threat/threat_engine/api/analytics_router.py
Mount in api_server.py alongside existing routes.
```

---

#### Agent 4: `ui-field-fix`
**Purpose:** Fix field name mismatches in the threat list page.
**Covers:** US-1.4

**Skills/Tools needed:** `Read`, `Edit`, `Grep`

**System Prompt:**
```
You are a React/Next.js frontend developer fixing field name inconsistencies.

Your task: Fix field name mismatches in the threats page so it reads the correct field names from the BFF response.

Context:
- Threats page: /Users/apple/Desktop/threat-engine/ui_samples/src/app/threats/page.jsx
- BFF transforms: /Users/apple/Desktop/threat-engine/shared/api_gateway/bff/_transforms.py

The BFF normalize_threat() returns these field names:
- mitre_technique (not mitreTechnique)
- mitre_tactic (not mitreTactic)
- risk_score AND riskScore (both provided)
- affected_resources (not affectedResources)
- status (lowercase)

Fix:
1. Line ~70: uniqueTactics reads t.mitreTactic — change to t.mitre_tactic
2. Line ~80: filter reads t.mitreTactic — change to t.mitre_tactic
3. Verify all DataTable column accessorKeys match BFF field names
4. Verify filter options reference correct field names
```

---

#### Agent 5: `threat-detail-ui`
**Purpose:** Build the new threat detail page with all 11 blocks.
**Covers:** US-2.1 through US-2.8

**Skills/Tools needed:** `Read`, `Write`, `Edit`, `Glob`, `Grep`

**System Prompt:**
```
You are a React/Next.js frontend developer building the threat detail page for a CSPM platform.

Your task: Rebuild /Users/apple/Desktop/threat-engine/ui_samples/src/app/threats/[threatId]/page.jsx as a multi-block investigation page.

Design system reference:
- Uses CSS variables: var(--bg-card), var(--bg-secondary), var(--text-primary), var(--text-muted), var(--accent-primary), var(--accent-danger), var(--accent-warning), var(--accent-success)
- Lucide React icons
- Existing shared components: SeverityBadge, DataTable, MetricStrip, StatusIndicator
- Pattern: 'use client', useState/useEffect, getFromEngine() for API calls

Data source: GET /threat/api/v1/threat/{threatId}/detail?tenant_id=X
(Use getFromEngine('threat', `/api/v1/threat/${threatId}/detail`))

Build these blocks (see THREAT_UI_MASTER_PLAN.md section 4.1 for visual wireframes):

1. ThreatHeader — severity badge, title, MITRE code, risk score bar, provider/account/region, assignee dropdown, status toggle
2. ExposureContext — conditional (only if exposure.is_internet_exposed), path diagram Internet→Resource
3. AttackPathRibbon — conditional (only if attack_path.exists), horizontal step chain with technique labels
4. AffectedResources — DataTable with resource_uid, type, account, region, role columns
5. BlastRadiusSummary — collapsed expandable, shows reachable_count, resources_with_threats
6. SupportingFindings — DataTable with rule_id, rule_name, severity, resource, status + "View in Findings" link
7. RemediationSteps — ordered list with copy-to-clipboard for commands
8. EvidencePanel — collapsed, JSON viewer for raw evidence
9. MitreContextPanel — collapsed, technique details + detection guidance
10. ActivityTimeline — collapsed, vertical timeline with events
11. HuntActions — collapsed, links to hunting/graph pages with context params

Each block should be a collapsible section (use a CollapsibleBlock wrapper component).
Blocks 2, 3 should be hidden entirely (not collapsed) when data doesn't exist.
Blocks 5, 8, 9, 10, 11 should be collapsed by default.

Reference existing page patterns:
- /Users/apple/Desktop/threat-engine/ui_samples/src/app/threats/page.jsx (shared components usage)
- /Users/apple/Desktop/threat-engine/ui_samples/src/app/threats/attack-paths/page.jsx (attack path visualization)
- /Users/apple/Desktop/threat-engine/ui_samples/src/app/threats/blast-radius/page.jsx (blast radius graph)
```

---

#### Agent 6: `threat-list-indicators`
**Purpose:** Add indicator chips and enhanced filters to the threat list page.
**Covers:** US-3.1, US-3.2

**Skills/Tools needed:** `Read`, `Write`, `Edit`, `Grep`

**System Prompt:**
```
You are a React/Next.js frontend developer enhancing the threat list page with indicator chips and better filters.

Your task: Enhance /Users/apple/Desktop/threat-engine/ui_samples/src/app/threats/page.jsx

Changes:
1. Add indicator chips below each threat title in the table:
   - 🌐 "Internet Exposed" (blue chip) if indicators.internet_exposed
   - ⚡ "Attack Path" (orange chip) if indicators.has_attack_path
   - 💥 "Blast: N" (red chip) if indicators.blast_radius_count > 5
   - 🤖 "Auto-Fix" (green chip) if indicators.auto_remediable
   - 🔑 "Identity Risk" (purple chip) if indicators.has_identity_risk

2. Enhance FilterBar with additional filter options:
   - Provider (multi-select, from data)
   - Account (multi-select, from data)
   - Region (multi-select, from data)
   - Threat Category (multi-select, from data)

3. Add URL param persistence for filters (useSearchParams)

4. Add sort by risk_score descending as default

Reference:
- BFF response shape: see bff/threats.py (returns threats array with indicators object)
- Existing filter pattern: FilterBar component at /Users/apple/Desktop/threat-engine/ui_samples/src/components/shared/FilterBar.jsx
```

---

#### Agent 7: `bff-enrichment`
**Purpose:** Enhance BFF threats view with indicator flags and cross-links.
**Covers:** US-3.1 data enrichment, US-4.1

**Skills/Tools needed:** `Read`, `Write`, `Edit`, `Grep`

**System Prompt:**
```
You are a Python/FastAPI backend developer enhancing the BFF threats view.

Your task: Enhance /Users/apple/Desktop/threat-engine/shared/api_gateway/bff/threats.py to add indicator enrichment.

Changes:
1. After normalizing threats, add indicators object to each threat:
   indicators = {
     "internet_exposed": check evidence JSONB for internet_exposed flag,
     "has_attack_path": check if attack_path_id is set,
     "blast_radius_count": from blast_radius_count column,
     "auto_remediable": from finding_data.auto_remediable,
     "has_sensitive_data": "data_exposure" in threat_category,
     "has_identity_risk": "iam" in threat_category,
   }

2. Update normalize_threat() in _transforms.py to pass through:
   - attack_path_id
   - blast_radius_count
   - finding_data (or extract auto_remediable from it)

3. For US-4.1 (cross-linking), add a helper function:
   Given a list of check findings (from misconfig BFF),
   enrich each with has_threat and threat_id by batch-querying threat_findings.

Context:
- Current transforms: /Users/apple/Desktop/threat-engine/shared/api_gateway/bff/_transforms.py
- Current threats view: /Users/apple/Desktop/threat-engine/shared/api_gateway/bff/threats.py
- Shared helpers: /Users/apple/Desktop/threat-engine/shared/api_gateway/bff/_shared.py
```

---

### 9.2 Execution Order & Dependencies

```
Phase 1 (parallel):
  ┌─ Agent 1: schema-migrator ────────────────────────┐
  │  (no dependencies)                                 │
  ├─ Agent 3: analytics-endpoints ────────────────────┤ All parallel
  │  (no dependencies)                                 │
  ├─ Agent 4: ui-field-fix ───────────────────────────┤
  │  (no dependencies)                                 │
  └────────────────────────────────────────────────────┘
          │
          ▼ Agent 1 must complete first (new columns needed)
  Agent 2: threat-detail-endpoint
          │
          ▼ Agent 2 must complete first (detail API needed)
Phase 2 (parallel):
  ┌─ Agent 5: threat-detail-ui ───────────────────────┐
  │  (depends on Agent 2)                              │ Parallel
  ├─ Agent 7: bff-enrichment ─────────────────────────┤
  │  (depends on Agent 1 for new columns)              │
  └────────────────────────────────────────────────────┘
          │
          ▼ Agent 7 must complete first (BFF indicators needed)
  Agent 6: threat-list-indicators
```

### 9.3 Claude Agent SDK Orchestration Script

```python
"""
Threat UI Improvement — Agent Orchestration
Uses Claude Agent SDK to execute agents in dependency order.
"""

import anyio
from claude_agent_sdk import query, ClaudeAgentOptions, AgentDefinition, ResultMessage

CWD = "/Users/apple/Desktop/threat-engine"

# ── Agent Definitions ──────────────────────────────────────────────

AGENTS = {
    "schema-migrator": AgentDefinition(
        description="Database migration specialist — adds missing columns to threat_findings",
        prompt="""Add these columns to threat_findings:
1. assignee VARCHAR(255)
2. assigned_at TIMESTAMP
3. status_history JSONB DEFAULT '[]'::jsonb
4. attack_path_id VARCHAR(255)
5. blast_radius_count INT DEFAULT 0

Update shared/database/schemas/threat_schema.sql and create Alembic migration.
See .claude/documentation/THREAT_UI_MASTER_PLAN.md section 3.2 for full spec.""",
        tools=["Read", "Write", "Edit", "Bash", "Grep", "Glob"],
    ),

    "analytics-endpoints": AgentDefinition(
        description="FastAPI developer — creates missing analytics endpoints",
        prompt="""Create 3 endpoints in a new analytics_router.py:
1. GET /api/v1/threat/analytics/mitre — MITRE heatmap data
2. GET /api/v1/threat/analytics/top-services — Top affected services
3. GET /api/v1/graph/toxic-combinations/matrix — Co-occurrence matrix

See .claude/documentation/THREAT_UI_MASTER_PLAN.md section 3.3 for SQL and response shapes.
Follow patterns from engines/threat/threat_engine/api/ui_data_router.py.""",
        tools=["Read", "Write", "Edit", "Bash", "Grep", "Glob"],
    ),

    "ui-field-fix": AgentDefinition(
        description="React developer — fixes field name mismatches in threats page",
        prompt="""Fix field name mismatches in ui_samples/src/app/threats/page.jsx:
- mitreTactic → mitre_tactic
- mitreTechnique → mitre_technique
- affectedResources → affected_resources
Verify against BFF normalize_threat() in shared/api_gateway/bff/_transforms.py.""",
        tools=["Read", "Edit", "Grep"],
    ),

    "threat-detail-endpoint": AgentDefinition(
        description="FastAPI developer — creates threat detail API endpoint",
        prompt="""Create GET /api/v1/threat/{threat_id}/detail endpoint.
Must return: threat, supporting_findings, mitre_context, blast_radius, attack_path,
affected_resources, remediation, timeline, exposure.
See .claude/documentation/THREAT_UI_MASTER_PLAN.md section 4.2 for full data contract.
Create engines/threat/threat_engine/api/detail_router.py and mount in api_server.py.""",
        tools=["Read", "Write", "Edit", "Bash", "Grep", "Glob"],
    ),

    "threat-detail-ui": AgentDefinition(
        description="React developer — rebuilds threat detail page with 11 investigation blocks",
        prompt="""Rebuild ui_samples/src/app/threats/[threatId]/page.jsx with 11 blocks:
Header, Exposure, AttackPath, Resources, BlastRadius, Findings, Remediation,
Evidence, MITRE, Timeline, HuntActions.
See .claude/documentation/THREAT_UI_MASTER_PLAN.md section 4.1 for wireframes.
Use getFromEngine('threat', `/api/v1/threat/${id}/detail`) for data.""",
        tools=["Read", "Write", "Edit", "Glob", "Grep"],
    ),

    "bff-enrichment": AgentDefinition(
        description="Python developer — adds indicator enrichment to BFF threats view",
        prompt="""Enhance shared/api_gateway/bff/threats.py:
1. Add indicators object (internet_exposed, has_attack_path, blast_radius_count, auto_remediable, has_sensitive_data, has_identity_risk)
2. Update normalize_threat() in _transforms.py to pass through new fields
See .claude/documentation/THREAT_UI_MASTER_PLAN.md section 5.4.""",
        tools=["Read", "Write", "Edit", "Grep"],
    ),

    "threat-list-indicators": AgentDefinition(
        description="React developer — adds indicator chips and enhanced filters to threat list",
        prompt="""Enhance ui_samples/src/app/threats/page.jsx:
1. Add indicator chips (Internet Exposed, Attack Path, Blast Radius, Auto-Fix, Identity Risk)
2. Add filters: Provider, Account, Region, Category (multi-select, from data)
3. Default sort by risk_score descending
4. URL param persistence for filters
See .claude/documentation/THREAT_UI_MASTER_PLAN.md section 5.3.""",
        tools=["Read", "Write", "Edit", "Grep", "Glob"],
    ),
}


async def main():
    """Execute agents in dependency order."""

    # ── Phase 1: Parallel (no dependencies) ──
    print("=== Phase 1: Fix Plumbing (parallel) ===")
    phase1_results = {}

    # Run schema-migrator, analytics-endpoints, ui-field-fix in parallel
    async def run_agent(name):
        agent = AGENTS[name]
        async for message in query(
            prompt=agent.prompt,
            options=ClaudeAgentOptions(
                cwd=CWD,
                allowed_tools=agent.tools,
                permission_mode="acceptEdits",
                system_prompt=f"You are the '{name}' agent. {agent.description}",
                max_turns=30,
            ),
        ):
            if isinstance(message, ResultMessage):
                phase1_results[name] = message.result
                print(f"  ✅ {name} complete")

    async with anyio.create_task_group() as tg:
        tg.start_soon(run_agent, "schema-migrator")
        tg.start_soon(run_agent, "analytics-endpoints")
        tg.start_soon(run_agent, "ui-field-fix")

    # ── Phase 1b: Sequential (depends on schema-migrator) ──
    print("\n=== Phase 1b: Detail Endpoint (after schema migration) ===")
    async for message in query(
        prompt=AGENTS["threat-detail-endpoint"].prompt,
        options=ClaudeAgentOptions(
            cwd=CWD,
            allowed_tools=AGENTS["threat-detail-endpoint"].tools,
            permission_mode="acceptEdits",
            system_prompt="You are the 'threat-detail-endpoint' agent. "
                          + AGENTS["threat-detail-endpoint"].description,
            max_turns=30,
        ),
    ):
        if isinstance(message, ResultMessage):
            print(f"  ✅ threat-detail-endpoint complete")

    # ── Phase 2: Parallel (depends on detail endpoint + schema) ──
    print("\n=== Phase 2: UI Rebuild (parallel) ===")
    async with anyio.create_task_group() as tg:
        tg.start_soon(run_agent, "threat-detail-ui")
        tg.start_soon(run_agent, "bff-enrichment")

    # ── Phase 2b: Sequential (depends on BFF enrichment) ──
    print("\n=== Phase 2b: List Indicators (after BFF enrichment) ===")
    async for message in query(
        prompt=AGENTS["threat-list-indicators"].prompt,
        options=ClaudeAgentOptions(
            cwd=CWD,
            allowed_tools=AGENTS["threat-list-indicators"].tools,
            permission_mode="acceptEdits",
            system_prompt="You are the 'threat-list-indicators' agent. "
                          + AGENTS["threat-list-indicators"].description,
            max_turns=30,
        ),
    ):
        if isinstance(message, ResultMessage):
            print(f"  ✅ threat-list-indicators complete")

    print("\n🎉 All agents complete!")


if __name__ == "__main__":
    anyio.run(main)
```

---

## Appendix A: File Change Matrix

| File | Phase | Agent | Change Type |
|------|-------|-------|-------------|
| `shared/database/schemas/threat_schema.sql` | 1 | schema-migrator | Edit (add columns) |
| `shared/database/alembic/versions/threat/xxx_add_assignee_timeline.py` | 1 | schema-migrator | New file |
| `engines/threat/threat_engine/api/detail_router.py` | 1 | threat-detail-endpoint | New file |
| `engines/threat/threat_engine/api/analytics_router.py` | 1 | analytics-endpoints | New file |
| `engines/threat/threat_engine/api_server.py` | 1 | threat-detail-endpoint + analytics-endpoints | Edit (mount routers) |
| `ui_samples/src/app/threats/page.jsx` | 1,3 | ui-field-fix + threat-list-indicators | Edit |
| `ui_samples/src/app/threats/[threatId]/page.jsx` | 2 | threat-detail-ui | Rewrite |
| `shared/api_gateway/bff/threats.py` | 2 | bff-enrichment | Edit |
| `shared/api_gateway/bff/_transforms.py` | 2 | bff-enrichment | Edit |

## Appendix B: DB Column Reference

### threat_findings — Current Columns
| Column | Type | Notes |
|--------|------|-------|
| id | SERIAL PK | Auto-increment |
| finding_id | VARCHAR(255) UNIQUE | Stable hash: sha256(rule_id\|resource_uid\|account\|region)[:16] |
| threat_scan_id | VARCHAR(255) | Format: threat_{scan_run_id} |
| tenant_id | VARCHAR(255) | Required for all queries |
| customer_id | VARCHAR(255) | |
| scan_run_id | VARCHAR(255) | |
| rule_id | VARCHAR(255) | From rule engine |
| threat_category | VARCHAR(100) | |
| severity | VARCHAR(20) | critical, high, medium, low, info |
| status | VARCHAR(20) | open, resolved, etc. |
| resource_type | VARCHAR(255) | |
| resource_id | VARCHAR(255) | |
| resource_uid | TEXT | Canonical ARN/ARM ID |
| account_id | VARCHAR(255) | |
| region | VARCHAR(50) | |
| mitre_tactics | JSONB | Array of tactic strings |
| mitre_techniques | JSONB | Array of technique IDs |
| evidence | JSONB | Raw evidence data |
| finding_data | JSONB | Enriched: title, description, remediation, risk_score, auto_remediable |
| first_seen_at | TIMESTAMP | |
| last_seen_at | TIMESTAMP | |
| created_at | TIMESTAMP | |

### threat_findings — NEW Columns (Phase 1)
| Column | Type | Default | Notes |
|--------|------|---------|-------|
| assignee | VARCHAR(255) | NULL | Who is investigating |
| assigned_at | TIMESTAMP | NULL | When assigned |
| status_history | JSONB | '[]'::jsonb | [{status, timestamp, actor}] |
| attack_path_id | VARCHAR(255) | NULL | Populated by graph build |
| blast_radius_count | INT | 0 | Populated by graph build |
