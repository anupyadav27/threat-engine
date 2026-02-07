# Engine API Reference — UI Developer Guide

> Complete API endpoint map for all engines with request/response formats, UI page mapping, and sample responses.
> Port assignments, Docker images, and database dependencies included.

---

## Architecture Overview

```
                        API Gateway (:8080)
                              |
        +---------+-----------+-----------+---------+----------+
        |         |           |           |         |          |
   engine_threat engine_check engine_inv engine_comp engine_rule ...
     (:8020)      (:8010)     (:8030)    (:8040)    (:8050)
        |         |           |           |         |
   PostgreSQL   PostgreSQL  PostgreSQL  PostgreSQL PostgreSQL
   + Neo4j      (check DB)  (inv DB)   (check DB) (check DB)
```

---

## Table of Contents

1. [engine_threat (Port 8020)](#1-engine_threat-port-8020)
2. [engine_check (Port 8010)](#2-engine_check-port-8010)
3. [engine_inventory (Port 8030)](#3-engine_inventory-port-8030)
4. [engine_compliance (Port 8040)](#4-engine_compliance-port-8040)
5. [engine_rule (Port 8050)](#5-engine_rule-port-8050)
6. [engine_datasec](#6-engine_datasec)
7. [engine_iam](#7-engine_iam)
8. [engine_discoveries](#8-engine_discoveries)
9. [engine_onboarding](#9-engine_onboarding)
10. [engine_secops](#10-engine_secops)
11. [engine_pythonsdk](#11-engine_pythonsdk)

---

## 1. engine_threat (Port 8020)

**Docker Image:** `yadavanup84/threat-engine:latest`
**Databases:** PostgreSQL (threat_engine_threat, threat_engine_check, threat_engine_inventory) + Neo4j
**Code:** `engine_threat/threat_engine/`

### Architecture

```
engine_threat/threat_engine/
├── api_server.py              # FastAPI (63 endpoints)
├── analyzer/
│   └── threat_analyzer.py     # Risk scoring, blast radius, attack chains
├── graph/
│   ├── graph_builder.py       # PostgreSQL → Neo4j graph population
│   └── graph_queries.py       # Cypher attack path queries
├── database/
│   └── metadata_enrichment.py # JOIN check_findings + rule_metadata
├── detector/
│   └── threat_detector.py     # Threat grouping + MITRE correlation
├── schemas/
│   ├── threat_report_schema.py
│   └── misconfig_normalizer.py
└── storage/
    ├── threat_db_writer.py    # threat_report + detections + findings + analysis
    └── threat_intel_writer.py # intelligence + hunt queries + results
```

### UI Page Mapping

| UI Page | API Endpoints | Description |
|---------|--------------|-------------|
| **Threat Dashboard** | `GET /api/v1/threat/analysis/prioritized`, `GET /api/v1/graph/summary` | Top threats by risk score + graph stats |
| **Threat List** | `GET /api/v1/threat/threats` | Filterable threat table |
| **Threat Detail** | `GET /api/v1/threat/analysis/{detection_id}` | Blast radius, attack chain, recommendations |
| **Security Graph** | `GET /api/v1/graph/attack-paths`, `GET /api/v1/graph/internet-exposed` | Neo4j graph visualization |
| **Attack Paths** | `GET /api/v1/graph/attack-paths` | Internet → resource paths |
| **Resource Detail** | `GET /api/v1/graph/resource/{uid}`, `GET /api/v1/graph/blast-radius/{uid}` | Resource neighbors + blast radius |
| **Toxic Combos** | `GET /api/v1/graph/toxic-combinations` | Resources with multiple threats |
| **Threat Intel** | `GET /api/v1/intel`, `GET /api/v1/intel/correlate` | IOC feeds + correlation |
| **Threat Hunting** | `GET /api/v1/hunt/predefined`, `POST /api/v1/hunt/execute` | Cypher queries + results |
| **Reports** | `GET /api/v1/threat/reports`, `POST /api/v1/threat/generate` | Generate + list reports |
| **Scan Summary** | `GET /api/v1/scans/{scan_run_id}/summary` | Scan overview |

### Endpoint Reference

#### Core Threat Operations

##### POST /api/v1/threat/generate
Generate a threat report (runs full pipeline: enrich → detect → analyze → store).

**Request:**
```json
{
  "tenant_id": "588989875114",
  "scan_run_id": "ece8c3a6-ca19-46d2-83bb-2691dfbc4641",
  "cloud": "aws",
  "trigger_type": "manual",
  "accounts": ["588989875114"],
  "regions": ["ap-south-1"],
  "started_at": "2025-02-05T10:00:00Z"
}
```

**Response (truncated):**
```json
{
  "schema_version": "cspm_threat_report.v1",
  "tenant": { "tenant_id": "588989875114", ... },
  "scan_context": { "scan_run_id": "ece8c3a6-...", "cloud": "aws", ... },
  "threat_summary": {
    "total_threats": 21,
    "threats_by_severity": { "high": 21 },
    "threats_by_category": { "misconfiguration": 21 },
    "threats_by_status": { "open": 21 }
  },
  "threats": [ { "threat_id": "...", "severity": "high", ... } ],
  "misconfig_findings": [ ... ],
  "analysis_summary": {
    "analyses_count": 21,
    "verdicts": { "medium_risk": 21 },
    "avg_risk_score": 55.1
  }
}
```

##### GET /api/v1/threat/threats
List threat detections with filters.

**Query Params:** `tenant_id` (required), `scan_run_id`, `severity`, `category`, `status`, `resource_uid`, `limit`, `offset`

**Response:**
```json
{
  "threats": [
    {
      "detection_id": "ac1e6e7e-d625-52c7-8fc9-34cb675b2076",
      "scan_id": "ece8c3a6-...",
      "resource_arn": "arn:aws:s3:::aiwebsite01",
      "resource_type": "s3",
      "severity": "high",
      "confidence": "low",
      "status": "open",
      "threat_category": "misconfiguration",
      "mitre_techniques": ["T1562","T1040","T1098","T1190","T1537"],
      "mitre_tactics": ["defense-evasion","credential-access"],
      "evidence": { "remediation": "...", "finding_refs": [...] },
      "detection_timestamp": "2026-02-07T..."
    }
  ],
  "total": 21, "limit": 100, "offset": 0
}
```

#### Threat Analysis (Risk Scoring)

##### POST /api/v1/threat/analysis/run
Run threat analysis on existing detections.

**Request:** `{ "tenant_id": "588989875114", "scan_run_id": "ece8c3a6-..." }`

**Response:**
```json
{
  "status": "completed",
  "scan_run_id": "ece8c3a6-...",
  "analyses_saved": 21,
  "verdicts": { "medium_risk": 21 },
  "avg_risk_score": 55.1,
  "duration_ms": 2024.3
}
```

##### GET /api/v1/threat/analysis/prioritized
Top-N threats by risk score (for dashboard).

**Query Params:** `tenant_id`, `scan_run_id`, `top_n` (default 10)

**Response:**
```json
{
  "prioritized_threats": [
    {
      "analysis_id": "c002b20b-...",
      "detection_id": "ee8b74ba-...",
      "risk_score": 62,
      "verdict": "medium_risk",
      "resource_arn": "arn:aws:s3:::elasticbeanstalk-ap-south-1-...",
      "analysis_results": {
        "blast_radius": {
          "reachable_count": 4,
          "reachable_resources": ["arn:aws:iam::...role/...", "..."],
          "depth_distribution": { "1": 4 }
        },
        "mitre_analysis": {
          "techniques": ["T1485","T1490","T1537","T1530"],
          "tactics": ["defense-evasion","credential-access"],
          "impact_score": 0.785
        },
        "reachability": { "is_internet_reachable": false },
        "composite_formula": "severity*40 + blast_radius*25 + mitre_impact*25 + reachability*10"
      },
      "recommendations": [
        { "priority": "high", "action": "remediate_misconfiguration", "description": "Fix the high-severity..." },
        { "priority": "critical", "action": "enable_backups", "description": "MITRE techniques indicate data destruction..." },
        { "priority": "high", "action": "review_iam_policies", "description": "..." }
      ],
      "attack_chain": [
        { "step": 1, "resource": "arn:aws:s3:::elastic...", "action": "initial_compromise" },
        { "step": 2, "resource": "arn:aws:iam::...role/...", "action": "references" },
        { "step": 3, "resource": "arn:aws:s3:::.../resources/...", "action": "references" }
      ],
      "related_threats": []
    }
  ],
  "total_analyzed": 21,
  "top_n": 10
}
```

##### GET /api/v1/threat/analysis/{detection_id}
Full analysis detail for one threat.

**Query Params:** `tenant_id`

##### GET /api/v1/threat/analysis
List all analyses with filters.

**Query Params:** `tenant_id`, `scan_run_id`, `min_risk_score`, `verdict`, `limit`, `offset`

#### Security Graph (Neo4j)

##### POST /api/v1/graph/build
Build/rebuild the Neo4j security graph.

**Request:** `{ "tenant_id": "588989875114" }`

**Response:**
```json
{
  "status": "completed",
  "stats": {
    "virtual_nodes": 5, "resource_nodes": 301,
    "resource_rels": 32, "hierarchy_rels": 602,
    "threat_nodes": 21, "finding_nodes": 1528,
    "analysis_edges": 49, "exposure_edges": 21,
    "total_nodes": 1855, "total_relationships": 704
  },
  "duration_ms": 228725.9
}
```

##### GET /api/v1/graph/summary
Graph statistics for dashboard header.

**Response:**
```json
{
  "node_counts": {
    "Finding": 1528, "Resource": 280, "IAMRole": 140,
    "IAMPolicy": 54, "SecurityGroup": 31, "S3Bucket": 21,
    "ThreatDetection": 21, "Internet": 1
  },
  "relationship_counts": {
    "HAS_FINDING": 1528, "CONTAINS": 280, "HOSTS": 280,
    "EXPOSES": 21, "HAS_THREAT": 21
  },
  "resources_by_type": { "iam.role": 140, "iam.policy": 54, "ec2.security-group": 31, "s3.resource": 21 },
  "threats_by_severity": { "high": 21 }
}
```

##### GET /api/v1/graph/attack-paths
Attack paths from Internet to threatened resources.

**Query Params:** `tenant_id`, `max_hops` (1-10), `min_severity`

**Response:**
```json
{
  "attack_paths": [
    {
      "resource_uid": "arn:aws:s3:::elasticbeanstalk-ap-south-1-...",
      "resource_type": "s3.resource",
      "threat_id": "ee8b74ba-...",
      "threat_severity": "high",
      "risk_score": 62,
      "mitre_techniques": ["T1562","T1040","T1098"],
      "node_names": ["Internet", "elasticbeanstalk-ap-south-1-..."],
      "rel_types": ["EXPOSES"],
      "hops": 1
    }
  ],
  "total": 23
}
```

##### GET /api/v1/graph/internet-exposed
Resources exposed to the internet.

**Response:**
```json
{
  "exposed_resources": [
    {
      "resource_uid": "arn:aws:s3:::aiwebsite01",
      "resource_type": "s3.resource",
      "risk_score": 20,
      "exposure_hops": 1,
      "threat_severities": ["high"],
      "threat_count": 1
    }
  ],
  "total": 21
}
```

##### GET /api/v1/graph/blast-radius/{resource_uid}
Blast radius from a specific resource.

**Query Params:** `tenant_id`, `max_hops`

**Response:**
```json
{
  "source_resource": "arn:aws:s3:::elasticbeanstalk-...",
  "reachable_count": 4,
  "reachable_resources": [
    { "uid": "arn:aws:iam::...role/...", "resource_type": "iam.role", "hops": 1, "threats": [], "finding_count": 23 }
  ],
  "depth_distribution": { "1": 4 },
  "resources_with_threats": 0
}
```

##### GET /api/v1/graph/toxic-combinations
Resources with multiple overlapping threats.

**Query Params:** `tenant_id`, `min_threats`

##### GET /api/v1/graph/resource/{resource_uid}
Full graph context for one resource.

**Response:**
```json
{
  "resource": { "uid": "arn:aws:s3:::aiwebsite01", "resource_type": "s3.resource", "risk_score": 20 },
  "neighbors": [
    { "relationship": "RELATES_TO", "neighbor_uid": "arn:aws:s3:::anup-backup", "neighbor_labels": ["Resource","S3Bucket"] },
    { "relationship": "CONTAINS", "neighbor_uid": "account:588989875114", "neighbor_labels": ["VirtualNode","Account"] }
  ],
  "threats": [{ "detection_id": "...", "severity": "high", "mitre_techniques": [...] }],
  "findings": [{ "finding_id": "...", "rule_id": "aws.s3.bucket...", "severity": "high" }],
  "neighbor_count": 50, "threat_count": 1, "finding_count": 56
}
```

#### Threat Intelligence

##### POST /api/v1/intel/feed
Ingest a threat intelligence entry.

**Request:**
```json
{
  "tenant_id": "588989875114",
  "source": "cisa_kev",
  "intel_type": "vulnerability",
  "category": "credential_abuse",
  "severity": "high",
  "confidence": "high",
  "threat_data": { "name": "IAM Credential Abuse", "cve_ids": ["CVE-2024-1234"] },
  "ttps": ["T1078", "T1098"],
  "tags": ["iam", "credential-abuse"]
}
```

**Response:** `{ "intel_id": "b519c8e4-...", "status": "saved" }`

##### GET /api/v1/intel
List intel entries. **Query Params:** `tenant_id`, `intel_type`, `severity`, `source`, `active_only`, `limit`

##### GET /api/v1/intel/correlate
Correlate intel with detections by MITRE technique overlap.

**Response:**
```json
{
  "correlations": [
    {
      "detection_id": "ac1e6e7e-...",
      "resource_arn": "arn:aws:s3:::aiwebsite01",
      "detection_severity": "high",
      "detection_techniques": ["T1562","T1040","T1098"],
      "intel_id": "2bb0d686-...",
      "intel_source": "mitre_attack_ics",
      "intel_severity": "critical"
    }
  ],
  "total": 42
}
```

#### Threat Hunting

##### GET /api/v1/hunt/predefined
List built-in hunt queries.

**Response:**
```json
{
  "hunts": [
    { "id": "internet_to_sensitive_data", "name": "Internet -> Sensitive Data Path", "description": "..." },
    { "id": "lateral_movement_iam", "name": "IAM Lateral Movement Paths", "description": "..." },
    { "id": "public_buckets_with_threats", "name": "Public S3 Buckets with Active Threats", "description": "..." },
    { "id": "high_blast_radius", "name": "Resources with High Blast Radius", "description": "..." },
    { "id": "unprotected_critical_resources", "name": "Critical Resources Without Protection", "description": "..." }
  ]
}
```

##### POST /api/v1/hunt/execute
Execute a hunt (saved, predefined, or ad-hoc Cypher).

**Request (predefined):** `{ "tenant_id": "588989875114", "predefined_id": "public_buckets_with_threats" }`
**Request (ad-hoc):** `{ "tenant_id": "588989875114", "cypher": "MATCH (b:S3Bucket {tenant_id: $tid})-[:HAS_THREAT]->(t) RETURN b.uid, t.severity" }`

**Response:**
```json
{
  "status": "completed",
  "query_name": "public_buckets_with_threats",
  "results": [ ... ],
  "total": 21,
  "execution_time_ms": 895.0,
  "result_id": "a2a82f1c-..."
}
```

##### POST /api/v1/hunt/queries
Save a custom hunt query.

##### GET /api/v1/hunt/queries
List saved hunt queries.

##### GET /api/v1/hunt/results
List past hunt results.

---

## 2. engine_check (Port 8010)

**Code:** `engine_check/engine_check_aws/`

### UI Page Mapping

| UI Page | API Endpoints |
|---------|--------------|
| **Run Scan** | `POST /api/v1/check` |
| **Scan Status** | `GET /api/v1/check/{check_scan_id}/status` |
| **Scan History** | `GET /api/v1/checks` |

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/check` | Create a new check scan |
| GET | `/api/v1/check/{check_scan_id}/status` | Get scan status |
| GET | `/api/v1/checks` | List all check scans |
| GET | `/api/v1/health` | Health check |
| GET | `/api/v1/health/ready` | Readiness probe |
| GET | `/api/v1/health/live` | Liveness probe |
| GET | `/api/v1/metrics` | Prometheus metrics |

---

## 3. engine_inventory (Port 8030)

**Code:** `engine_inventory/inventory_engine/`

### UI Page Mapping

| UI Page | API Endpoints |
|---------|--------------|
| **Asset Inventory** | `GET /api/v1/inventory/assets` |
| **Asset Detail** | `GET /api/v1/inventory/assets/{uid}`, `GET .../relationships`, `GET .../drift` |
| **Asset Graph** | `GET /api/v1/inventory/graph` |
| **Drift Detection** | `GET /api/v1/inventory/drift` |
| **Run Scan** | `POST /api/v1/inventory/scan` |
| **Scan History** | `GET /api/v1/inventory/scans` |
| **Account Summary** | `GET /api/v1/inventory/accounts/{id}` |
| **Collections** | `GET /collections`, `POST /collections` |
| **Tag Management** | `GET /tags/search`, `GET /tags/statistics` |
| **Metrics** | `POST /metrics/compute`, `GET /metrics` |

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/inventory/scan` | Run inventory scan |
| POST | `/api/v1/inventory/scan/async` | Async inventory scan |
| POST | `/api/v1/inventory/scan/discovery` | Run discovery scan |
| GET | `/api/v1/inventory/jobs/{job_id}` | Get job status |
| GET | `/api/v1/inventory/runs/{scan_run_id}/summary` | Scan summary |
| GET | `/api/v1/inventory/runs/latest/summary` | Latest scan summary |
| GET | `/api/v1/inventory/assets` | List assets |
| GET | `/api/v1/inventory/assets/{uid}` | Get asset detail |
| GET | `/api/v1/inventory/assets/{uid}/relationships` | Asset relationships |
| GET | `/api/v1/inventory/assets/{uid}/drift` | Asset drift history |
| GET | `/api/v1/inventory/graph` | Asset graph |
| GET | `/api/v1/inventory/drift` | Drift records |
| GET | `/api/v1/inventory/accounts/{account_id}` | Account summary |
| GET | `/api/v1/inventory/services/{service}` | Service summary |
| GET | `/api/v1/inventory/scans` | List scans |
| GET | `/api/v1/inventory/relationships` | List relationships |
| POST | `/collections` | Create collection |
| GET | `/collections` | List collections |
| GET | `/collections/{id}/assets` | Collection assets |
| GET | `/history/{asset_id}` | Asset change history |
| POST | `/metrics/compute` | Compute metrics |
| GET | `/metrics/trends/{type}` | Metric trends |
| GET | `/tags/search` | Search by tags |
| POST | `/relationships/build` | Build relationship graph |

---

## 4. engine_compliance (Port 8040)

**Code:** `engine_compliance/compliance_engine/`

### UI Page Mapping

| UI Page | API Endpoints |
|---------|--------------|
| **Compliance Dashboard** | `GET /api/v1/compliance/dashboard` |
| **Framework List** | `GET /api/v1/compliance/frameworks/all` |
| **Framework Detail** | `GET /api/v1/compliance/framework-detail/{fw}`, `GET .../structure` |
| **Control Detail** | `GET /api/v1/compliance/control-detail/{fw}/{ctrl}` |
| **Resource Compliance** | `GET /api/v1/compliance/resource/{uid}/compliance` |
| **Generate Report** | `POST /api/v1/compliance/generate` |
| **Report List** | `GET /api/v1/compliance/reports` |
| **Report Detail** | `GET /api/v1/compliance/report/{id}` |
| **Export** | `GET .../download/pdf`, `GET .../download/excel` |
| **Trends** | `GET /api/v1/compliance/trends` |
| **Account View** | `GET /api/v1/compliance/accounts/{id}` |
| **Resource Drilldown** | `GET /api/v1/compliance/resource/drilldown` |

### Endpoints (35 total)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/compliance/generate` | Generate compliance report |
| POST | `/api/v1/compliance/generate/from-check-db` | Generate from check database |
| POST | `/api/v1/compliance/generate/from-threat-db` | Generate from threat database |
| GET | `/api/v1/compliance/report/{report_id}` | Get report |
| GET | `/api/v1/compliance/reports` | List reports |
| GET | `/api/v1/compliance/dashboard` | Dashboard data |
| GET | `/api/v1/compliance/frameworks/all` | All frameworks |
| GET | `/api/v1/compliance/framework/{fw}/status` | Framework status |
| GET | `/api/v1/compliance/framework-detail/{fw}` | Framework detail |
| GET | `/api/v1/compliance/framework/{fw}/structure` | Framework structure |
| GET | `/api/v1/compliance/framework/{fw}/controls/grouped` | Controls grouped |
| GET | `/api/v1/compliance/framework/{fw}/resources/grouped` | Resources grouped |
| GET | `/api/v1/compliance/control-detail/{fw}/{ctrl}` | Control detail |
| GET | `/api/v1/compliance/resource/{uid}/compliance` | Resource compliance |
| GET | `/api/v1/compliance/resource/drilldown` | Resource drilldown |
| GET | `/api/v1/compliance/trends` | Compliance trends |
| GET | `/api/v1/compliance/accounts/{id}` | Account compliance |
| GET | `/api/v1/compliance/controls/search` | Search controls |
| GET | `/api/v1/compliance/framework/{fw}/download/pdf` | Export PDF |
| GET | `/api/v1/compliance/framework/{fw}/download/excel` | Export Excel |
| DELETE | `/api/v1/compliance/reports/{id}` | Delete report |

---

## 5. engine_rule (Port 8050)

**Code:** `engine_rule/`

### UI Page Mapping

| UI Page | API Endpoints |
|---------|--------------|
| **Rule Browser** | `GET /api/v1/rules`, `GET /api/v1/rules/search` |
| **Rule Detail** | `GET /api/v1/rules/{rule_id}` |
| **Rule Editor** | `PUT /api/v1/rules/{rule_id}`, `POST /api/v1/rules/validate` |
| **Rule Creator** | `POST /api/v1/rules/generate`, `GET /api/v1/rules/templates` |
| **Provider Browser** | `GET /api/v1/providers`, `GET /api/v1/providers/{p}/services` |
| **Service Rules** | `GET /api/v1/providers/{p}/services/{s}/rules` |
| **Statistics** | `GET /api/v1/rules/statistics` |
| **Import/Export** | `POST /api/v1/rules/import`, `GET /api/v1/rules/export` |

### Endpoints (23 total)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/providers` | List cloud providers |
| GET | `/api/v1/providers/{provider}/services` | Provider services |
| GET | `/api/v1/providers/{provider}/services/{service}/rules` | Service rules |
| GET | `/api/v1/providers/{provider}/services/{service}/capabilities` | Service capabilities |
| GET | `/api/v1/rules` | List all rules |
| GET | `/api/v1/rules/search` | Search rules |
| GET | `/api/v1/rules/{rule_id}` | Get rule detail |
| PUT | `/api/v1/rules/{rule_id}` | Update rule |
| DELETE | `/api/v1/rules/{rule_id}` | Delete rule |
| POST | `/api/v1/rules/validate` | Validate rule YAML |
| POST | `/api/v1/rules/generate` | AI-generate rule |
| POST | `/api/v1/rules/preview` | Preview rule execution |
| POST | `/api/v1/rules/{rule_id}/copy` | Clone rule |
| POST | `/api/v1/rules/bulk-delete` | Bulk delete |
| GET | `/api/v1/rules/export` | Export rules |
| POST | `/api/v1/rules/import` | Import rules |
| GET | `/api/v1/rules/templates` | Rule templates |
| POST | `/api/v1/rules/templates/{id}/create` | Create from template |
| GET | `/api/v1/rules/statistics` | Rule statistics |

---

## 6. engine_datasec

**Code:** `engine_datasec/data_security_engine/`

### UI Page Mapping

| UI Page | API Endpoints |
|---------|--------------|
| **Data Security Dashboard** | `POST /api/v1/data-security/scan` |
| **Data Catalog** | `GET /api/v1/data-security/catalog` |
| **Data Classification** | `GET /api/v1/data-security/classification` |
| **Data Lineage** | `GET /api/v1/data-security/lineage` |
| **Data Residency** | `GET /api/v1/data-security/residency` |
| **Access Governance** | `GET /api/v1/data-security/governance/{id}` |
| **Protection Status** | `GET /api/v1/data-security/protection/{id}` |
| **Findings** | `GET /api/v1/data-security/findings` |
| **Activity Monitor** | `GET /api/v1/data-security/activity` |

### Endpoints (17 total)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/data-security/scan` | Run data security scan |
| GET | `/api/v1/data-security/catalog` | Data catalog |
| GET | `/api/v1/data-security/classification` | Classification results |
| GET | `/api/v1/data-security/lineage` | Data lineage |
| GET | `/api/v1/data-security/residency` | Data residency |
| GET | `/api/v1/data-security/activity` | Activity monitoring |
| GET | `/api/v1/data-security/compliance` | Data compliance |
| GET | `/api/v1/data-security/findings` | Security findings |
| GET | `/api/v1/data-security/governance/{id}` | Access governance |
| GET | `/api/v1/data-security/protection/{id}` | Protection status |
| GET | `/api/v1/data-security/rules/{id}` | Rule detail |
| GET | `/api/v1/data-security/modules` | List modules |
| GET | `/api/v1/data-security/modules/{m}/rules` | Module rules |
| GET | `/api/v1/data-security/accounts/{id}` | Account data security |
| GET | `/api/v1/data-security/services/{s}` | Service data security |

---

## 7. engine_iam

**Code:** `engine_iam/iam_engine/`

### UI Page Mapping

| UI Page | API Endpoints |
|---------|--------------|
| **IAM Dashboard** | `POST /api/v1/iam-security/scan` |
| **IAM Findings** | `GET /api/v1/iam-security/findings` |
| **IAM Rules** | `GET /api/v1/iam-security/rule-ids`, `GET .../modules` |

### Endpoints (8 total)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/iam-security/scan` | Run IAM security scan |
| GET | `/api/v1/iam-security/findings` | IAM findings |
| GET | `/api/v1/iam-security/rules/{id}` | Rule detail |
| GET | `/api/v1/iam-security/modules` | List modules |
| GET | `/api/v1/iam-security/modules/{m}/rules` | Module rules |
| GET | `/api/v1/iam-security/rule-ids` | All IAM rule IDs |

---

## 8. engine_discoveries

**Code:** `engine_discoveries/engine_discoveries_aws/`

### UI Page Mapping

| UI Page | API Endpoints |
|---------|--------------|
| **Run Discovery** | `POST /api/v1/discovery` |
| **Discovery Status** | `GET /api/v1/discovery/{id}/status` |
| **Discovery History** | `GET /api/v1/discoveries` |
| **Services** | `GET /api/v1/services` |

### Endpoints (8 total)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/discovery` | Create discovery scan |
| GET | `/api/v1/discovery/{id}/status` | Discovery status |
| GET | `/api/v1/discoveries` | List discoveries |
| GET | `/api/v1/services` | Available services |
| GET | `/api/v1/health` | Health check |

---

## 9. engine_onboarding

**Code:** `engine_onboarding/`

### UI Page Mapping

| UI Page | API Endpoints |
|---------|--------------|
| **Onboard Account** | `POST /onboarding/{provider}/init`, `POST .../validate` |
| **Account List** | `GET /onboarding/accounts` |
| **Account Detail** | `GET /onboarding/accounts/{id}`, `GET .../health`, `GET .../statistics` |
| **Tenant Management** | `POST /tenants`, `GET /tenants` |
| **Provider Management** | `POST /providers`, `GET /providers` |
| **Credentials** | `POST /{id}/credentials`, `GET .../validate` |
| **Schedules** | `POST /schedules`, `GET /schedules`, `PUT /schedules/{id}` |
| **Schedule Execution** | `POST /schedules/{id}/trigger`, `GET .../executions` |
| **CloudFormation** | `GET /onboarding/aws/cloudformation-template` |

### Endpoints (30+ total)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/onboarding/{provider}/init` | Initialize account onboarding |
| POST | `/onboarding/{provider}/validate` | Validate and activate |
| GET | `/onboarding/{provider}/auth-methods` | Available auth methods |
| GET | `/onboarding/aws/cloudformation-template` | CF template |
| GET | `/onboarding/accounts` | List accounts |
| GET | `/onboarding/accounts/{id}` | Account detail |
| DELETE | `/onboarding/accounts/{id}` | Remove account |
| POST | `/onboarding/tenants` | Create tenant |
| GET | `/onboarding/tenants` | List tenants |
| POST | `/onboarding/providers` | Create provider |
| POST | `/{id}/credentials` | Store credentials |
| POST | `/schedules` | Create schedule |
| GET | `/schedules` | List schedules |
| PUT | `/schedules/{id}` | Update schedule |
| POST | `/schedules/{id}/trigger` | Manual trigger |
| DELETE | `/schedules/{id}` | Delete schedule |

---

## 10. engine_secops

**Code:** `engine_secops/scanner_engine/`

### Endpoints (8 total)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/scan` | Scan project |
| POST | `/scan-local` | Local scan |
| GET | `/results/{project_name}` | Latest results |
| GET | `/api/v1/secops/scans` | List scans |
| GET | `/api/v1/secops/scans/{id}` | Scan detail |
| GET | `/api/v1/secops/scans/{id}/findings` | Scan findings |

---

## 11. engine_pythonsdk

**Code:** `engine_pythonsdk/pythonsdk_service/`

### Endpoints (18 total)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/services` | List AWS services |
| GET | `/api/v1/service/{name}` | Service detail |
| GET | `/api/v1/field-metadata` | Field metadata |
| GET | `/api/v1/fields/security` | Security fields |
| GET | `/api/v1/fields/compliance/{cat}` | Compliance fields |
| GET | `/api/v1/operations` | Available operations |
| GET | `/api/v1/operation/{name}` | Operation detail |
| GET | `/api/v1/references/{type}` | Resource references |
| GET | `/api/v1/relationships/{type}` | Resource relationships |
| GET | `/api/v1/boto3/{service}` | Boto3 data |
| GET | `/api/v1/yaml/{service}` | Discovery YAML |
| POST | `/api/v1/admin/load-data` | Load data |
| POST | `/api/v1/admin/generate-enhancements` | Generate enhancements |

---

## Engines Without API Endpoints

| Engine | Type |
|--------|------|
| engine_input | Data pipeline (no REST API) |
| engine_output | Data export (no REST API) |
| engine_adminportal | Admin UI (frontend) |
| engine_userportal | User UI (frontend) |
| engine_common | Shared library |
