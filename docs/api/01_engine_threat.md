# engine_threat — Threat Detection, Analysis & Security Graph

> Port: **8020** | Docker: `yadavanup84/threat-engine:latest`
> Databases: PostgreSQL (threat_engine_threat, threat_engine_check, threat_engine_inventory) + Neo4j (Aura SaaS)

---

## Folder Structure

```
engine_threat/threat_engine/
├── api_server.py                  # FastAPI (63+ endpoints)
├── analyzer/
│   ├── __init__.py
│   └── threat_analyzer.py         # Risk scoring, blast radius, attack chains
├── graph/
│   ├── __init__.py
│   ├── graph_builder.py           # PostgreSQL → Neo4j graph population
│   └── graph_queries.py           # Attack paths, blast radius, hunting queries
├── database/
│   ├── connection/
│   │   └── database_config.py     # DB connection factory
│   ├── metadata_enrichment.py     # JOIN check_findings + rule_metadata
│   ├── check_db_reader.py         # Read from check DB
│   ├── check_queries.py           # Check query helpers
│   ├── discovery_ndjson_reader.py # Legacy NDJSON reader
│   ├── discovery_queries.py       # Discovery query helpers
│   └── ndjson_reader.py           # Generic NDJSON parser
├── detector/
│   ├── __init__.py
│   ├── threat_detector.py         # Threat grouping + MITRE correlation
│   ├── drift_detector.py          # Config drift detection
│   └── check_drift_detector.py    # Check-level drift
├── reporter/
│   ├── __init__.py
│   └── threat_reporter.py         # Report formatting
├── schemas/
│   ├── __init__.py
│   ├── threat_report_schema.py    # Pydantic models (ThreatReport, ThreatAnalysisResult)
│   ├── misconfig_normalizer.py    # Normalize misconfigs with MITRE JSONB
│   ├── check_models.py            # Check scan models
│   └── discovery_models.py        # Discovery models
├── storage/
│   ├── __init__.py
│   ├── threat_storage.py          # S3/local file storage
│   ├── threat_db_writer.py        # threat_report + detections + findings + analysis
│   └── threat_intel_writer.py     # intelligence + hunt queries + results
├── api/
│   ├── __init__.py
│   ├── check_router.py            # Check sub-routes
│   └── discovery_router.py        # Discovery sub-routes
└── config/
    └── (threat_rules.yaml DELETED — 42MB, rules now in PostgreSQL)
```

---

## UI Page Mapping

| UI Page | API Endpoints | Description |
|---------|--------------|-------------|
| **Threat Dashboard** | `GET /analysis/prioritized`, `GET /graph/summary` | Top threats by risk score, graph stats |
| **Threat List** | `GET /threats` | Filterable/paginated threat table |
| **Threat Detail** | `GET /analysis/{detection_id}`, `GET /{threat_id}` | Blast radius, attack chain, recommendations |
| **Threat Findings** | `GET /{threat_id}/misconfig-findings` | Root cause misconfiguration details |
| **Threat Assets** | `GET /{threat_id}/assets` | Affected resources for a threat |
| **Security Graph** | `GET /graph/attack-paths`, `GET /graph/internet-exposed` | Neo4j graph visualization |
| **Attack Paths** | `GET /graph/attack-paths` | Internet → resource attack paths |
| **Resource Graph** | `GET /graph/resource/{uid}`, `GET /graph/blast-radius/{uid}` | Resource neighbors + blast radius |
| **Toxic Combos** | `GET /graph/toxic-combinations` | Resources with multiple overlapping threats |
| **Threat Intel** | `GET /intel`, `GET /intel/correlate` | IOC/TTP feeds + MITRE correlation |
| **Threat Hunting** | `GET /hunt/predefined`, `POST /hunt/execute` | Cypher queries + saved hunts |
| **Geographic Map** | `GET /map/geographic` | Threats by AWS region |
| **Service Map** | `GET /map/service` | Threats by AWS service |
| **Analytics** | `GET /analytics/trend`, `GET /analytics/patterns` | Trend lines, pattern analysis |
| **Remediation Queue** | `GET /remediation/queue`, `GET /{id}/remediation` | Prioritized fix queue |
| **Reports** | `GET /reports`, `POST /generate` | Generate + list threat reports |
| **Drift Detection** | `GET /drift` | Config and check-status drift |
| **Scan Summary** | `GET /scans/{scan_run_id}/summary` | Per-scan overview |

---

## Endpoint Reference

### Core Threat Operations

#### POST /api/v1/threat/generate
Generate a full threat report (enrich → detect → analyze → store).

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

**Response:**
```json
{
  "schema_version": "cspm_threat_report.v1",
  "tenant": { "tenant_id": "588989875114" },
  "scan_context": {
    "scan_run_id": "ece8c3a6-...",
    "cloud": "aws",
    "trigger_type": "manual"
  },
  "threat_summary": {
    "total_threats": 21,
    "threats_by_severity": { "high": 21 },
    "threats_by_category": { "misconfiguration": 21 },
    "threats_by_status": { "open": 21 }
  },
  "threats": [
    {
      "threat_id": "ac1e6e7e-...",
      "severity": "high",
      "resource_arn": "arn:aws:s3:::aiwebsite01",
      "threat_category": "misconfiguration",
      "mitre_techniques": ["T1562", "T1040", "T1098"],
      "finding_count": 56
    }
  ],
  "misconfig_findings": [ "..." ],
  "analysis_summary": {
    "analyses_count": 21,
    "verdicts": { "medium_risk": 21 },
    "avg_risk_score": 55.1
  }
}
```

#### POST /api/v1/threat/generate/async
Same as above but returns immediately with a job ID.

**Response:** `{ "job_id": "abc-123", "status": "started" }`

#### GET /api/v1/threat/jobs/{job_id}
Poll async job status.

**Response:** `{ "job_id": "abc-123", "status": "completed", "result": { ... } }`

---

### Threat Retrieval

#### GET /api/v1/threat/threats
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
      "mitre_techniques": ["T1562", "T1040", "T1098", "T1190", "T1537"],
      "mitre_tactics": ["defense-evasion", "credential-access"],
      "evidence": {
        "remediation": "Enable S3 bucket versioning...",
        "finding_refs": ["aws.s3.bucket.versioning_enabled", "..."]
      },
      "detection_timestamp": "2026-02-07T..."
    }
  ],
  "total": 21,
  "limit": 100,
  "offset": 0
}
```

#### GET /api/v1/threat/threats/{threat_id}
Get single threat detail.

#### GET /api/v1/threat/{threat_id}
Get threat by ID (legacy route).

#### GET /api/v1/threat/{threat_id}/misconfig-findings
Get root cause findings for a threat.

#### GET /api/v1/threat/{threat_id}/assets
Get affected assets for a threat.

#### PATCH /api/v1/threat/{threat_id}
Update threat status, notes, or assignee.

**Request:** `{ "status": "investigating", "assignee": "security-team", "notes": "Under review" }`

#### GET /api/v1/threat/list
List threats with filters (severity, type, status).

#### GET /api/v1/threat/summary
Lightweight summary only.

#### GET /api/v1/threat/reports
List all threat reports for a tenant.

#### GET /api/v1/threat/reports/{scan_run_id}
Get full threat report for a scan.

---

### Threat Analysis (Risk Scoring)

#### POST /api/v1/threat/analysis/run
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

#### GET /api/v1/threat/analysis/prioritized
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
          "techniques": ["T1485", "T1490", "T1537", "T1530"],
          "tactics": ["defense-evasion", "credential-access"],
          "impact_score": 0.785
        },
        "reachability": { "is_internet_reachable": false },
        "composite_formula": "severity*40 + blast_radius*25 + mitre_impact*25 + reachability*10"
      },
      "recommendations": [
        { "priority": "high", "action": "remediate_misconfiguration", "description": "Fix high-severity..." },
        { "priority": "critical", "action": "enable_backups", "description": "MITRE T1485 data destruction..." },
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

#### GET /api/v1/threat/analysis/{detection_id}
Full analysis for one threat.

**Query Params:** `tenant_id`

#### GET /api/v1/threat/analysis
List all analyses with filters.

**Query Params:** `tenant_id`, `scan_run_id`, `min_risk_score`, `verdict`, `limit`, `offset`

---

### Security Graph (Neo4j)

#### POST /api/v1/graph/build
Build/rebuild the Neo4j security graph from PostgreSQL data.

**Request:** `{ "tenant_id": "588989875114" }`

**Response:**
```json
{
  "status": "completed",
  "stats": {
    "virtual_nodes": 5,
    "resource_nodes": 301,
    "resource_rels": 32,
    "hierarchy_rels": 602,
    "threat_nodes": 21,
    "finding_nodes": 1528,
    "analysis_edges": 49,
    "exposure_edges": 21,
    "total_nodes": 1855,
    "total_relationships": 704
  },
  "duration_ms": 228725.9
}
```

#### GET /api/v1/graph/summary
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

#### GET /api/v1/graph/attack-paths
Find attack paths from Internet to threatened resources.

**Query Params:** `tenant_id`, `max_hops` (1-10, default 5), `min_severity` (default "high")

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
      "mitre_techniques": ["T1562", "T1040", "T1098"],
      "node_names": ["Internet", "elasticbeanstalk-ap-south-1-..."],
      "rel_types": ["EXPOSES"],
      "hops": 1
    }
  ],
  "total": 23
}
```

#### GET /api/v1/graph/internet-exposed
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

#### GET /api/v1/graph/blast-radius/{resource_uid}
Compute blast radius from a specific resource.

**Query Params:** `tenant_id`, `max_hops` (default 5)

**Response:**
```json
{
  "source_resource": "arn:aws:s3:::elasticbeanstalk-...",
  "reachable_count": 4,
  "reachable_resources": [
    {
      "uid": "arn:aws:iam::...role/...",
      "resource_type": "iam.role",
      "hops": 1,
      "threats": [],
      "finding_count": 23
    }
  ],
  "depth_distribution": { "1": 4 },
  "resources_with_threats": 0
}
```

#### GET /api/v1/graph/toxic-combinations
Resources with multiple overlapping threats.

**Query Params:** `tenant_id`, `min_threats` (default 2)

#### GET /api/v1/graph/resource/{resource_uid}
Full graph context for one resource.

**Response:**
```json
{
  "resource": {
    "uid": "arn:aws:s3:::aiwebsite01",
    "resource_type": "s3.resource",
    "risk_score": 20
  },
  "neighbors": [
    {
      "relationship": "RELATES_TO",
      "neighbor_uid": "arn:aws:s3:::anup-backup",
      "neighbor_labels": ["Resource", "S3Bucket"]
    },
    {
      "relationship": "CONTAINS",
      "neighbor_uid": "account:588989875114",
      "neighbor_labels": ["VirtualNode", "Account"]
    }
  ],
  "threats": [
    { "detection_id": "...", "severity": "high", "mitre_techniques": ["..."] }
  ],
  "findings": [
    { "finding_id": "...", "rule_id": "aws.s3.bucket...", "severity": "high" }
  ],
  "neighbor_count": 50,
  "threat_count": 1,
  "finding_count": 56
}
```

---

### Threat Intelligence

#### POST /api/v1/intel/feed
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

#### POST /api/v1/intel/feed/batch
Ingest multiple intel entries.

**Request:** `{ "items": [ { ... }, { ... } ] }`

**Response:** `{ "saved": 2, "total_submitted": 2 }`

#### GET /api/v1/intel
List intel entries.

**Query Params:** `tenant_id`, `intel_type`, `severity`, `source`, `active_only`, `limit`

#### GET /api/v1/intel/correlate
Correlate intel with detections by MITRE technique overlap.

**Response:**
```json
{
  "correlations": [
    {
      "detection_id": "ac1e6e7e-...",
      "resource_arn": "arn:aws:s3:::aiwebsite01",
      "detection_severity": "high",
      "detection_techniques": ["T1562", "T1040", "T1098"],
      "intel_id": "2bb0d686-...",
      "intel_source": "mitre_attack_ics",
      "intel_severity": "critical"
    }
  ],
  "total": 42
}
```

---

### Threat Hunting

#### GET /api/v1/hunt/predefined
List built-in hunt queries.

**Response:**
```json
{
  "hunts": [
    { "id": "internet_to_sensitive_data", "name": "Internet -> Sensitive Data Path" },
    { "id": "lateral_movement_iam", "name": "IAM Lateral Movement Paths" },
    { "id": "public_buckets_with_threats", "name": "Public S3 Buckets with Active Threats" },
    { "id": "high_blast_radius", "name": "Resources with High Blast Radius" },
    { "id": "unprotected_critical_resources", "name": "Critical Resources Without Protection" }
  ]
}
```

#### POST /api/v1/hunt/execute
Execute a hunt (saved, predefined, or ad-hoc Cypher).

**Request (predefined):**
```json
{ "tenant_id": "588989875114", "predefined_id": "public_buckets_with_threats" }
```

**Request (ad-hoc Cypher):**
```json
{
  "tenant_id": "588989875114",
  "cypher": "MATCH (b:S3Bucket {tenant_id: $tid})-[:HAS_THREAT]->(t) RETURN b.uid, t.severity"
}
```

**Response:**
```json
{
  "status": "completed",
  "query_name": "public_buckets_with_threats",
  "results": [ "..." ],
  "total": 21,
  "execution_time_ms": 895.0,
  "result_id": "a2a82f1c-..."
}
```

#### POST /api/v1/hunt/queries
Save a custom hunt query.

**Request:**
```json
{
  "tenant_id": "588989875114",
  "query_name": "S3 public with threats",
  "query_text": "MATCH (b:S3Bucket)-[:HAS_THREAT]->(t) WHERE b.tenant_id = $tid RETURN b, t",
  "hunt_type": "graph",
  "query_language": "cypher",
  "mitre_techniques": ["T1530"]
}
```

#### GET /api/v1/hunt/queries
List saved hunt queries. **Query Params:** `tenant_id`, `active_only`, `limit`

#### GET /api/v1/hunt/results
List past hunt execution results. **Query Params:** `tenant_id`, `hunt_id`, `limit`

---

### Maps & Analytics

#### GET /api/v1/threat/map/geographic
Threats grouped by AWS region.

#### GET /api/v1/threat/map/account
Threats grouped by account ID.

#### GET /api/v1/threat/map/service
Threats grouped by AWS service.

#### GET /api/v1/threat/analytics/trend
Historical threat trends over time.

#### GET /api/v1/threat/analytics/patterns
Common threat patterns (misconfiguration combinations).

#### GET /api/v1/threat/analytics/correlation
Threat correlation matrix.

#### GET /api/v1/threat/analytics/distribution
Threat distribution statistics.

---

### Remediation

#### GET /api/v1/threat/remediation/queue
Get prioritized remediation queue (all threats).

#### GET /api/v1/threat/{threat_id}/remediation
Get remediation workflow for a single threat.

---

### Drift Detection

#### GET /api/v1/threat/drift
Get configuration and check-status drift detections.

---

### Resource Posture

#### GET /api/v1/threat/resources/{resource_uid}/posture
Get check posture for a resource.

#### GET /api/v1/threat/resources/{resource_uid}/threats
Get all threats for a specific resource.

---

### Scan Management

#### GET /api/v1/threat/scans/{scan_run_id}/summary
Get threat scan summary.

---

### Risk Scoring Formula

```
risk_score = severity_weight × 40
           + blast_radius_factor × 25
           + mitre_impact_score × 25
           + reachability_bonus × 10

Where:
  severity_weight:      critical=1.0, high=0.8, medium=0.5, low=0.2
  blast_radius_factor:  min(reachable_resources / 10, 1.0)
  mitre_impact_score:   avg(technique_weights) where T1190=1.0, T1078=0.9, T1485=0.8, etc.
  reachability_bonus:   1.0 if internet-reachable, else 0.0

Verdict thresholds:
  ≥85 → critical_action_required
  ≥70 → high_risk
  ≥50 → medium_risk
  ≥30 → low_risk
  <30 → informational
```
