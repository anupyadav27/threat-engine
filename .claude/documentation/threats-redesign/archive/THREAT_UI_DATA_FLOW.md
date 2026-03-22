# Threat UI — Complete Data Flow Reference

> Quick reference: What data each UI component needs, how it flows through the stack.

## Layer Diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│                           NEXT.JS FRONTEND                               │
│  fetchView('threats') ──→ /gateway/api/v1/views/threats                 │
│  getFromEngine('threat', path) ──→ /threat/api/v1/threat/...            │
└─────────────────────────────────┬────────────────────────────────────────┘
                                  │ HTTP (via Next.js rewrites → NLB → Ingress)
┌─────────────────────────────────▼────────────────────────────────────────┐
│                         BFF LAYER (API Gateway)                          │
│  bff/threats.py → normalize_threat() → indicators enrichment            │
│  Aggregates: threat ui-data + onboarding ui-data                        │
│  Returns: {kpi, threats[], mitreMatrix, attackChains, trendData, ...}   │
└─────────────────────────────────┬────────────────────────────────────────┘
                                  │ HTTP (K8s service → engine pod)
┌─────────────────────────────────▼────────────────────────────────────────┐
│                        THREAT ENGINE (Port 8020)                         │
│  /api/v1/threat/ui-data → Aggregated response                           │
│  /api/v1/threat/{id}/detail → Single threat with all context (NEW)      │
│  /api/v1/threat/analytics/* → Aggregation queries                       │
│  /api/v1/graph/* → Neo4j graph queries                                  │
└─────────────────────────────────┬────────────────────────────────────────┘
                                  │ psycopg2 (RDS) + Neo4j driver
┌─────────────────────────────────▼────────────────────────────────────────┐
│                         DATABASES                                        │
│  PostgreSQL RDS: threat_engine_threat (7 tables)                        │
│  PostgreSQL RDS: threat_engine_check (cross-DB for supporting findings) │
│  Neo4j: Security graph (attack paths, blast radius, exposure)           │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Data Flow: Threat List Page

### What UI Renders
```
KPI Strip → {total, critical, high, active, unassigned, avgRiskScore}
Filter Bar → {severity[], status[], mitre_tactic[], provider[], account[], region[]}
MITRE Matrix → {tactic: [{technique_id, name, severity, count}]}
Attack Chains → [{id, name, severity, techniques[], account, affectedResources}]
Threat Table → [{id, title, severity, risk_score, mitre_technique, mitre_tactic,
                  affected_resources, provider, account, status, assignee, indicators{}}]
Severity Donut → [{name, value, color}]
30-Day Trend → [{date, critical, high, medium, low, total}]
Threat Intel → [{source, indicator, type, relevance, matchedAssets}]
```

### How Data Flows

```
UI: fetchView('threats', {provider, account, region})
  ↓
BFF: GET /api/v1/views/threats?tenant_id=X&provider=Y
  │
  ├── fetch_many([
  │     ("threat", "/api/v1/threat/ui-data", {tenant_id, scan_run_id, limit, days}),
  │     ("onboarding", "/api/v1/onboarding/ui-data", {tenant_id}),
  │   ])
  │
  ├── Build account→provider map from onboarding data
  ├── normalize_threat(t) for each threat
  ├── _enrich_threats_provider(threats, map)
  ├── apply_global_filters(threats, provider, account, region)
  ├── Add indicators{} to each threat (NEW — Phase 2)
  ├── Build KPI from filtered threats
  ├── Build MITRE matrix from engine data or threats
  ├── Normalize attack chains
  ├── Normalize threat intel
  ├── Build severity chart
  ├── Process trend data
  │
  └── Return: {kpi, threats, mitreMatrix, attackChains, trendData, severityChart, threatIntel, byProvider}
```

### DB Queries Behind /api/v1/threat/ui-data

```sql
-- Summary
SELECT severity, COUNT(*) FROM threat_findings
WHERE tenant_id = %s GROUP BY severity;

-- Threats (paginated)
SELECT * FROM threat_findings
WHERE tenant_id = %s
ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 ... END
LIMIT %s OFFSET %s;

-- Trend (last N days)
SELECT DATE(created_at) as date, severity, COUNT(*) as count
FROM threat_findings WHERE tenant_id = %s AND created_at >= NOW() - INTERVAL '%s days'
GROUP BY date, severity ORDER BY date;

-- MITRE matrix
SELECT mt.technique_id, mt.technique_name, mt.tactics, mt.severity_base, COUNT(tf.id)
FROM threat_findings tf, jsonb_array_elements_text(tf.mitre_techniques) tech
JOIN mitre_technique_reference mt ON mt.technique_id = tech
WHERE tf.tenant_id = %s GROUP BY 1,2,3,4;

-- Attack paths (from Neo4j, fallback to empty)
-- Internet exposed (from Neo4j, fallback to empty)
-- Toxic combinations (from Neo4j, fallback to empty)

-- Threat intel
SELECT * FROM threat_intelligence WHERE tenant_id = %s AND is_active = true ORDER BY created_at DESC LIMIT 50;

-- Detections
SELECT * FROM threat_detections WHERE tenant_id = %s AND status = 'open' ORDER BY detection_timestamp DESC;

-- Analysis
SELECT * FROM threat_analysis WHERE tenant_id = %s ORDER BY created_at DESC LIMIT 20;
```

---

## Data Flow: Threat Detail Page (NEW)

### What UI Renders
```
Block ①: ThreatHeader → {finding_id, title, severity, risk_score, mitre_technique, status, assignee, provider, account, region}
Block ②: ExposureContext → {is_internet_exposed, exposure_type, exposure_path[]}
Block ③: AttackPathRibbon → {exists, steps[{resource_type, resource_name, technique}]}
Block ④: AffectedResources → [{resource_uid, resource_type, account_id, region, role}]
Block ⑤: BlastRadiusSummary → {reachable_count, resources_with_threats, depth_distribution{}}
Block ⑥: SupportingFindings → [{finding_id, rule_id, rule_name, severity, resource_uid, status}]
Block ⑦: RemediationSteps → {priority, auto_remediable, steps[{order, action, command}]}
Block ⑧: EvidencePanel → {evidence: JSONB}
Block ⑨: MitreContext → {technique_id, name, tactics[], description, detection_guidance{}, remediation_guidance{}}
Block ⑩: Timeline → [{timestamp, event, actor, details}]
Block ⑪: HuntActions → static links with context params
```

### How Data Flows

```
UI: getFromEngine('threat', `/api/v1/threat/${threatId}/detail`)
  ↓
Engine: GET /api/v1/threat/{threat_id}/detail?tenant_id=X
  │
  ├── Query 1: SELECT * FROM threat_findings WHERE finding_id = %s AND tenant_id = %s
  │   → threat object + evidence + finding_data + mitre_techniques + status_history
  │
  ├── Query 2: Cross-DB to threat_engine_check
  │   SELECT cf.finding_id, cf.rule_id, rm.rule_name, cf.severity, cf.resource_uid, cf.status
  │   FROM check_findings cf LEFT JOIN rule_metadata rm ON cf.rule_id = rm.rule_id
  │   WHERE cf.resource_uid = %s AND cf.tenant_id = %s AND cf.status = 'FAIL'
  │   → supporting_findings[]
  │
  ├── Query 3: SELECT * FROM mitre_technique_reference
  │   WHERE technique_id = (first technique from threat.mitre_techniques)
  │   → mitre_context{}
  │
  ├── Query 4: Neo4j — MATCH path from internet to resource
  │   → exposure{} (is_internet_exposed, exposure_path[])
  │
  ├── Query 5: Neo4j — MATCH attack paths involving this resource
  │   → attack_path{} (exists, steps[])
  │
  ├── Query 6: Neo4j — BFS from resource_uid, count reachable
  │   → blast_radius{} (reachable_count, resources_with_threats)
  │
  ├── Build affected_resources from evidence.affected_assets
  ├── Build remediation from finding_data.remediation
  ├── Build timeline from first_seen_at + last_seen_at + status_history
  │
  └── Return: {threat, exposure, attack_path, affected_resources, blast_radius,
               supporting_findings, remediation, mitre_context, timeline}
```

---

## Data Flow: Analytics Page

### Endpoints

```
UI: getFromEngine('threat', '/api/v1/threat/analytics/distribution')
  → {distribution: {critical: N, high: N, medium: N, low: N}}

UI: getFromEngine('threat', '/api/v1/threat/analytics/trend', {days: 30})
  → {trend: [{date, total, critical, high, medium, low}]}

UI: getFromEngine('threat', '/api/v1/threat/analytics/top-services') (NEW)
  → {services: [{service, count, critical, high, medium, low}]}

UI: getFromEngine('threat', '/api/v1/threat/analytics/mitre') (NEW)
  → {matrix: [{technique_id, technique_name, tactics: [], count, severity_base}]}
```

---

## Data Flow: Attack Paths Page

```
UI: getFromEngine('threat', '/api/v1/graph/attack-paths', {scan_run_id: 'latest'})
  ↓
Engine: Neo4j query — find all paths from internet-facing to sensitive resources
  → {attack_paths: [{path_id, title, severity, steps[], mitre_tactics, affected_resources, blast_radius, detected_at}]}
```

---

## Data Flow: Blast Radius Page

```
UI: getFromEngine('threat', '/api/v1/graph/summary')
  → {total_nodes, total_edges, internet_exposed, high_risk}

UI: getFromEngine('threat', '/api/v1/graph/internet-exposed')
  → {resources: [{uid, type, account, region, exposure_type}]}

UI: getFromEngine('threat', '/api/v1/graph/blast-radius/{resource_uid}')
  → {source_resource, reachable_resources[], depth_distribution{}, reachable_count, resources_with_threats}
```

---

## Data Flow: Toxic Combinations Page

```
UI: getFromEngine('threat', '/api/v1/graph/toxic-combinations')
  → {combinations: [{id, factors[], severity, toxicity_score, affected_resources}]}

UI: getFromEngine('threat', '/api/v1/graph/toxic-combinations/matrix') (NEW)
  → {matrix: [{category1, category2, co_occurrence_count, example_resources[]}]}
```

---

## Data Flow: Hunting Page

```
UI: getFromEngine('threat', '/api/v1/intel')
  → {intelligence: [{intel_id, source, intel_type, severity, confidence, indicators[], ttps[]}]}

UI: getFromEngine('threat', '/api/v1/hunt/queries')
  → {queries: [{hunt_id, query_name, description, hunt_type, last_executed_at, hit_count}]}
```

---

## BFF Normalization Reference

### normalize_threat(t) → output fields

| Output Field | Source Field(s) | Transform |
|-------------|----------------|-----------|
| id | threat_id \| finding_id \| id | First non-empty |
| title | title \| recommendation \| resource_uid | Fallback chain |
| mitre_technique | mitre_techniques[0] \| mitre_technique | _first() helper |
| mitre_tactic | mitre_tactics[0] \| mitre_tactic | _first() helper |
| severity | severity | .lower() |
| affected_resources | affected_assets \| affected_resources | Count |
| provider | provider | .upper() |
| account | account_id \| account | Extract from assets if missing |
| region | region | Extract from assets if missing |
| status | status | Default "active" |
| riskScore | risk_score | Default from severity map |
| risk_score | risk_score | Same (backward compat) |
| assignee | assignee | Default "" |
| detected | detected_at \| first_seen_at | |
| resource_type | resource_type | |
| remediation_steps | remediation_steps | Default [] |

### New fields (Phase 2 — bff-enrichment agent):

| Output Field | Source Field | Notes |
|-------------|-------------|-------|
| threat_category | threat_category | For indicator logic |
| attack_path_id | attack_path_id | For has_attack_path indicator |
| blast_radius_count | blast_radius_count | For blast radius chip |
| indicators | (computed) | {internet_exposed, has_attack_path, blast_radius_count, auto_remediable, has_sensitive_data, has_identity_risk} |
