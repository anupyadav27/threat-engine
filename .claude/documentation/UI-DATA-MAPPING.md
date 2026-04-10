
# UI Data Architecture Mapping — Threat Engine CSPM Platform

**Version:** 1.0
**Date:** 2026-03-31
**Audience:** Backend developers, BFF layer implementers, frontend integration engineers
**Purpose:** Authoritative reference mapping every frontend page to its exact backend data sources, engine endpoints, SQL queries, and derived/calculated metric formulas.

---

## 1. Executive Summary

All 12 UI pages follow a single data-fetching contract:
```
fetchView(pageName, { provider, account, region })
→ GET /gateway/api/v1/views/{pageName}?tenant_id=X&provider=Y&account_id=Z&region=R
```

The **BFF layer** (`shared/api_gateway/bff_views.py`) fans out to 1–8 internal engine HTTP calls in parallel using `asyncio.gather`, then returns a single UI-ready JSON response.

### Data Category Definitions

| Symbol | Category | Meaning |
|--------|----------|---------|
| 🟢 **DIRECT** | Single-engine direct | Data exists in one engine table/endpoint. BFF makes 1 call. No calculation needed. |
| 🟡 **COMBINED** | Multi-engine aggregated | BFF makes 2+ parallel engine calls and merges results in Python. |
| 🔴 **CALCULATED** | Derived/computed metric | Value is calculated inside BFF (or engine) from raw data using a formula. No 1:1 DB field. |

---

## 2. Data Category per Page (Overview)

| Page | BFF View | Engines Involved | Category |
|------|----------|-----------------|----------|
| Dashboard | `/views/dashboard` | inventory, threat, compliance, check, onboarding | 🟡 COMBINED + 🔴 CALCULATED |
| Threat Detection | `/views/threats` | threat | 🟢 DIRECT |
| IAM Security | `/views/iam` | iam | 🟢 DIRECT |
| Network Security | `/views/network-security` | network *(BFF missing)* | 🟢 DIRECT *(needs BFF view)* |
| Data Security | `/views/datasec` | datasec | 🟢 DIRECT |
| Encryption | `/views/encryption` | encryption *(BFF missing)* | 🟢 DIRECT *(needs BFF view)* |
| Database Security | `/views/database-security` | check + discoveries *(BFF missing)* | 🟡 COMBINED *(needs BFF view)* |
| Container Security | `/views/container-security` | check + discoveries *(BFF missing)* | 🟡 COMBINED *(needs BFF view)* |
| Posture Security | `/views/misconfig` | check | 🟢 DIRECT + 🔴 CALCULATED |
| CIEM | `/views/ciem` | threat (CIEM module) | 🟢 DIRECT |
| Compliance | `/views/compliance` | compliance + check | 🟡 COMBINED |
| Inventory | `/views/inventory` | inventory + check | 🟡 COMBINED |
| Risk | `/views/risk` | risk (aggregates from all engines) | 🔴 CALCULATED |

---

## 3. Page-by-Page Data Mapping

---

### 3.1 Threat Detection (`/threats`)

**BFF View:** `GET /gateway/api/v1/views/threats` ✅ Implemented
**Primary Engine:** Threat Engine (`http://engine-threat:8020`)

#### KPI Cards

| KPI Label | Source Field | Engine | Category | Formula / Notes |
|-----------|-------------|--------|----------|-----------------|
| Total Threats | `kpi.total` | threat | 🟢 DIRECT | `COUNT(*)` from `threat_findings WHERE tenant_id=X AND scan_run_id=latest` |
| Critical | `kpi.critical` | threat | 🟢 DIRECT | `COUNT(*) WHERE severity='critical'` |
| High Severity | `kpi.high` | threat | 🟢 DIRECT | `COUNT(*) WHERE severity='high'` |
| Avg Risk Score | `kpi.avgRiskScore` | threat | 🔴 CALCULATED | `AVG(risk_score)` from `threat_findings` |
| Attack Paths | Computed from `threats[].hasAttackPath` | threat | 🔴 CALCULATED | `COUNT(*) WHERE has_attack_path=true` |
| Active Threats | `kpi.active` | threat | 🟢 DIRECT | `COUNT(*) WHERE status='active'` |
| Resolved | `kpi.resolved` | threat | 🟢 DIRECT | `COUNT(*) WHERE status='resolved'` |
| Unassigned | `kpi.unassigned` | threat | 🟢 DIRECT | `COUNT(*) WHERE assignee IS NULL` |

#### Sparkline Data (10-week trend per KPI)

```sql
-- Query per KPI: weekly aggregate from threat_findings grouped by ISO week
SELECT
  DATE_TRUNC('week', last_seen_at) AS week,
  COUNT(*) FILTER (WHERE severity='critical') AS critical,
  COUNT(*) FILTER (WHERE severity='high') AS high,
  COUNT(*) FILTER (WHERE severity='medium') AS medium,
  COUNT(*) FILTER (WHERE severity='low') AS low,
  COUNT(*) AS total,
  COUNT(*) FILTER (WHERE status='active') AS active,
  COUNT(*) FILTER (WHERE has_attack_path=true) AS attack_paths,
  ROUND(AVG(risk_score), 1) AS avg_risk_score
FROM threat_findings
WHERE tenant_id = :tenant_id
  AND last_seen_at >= NOW() - INTERVAL '10 weeks'
GROUP BY DATE_TRUNC('week', last_seen_at)
ORDER BY week ASC;
```
Returns 10 rows → each KPI gets its own array sliced from this result.

#### Trend Chart (30-day area chart)

```sql
-- Same as sparklines but daily granularity for last 30 days
SELECT DATE_TRUNC('day', last_seen_at) AS date,
  COUNT(*) FILTER (WHERE severity='critical') AS critical,
  COUNT(*) FILTER (WHERE severity='high') AS high,
  COUNT(*) FILTER (WHERE severity='medium') AS medium,
  COUNT(*) FILTER (WHERE severity='low') AS low
FROM threat_findings
WHERE tenant_id=:tenant_id AND last_seen_at >= NOW() - INTERVAL '30 days'
GROUP BY 1 ORDER BY 1;
```

#### MITRE Matrix

```sql
SELECT mitre_tactic, mitre_technique, COUNT(*) AS count, MAX(severity) AS top_severity
FROM threat_findings
WHERE tenant_id=:tenant_id AND scan_run_id=:scan_run_id
  AND mitre_tactic IS NOT NULL
GROUP BY mitre_tactic, mitre_technique
ORDER BY mitre_tactic, count DESC;
```

#### Tables

| Tab | accessorKey values | Source Table | Key Filter |
|-----|-------------------|-------------|-----------|
| All Threats | provider, account, region, resourceType, title, mitreTechnique, threat_category, riskScore, severity, lastSeen | `threat_findings` | `tenant_id + scan_run_id` |
| Critical | same | same | `+ severity='critical'` |
| Has Attack Path | same | same | `+ has_attack_path=true` |
| Unassigned | same | same | `+ assignee IS NULL` |

#### BFF Response Shape
```typescript
{
  threats: ThreatFinding[],        // from /api/v1/threat/list
  trendData: ThreatTrendPoint[],   // from /api/v1/threat/analytics/trend
  mitreMatrix: MitreMatrix,        // from /api/v1/threat/analytics/mitre
  attackChains: AttackChain[],     // from /api/v1/graph/attack-paths
  threatIntel: ThreatIntel[],      // from /api/v1/intel
  kpi: ThreatKpi                   // from /api/v1/threat/kpi
}
```

---

### 3.2 IAM Security (`/iam`)

**BFF View:** `GET /gateway/api/v1/views/iam` ✅ Implemented
**Primary Engine:** IAM Engine (`http://engine-iam:8003`)

#### KPI Cards

| KPI Label | Source Field | Engine | Category | Formula |
|-----------|-------------|--------|----------|---------|
| Posture Score | `kpiGroups[0].items[posture_score].value` | iam | 🔴 CALCULATED | `AVG(control_weight × pass_rate)` across iam_modules. Stored in `iam_report.posture_score` |
| Total Findings | `kpiGroups[0].items[total_findings].value` | iam | 🟢 DIRECT | `iam_report.total_findings` |
| Identities | `kpiGroups[1].items[identities].value` | iam | 🟢 DIRECT | `COUNT(DISTINCT resource_uid) WHERE resource_type='user'` in `iam_findings` |
| Keys to Rotate | `kpiGroups[1].items[keys_to_rotate].value` | iam | 🔴 CALCULATED | `COUNT(*) WHERE iam_modules @> '{key_rotation}' AND status='FAIL'` |
| MFA Adoption | `kpiGroups[1].items[mfa_adoption].value` | iam | 🔴 CALCULATED | `100 - (mfa_fail_count / identity_count × 100)` |
| Critical | `kpiGroups[0].items[critical].value` | iam | 🟢 DIRECT | `iam_report.critical_findings` |
| High | `kpiGroups[0].items[high].value` | iam | 🟢 DIRECT | `iam_report.high_findings` |

#### Identity Risk Trend (Stacked Area Chart — 8 weeks)

```sql
-- From iam_report table, one row per scan (ordered chronologically)
SELECT
  s.scan_start_time AS date,
  ir.total_findings,
  ir.overprivileged_count,   -- from iam_report.findings_by_module JSONB->>'overprivileged'
  ir.no_mfa_count,           -- from iam_report.findings_by_module JSONB->>'no_mfa'
  ir.total_identities        -- iam_report.identity_count
FROM iam_report ir
JOIN scan_orchestration s USING (scan_run_id)
WHERE ir.tenant_id=:tenant_id
ORDER BY s.scan_start_time DESC
LIMIT 8;
-- Then: safe = total_identities - overprivileged_count - no_mfa_count
```

#### Module Scores (for middle panel compact list)

```sql
-- From iam_report.findings_by_module JSONB
-- OR from aggregated iam_findings grouped by iam_modules
SELECT
  unnest(iam_modules) AS module,
  COUNT(*) AS total,
  COUNT(*) FILTER (WHERE status='PASS') AS pass
FROM iam_findings
WHERE tenant_id=:tenant_id AND scan_run_id=:scan_run_id
GROUP BY module;
```

Expected modules: `overprivileged`, `no_mfa`, `key_rotation`, `service_accounts`, `privilege_escalation`, `cross_account`, `admin_policies`

#### Tables

| Tab | accessorKey | Source Table | Key Fields |
|-----|------------|-------------|-----------|
| Overview (Identities) | username, type, account, policies, severity, risk_score, mfa | `iam_findings` | `resource_type='user' OR 'role'` |
| Roles & Policies | name, type, rule_id, severity, status, account_id, region | `iam_findings` | `resource_type IN ('role','policy')` |
| Access Control | user, type, rule_id, severity, status, account_id, region | `iam_findings` | `iam_modules @> '{key_rotation}'` |
| Privilege Escalation | name, type, rule_id, severity, status, account_id, region | `iam_findings` | `iam_modules @> '{privilege_escalation}'` |

#### BFF Response Shape
```typescript
{
  identities: IamFinding[],
  roles: IamFinding[],
  accessKeys: IamFinding[],
  privilegeEscalation: IamFinding[],
  kpiGroups: KpiGroup[],
  pageContext: PageContext
}
```

---

### 3.3 Network Security (`/network-security`)

**BFF View:** `GET /gateway/api/v1/views/network-security` ❌ NOT YET BUILT
**Primary Engine:** Network Engine (`http://engine-network:8006`)

#### KPI Cards

| KPI Label | Source Field | Engine | Category | Formula |
|-----------|-------------|--------|----------|---------|
| Posture Score | `kpiGroups[0].items[posture_score].value` | network | 🔴 CALCULATED | `network_report.posture_score` — weighted avg of module scores |
| Total Findings | `kpiGroups[0].items[total_findings].value` | network | 🟢 DIRECT | `network_report.total_findings` |
| Exposed Resources | `kpiGroups[1].items[exposed_resources].value` | network | 🔴 CALCULATED | `COUNT(DISTINCT resource_uid) WHERE effective_exposure IN ('internet','any')` |
| WAF Coverage | `kpiGroups[1].items[waf_coverage].value` | network | 🔴 CALCULATED | `(waf_protected_resources / total_lb_resources) × 100` |
| Internet Exposed | `kpiGroups[1].items[internet_exposed].value` | network | 🟢 DIRECT | `network_report.exposure_summary->>'internet_exposed'` |
| Open Security Groups | `kpiGroups[1].items[open_sgs].value` | network | 🔴 CALCULATED | `COUNT(*) WHERE network_modules @> '{security_groups}' AND effective_exposure != 'none'` |

#### 8-Week Trend (ComposedChart: stacked bars + pass rate line)

```sql
SELECT
  s.scan_start_time AS date,
  nr.critical_findings AS critical,
  nr.high_findings AS high,
  nr.medium_findings AS medium,
  nr.low_findings AS low,
  nr.total_findings AS total,
  nr.posture_score AS passRate,
  nr.exposure_summary->>'exposed_ports' AS exposed_ports,
  nr.exposure_summary->>'open_sgs' AS open_sgs
FROM network_report nr
JOIN scan_orchestration s USING (scan_run_id)
WHERE nr.tenant_id=:tenant_id
ORDER BY s.scan_start_time DESC
LIMIT 8;
```

#### Module Scores

From `network_report.findings_by_module JSONB`:
```json
{ "security_groups": {"pass": 14, "total": 25},
  "internet_exposure": {"pass": 4, "total": 12},
  "waf_ddos": {"pass": 8, "total": 13},
  "vpc_topology": {"pass": 11, "total": 15},
  "dns_security": {"pass": 6, "total": 10},
  "load_balancer": {"pass": 9, "total": 12} }
```

#### Tables

| Tab | accessorKey | Source | Key Filter |
|-----|------------|--------|-----------|
| Overview/Findings | resource_name, rule_id, module, severity, status, account_id, region, resource_type | `network_findings` | all |
| Security Groups | group_name, group_id, vpc_id, open_to_internet, inbound_rules, outbound_rules, severity | `network_security_groups` | - |
| Internet Exposure | resource_name, resource_type, exposure_type, ports, protocols, severity | `network_findings` | `effective_exposure='internet'` |
| VPC Topology | vpc_id, cidr_block, subnets, peering_connections, transit_gateways, internet_gateways, nat_gateways | `network_topology_snapshot` | - |
| WAF/DDoS | resource_name, waf_enabled, shield_enabled, web_acl_name, rule_count, severity | `network_findings` | `network_modules @> '{waf}'` |

#### ❌ BFF Actions Required
1. Add `network-security` view in `bff_views.py`
2. Call `GET http://engine-network:8006/api/v1/network/ui-data?tenant_id=X&scan_run_id=Y`
3. Return normalized response with `kpiGroups`, `findings`, security_groups, topology, waf arrays

---

### 3.4 Data Security (`/datasec`)

**BFF View:** `GET /gateway/api/v1/views/datasec` ✅ Implemented
**Primary Engine:** DataSec Engine (`http://engine-datasec:8004`)

#### KPI Cards

| KPI Label | Source Field | Engine | Category | Formula |
|-----------|-------------|--------|----------|---------|
| Posture Score | `kpiGroups[0].items[posture_score]` | datasec | 🔴 CALCULATED | `datasec_report.data_risk_score` — weighted: encryption(30%), classification(25%), access(25%), residency(20%) |
| Total Findings | `kpiGroups[0].items[total_findings]` | datasec | 🟢 DIRECT | `datasec_report.total_findings` |
| Exposed Stores | `kpiGroups[1].items[exposed_stores]` | datasec | 🔴 CALCULATED | `COUNT(DISTINCT resource_uid) WHERE datasec_modules @> '{public_access}' AND status='FAIL'` |
| DLP Violations | `kpiGroups[1].items[dlp_violations]` | datasec | 🟢 DIRECT | `COUNT(*) WHERE datasec_modules @> '{dlp}'` |
| Unencrypted Stores | derived | datasec | 🔴 CALCULATED | `COUNT(*) WHERE datasec_modules @> '{encryption}' AND status='FAIL'` |
| Classified Resources % | `datasec_report.classified_pct` | datasec | 🔴 CALCULATED | `classified_resources / total_data_stores × 100` |

#### 8-Week Trend

```sql
SELECT s.scan_start_time AS date,
  dr.data_risk_score AS posture_score,
  dr.critical_findings AS critical,
  dr.high_findings AS high,
  dr.medium_findings AS medium,
  dr.total_findings AS total
FROM datasec_report dr
JOIN scan_orchestration s USING (scan_run_id)
WHERE dr.tenant_id=:tenant_id ORDER BY s.scan_start_time DESC LIMIT 8;
```

#### Module Scores

From `datasec_report.findings_by_module JSONB`:
```json
{ "data_classification": {"pass":18,"total":25},
  "encryption_coverage": {"pass":14,"total":22},
  "public_access": {"pass":5,"total":12},
  "dlp_rules": {"pass":8,"total":15},
  "data_residency": {"pass":11,"total":18},
  "access_monitoring": {"pass":9,"total":14} }
```

#### Tables

| Tab | accessorKey | Source Table | Notes |
|-----|------------|-------------|-------|
| Catalog | resource, type, classification, encryption_status, access_level, region | `datasec_findings` | grouped by data store |
| Classifications | name, type, sensitivity_score, count, severity | `datasec_findings` | `datasec_modules @> '{classification}'` |
| DLP | resource_uid, rule_id, dlp_policy, severity, status | `datasec_findings` | `datasec_modules @> '{dlp}'` |
| Encryption | resource_uid, resource_type, encryption_status, key_type, severity | `datasec_findings` | `datasec_modules @> '{encryption}'` |
| Residency | resource_uid, region, expected_region, violation_type | `datasec_findings` | `datasec_modules @> '{residency}'` |
| Access Monitoring | resource_uid, access_pattern, last_access, anomaly_score | `datasec_findings` | `datasec_modules @> '{access_monitoring}'` |

---

### 3.5 Encryption (`/encryption`)

**BFF View:** `GET /gateway/api/v1/views/encryption` ❌ NOT YET BUILT
**Primary Engine:** Encryption Engine (`http://engine-encryption:8007`)

#### KPI Cards

| KPI Label | Source Field | Engine | Category | Formula |
|-----------|-------------|--------|----------|---------|
| Posture Score | `encryption_report.posture_score` | encryption | 🔴 CALCULATED | `(coverage×0.35 + rotation×0.25 + algorithm×0.20 + transit×0.20)` |
| Total Findings | `encryption_report.total_findings` | encryption | 🟢 DIRECT | direct |
| Unencrypted | `encryption_report.unencrypted_resources` | encryption | 🟢 DIRECT | `total_resources - encrypted_resources` |
| Expiring Certs | derived | encryption | 🔴 CALCULATED | `COUNT(*) FROM encryption_key_inventory WHERE pending_deletion_days < 30 OR (cert_expiry IS NOT NULL AND cert_expiry < NOW() + INTERVAL '90 days')` |

#### 8-Week Trend (same pattern)

```sql
SELECT s.scan_start_time AS date,
  er.posture_score,
  er.critical_findings AS critical,
  er.high_findings AS high,
  er.medium_findings AS medium,
  er.total_findings AS total
FROM encryption_report er
JOIN scan_orchestration s USING (scan_run_id)
WHERE er.tenant_id=:tenant_id ORDER BY s.scan_start_time DESC LIMIT 8;
```

#### Module Scores

From `encryption_report.coverage_by_service JSONB`:
```json
{ "kms_keys": {"pass":18,"total":22},
  "s3_encryption": {"pass":24,"total":30},
  "rds_encryption": {"pass":12,"total":15},
  "ebs_volumes": {"pass":8,"total":14},
  "tls_https": {"pass":16,"total":20},
  "certificates": {"pass":11,"total":14} }
```

#### Tables

| Tab | accessorKey | Source Table | Notes |
|-----|------------|-------------|-------|
| Findings | resource_uid, resource_type, encryption_domain, encryption_status, severity, status, rule_id | `encryption_findings` | all |
| Key Inventory | key_arn, key_alias, key_state, rotation_enabled, rotation_interval_days, pending_deletion_days | `encryption_key_inventory` | - |
| Certificates | resource_uid, cert_domain, expiry_date, days_remaining, algorithm, severity | `encryption_findings` | `encryption_domain='certificate'` |
| Secrets | resource_uid, secret_name, rotation_enabled, last_rotated, days_since_rotation | `encryption_findings` | `encryption_domain='secret'` |

#### ❌ BFF Actions Required
1. Add `encryption` view in `bff_views.py`
2. Call `GET http://engine-encryption:8007/api/v1/encryption/ui-data`

---

### 3.6 Database Security (`/database-security`)

**BFF View:** `GET /gateway/api/v1/views/database-security` ❌ NOT YET BUILT
**Category:** 🟡 COMBINED (check engine + discoveries engine)

#### KPI Cards

| KPI Label | Source | Engine | Category | Formula |
|-----------|--------|--------|----------|---------|
| Posture Score | `check_findings` grouped | check | 🔴 CALCULATED | `passed_db_controls / total_db_controls × 100` where DB controls = rules with `resource_type IN ('rds','dynamodb','elasticache','redshift','aurora')` |
| Total Findings | `check_findings` count | check | 🟢 DIRECT | `COUNT(*) WHERE resource_type IN (db_types) AND status='FAIL'` |
| Public Databases | `check_findings` | check | 🔴 CALCULATED | `COUNT(DISTINCT resource_uid) WHERE rule_id LIKE '%public%' AND resource_type IN (db_types) AND status='FAIL'` |
| Unencrypted DBs | `check_findings` | check | 🔴 CALCULATED | `COUNT(DISTINCT resource_uid) WHERE rule_id LIKE '%encryption%' AND resource_type IN (db_types) AND status='FAIL'` |

**DB resource types:** `rds, aurora, dynamodb, elasticache, redshift, documentdb, neptune`

#### Module Scores — 6 modules derived from check findings rule categories:

| Module | Source | Formula |
|--------|--------|---------|
| Access Control | check_findings | `WHERE rule_id LIKE '%access%' OR '%auth%' AND resource_type IN db_types` |
| Encryption | check_findings | `WHERE rule_id LIKE '%encrypt%' AND resource_type IN db_types` |
| Audit Logging | check_findings | `WHERE rule_id LIKE '%log%' OR '%audit%' AND resource_type IN db_types` |
| Backup & Recovery | check_findings | `WHERE rule_id LIKE '%backup%' OR '%retention%' AND resource_type IN db_types` |
| Network Security | check_findings | `WHERE rule_id LIKE '%vpc%' OR '%public%' AND resource_type IN db_types` |
| Configuration | check_findings | remaining DB findings |

#### 8-Week Trend — COMBINED query

```sql
-- Need to derive from check_findings historical by week (no dedicated db_security_report table yet)
SELECT
  DATE_TRUNC('week', last_seen_at) AS date,
  COUNT(*) FILTER (WHERE severity='critical') AS critical,
  COUNT(*) FILTER (WHERE severity='high') AS high,
  COUNT(*) FILTER (WHERE severity='medium') AS medium,
  COUNT(*) FILTER (WHERE status='PASS') AS passed,
  COUNT(*) AS total,
  ROUND(COUNT(*) FILTER (WHERE status='PASS') * 100.0 / NULLIF(COUNT(*),0), 1) AS passRate
FROM check_findings
WHERE tenant_id=:tenant_id
  AND resource_type = ANY(ARRAY['rds','aurora','dynamodb','elasticache','redshift'])
  AND last_seen_at >= NOW() - INTERVAL '8 weeks'
GROUP BY DATE_TRUNC('week', last_seen_at)
ORDER BY 1;
```

#### Tables — from check_findings + discoveries

| Tab | accessorKey | Source | Notes |
|-----|------------|--------|-------|
| Overview | resource_name, rule_id, module, severity, status, account_id, region | `check_findings` | `resource_type IN db_types` |
| Access Control | resource_uid, finding_title, resource_type, severity | `check_findings` | rule category filter |
| Encryption | resource_uid, resource_type, finding_title, severity, status | `check_findings` | rule_id LIKE '%encrypt%' |
| Audit Logging | resource_uid, logging_enabled, trail_arn, severity | `check_findings` | rule_id LIKE '%log%' |
| Backup | resource_uid, backup_retention, last_backup, severity | `check_findings` | rule_id LIKE '%backup%' |
| Network | resource_uid, vpc_id, publicly_accessible, sg_count, severity | `check_findings` | rule_id LIKE '%public%' |

#### ❌ BFF Actions Required
1. Add `database-security` view in `bff_views.py`
2. Call check engine: `GET /api/v1/check/findings?resource_types=rds,dynamodb,...`
3. Optionally call discoveries engine for DB inventory enrichment
4. Derive posture_score and module scores in BFF Python

---

### 3.7 Container Security (`/container-security`)

**BFF View:** `GET /gateway/api/v1/views/container-security` ❌ NOT YET BUILT
**Category:** 🟡 COMBINED (check engine + discoveries engine)

#### KPI Cards

| KPI Label | Source | Engine | Category | Formula |
|-----------|--------|--------|----------|---------|
| Posture Score | check_findings | check | 🔴 CALCULATED | `passed_container_controls / total_container_controls × 100` |
| Total Findings | check_findings | check | 🟢 DIRECT | `COUNT(*) WHERE resource_type IN (container_types) AND status='FAIL'` |
| Vulnerable Images | check_findings | check | 🔴 CALCULATED | `COUNT(DISTINCT resource_uid) WHERE resource_type IN ('ecr','ecs_task_definition') AND severity IN ('critical','high') AND status='FAIL'` |
| Privileged Containers | check_findings | check | 🔴 CALCULATED | `COUNT(DISTINCT resource_uid) WHERE rule_id LIKE '%privileged%' AND status='FAIL'` |

**Container resource types:** `eks_cluster, ecs_cluster, ecs_task_definition, ecr_repository, ecs_service, k8s_deployment, k8s_pod`

#### Module Scores

| Module | Rule ID Pattern | Source |
|--------|----------------|--------|
| Cluster Security | `%cluster%`, `%control_plane%` | check_findings |
| Workload Security | `%workload%`, `%pod_security%` | check_findings |
| Image Security | `%image%`, `%ecr%`, `%scan%` | check_findings |
| Network Exposure | `%network%`, `%ingress%` | check_findings |
| RBAC Access | `%rbac%`, `%iam_role%` | check_findings |
| Runtime Audit | `%runtime%`, `%logging%`, `%audit%` | check_findings |

#### ❌ BFF Actions Required
1. Add `container-security` view in `bff_views.py`
2. Call check engine filtered by container resource types
3. Call discoveries engine for ECS/EKS cluster inventory (optional enrichment)

---

### 3.8 Posture Security / Misconfigurations (`/misconfig`)

**BFF View:** `GET /gateway/api/v1/views/misconfig` ✅ Implemented (via threat engine findings)
**Primary Engine:** Check Engine (`http://engine-check:8002`)

#### KPI Cards — All Calculated from check_findings

| KPI Label | Category | Formula |
|-----------|----------|---------|
| Pass Rate | 🔴 CALCULATED | `COUNT(*) FILTER (WHERE status='PASS') / COUNT(*) × 100` |
| Services Affected | 🔴 CALCULATED | `COUNT(DISTINCT service)` from check_findings |
| Auto-Remediable | 🔴 CALCULATED | `COUNT(*) WHERE auto_remediable=true AND status='FAIL'` — needs `auto_remediable` flag in check_findings |
| SLA Breached | 🔴 CALCULATED | `COUNT(*) WHERE status='FAIL' AND first_seen_at < NOW() - (CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 7 WHEN 'medium' THEN 30 ELSE 90 END * INTERVAL '1 day')` |
| Avg Finding Age | 🔴 CALCULATED | `AVG(NOW() - first_seen_at)` in days, for FAIL findings |
| New This Scan | 🔴 CALCULATED | Findings in current scan_run_id NOT in previous scan_run_id |

#### SLA Breach Formula (important)

```sql
-- SLA thresholds by severity:
-- Critical: 1 day, High: 7 days, Medium: 30 days, Low: 90 days
SELECT COUNT(*) AS sla_breached
FROM check_findings
WHERE tenant_id=:tenant_id AND status='FAIL'
  AND first_seen_at < NOW() - CASE
    WHEN severity='critical' THEN INTERVAL '1 day'
    WHEN severity='high'     THEN INTERVAL '7 days'
    WHEN severity='medium'   THEN INTERVAL '30 days'
    ELSE                          INTERVAL '90 days'
  END;
```

#### New This Scan (delta) Formula

```sql
-- Findings in latest scan NOT in the previous scan
WITH latest AS (SELECT scan_run_id FROM scan_orchestration WHERE tenant_id=:tenant_id ORDER BY scan_start_time DESC LIMIT 1),
prev AS (SELECT scan_run_id FROM scan_orchestration WHERE tenant_id=:tenant_id ORDER BY scan_start_time DESC LIMIT 1 OFFSET 1)
SELECT COUNT(*) AS new_findings
FROM check_findings cf_new
WHERE cf_new.scan_run_id = (SELECT scan_run_id FROM latest)
  AND NOT EXISTS (
    SELECT 1 FROM check_findings cf_old
    WHERE cf_old.scan_run_id = (SELECT scan_run_id FROM prev)
      AND cf_old.resource_uid = cf_new.resource_uid
      AND cf_old.rule_id = cf_new.rule_id
  );
```

#### Charts

| Chart | Data | Source | Formula |
|-------|------|--------|---------|
| Severity Donut | {critical, high, medium, low, passed} | check_findings | `COUNT GROUP BY severity` |
| By Category Radar | [{category, fail, total}] | check_findings | `COUNT GROUP BY posture_category` |
| By Service Bar | [{service, count}] | check_findings | `COUNT GROUP BY service ORDER BY count DESC LIMIT 10` |
| Coverage Trend | [{date, passRate, critical, high}] | check_findings weekly | `GROUP BY week` |

#### Table

| accessorKey | Source Field | Notes |
|------------|-------------|-------|
| rule_id | `check_findings.rule_id` | direct |
| title | `check_findings.title` or from rule metadata | join `rule_metadata.title` |
| severity | `check_findings.severity` | direct |
| status | `check_findings.status` | direct |
| service | `check_findings.service` | direct |
| provider | `check_findings.provider` | direct |
| account_id | `check_findings.account_id` | direct |
| region | `check_findings.region` | direct |
| resource_uid | `check_findings.resource_uid` | direct |
| posture_category | `check_findings.posture_category` | direct |
| age_days | 🔴 CALCULATED | `EXTRACT(day FROM NOW() - first_seen_at)` |
| sla_status | 🔴 CALCULATED | See SLA formula above per row |
| auto_remediable | `check_findings.auto_remediable` | needs flag in schema |
| risk_score | `check_findings.risk_score` or 🔴 CALCULATED | from rule metadata weight |

---

### 3.9 CIEM — Log Analysis (`/ciem`)

**BFF View:** `GET /gateway/api/v1/views/ciem` ❌ NOT YET BUILT (uses `threats` view currently)
**Primary Engine:** Threat Engine (`http://engine-threat:8020`) — CIEM module

#### KPI Cards

| KPI Label | Source Field | Engine | Category | Formula |
|-----------|-------------|--------|----------|---------|
| Posture Score | derived | threat | 🔴 CALCULATED | `(detected_threats / total_events × 100)` or `(rules_triggered / total_rules × 100)` |
| Total Findings | `totalFindings` | threat | 🟢 DIRECT | `COUNT(*) FROM threat_findings WHERE threat_category IN ('ciem','identity_risk','log_analysis')` |
| Identities at Risk | `uniqueActors` | threat | 🔴 CALCULATED | `COUNT(DISTINCT actor_principal)` |
| Rules Triggered | `rulesTriggered` | threat | 🔴 CALCULATED | `COUNT(DISTINCT rule_id)` from CIEM findings |
| L2 Correlations | `l2Findings` | threat | 🟢 DIRECT | `COUNT(*) WHERE threat_category='correlation'` |
| L3 Anomalies | `l3Findings` | threat | 🟢 DIRECT | `COUNT(*) WHERE threat_category='anomaly' OR l3_anomaly_score > 0` |

#### Module Scores

| Module | Formula |
|--------|---------|
| Log Collection | `log_sources collected / total_accounts × 100` — from onboarding/discoveries |
| Rule Detection | `rules_with_findings / total_ciem_rules × 100` — from rule engine |
| Identity Risk | `identities_at_risk / total_identities × 100` — from iam + threat engines |
| Correlation Engine | `l2_findings / total_findings × 100` — from threat engine |
| Anomaly Detection | `l3_findings / total_findings × 100` — from threat engine |
| Threat Intel | `intel_matched_findings / total_findings × 100` — from threat intel module |

> ⚠️ **COMBINED**: Full module scores require data from threat engine + iam engine + onboarding engine

#### 8-Week Trend

```sql
SELECT
  DATE_TRUNC('week', last_seen_at) AS date,
  COUNT(*) FILTER (WHERE severity='critical') AS critical,
  COUNT(*) FILTER (WHERE severity='high') AS high,
  COUNT(*) FILTER (WHERE severity='medium') AS medium,
  COUNT(*) AS total,
  COUNT(DISTINCT actor_principal) AS overprivileged,
  COUNT(*) FILTER (WHERE threat_category='anomaly') AS detections,
  ROUND(COUNT(*) FILTER (WHERE status='PASS') * 100.0 / NULLIF(COUNT(*),0), 1) AS passRate
FROM threat_findings
WHERE tenant_id=:tenant_id
  AND threat_category IN ('ciem','identity_risk','log_analysis','correlation','anomaly')
  AND last_seen_at >= NOW() - INTERVAL '8 weeks'
GROUP BY DATE_TRUNC('week', last_seen_at)
ORDER BY 1;
```

#### Tables

| Tab | accessorKey | Source | Filter |
|-----|------------|--------|--------|
| Overview | severity, title, rule_id, actor_principal, resource_uid, event_time | `threat_findings` | `threat_category IN (ciem_types)` ORDER BY risk_score DESC |
| Identity Risk | actor_principal, risk_score, total_findings, critical, high, rules_triggered, services_used, resources_touched | `threat_findings` | `GROUP BY actor_principal` |
| Detection Rules | rule_id, severity, title, finding_count, rule_source, unique_actors, unique_resources | `threat_findings` | `GROUP BY rule_id` |
| Log Sources | source_type, source_bucket, source_region, event_count, earliest, latest | CIEM log metadata table (new) | - |

#### ❌ BFF Actions Required
1. Add `ciem` view in `bff_views.py` (separate from threats view)
2. Aggregate from threat engine CIEM module + iam engine
3. Build log_sources from a new `ciem_log_sources` table or onboarding metadata

---

### 3.10 Compliance (`/compliance`)

**BFF View:** `GET /gateway/api/v1/views/compliance` ✅ Implemented
**Engines:** Compliance Engine + Check Engine
**Category:** 🟡 COMBINED

#### KPI Cards

| KPI Label | Source | Engine | Category | Formula |
|-----------|--------|--------|----------|---------|
| Overall Score | `overallScore` | compliance | 🔴 CALCULATED | `AVG(framework_score)` across enabled frameworks |
| Total Controls | `postureSummary.total_controls` | compliance | 🟢 DIRECT | from compliance_report |
| Passing Controls | `postureSummary.controls_passed` | compliance | 🟢 DIRECT | direct |
| Failing Controls | `postureSummary.controls_failed` | compliance | 🟢 DIRECT | direct |
| Frameworks Passing | `frameworkSummary.passing` | compliance | 🔴 CALCULATED | `COUNT(frameworks WHERE framework_score >= 70)` |

#### Framework Matrix

```sql
-- From compliance engine
SELECT
  compliance_framework,
  total_controls,
  passed_controls,
  failed_controls,
  partial_controls,
  ROUND(passed_controls * 100.0 / NULLIF(total_controls,0), 1) AS framework_score
FROM compliance_report
WHERE tenant_id=:tenant_id AND scan_run_id=:scan_run_id
ORDER BY framework_score DESC;
```

#### Account × Framework Matrix (cross-engine)

```sql
-- COMBINED: compliance engine (per framework) × onboarding (account list)
SELECT
  o.account_id,
  o.account_name,
  o.provider,
  cr.compliance_framework,
  cr.framework_score
FROM compliance_report cr
JOIN cloud_accounts o USING (account_id)
WHERE cr.tenant_id=:tenant_id AND cr.scan_run_id=:scan_run_id;
```

#### Failing Controls Table

```sql
-- COMBINED: compliance_control_findings + check_findings joined on control_id
SELECT
  ccf.control_id,
  ccf.control_title,
  ccf.framework,
  ccf.severity,
  COUNT(cf.finding_id) AS failing_resources,
  COUNT(cf.finding_id) FILTER (WHERE cf.status='PASS') AS passing_resources
FROM compliance_control_findings ccf
JOIN check_findings cf ON cf.rule_id = ccf.rule_id
WHERE ccf.tenant_id=:tenant_id AND ccf.scan_run_id=:scan_run_id
  AND cf.status='FAIL'
GROUP BY ccf.control_id, ccf.control_title, ccf.framework, ccf.severity
ORDER BY failing_resources DESC;
```

---

### 3.11 Inventory (`/inventory`)

**BFF View:** `GET /gateway/api/v1/views/inventory` ✅ Implemented
**Engines:** Inventory Engine + Check Engine
**Category:** 🟡 COMBINED

#### KPI Cards

| KPI Label | Source | Engine | Category |
|-----------|--------|--------|----------|
| Total Assets | `summary.total_assets` | inventory | 🟢 DIRECT |
| New Assets | `summary.new_assets` | inventory | 🔴 CALCULATED | New since last scan |
| Removed Assets | `summary.removed_assets` | inventory | 🔴 CALCULATED | In prev scan, not current |
| Changed Assets | `summary.changed_assets` | inventory | 🔴 CALCULATED | `config_hash` changed |
| Total Findings | 🟡 COMBINED | check | 🟢 DIRECT | COUNT from check_findings |
| Risk Score | 🟡 COMBINED | check | 🔴 CALCULATED | `AVG(risk_score)` per asset |

#### Asset Enrichment (cross-engine JOIN)

```sql
-- COMBINED: inventory assets + check findings joined by resource_uid
SELECT
  ia.resource_uid,
  ia.resource_name,
  ia.resource_type,
  ia.account_id,
  ia.provider,
  ia.region,
  ia.owner,
  ia.environment,
  ia.tags,
  ia.last_scanned,
  ia.config_hash,
  COUNT(cf.finding_id) FILTER (WHERE cf.severity='critical') AS critical_findings,
  COUNT(cf.finding_id) FILTER (WHERE cf.severity='high') AS high_findings,
  COUNT(cf.finding_id) FILTER (WHERE cf.severity='medium') AS medium_findings,
  COUNT(cf.finding_id) FILTER (WHERE cf.severity='low') AS low_findings,
  MAX(cf.risk_score) AS max_risk_score
FROM inventory_assets ia
LEFT JOIN check_findings cf ON cf.resource_uid = ia.resource_uid
  AND cf.tenant_id = ia.tenant_id
  AND cf.scan_run_id = :scan_run_id
WHERE ia.tenant_id=:tenant_id AND ia.scan_run_id=:scan_run_id
GROUP BY ia.resource_uid, ia.resource_name, ia.resource_type,
  ia.account_id, ia.provider, ia.region, ia.owner, ia.environment, ia.tags, ia.last_scanned, ia.config_hash;
```

---

### 3.12 Risk (`/risk`)

**BFF View:** `GET /gateway/api/v1/views/risk` ✅ Implemented
**Engines:** Risk Engine (aggregates from all)
**Category:** 🔴 CALCULATED (heavily derived)

#### Risk Score Formula

```
Risk Score = (
  threat_score     × 0.35 +   -- from threat engine: AVG(risk_score) normalized 0-100
  compliance_score × 0.25 +   -- from compliance engine: 100 - overall_framework_score
  posture_score    × 0.25 +   -- from check engine: 100 - pass_rate
  iam_score        × 0.15     -- from iam engine: 100 - iam_posture_score
) / 100
```

#### Risk Level Thresholds

```
score >= 80 → critical
score >= 60 → high
score >= 40 → medium
score >= 20 → low
score <  20 → minimal
```

#### Data Sources for Risk Page

| Component | Source | Engines |
|-----------|--------|---------|
| Risk Score | formula above | threat + compliance + check + iam |
| Risk Register | top findings by composite risk | threat + check (COMBINED) |
| Risk Categories | grouped from risk register | derived |
| Mitigation Roadmap | ordered by impact×ease | derived from risk register |
| Trend Data | 8-week risk score history | risk engine stores historical scores |
| Scenarios | predefined + dynamic scenarios | risk engine config + threat engine |

---

## 4. Cross-Engine Data Flows

| BFF View | Engine Calls (parallel) | Merge Logic |
|----------|------------------------|-------------|
| `/views/dashboard` | inventory(summary) + threat(kpi,mitre,tox) + compliance(scores) + check(categories) + onboarding(accounts,scans) | Stitch into `{kpi, frameworks, mitreTopTechniques, toxicCombinations, cloudAccounts, ...}` |
| `/views/compliance` | compliance(frameworks,failing) + check(control mappings) + onboarding(accounts) | Join controls to findings by rule_id |
| `/views/inventory` | inventory(assets) + check(findings summary per resource_uid) | LEFT JOIN on resource_uid |
| `/views/risk` | risk(score,register) + threat(kpi) + compliance(score) + iam(posture) + check(pass_rate) | Formula calculation |
| `/views/ciem` *(new)* | threat(ciem findings) + iam(identity count) + onboarding(log sources) | Merge identity risk |
| `/views/database-security` *(new)* | check(db findings) + discoveries(db inventory) | Filter + enrich |
| `/views/container-security` *(new)* | check(container findings) + discoveries(cluster inventory) | Filter + enrich |

---

## 5. BFF View Response Contracts

### Standard Response Wrapper
```typescript
interface BffResponse<T> {
  data?: T;
  error?: string;
  pageContext?: PageContext;
  kpiGroups?: KpiGroup[];
  metadata?: { scan_run_id: string; tenant_id: string; generated_at: string; }
}

interface KpiGroup {
  title: string;
  items: Array<{ label: string; value: number | string; }>
}

interface PageContext {
  title: string;
  brief: string;
  tabs: Array<{ id: string; label: string; count: number; }>
  details?: string[];
}
```

### View-Specific Shapes

```typescript
// /views/threats
interface ThreatsView {
  threats: ThreatFinding[];
  kpi: { total:number; critical:number; high:number; medium:number; low:number; active:number; resolved:number; unassigned:number; avgRiskScore:number; };
  trendData: Array<{ date:string; critical:number; high:number; medium:number; low:number; }>;
  mitreMatrix: Record<string, Array<{ technique:string; count:number; severity:string; }>>;
  attackChains: AttackChain[];
  threatIntel: ThreatIntel[];
}

// /views/iam
interface IamView {
  identities: IamFinding[];
  roles: IamFinding[];
  accessKeys: IamFinding[];
  privilegeEscalation: IamFinding[];
  kpiGroups: KpiGroup[];
  pageContext: PageContext;
  scanTrend: Array<{ date:string; total:number; overprivileged:number; no_mfa:number; safe:number; }>;
  moduleScores: Array<{ module:string; pass:number; total:number; }>;
}

// /views/network-security (new)
interface NetworkView {
  findings: NetworkFinding[];
  securityGroups: SgFinding[];
  internetExposure: ExposureFinding[];
  topology: VpcTopology[];
  waf: WafFinding[];
  kpiGroups: KpiGroup[];
  pageContext: PageContext;
  scanTrend: Array<{ date:string; passRate:number; critical:number; high:number; medium:number; total:number; exposed_ports:number; open_sgs:number; }>;
  moduleScores: Array<{ module:string; pass:number; total:number; color:string; }>;
}

// /views/database-security (new)
interface DatabaseSecurityView {
  findings: DbFinding[];
  kpiGroups: KpiGroup[];
  pageContext: PageContext;
  scanTrend: Array<{ date:string; passRate:number; critical:number; high:number; medium:number; total:number; }>;
  moduleScores: Array<{ module:string; pass:number; total:number; }>;
}

// /views/container-security (new)
interface ContainerSecurityView {
  findings: ContainerFinding[];
  kpiGroups: KpiGroup[];
  pageContext: PageContext;
  scanTrend: Array<{ date:string; passRate:number; critical:number; high:number; medium:number; total:number; }>;
  moduleScores: Array<{ module:string; pass:number; total:number; }>;
}

// /views/ciem (new)
interface CiemView {
  totalFindings: number;
  rulesTriggered: number;
  uniqueActors: number;
  l2Findings: number;
  l3Findings: number;
  postureScore: number;
  severityBreakdown: Array<{ severity:string; count:number; }>;
  topCritical: CiemFinding[];
  identities: IdentityRisk[];
  topRules: DetectionRule[];
  logSources: LogSource[];
  scanTrend: Array<{ date:string; passRate:number; critical:number; high:number; medium:number; total:number; overprivileged:number; detections:number; }>;
  moduleScores: Array<{ module:string; pass:number; total:number; }>;
}
```

---

## 6. Historical Trend Data Strategy

All pages need 8-week sparklines. The pattern is the same across all engines:

### Pattern A — Engine has a `{engine}_report` table (IAM, DataSec, Network, Encryption)
```sql
SELECT
  s.scan_start_time AS date,
  r.posture_score,
  r.total_findings,
  r.critical_findings AS critical,
  r.high_findings AS high,
  r.medium_findings AS medium,
  r.low_findings AS low
FROM {engine}_report r
JOIN scan_orchestration s USING (scan_run_id)
WHERE r.tenant_id = :tenant_id
  AND (:account_id IS NULL OR r.account_id = :account_id)
ORDER BY s.scan_start_time DESC
LIMIT 8;
```

### Pattern B — No report table, derive from findings (Check, Database, Container)
```sql
SELECT
  DATE_TRUNC('week', cf.last_seen_at) AS date,
  COUNT(*) FILTER (WHERE severity='critical') AS critical,
  COUNT(*) FILTER (WHERE severity='high') AS high,
  COUNT(*) FILTER (WHERE severity='medium') AS medium,
  COUNT(*) AS total,
  ROUND(COUNT(*) FILTER (WHERE status='PASS') * 100.0 / NULLIF(COUNT(*),0), 1) AS passRate
FROM check_findings cf
WHERE cf.tenant_id = :tenant_id
  AND cf.resource_type = ANY(:resource_types)   -- filter for page context
  AND cf.last_seen_at >= NOW() - INTERVAL '8 weeks'
GROUP BY DATE_TRUNC('week', cf.last_seen_at)
ORDER BY 1;
```

### Pattern C — Threat engine (weekly aggregated historical)
Already supported via `/api/v1/threat/analytics/trend` endpoint.

---

## 7. Missing Implementations — Action Items

### Missing BFF Views (add to `bff_views.py`)

| Priority | View | Engines to Call | Complexity |
|----------|------|----------------|-----------|
| HIGH | `network-security` | network engine | Low — single engine, add ui-data endpoint |
| HIGH | `encryption` | encryption engine | Low — single engine, add ui-data endpoint |
| HIGH | `ciem` | threat engine (ciem module) + iam + onboarding | Medium |
| MEDIUM | `database-security` | check engine (filtered) + discoveries | Medium |
| MEDIUM | `container-security` | check engine (filtered) + discoveries | Medium |

### Missing Engine Endpoints

| Engine | Missing Endpoint | Returns |
|--------|-----------------|---------|
| network engine | `GET /api/v1/network/ui-data` | kpiGroups, findings, topology, security_groups, waf, scanTrend, moduleScores |
| encryption engine | `GET /api/v1/encryption/ui-data` | kpiGroups, findings, keys, certificates, secrets, scanTrend, moduleScores |
| check engine | `GET /api/v1/check/findings?resource_types=X` | filtered findings for DB/container pages |
| threat engine | `GET /api/v1/ciem/ui-data` | CIEM-specific aggregations |
| iam engine | `GET /api/v1/iam/scan-trend?weeks=8` | historical iam_report data |

### Missing DB Schema Fields

| Table | Missing Column | Type | Purpose |
|-------|---------------|------|---------|
| `check_findings` | `auto_remediable` | BOOLEAN | Misconfig page KPI |
| `check_findings` | `sla_status` | VARCHAR | Pre-computed SLA breach flag |
| `check_findings` | `posture_category` | VARCHAR | Category grouping for misconfig radar chart |
| `check_findings` | `service` | VARCHAR | Service-level grouping |
| `threat_findings` | `has_attack_path` | BOOLEAN | Threat page filter |
| `threat_findings` | `assignee` | VARCHAR | Unassigned threat filter |

### Missing Data for Sparklines

Each `{engine}_report` table needs a row **per scan** (not just the latest). Verify that:
- `iam_report`, `datasec_report`, `network_report`, `encryption_report` retain historical rows (don't delete/overwrite on new scan)
- `scan_orchestration` has accurate `scan_start_time` timestamps
- Queries use `LIMIT 8 ORDER BY scan_start_time DESC` pattern

---

## 8. Data Calculation Reference

All formulas used across pages:

| Metric | Formula | Used In |
|--------|---------|---------|
| Posture Score (check-based) | `passed_controls / total_controls × 100` | DB Security, Container, Misconfig |
| Posture Score (report-based) | Stored in `{engine}_report.posture_score` | IAM, Network, DataSec, Encryption |
| Pass Rate | `COUNT(PASS) / COUNT(*) × 100` | Misconfig |
| SLA Breached | `first_seen_at < NOW() - sla_days(severity)` | Misconfig |
| New This Scan | `findings in latest_scan WHERE NOT EXISTS in prev_scan (same resource_uid + rule_id)` | Misconfig |
| Avg Risk Score | `AVG(risk_score)` from findings | Threats, IAM |
| WAF Coverage | `waf_protected / total_lb_resources × 100` | Network |
| Exposed Resources | `COUNT(DISTINCT resource_uid) WHERE effective_exposure IN ('internet','any')` | Network |
| Unencrypted | `total_resources - encrypted_resources` | Encryption |
| Expiring Certs | `COUNT(*) WHERE cert_expiry < NOW() + 90 days` | Encryption |
| Keys to Rotate | `COUNT(*) WHERE iam_modules @> '{key_rotation}' AND status='FAIL'` | IAM |
| No MFA count | `COUNT(*) WHERE iam_modules @> '{no_mfa}' AND status='FAIL'` | IAM |
| Overprivileged | `COUNT(*) WHERE iam_modules @> '{overprivileged}'` | IAM |
| Safe identities | `total_identities - overprivileged - no_mfa` | IAM trend chart |
| Public DBs | `COUNT(DISTINCT resource_uid) WHERE rule_id LIKE '%public%' AND resource_type IN (db_types)` | DB Security |
| Identities at Risk | `COUNT(DISTINCT actor_principal)` from CIEM findings | CIEM |
| CIEM Posture Score | `rules_triggered / total_ciem_rules × 100` or detection rate | CIEM |
| L2 Correlations | `COUNT(*) WHERE threat_category='correlation'` | CIEM |
| L3 Anomalies | `COUNT(*) WHERE l3_anomaly_score > threshold` | CIEM |
| Risk Score (composite) | `(threat×0.35 + compliance×0.25 + posture×0.25 + iam×0.15)` | Risk |
| New Assets (drift) | `assets in scan_N NOT in scan_(N-1)` by resource_uid | Inventory |
| Removed Assets (drift) | `assets in scan_(N-1) NOT in scan_N` | Inventory |
| Changed Assets (drift) | `assets where config_hash changed between scans` | Inventory |
| Compliance Framework Score | `passed_controls / total_controls × 100` per framework | Compliance |
| Overall Compliance | `AVG(framework_score)` | Compliance, Dashboard |

---

## 9. Environment Variables Required (BFF)

```bash
# Engine internal URLs (Kubernetes service DNS)
THREAT_ENGINE_URL=http://engine-threat:8020
IAM_ENGINE_URL=http://engine-iam:8003
DATASEC_ENGINE_URL=http://engine-datasec:8004
NETWORK_ENGINE_URL=http://engine-network:8006
ENCRYPTION_ENGINE_URL=http://engine-encryption:8007
CHECK_ENGINE_URL=http://engine-check:8002
COMPLIANCE_ENGINE_URL=http://engine-compliance:8010
INVENTORY_ENGINE_URL=http://engine-inventory:8022
RISK_ENGINE_URL=http://engine-risk:8009
ONBOARDING_ENGINE_URL=http://engine-onboarding:8008
DISCOVERIES_ENGINE_URL=http://engine-discoveries:8001

# Timeouts
ENGINE_TIMEOUT=15        # seconds per engine call
BFF_PARALLEL_TIMEOUT=20  # seconds total for parallel gather
```

---

*Document generated from codebase analysis of `/Users/apple/Desktop/threat-engine` on 2026-03-31.*
*Maintained in: `.claude/documentation/UI-DATA-MAPPING.md`*
