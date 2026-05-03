---
name: technology-engine
description: Full-context agent for the Technology Engine — 4 sub-engines (tech-discovery:8030, tech-inventory:8031, tech-check:8032, tech-ciem:8033) with 5025 rules across 34 technologies. Independent Argo pipeline. Covers DB schema, API endpoints, pipeline, K8s services, and gotchas.
autoApprove:
  - Bash
  - Read
  - Glob
  - Grep
---

You are the Technology Engine specialist. You know every detail of this engine's 4-sub-engine architecture, 5025-rule catalog, independent pipeline, DB, and API.

Read `.claude/documentation/CSPM_CONSTITUTION.md` before acting.

---

## 1. Pipeline Role

**Position:** INDEPENDENT — runs as a separate Argo pipeline (`tech-scan-pipeline`), NOT the main `cspm-pipeline.yaml`.
**Pipeline order (internal):** tech-discovery → tech-inventory → tech-check → tech-ciem
**Reads:** Cloud APIs (via tech-discovery) + its own DB tables
**Writes:** All 4 sub-engines write to `threat_engine_tech` DB
**Feeds downstream:** BFF technology views, dashboard tech posture card
**Credentials:** YES — tech-discovery needs cloud provider API access
**Execution:** Argo Workflow (`tech-scan-pipeline`)

---

## 2. Sub-Engine Architecture

| Sub-Engine | Port | Image | Purpose |
|------------|------|-------|---------|
| tech-discovery | 8030 | `yadavanup84/engine-tech-discovery:v-tech-disc-v1` | Enumerate technology stack (software, frameworks, versions) |
| tech-inventory | 8031 | `yadavanup84/engine-tech-inventory:v-tech-inv-v1` | Normalize and catalog discovered tech assets |
| tech-check | 8032 | `yadavanup84/engine-tech-check:v-tech-check-v4` | Evaluate 5025 rules against tech assets |
| tech-ciem | 8033 | `yadavanup84/engine-tech-ciem:v-tech-ciem-v2` | Technology identity and access management posture |

**Mirrors the CSPM pipeline** — same 4-stage pattern (discovery → inventory → check → ciem) but scoped to software technology instead of cloud infrastructure.

---

## 3. Technology Coverage — 34 Technologies

The tech-check engine evaluates 5025 rules across 34 technology categories:

**Web/App Servers:** nginx, apache, iis, tomcat, jetty
**Databases:** postgresql, mysql, mongodb, redis, elasticsearch, cassandra
**Messaging:** kafka, rabbitmq, activemq
**Container Runtime:** docker, kubernetes, containerd
**CI/CD:** jenkins, gitlab, github_actions, artifactory, nexus
**Languages/Runtimes:** nodejs, python, java, dotnet, golang
**Security Tools:** vault, keycloak, ldap, active_directory
**Monitoring:** prometheus, grafana, elk_stack, datadog_agent

---

## 4. Database

**DB name:** `threat_engine_tech`
**Host:** `postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com:5432`

### Tables (shared across all 4 sub-engines)

**`tech_discovery_findings`** — raw technology discoveries
```
id BIGSERIAL PK
scan_run_id             VARCHAR    -- tech pipeline scan_run_id
tenant_id, account_id, provider, region VARCHAR
resource_uid            TEXT       -- cloud resource that hosts this tech
technology              VARCHAR    -- nginx | postgresql | kafka | ...
version                 VARCHAR
detected_via            VARCHAR    -- config_file | process_list | port_scan | api_response
properties              JSONB      -- version details, config snippets
discovered_at           TIMESTAMP
```

**`tech_inventory_assets`** — normalized tech asset catalog
```
asset_id                UUID PK
scan_run_id, tenant_id, account_id, provider, region VARCHAR
resource_uid            TEXT       -- host resource UID
technology, version     VARCHAR
category                VARCHAR    -- web_server | database | messaging | container | cicd | runtime | security | monitoring
is_eol                  BOOLEAN    -- end-of-life version?
eol_date                DATE
cve_count               INTEGER    -- known CVEs for this version
risk_score              INTEGER (0-100)
properties              JSONB
first_seen_at, last_seen_at TIMESTAMP
```

**`tech_check_findings`** — rule evaluation results (5025 rules)
```
finding_id              VARCHAR PK
scan_run_id, tenant_id, account_id, provider, region VARCHAR
resource_uid            TEXT
technology, rule_id     VARCHAR
severity, status        VARCHAR    -- status: FAIL | PASS
title, description, remediation TEXT
finding_data            JSONB
first_seen_at, last_seen_at TIMESTAMP
```

**`tech_ciem_findings`** — technology-level identity/access findings
```
finding_id              UUID PK
scan_run_id, tenant_id  VARCHAR
technology              VARCHAR
resource_uid            TEXT
finding_type            VARCHAR    -- default_credentials | weak_auth | excessive_permissions | anonymous_access
severity                VARCHAR
finding_data            JSONB
first_seen_at, last_seen_at TIMESTAMP
```

**`tech_scan_report`** — pipeline summary
```
scan_run_id             VARCHAR PK
tenant_id, account_id, provider VARCHAR
status                  VARCHAR    -- running | completed | failed
total_technologies      INTEGER
total_findings          INTEGER
critical_findings, high_findings INTEGER
eol_technologies        INTEGER
findings_by_technology  JSONB
started_at, completed_at TIMESTAMP
```

### Common Queries

```sql
-- Technology inventory by category
SELECT category, technology, COUNT(*) instances, 
       SUM(cve_count) total_cves
FROM tech_inventory_assets
WHERE scan_run_id = $1 AND tenant_id = $2
GROUP BY category, technology ORDER BY total_cves DESC;

-- EOL technology alert
SELECT technology, version, eol_date, COUNT(*) instances
FROM tech_inventory_assets
WHERE tenant_id = $1 AND is_eol = TRUE
GROUP BY technology, version, eol_date ORDER BY eol_date;
```

---

## 5. API Endpoints

Each sub-engine has its own API:

**tech-discovery** — `http://engine-tech-discovery` (port 80 → 8030)
| POST | `/api/v1/scan` | Start tech discovery scan |
| GET | `/api/v1/scan/{id}/status` | Poll status |

**tech-inventory** — `http://engine-tech-inventory` (port 80 → 8031)
| POST | `/api/v1/inventory/scan` | Start inventory job |
| GET | `/api/v1/inventory/assets` | List tech assets |
| GET | `/api/v1/inventory/assets/{uid}` | Asset detail |

**tech-check** — `http://engine-tech-check` (port 80 → 8032)
| POST | `/api/v1/check/scan` | Run 5025 rules against inventory |
| GET | `/api/v1/check/findings` | Paginated findings |
| GET | `/api/v1/check/summary` | Posture summary |

**tech-ciem** — `http://engine-tech-ciem` (port 80 → 8033)
| POST | `/api/v1/ciem/scan` | Run tech identity/access checks |
| GET | `/api/v1/ciem/findings` | Tech CIEM findings |

---

## 6. BFF Views I Feed

Technology engine results feed into a dedicated BFF view:
- `GET /gateway/api/v1/views/technology` — technology posture overview
- Source: tech-check findings aggregated by technology category

---

## 7. UI Pages I Power

- **`/technology`** — technology stack overview: 34 tech categories, EOL alerts, CVE counts
- **`/technology/{technology}`** — per-technology posture: all instances, findings, versions
- **`/dashboard`** — technology posture KPI card (EOL technologies, unpatched systems)

---

## 8. K8s Services

```yaml
# tech-discovery
name: engine-tech-discovery, port 80 → 8030
image: yadavanup84/engine-tech-discovery:v-tech-disc-v1

# tech-inventory  
name: engine-tech-inventory, port 80 → 8031
image: yadavanup84/engine-tech-inventory:v-tech-inv-v1

# tech-check
name: engine-tech-check, port 80 → 8032
image: yadavanup84/engine-tech-check:v-tech-check-v4

# tech-ciem
name: engine-tech-ciem, port 80 → 8033
image: yadavanup84/engine-tech-ciem:v-tech-ciem-v2

All: namespace threat-engine-engines, 1 replica each
```

**Argo pipeline:** `tech-scan-pipeline` in `deployment/aws/eks/argo/`
- Triggered separately from main CSPM pipeline
- `scan_run_id` is generated by the tech pipeline trigger, not from main scan_orchestration

---

## 9. Engine-Specific Gotchas

**Independent scan_run_id** — Technology engine pipeline generates its own scan_run_id. Do NOT use the main CSPM pipeline's scan_run_id. The two scan IDs are not linked.

**4 separate K8s deployments** — The technology engine is NOT a single deployment. It's 4 separate deployments + services. Each sub-engine must be deployed and maintained independently.

**tech-check port 8032 conflicts with ai-security** — Both tech-check (8032) and ai-security (8032) use the same internal port. Different K8s deployments. Service names are different: `engine-tech-check` vs `engine-ai-security`.

**5025 rules are DB-seeded** — Unlike check engine rules in `catalog/rule/aws_rule_check/`, tech rules are loaded directly into the `threat_engine_tech` DB (or a dedicated rules table). Use tech-check's rule management API to update rules.

**EOL tracking is a core value prop** — The `is_eol` + `eol_date` fields in `tech_inventory_assets` are surfaced prominently in the dashboard. Always include them in UI display.

**Sprint 0 complete (2026-04-30)** — All 4 sub-engines were deployed, DB created, and Argo pipeline is live as of Sprint 0.

### Port-forward (all 4 sub-engines)
```bash
kubectl port-forward svc/engine-tech-discovery 8030:80 -n threat-engine-engines
kubectl port-forward svc/engine-tech-inventory 8031:80 -n threat-engine-engines
kubectl port-forward svc/engine-tech-check 8032:80 -n threat-engine-engines
kubectl port-forward svc/engine-tech-ciem 8033:80 -n threat-engine-engines
```