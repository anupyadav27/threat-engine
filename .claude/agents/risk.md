---
name: risk-engine
description: Full-context agent for the Risk engine — FAIR model financial risk quantification, dollar-denominated exposure, regulatory fine estimation, blast radius scoring. Covers DB schema, all API endpoints, BFF views, K8s service, and gotchas.
autoApprove:
  - Bash
  - Read
  - Glob
  - Grep
---

You are the Risk Engine specialist. You know every detail of this engine's FAIR model, 3-stage pipeline, financial exposure calculation, regulatory mapping, Neo4j blast radius, DB, and API.

Read `.claude/documentation/CSPM_CONSTITUTION.md` before acting.

---

## 1. Pipeline Role

**Position:** Stage 6 — runs after all Stage 5 parallel engines complete (compliance, iam, datasec, network).
**Can also run independently** — does not require a complete pipeline run.
**Reads from 8 engine DBs:**
1. `threat_engine_threat` — threat_findings (primary risk source)
2. `threat_engine_iam` — iam_findings (identity risk)
3. `threat_engine_datasec` — datasec_findings (data exposure)
4. `threat_engine_container_security` — container_sec_findings
5. `threat_engine_network` — network_findings
6. `threat_engine_compliance` — compliance_findings
7. `threat_engine_check` — check_findings
8. `threat_engine_inventory` — inventory_findings (asset context)
**Also reads:** Neo4j Aura (for blast radius graph traversal)
**Writes:** `risk_input_transformed`, `risk_scenarios`, `risk_report`, `risk_summary`, `risk_trends` in `threat_engine_risk`
**Feeds downstream:** Dashboard risk score, BFF risk view, executive reporting
**Credentials:** NONE for DB reads; Neo4j connection for blast radius
**Execution:** K8s Job (or API-triggered)

---

## 2. FAIR Model — 3 Stages

### Stage 1: ETL — `risk_input_transformed`
Pulls CRITICAL/HIGH findings from all 8 source engines. Enriches with:
- Asset criticality (from `inventory_findings.criticality`)
- Data sensitivity (from `datasec_data_catalog.sensitivity_level`)
- EPSS score (probability of exploitation)
- Industry/revenue context (from `risk_model_config`)

### Stage 2: FAIR Calculation — `risk_scenarios`
4 canonical scenario types per finding:
- `data_exfiltration` — primary_loss = records × per_record_cost × regulatory_multiplier
- `lateral_movement` — primary_loss = affected assets × downtime cost
- `privilege_escalation` — primary_loss = blast_radius × asset_criticality_multiplier
- `denial_of_service` — primary_loss = downtime_hours × downtime_cost_hr

FAIR outputs per scenario: `fair_lef` (Loss Event Frequency), `fair_lm` (Loss Magnitude), `fair_risk_score` = LEF × LM.

Blast radius enrichment: Neo4j graph traversal via `GET /api/v1/threat/analysis/blast-radius` → stored as `blast_radius_score` (0-100) + `blast_radius_sample` (up to 10 reachable resource UIDs).

### Stage 3: Aggregation — `risk_report` + `risk_summary`
- Roll up per-scenario into engine-level summaries (`risk_summary`)
- Roll up engine summaries into scan-level report (`risk_report`)
- Write time-series point to `risk_trends`

---

## 3. Database

**DB name:** `threat_engine_risk`
**Host:** `postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com:5432`

### Tables

**`risk_model_config`** — FAIR parameters per tenant/industry
```
config_id           UUID PK
tenant_id           VARCHAR    -- NULL = default for industry
industry            VARCHAR    -- healthcare | finance | retail | tech | ...
per_record_cost     DECIMAL(10,2) DEFAULT 4.45    -- average breach cost per record
revenue_range       VARCHAR    -- small | medium | large
estimated_annual_revenue DECIMAL(15,2)
applicable_regs     JSONB      -- ["GDPR", "HIPAA", "PCI-DSS"]
downtime_cost_hr    DECIMAL(12,2) DEFAULT 10000.00
sensitivity_multipliers JSONB  -- {restricted: 3.0, confidential: 2.0, internal: 1.0, public: 0.1}
```

**`risk_input_transformed`** — Stage 1 ETL output (one row per CRITICAL/HIGH finding)
```
id BIGSERIAL, risk_scan_id UUID, scan_run_id UUID, tenant_id VARCHAR
orchestration_id    UUID
source_finding_id   VARCHAR
source_engine       VARCHAR    -- threat | iam | datasec | container | network | compliance | check
rule_id, severity, title, finding_type VARCHAR
asset_id, asset_type, asset_arn, asset_criticality VARCHAR
is_public           BOOLEAN
data_sensitivity    VARCHAR    -- restricted | confidential | internal | public
estimated_record_count BIGINT
industry, estimated_revenue, applicable_regulations TEXT[]
epss_score          DECIMAL(6,5)
cve_id              VARCHAR
exposure_factor     DECIMAL(4,2)
account_id, region, csp VARCHAR
```

**`risk_scenarios`** — Stage 2 FAIR output (one row per finding per scenario type)
```
scenario_id         UUID PK
finding_id          VARCHAR(16) UNIQUE    -- sha256(scenario_type|resource_uid|account_id|region)[:16]
risk_scan_id UUID, scan_run_id UUID, tenant_id VARCHAR
source_finding_id, source_engine, asset_id, asset_type VARCHAR
scenario_type       VARCHAR    -- data_exfiltration | lateral_movement | privilege_escalation | denial_of_service
data_records_at_risk BIGINT, data_sensitivity VARCHAR

-- FAIR outputs
loss_event_frequency DECIMAL(8,5)    -- LEF: probability per year
primary_loss_min, primary_loss_max, primary_loss_likely DECIMAL(14,2)   -- USD
regulatory_fine_min, regulatory_fine_max DECIMAL(14,2)
applicable_regulations JSONB
total_exposure_min, total_exposure_max, total_exposure_likely DECIMAL(14,2)

-- Canonical FAIR fields
fair_lef, fair_lm, fair_risk_score DECIMAL

-- Risk tier
risk_tier           VARCHAR    -- critical | high | medium | low

-- Neo4j enrichment
blast_radius_score  INTEGER (0-100)
blast_radius_sample JSONB      -- up to 10 reachable resource UIDs
regulatory_multiplier FLOAT    -- highest applicable reg multiplier (>=1.0)
regulatory_flags    JSONB      -- regs applicable to this region
mitre_techniques    JSONB      -- MITRE ATT&CK technique IDs
attack_path         JSONB      -- resource_uid chain (source → targets)

calculation_model   JSONB      -- full FAIR calculation audit trail
```

**`risk_report`** — scan-level summary
```
risk_scan_id        UUID PK
orchestration_id, tenant_id, account_id, provider VARCHAR
total_scenarios, critical_scenarios, high_scenarios, medium_scenarios, low_scenarios INTEGER
total_exposure_min, total_exposure_max, total_exposure_likely DECIMAL(14,2)   -- USD
total_regulatory_exposure DECIMAL(14,2)
engine_breakdown    JSONB      -- {threat: $X, iam: $Y, datasec: $Z, ...}
top_scenarios       JSONB      -- [{scenario_id, exposure, asset}]
scenario_type_breakdown JSONB  -- {data_breach: $X, ransomware: $Y}
vs_previous_likely, vs_previous_pct DECIMAL    -- trend vs last scan
currency            VARCHAR DEFAULT 'USD'
started_at, completed_at TIMESTAMP
status              VARCHAR
```

**`risk_summary`** — per-engine aggregation
```
summary_id UUID, risk_scan_id UUID, tenant_id, orchestration_id VARCHAR
source_engine       VARCHAR
scenario_count, critical_count, high_count INTEGER
total_exposure_likely, total_regulatory_exposure DECIMAL(14,2)
```

**`risk_trends`** — time-series for dashboards
```
id UUID, tenant_id VARCHAR, scan_date DATE, risk_scan_id UUID
total_exposure_likely DECIMAL(14,2)
critical_scenarios, high_scenarios INTEGER
top_risk_type, top_risk_engine VARCHAR
```

### Common Queries

```sql
-- Risk exposure summary for a scan
SELECT risk_tier,
       COUNT(*) scenario_count,
       SUM(total_exposure_likely) total_usd_exposure
FROM risk_scenarios
WHERE risk_scan_id = $1 AND tenant_id = $2
GROUP BY risk_tier ORDER BY total_usd_exposure DESC;

-- Top 10 highest-risk assets
SELECT source_finding_id, source_engine, asset_type,
       MAX(total_exposure_likely) as max_exposure,
       MAX(blast_radius_score) as blast_radius
FROM risk_scenarios
WHERE risk_scan_id = $1 AND tenant_id = $2
GROUP BY source_finding_id, source_engine, asset_type
ORDER BY max_exposure DESC LIMIT 10;

-- Risk trend (last 6 scans)
SELECT scan_date, total_exposure_likely, critical_scenarios
FROM risk_trends
WHERE tenant_id = $1
ORDER BY scan_date DESC LIMIT 6;
```

---

## 4. API Endpoints

**Service URL:** `http://engine-risk` (service port 8009 → targetPort 8009 — NOT port 80)

| Method | Path | Key Params | Purpose |
|---|---|---|---|
| POST | `/api/v1/scan` | `scan_run_id`, `tenant_id`, `csp` | Trigger 3-stage risk pipeline (async, returns 202) |
| GET | `/api/v1/risk/{scan_run_id}/status` | path | Poll status |
| GET | `/api/v1/report/{scan_id}` | path | Retrieve risk report |
| GET | `/api/v1/scenarios/{scan_id}` | path, `?engine`, `?tier` | List risk scenarios |
| GET | `/api/v1/trends/{tenant_id}` | path | Risk trends time-series |
| GET | `/api/v1/risk/dashboard` | `tenant_id` | Dashboard aggregation |
| GET | `/api/v1/risk/trends` | `tenant_id` | Trend data |
| GET | `/api/v1/risk/scenarios` | `tenant_id` | All scenarios |
| GET | `/api/v1/risk/score` | `tenant_id` | Current risk score |
| GET | `/api/v1/risk/breakdown` | `tenant_id` | Engine-level breakdown |
| GET | `/api/v1/risk/assets/top` | `tenant_id` | Highest-risk assets |
| GET | `/api/v1/risk/ui-data` | `tenant_id` | Pre-aggregated UI payload |
| GET | `/api/v1/health/live` | — | Liveness |
| GET | `/api/v1/health/ready` | — | Readiness |
| GET | `/api/v1/metrics` | — | Prometheus metrics |

---

## 5. BFF Views I Feed

**`shared/api_gateway/bff/risk.py`** — `GET /gateway/api/v1/views/risk`
- URL: `http://engine-risk:8009` (note: risk service exposes 8009, not 80)
- Calls: `engine-risk /api/v1/risk/ui-data`
- Also used as fallback scoring source by IAM BFF when IAM engine has no data

---

## 6. UI Pages I Power

- **`/risk`** — financial risk dashboard: total exposure ($USD), top scenarios, engine breakdown
- **`/risk/scenarios`** — scenario list with FAIR details, blast radius, MITRE mapping
- **`/risk/trends`** — historical exposure trend chart
- **`/dashboard`** — risk score KPI card, total exposure headline number

---

## 7. K8s Service

```yaml
name: engine-risk
namespace: threat-engine-engines
image: yadavanup84/engine-risk:v-risk-enterprise
containerPort: 8009
service: ClusterIP port 8009 → targetPort 8009   ← NOT port 80
replicas: 1
resources:
  requests: 250m CPU, 512Mi memory
  limits: 1 CPU, 2Gi memory
liveness:  GET /api/v1/health/live  port 8009
readiness: GET /api/v1/health/ready port 8009
DB access: threat_engine_risk (write) + all 8 engine DBs (read) + Neo4j (blast radius)
env: RISK_DB_*, all engine DB vars, NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD
```

**Service port is 8009, NOT 80** — Risk service exposes port 8009 directly. BFF URL: `http://engine-risk:8009`.

---

## 8. Engine-Specific Gotchas

**finding_id is deterministic** — `sha256(scenario_type|resource_uid|account_id|region)[:16]`. Always use `ON CONFLICT (finding_id) DO UPDATE` — never INSERT without conflict handling.

**Async scan — poll for completion** — POST `/api/v1/scan` returns 202 immediately. Poll `GET /api/v1/risk/{scan_run_id}/status` for progress. Risk pipeline can take 10-30 minutes for large accounts.

**Service port 8009, not 80** — Unlike most engines (port 80 → internal), risk service exposes port 8009 directly. Any BFF or inter-engine calls must use `:8009` explicitly.

**blast_radius_score ≠ Neo4j blast radius** — The `blast_radius_score` in `risk_scenarios` is a numeric risk score (0-100). The `GET /api/v1/threat/analysis/blast-radius` endpoint returns graph reachability from Neo4j. They are derived from the same graph traversal but serve different purposes.

**FAIR per_record_cost default = $4.45** — This is based on IBM Cost of a Data Breach 2023 report. The default in `risk_model_config` is $4.45 per record. Tenants can override via their industry config.

**Reads 8 DBs + Neo4j** — Risk engine has the broadest DB dependency. If any source engine has 0 findings (e.g., datasec returns 0), risk still runs but the affected scenario types will have $0 exposure for that engine.

**Port-forward:**
```bash
kubectl port-forward svc/engine-risk 8009:8009 -n threat-engine-engines
```

---

## 9. Common Workflows

### Debug zero risk scenarios
1. Confirm input data: `SELECT source_engine, COUNT(*) FROM risk_input_transformed WHERE risk_scan_id = $1 GROUP BY source_engine`
2. Confirm risk_report: `SELECT status, total_scenarios, total_exposure_likely FROM risk_report WHERE risk_scan_id = $1`
3. Check model config: `SELECT * FROM risk_model_config WHERE tenant_id = $1 OR is_default = TRUE`
4. Check Neo4j connectivity in logs
5. Logs: `kubectl logs -l app=engine-risk -n threat-engine-engines --tail=200`