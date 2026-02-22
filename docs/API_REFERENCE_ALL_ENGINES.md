# All-Engine API Reference

> Last updated: 2026-02-22
> Cluster: `vulnerability-eks-cluster` | Region: `ap-south-1` | Account: `588989875114`
>
> **For UI developers**: Use the ELB base URL to call all engines.
> **For backend/internal**: Use ClusterIP or K8s DNS.

---

## Access URLs

### External (ELB) — for UI and external clients

```
http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com
```

Pattern: `http://<ELB>/<engine-prefix>/<engine-path>`

Example:
```
http://<ELB>/inventory/api/v1/inventory/assets?tenant_id=T
```

### Internal (ClusterIP) — for engine-to-engine calls

```
http://<service-name>.<namespace>.svc.cluster.local:80/<engine-path>
# Short form (same namespace):
http://<service-name>:80/<engine-path>
```

### ClusterIP Quick Reference

| Service | ClusterIP | Container Port |
|---------|-----------|----------------|
| engine-onboarding | 10.100.138.231 | 8010 |
| engine-discoveries | 10.100.188.200 | 8001 |
| engine-check | 10.100.43.124 | 8002 |
| engine-inventory | 10.100.246.103 | 8022 |
| engine-compliance | 10.100.48.135 | 8000 |
| engine-threat | 10.100.60.108 | 8020 |
| engine-iam | 10.100.170.233 | 8001 |
| engine-datasec | 10.100.155.216 | 8003 |
| engine-secops | 10.100.192.50 | 8005 |
| engine-rule | 10.100.88.168 | 8011 |
| api-gateway | 10.100.209.181 | 8080 |

All ClusterIP services expose port **80** (maps to container port listed above).

---

## Common Patterns

- **tenant_id**: Required query param on most endpoints
- **account_id**: Filter by single cloud account
- **account_ids**: Comma-separated list for multi-account queries
- **orchestration_id**: Pipeline mode — engine reads scan metadata from `scan_orchestration` table
- **scan_id**: Ad-hoc mode — use a direct scan ID instead of orchestration_id
- **Pagination**: `limit` + `offset` query params; responses include `total` count

---

## 1. Engine Onboarding

**Service:** `engine-onboarding` | **Port:** 8010 | **Image:** `threat-engine-onboarding-api:latest`

**External:** `http://<ELB>/onboarding/...`
**Internal:** `http://engine-onboarding:80/...`

| Method | Path | Description | Key Params |
|--------|------|-------------|-----------|
| GET | `/health` | Health check | — |
| GET | `/api/v1/health/live` | Liveness probe | — |
| GET | `/api/v1/health/ready` | Readiness probe | — |
| GET | `/` | Root / service info | — |
| — | `/api/cloud-accounts-router/*` | Cloud account CRUD | tenant_id, account_id |
| — | `/api/credentials-router/*` | Credential management | tenant_id |

**Scan trigger (create orchestration row):**
```
POST /onboarding/api/v1/scan/trigger
Body: {"tenant_id":"...", "account_id":"588989875114", "provider_type":"aws"}
Returns: {"orchestration_id": "<uuid>"}
```

See `docs/api/09_engine_onboarding.md` for full endpoint list.

---

## 2. Engine Discoveries

**Service:** `engine-discoveries` | **Port:** 8001 | **Image:** `engine-discoveries:v10-multicloud`

**External:** `http://<ELB>/discoveries/...`
**Internal:** `http://engine-discoveries:80/...`

| Method | Path | Description | Key Params |
|--------|------|-------------|-----------|
| GET | `/health` | Health check | — |
| GET | `/api/v1/health/live` | Liveness probe | — |
| GET | `/api/v1/health/ready` | Readiness probe | — |
| POST | `/api/v1/discovery` | Trigger cloud resource discovery | `orchestration_id`, `provider`, `hierarchy_id`, `tenant_id` |

**Request body for discovery:**
```json
{
  "orchestration_id": "<uuid>",
  "provider": "aws",
  "hierarchy_id": "588989875114",
  "tenant_id": "..."
}
```

Writes `discovery_scan_id` to `scan_orchestration` when complete.

See `docs/api/08_engine_discoveries.md` for full endpoint list.

---

## 3. Engine Check

**Service:** `engine-check` | **Port:** 8002 | **Image:** `engine-check:latest`

**External:** `http://<ELB>/check/...`
**Internal:** `http://engine-check:80/...`

| Method | Path | Description | Key Params |
|--------|------|-------------|-----------|
| GET | `/api/v1/health` | Health check | — |
| GET | `/api/v1/health/live` | Liveness probe | — |
| GET | `/api/v1/health/ready` | Readiness probe | — |
| GET | `/api/v1/metrics` | Engine metrics (Prometheus format) | — |
| POST | `/api/v1/scan` | Start compliance check scan | `orchestration_id` OR `discovery_scan_id`, `provider`, `hierarchy_id`, `include_services`, `check_source` |
| GET | `/api/v1/check/{check_scan_id}/status` | Get check scan status | `check_scan_id` |
| GET | `/api/v1/checks` | List all check scans | `tenant_id`, `status`, `discovery_scan_id`, `limit` |

**Request body for scan:**
```json
{
  "orchestration_id": "<uuid>",
  "tenant_id": "...",
  "provider": "aws",
  "hierarchy_id": "588989875114"
}
```

See `docs/api/02_engine_check.md` for full endpoint list.

---

## 4. Engine Inventory

**Service:** `engine-inventory` | **Port:** 8022 | **Image:** `inventory-engine:v6-multi-csp`

**External:** `http://<ELB>/inventory/...`
**Internal:** `http://engine-inventory:80/...`

### Health

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness/readiness → `{"status":"healthy"}` |

### Scan Triggers

| Method | Path | Description | Key Params |
|--------|------|-------------|-----------|
| POST | `/api/v1/scan` | Synchronous scan (legacy) | `tenant_id`, `scan_run_id` |
| POST | `/api/v1/inventory/scan/discovery` | **Recommended** pipeline scan | `tenant_id`, `orchestration_id` OR `discovery_scan_id` |
| POST | `/api/v1/inventory/scan/discovery/async` | Async scan, returns `job_id` | same as above |
| GET | `/api/v1/inventory/jobs/{job_id}` | Poll async job status | — |

### Query Endpoints

| Method | Path | Description | Key Params |
|--------|------|-------------|-----------|
| GET | `/api/v1/inventory/runs/latest/summary` | Latest completed scan summary | `tenant_id` |
| GET | `/api/v1/inventory/runs/{scan_run_id}/summary` | Specific scan summary | `tenant_id` |
| GET | `/api/v1/inventory/scans` | List discovery scans | `tenant_id` |
| GET | `/api/v1/inventory/assets` | Paginated asset list | `tenant_id`, `scan_run_id`, `provider`, `region`, `resource_type`, `account_id`, `account_ids`, `limit`, `offset` |
| GET | `/api/v1/inventory/assets/{resource_uid}` | Single asset by UID | `tenant_id`, `scan_run_id` |
| GET | `/api/v1/inventory/assets/{resource_uid}/relationships` | Asset relationships | `tenant_id`, `scan_run_id`, `depth`, `relation_type`, `direction` |
| GET | `/api/v1/inventory/assets/{resource_uid}/drift` | Asset drift hint | `tenant_id` |
| GET | `/api/v1/inventory/relationships` | Paginated relationships | `tenant_id`, `scan_run_id`, `relation_type`, `from_uid`, `to_uid`, `limit`, `offset` |
| GET | `/api/v1/inventory/graph` | Graph (nodes + edges) | `tenant_id`, `scan_run_id`, `resource_uid`, `depth`, `limit` |
| GET | `/api/v1/inventory/drift` | Drift between two scans | `tenant_id`, `baseline_scan`, `compare_scan`, `provider`, `resource_type`, `account_id` |
| GET | `/api/v1/inventory/runs/{scan_run_id}/drift` | Scan-specific drift hint | `tenant_id` |
| GET | `/api/v1/inventory/accounts/{account_id}` | Account asset summary | `tenant_id`, `scan_run_id` |
| GET | `/api/v1/inventory/services/{service}` | Service asset summary | `tenant_id`, `scan_run_id` |

**Sample responses:**
```
GET /inventory/api/v1/inventory/runs/latest/summary?tenant_id=T
→ {"inventory_scan_id":"...","total_assets":1529,"total_relationships":199,...}

GET /inventory/api/v1/inventory/assets?tenant_id=T&limit=5
→ {"total":1440,"assets":[{"resource_uid":"arn:aws:...","resource_type":"ec2.instance",...}]}
```

See `docs/api/03_engine_inventory.md` for full documentation with verified results.

---

## 5. Engine Compliance

**Service:** `engine-compliance` | **Port:** 8000 | **Image:** `threat-engine-compliance-engine:v2-db-reports`

**External:** `http://<ELB>/compliance/...`
**Internal:** `http://engine-compliance:80/...`

| Method | Path | Description | Key Params |
|--------|------|-------------|-----------|
| GET | `/api/v1/health` | Health check | — |
| POST | `/api/v1/compliance/generate` | Generate compliance report | `orchestration_id` OR `scan_id`, `csp`, `frameworks` |
| POST | `/api/v1/compliance/generate/from-check-db` | Generate from check DB | `check_scan_id`, `csp` |
| POST | `/api/v1/scan` | Generic scan trigger | — |
| GET | `/api/v1/compliance/reports` | List compliance reports | `tenant_id`, `csp`, `limit`, `offset` |
| GET | `/api/v1/compliance/report/{report_id}` | Get specific report | — |
| GET | `/api/v1/compliance/report/{report_id}/export` | Export report | `format` (json/pdf/csv) |
| GET | `/api/v1/compliance/report/{report_id}/download/pdf` | Download PDF | — |
| GET | `/api/v1/compliance/report/{report_id}/download/excel` | Download Excel | — |
| DELETE | `/api/v1/compliance/reports/{report_id}` | Delete report | — |
| GET | `/api/v1/compliance/frameworks` | List available frameworks | — |
| GET | `/api/v1/compliance/frameworks/all` | All frameworks detailed | — |
| GET | `/api/v1/compliance/framework/{framework}` | Framework details + findings | `framework`, `account_id`, `region` |
| GET | `/api/v1/compliance/framework/{framework}/status` | Framework compliance status | `framework` |
| GET | `/api/v1/compliance/framework/{framework}/download/pdf` | PDF download | — |
| GET | `/api/v1/compliance/framework/{framework}/download/excel` | Excel download | — |
| GET | `/api/v1/compliance/framework/{framework}/detailed` | Detailed framework info | — |
| GET | `/api/v1/compliance/framework/{framework}/structure` | Control structure | — |
| GET | `/api/v1/compliance/framework/{framework}/controls/grouped` | Controls grouped | — |
| GET | `/api/v1/compliance/framework/{framework}/resources/grouped` | Resources grouped | — |
| GET | `/api/v1/compliance/framework/{framework}/control/{control_id}` | Specific control | — |
| GET | `/api/v1/compliance/controls/search` | Search controls | `q`, `framework`, `limit` |
| GET | `/api/v1/compliance/accounts/{account_id}` | Account compliance posture | `framework`, `csp` |
| GET | `/api/v1/compliance/trends` | Compliance trends | `tenant_id`, `days`, `framework` |
| GET | `/api/v1/compliance/dashboard` | Compliance dashboard | `tenant_id`, `csp` |
| GET | `/api/v1/compliance/resource/{resource_uid}/compliance` | Resource compliance | `framework` |

**Supported frameworks:** `cis_aws`, `nist_800_53`, `soc2`, `iso_27001`, `pci_dss`, `hipaa`, `gdpr`, `ccpa`, `aws_well_architected`, `fedramp`, `cmmc`, `swift_csp`, `mas_trm`

See `docs/api/04_engine_compliance.md` for full endpoint list.

---

## 6. Engine Threat

**Service:** `engine-threat` | **Port:** 8020 | **Image:** `threat-engine:latest`

**External:** `http://<ELB>/threat/...`
**Internal:** `http://engine-threat:80/...`

| Method | Path | Description | Key Params |
|--------|------|-------------|-----------|
| GET | `/health` | Health check | — |
| POST | `/api/v1/scan` | Generate threat report (sync) | `tenant_id`, `orchestration_id` OR `check_scan_id`, `scan_run_id`, `cloud` |
| POST | `/api/v1/threat/generate/async` | Async threat generation | same as above |
| GET | `/api/v1/threat/jobs/{job_id}` | Poll async job | — |
| — | `/api/v1/threat/check/*` | Check-based threat sub-routes | — |
| — | `/api/v1/threat/discovery/*` | Discovery-based sub-routes | — |

**Request body for scan:**
```json
{
  "tenant_id": "...",
  "orchestration_id": "<uuid>",
  "cloud": "aws"
}
```

See `docs/api/01_engine_threat.md` for full endpoint list (60+ endpoints including analytics, hunting, intel).

---

## 7. Engine IAM

**Service:** `engine-iam` | **Port:** 8001 | **Image:** `engine-iam:v2-fixes`

**External:** `http://<ELB>/iam/...`
**Internal:** `http://engine-iam:80/...`

| Method | Path | Description | Key Params |
|--------|------|-------------|-----------|
| GET | `/health` | Health check | — |
| GET | `/api/v1/health/live` | Liveness probe | — |
| GET | `/api/v1/health/ready` | Readiness probe | — |
| POST | `/api/v1/iam-security/scan` | Run IAM security scan | `orchestration_id` OR `scan_id`, `csp`, `tenant_id`, `max_findings` |
| GET | `/api/v1/iam-security/findings` | Get IAM findings | `csp`, `scan_id`, `tenant_id`, `account_id`, `service`, `module`, `status`, `resource_id` |
| GET | `/api/v1/iam-security/rules/{rule_id}` | Get IAM rule info | — |
| GET | `/api/v1/iam-security/modules` | List IAM modules | — |
| GET | `/api/v1/iam-security/rule-ids` | Get rule ID patterns | — |
| GET | `/api/v1/iam-security/accounts/{account_id}` | Account IAM posture | `csp`, `scan_id`, `tenant_id`, `module`, `status` |
| GET | `/api/v1/iam-security/services/{service}` | Service IAM posture | `csp`, `scan_id`, `tenant_id`, `account_id`, `module` |
| GET | `/api/v1/iam-security/resources/{resource_uid}` | Resource IAM findings | `csp`, `scan_id`, `tenant_id` |

**IAM Modules (57 rules):** `least_privilege`, `role_management`, `access_control`, `key_management`, `mfa`, `account_security`

See `docs/api/07_engine_iam.md` for full details.

---

## 8. Engine DataSec

**Service:** `engine-datasec` | **Port:** 8003 | **Image:** `engine-datasec:v3-fixes`

**External:** `http://<ELB>/datasec/...`
**Internal:** `http://engine-datasec:80/...`

| Method | Path | Description | Key Params |
|--------|------|-------------|-----------|
| GET | `/health` | Health check | — |
| GET | `/api/v1/health/live` | Liveness probe | — |
| GET | `/api/v1/health/ready` | Readiness probe | — |
| POST | `/api/v1/data-security/scan` | Run data security scan | `orchestration_id` OR `scan_id`, `csp`, `tenant_id`, `include_classification`, `include_lineage`, `include_residency`, `include_activity` |
| GET | `/api/v1/data-security/catalog` | Data catalog (data stores) | `csp`, `scan_id`, `tenant_id`, `account_id`, `service`, `region` |
| GET | `/api/v1/data-security/classification` | Data classification analysis | `csp`, `scan_id`, `tenant_id`, `account_id`, `service`, `resource_id` |
| GET | `/api/v1/data-security/lineage` | Data lineage | same filters |
| GET | `/api/v1/data-security/residency` | Residency compliance | same filters |
| GET | `/api/v1/data-security/activity` | Activity monitoring | same filters |
| GET | `/api/v1/data-security/governance/{resource_id}` | Access governance for resource | `csp`, `scan_id`, `tenant_id` |
| GET | `/api/v1/data-security/protection/{resource_id}` | Encryption/protection status | `csp`, `scan_id`, `tenant_id` |
| GET | `/api/v1/data-security/rules/{rule_id}` | Data security rule info | `service` (optional) |
| GET | `/api/v1/data-security/modules` | List data security modules | — |
| GET | `/api/v1/data-security/modules/{module}/rules` | Rules by module | `service` (optional) |

**DataSec Modules (62 rules):** `encryption_at_rest`, `encryption_in_transit`, `access_control`, `data_classification`, `data_residency`, `data_lineage`, `activity_monitoring`

See `docs/api/06_engine_datasec.md` for full details.

---

## 9. Engine SecOps

**Service:** `engine-secops` | **Port:** 8005 | **Image:** `secops-scanner:latest`

**External:** `http://<ELB>/secops/...`
**Internal:** `http://engine-secops:80/...`

| Method | Path | Description | Key Params |
|--------|------|-------------|-----------|
| GET | `/health` | Health check | — |
| POST | `/api/v1/secops/scan` | Scan git repository | `tenant_id`, `repo_url`, `branch`, `customer_id`, `orchestration_id`, `languages` |
| GET | `/api/v1/secops/scan/{secops_scan_id}/status` | Poll scan status | — |
| GET | `/api/v1/secops/scan/{secops_scan_id}/findings` | Get scan findings | `severity`, `language`, `limit` |
| GET | `/api/v1/secops/scans` | List scans for tenant | `tenant_id`, `project_name`, `limit` |
| GET | `/api/v1/secops/rules/stats` | Rule statistics | — |
| POST | `/api/v1/secops/rules/sync` | Sync rules to DB | — |
| POST | `/scan` | Legacy: scan pre-staged project | `project_name`, `save_results`, `fail_on_findings` |
| GET | `/results/{project_name}` | Legacy: get scan results | — |

**Supported languages (14):** Terraform, CloudFormation, Kubernetes, Helm, Ansible, Dockerfile, ARM Templates, Bicep, Pulumi, OpenTofu, CDK, Azure DevOps, GitHub Actions, GitLab CI

See `docs/api/10_engine_secops.md` for full details.

---

## 10. Engine Rule

**Service:** `engine-rule` | **Port:** 8011 | **Image:** `threat-engine-yaml-rule-builder:latest`
**Note:** No ingress — internal access only via ClusterIP `10.100.88.168`

**Internal:** `http://engine-rule:80/...`

| Method | Path | Description | Key Params |
|--------|------|-------------|-----------|
| GET | `/api/v1/health` | Health check with provider status | — |
| GET | `/api/v1/providers` | List CSP providers | — |
| GET | `/api/v1/providers/status` | All providers status | — |
| GET | `/api/v1/providers/{provider}/status` | Provider status | `provider` |
| GET | `/api/v1/providers/{provider}/services` | Provider services | `provider` |
| GET | `/api/v1/providers/{provider}/services/{service}/fields` | Service fields | `provider`, `service` |
| GET | `/api/v1/providers/{provider}/services/{service}/rules` | Service rules | `provider`, `service` |
| POST | `/api/v1/rules/validate` | Validate rule | `provider`, `service`, `rule_id`, `conditions`, `logical_operator` |
| POST | `/api/v1/rules/generate` | Generate YAML + metadata | `provider`, `service`, `title`, `description`, `rule_id`, `conditions` |
| GET | `/api/v1/rules/{rule_id}` | Get rule details | — |
| PUT | `/api/v1/rules/{rule_id}` | Update rule | — |
| DELETE | `/api/v1/rules/{rule_id}` | Delete rule | — |
| GET | `/api/v1/rules/search` | Full-text search | `q`, `provider`, `service`, `limit`, `offset` |
| GET | `/api/v1/rules/statistics` | Rule statistics | — |

See `docs/api/05_engine_rule.md` for full details.

---

## 11. API Gateway

**Service:** `api-gateway` | **Port:** 8080 | **Image:** `threat-engine-api-gateway:latest`

**External:** `http://<ELB>/gateway/...`
**Internal:** `http://api-gateway:80/...`

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Service list |
| GET | `/gateway/health` | Gateway health |
| GET | `/gateway/services` | List all registered services |
| POST | `/gateway/services/{name}/health-check` | Force health check on service |
| POST | `/gateway/orchestrate` | Trigger full pipeline orchestration |
| GET | `/gateway/configscan/csps` | List supported CSPs |
| GET | `/gateway/configscan/route-test` | Test CSP routing |

See `docs/api/12_api_gateway.md` for full details.

---

## Health Check Quick Reference

All engines respond to `GET /health`:

```bash
ELB=a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com

for engine in onboarding discoveries check inventory compliance threat iam datasec secops gateway; do
  echo -n "$engine: "
  curl -s http://$ELB/$engine/health | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','?'))" 2>/dev/null || echo "ERROR"
done
```

Expected output: all `healthy` or `ok`.
