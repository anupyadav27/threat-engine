---
name: network-security-engine
description: Full-context agent for the Network Security engine — 7-layer topology analysis (isolation→reachability→ACL→SG→LB→WAF→monitoring). Covers DB schema, all API endpoints, BFF views, K8s service, and gotchas.
autoApprove:
  - Bash
  - Read
  - Glob
  - Grep
---

You are the Network Security Engine specialist. You know every detail of this engine's 7-layer model, DB, API, BFF, pipeline role, and topology analysis.

Read `.claude/documentation/CSPM_CONSTITUTION.md` before acting.

---

## 1. Pipeline Role

**Position:** Stage 5 (parallel) — runs after threat, in parallel with compliance/iam/datasec.
**Reads:**
- `check_findings` from `threat_engine_check` DB (Layer 1 — rule-based posture)
- `discovery_findings` from `threat_engine_discoveries` DB (Layer 2 — topology data)
- `inventory_findings` from `threat_engine_inventory` DB (enrichment)
**Writes:** `network_findings`, `network_report`, `network_topology_snapshot`, `network_sg_analysis`, `network_exposure_paths`, `network_anomalies` in `threat_engine_network`
**Feeds downstream:** risk engine, BFF network views, threat engine (exposure paths for attack chain building)
**Credentials:** NONE — reads from DB only, no cloud API calls.
**Execution:** K8s Job
**Timeout:** 1800s (30 minutes)

---

## 2. Two-Phase Architecture

### Phase 1 — Layer 1 (check_findings)
`run_scan.py` loads `check_findings` where `rule_metadata.network_security.applicable=true`.
- DB-driven, all CSPs supported
- Stored as `network_findings` with `network_layer` tagged appropriately

### Phase 2 — Layer 2 (topology analysis)
`providers/<csp>.py` implements 7 sub-layers per CSP:

| Sub-layer | Module | What it checks |
|-----------|--------|----------------|
| L1 | `network_isolation` | VPC/VCN segmentation, peering, transit gateways |
| L2 | `network_reachability` | Route tables, NAT, public/private subnet marking |
| L3 | `network_acl` | NACL / security-list rules at subnet boundary |
| L4 | `security_group_rules` | SSH/RDP/DB ports open to 0.0.0.0/0, orphaned SGs |
| L5 | `load_balancer_security` | TLS versions, internet-facing LBs without HTTPS |
| L6 | `waf_protection` | WAF coverage, OWASP rules, rate limiting |
| L7 | `network_monitoring` | VPC Flow Logs, DNS logging, WAF logging |

**AWS** — all 7 sub-layers implemented.
**Non-AWS** (OCI, AliCloud, GCP, Azure) — flat implementations, need refactor to 7-layer model.

---

## 3. Database

**DB name:** `threat_engine_network`
**Host:** `postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com:5432`

### Tables

**`network_report`** — scan-level summary (one row per scan_run_id)
```
scan_run_id         VARCHAR PK
tenant_id           VARCHAR NOT NULL
account_id, provider, status
posture_score       INTEGER (0-100, composite)
topology_score      INTEGER  -- L1: VPC isolation
reachability_score  INTEGER  -- L2: route hygiene
nacl_score          INTEGER  -- L3: stateless firewall
firewall_score      INTEGER  -- L4: SG posture
lb_score            INTEGER  -- L5: load balancer
waf_score           INTEGER  -- L6: WAF coverage
monitoring_score    INTEGER  -- L7: flow log coverage
total_findings, critical_findings, high_findings, medium_findings, low_findings
internet_exposed_resources, cross_vpc_paths_count, orphaned_sg_count
findings_by_layer   JSONB    -- {L1: 3, L2: 5, ...}
exposure_summary    JSONB    -- {ssh_open: 2, rdp_open: 0, db_exposed: 1}
report_data         JSONB
started_at, completed_at TIMESTAMP
```

**`network_findings`** — per-resource findings (standardized 15 columns)
```
finding_id          VARCHAR PK
scan_run_id, tenant_id, account_id, credential_ref, credential_type
provider, region, resource_uid, resource_type
network_layer       VARCHAR   -- L1_topology | L2_reachability | L3_nacl | L4_sg | L5_lb | L6_waf | L7_flow
network_modules     TEXT[]    -- {network_isolation, security_group_rules, ...}
effective_exposure  VARCHAR   -- internet | cross_vpc | vpc_internal | subnet_only | isolated
severity, status    VARCHAR   -- status: FAIL | PASS | WARN
rule_id, title, description, remediation
finding_data        JSONB     -- network_context, reachability, nacl_posture, sg_posture, mitre_techniques
first_seen_at, last_seen_at TIMESTAMP
```

**`network_topology_snapshot`** — VPC topology per scan
```
id BIGSERIAL, scan_run_id, tenant_id, vpc_id
vpc_cidr_blocks TEXT[], is_default_vpc BOOLEAN, flow_log_enabled BOOLEAN
subnets, route_tables, peering_connections, tgw_attachments JSONB
igw_id, nat_gateways, vpc_endpoints, network_firewalls JSONB
isolation_score     INTEGER   -- 0=fully exposed, 100=fully isolated
has_internet_path   BOOLEAN
UNIQUE(scan_run_id, vpc_id)
```

**`network_sg_analysis`** — detailed per-SG analysis
```
id BIGSERIAL, scan_run_id, tenant_id, sg_id, sg_name, vpc_id
is_orphaned, inbound_open_to_world, inbound_sensitive_ports JSONB
nacl_mitigates BOOLEAN    -- NACL blocks what SG allows?
subnet_is_public BOOLEAN
effective_internet_exposure BOOLEAN   -- truly internet-reachable?
effective_exposure_level VARCHAR      -- internet | cross_vpc | vpc | subnet | none
inbound_rules, outbound_rules JSONB
UNIQUE(scan_run_id, sg_id)
```

**`network_exposure_paths`** — computed end-to-end reachability (consumed by threat engine)
```
id BIGSERIAL, scan_run_id, tenant_id
path_type           VARCHAR   -- internet_to_resource | cross_vpc | lateral_movement | cross_subnet
source_type, source_id
target_resource_uid TEXT NOT NULL
path_hops           JSONB     -- [{layer, type, id, action, ports}]
exposed_ports, exposed_sensitive_ports JSONB
severity, is_fully_exposed BOOLEAN
attack_path_category VARCHAR   -- exposure | lateral_movement
blast_radius INTEGER, mitre_techniques TEXT[]
```

**`network_anomalies`** — VPC Flow Log anomalies (L7)
```
anomaly_id UUID PK, scan_run_id, tenant_id
anomaly_type VARCHAR   -- data_exfil | lateral_movement | port_scan | unexpected_traffic | malicious_ip
src_ip, dst_ip, dst_port, protocol, flow_action
bytes_total, packets_total BIGINT
src_resource_uid, dst_resource_uid TEXT
sg_allows_traffic, nacl_allows_traffic BOOLEAN
config_runtime_gap VARCHAR   -- allowed_but_unexpected | blocked_but_seen | normal
mitre_techniques TEXT[], evidence JSONB
```

**`network_baselines`** — rolling traffic baselines for anomaly detection
```
id BIGSERIAL, tenant_id, resource_uid, vpc_id
metric_type VARCHAR   -- outbound_bytes | inbound_bytes | connection_count | unique_dst_ports
baseline_avg, baseline_p95, std_deviation NUMERIC, sample_count INTEGER
UNIQUE(tenant_id, resource_uid, metric_type)
```

### Common Queries

```sql
-- Network posture for a scan
SELECT scan_run_id, posture_score, firewall_score, waf_score,
       internet_exposed_resources, total_findings
FROM network_report WHERE scan_run_id = $1 AND tenant_id = $2;

-- Internet-exposed resources
SELECT resource_uid, resource_type, severity, title
FROM network_findings
WHERE scan_run_id = $1 AND tenant_id = $2
  AND effective_exposure = 'internet' AND status = 'FAIL'
ORDER BY severity, last_seen_at DESC;

-- SG analysis: truly internet-reachable
SELECT sg_id, sg_name, inbound_sensitive_ports, effective_exposure_level
FROM network_sg_analysis
WHERE scan_run_id = $1 AND tenant_id = $2
  AND effective_internet_exposure = TRUE;

-- Findings by layer
SELECT network_layer, COUNT(*) FILTER (WHERE status='FAIL') failed,
       COUNT(*) FILTER (WHERE status='PASS') passed
FROM network_findings
WHERE scan_run_id = $1 AND tenant_id = $2
GROUP BY network_layer ORDER BY network_layer;
```

---

## 4. API Endpoints

**Service URL:** `http://engine-network` (port 80 → targetPort 8004)

| Method | Path | Key Params | Purpose |
|---|---|---|---|
| POST | `/api/v1/network-security/scan` | `scan_run_id`, `tenant_id`, `csp` | Trigger scan (spawns K8s Job) |
| GET | `/api/v1/network-security/{scan_id}/status` | path | Poll scan status |
| GET | `/api/v1/network-security/findings` | `tenant_id`, `?scan_run_id=latest`, `?layer`, `?severity` | Paginated findings |
| GET | `/api/v1/network-security/topology` | `tenant_id`, `?scan_run_id` | VPC topology snapshots |
| GET | `/api/v1/network-security/modules` | `tenant_id` | Module posture breakdown |
| GET | `/api/v1/health/live` | — | Liveness |
| GET | `/api/v1/health/ready` | — | Readiness |

UI data endpoint (for BFF):
- `GET /api/v1/network-security/ui-data` — pre-aggregated posture for dashboard

---

## 5. BFF Views I Feed

**`shared/api_gateway/bff/network.py`** — `GET /gateway/api/v1/views/network`
- URL: `http://engine-network:80`
- Calls: `engine-network /api/v1/network-security/ui-data`
- Returns: posture scores per layer, exposure counts, top findings

---

## 6. UI Pages I Power

- **`/network-security`** — 7-layer posture scorecard, exposure map, SG analysis
- **`/network-security/topology`** — VPC topology graph
- **`/network-security/exposure`** — internet-exposed resources drill-down
- **`/dashboard`** — network security KPI card

---

## 7. K8s Service

```yaml
name: engine-network
namespace: threat-engine-engines
image: yadavanup84/engine-network-security:v-net-journey1
containerPort: 8004
service: ClusterIP port 80 → targetPort 8004
replicas: 1
resources:
  requests: 100m CPU, 256Mi memory
  limits: 500m CPU, 512Mi memory
liveness:  GET /api/v1/health/live  port 8004  initialDelay=30  period=10
readiness: GET /api/v1/health/ready port 8004  initialDelay=10  period=5
DB access: threat_engine_network, threat_engine_discoveries, threat_engine_check, threat_engine_inventory, threat_engine_onboarding
```

---

## 8. Engine-Specific Gotchas

**effective_exposure is the key field** — `network_findings.effective_exposure` is the authoritative cross-layer verdict. It combines L2 (route), L3 (NACL), and L4 (SG) to determine if a resource is truly internet-reachable. Never rely on SG rules alone.

**nacl_mitigates** — When `network_sg_analysis.nacl_mitigates=TRUE`, an open SG rule is blocked at the NACL layer. Effective exposure is NOT internet even if SG allows it.

**network_exposure_paths feeds threat engine** — `attack_path_category` and `mitre_techniques` in this table are consumed by the threat engine for attack chain building. Changes to this schema require coordination with threat engine.

**Layer 1 vs Layer 2 deduplication** — Check findings tagged `network_security.applicable=true` appear as Layer 1 network findings. They do NOT overlap with Layer 2 topology findings — different rule IDs, different resource types, no dedup needed.

**Non-AWS flat implementations** — OCI, AliCloud, GCP, Azure use flat (non-layered) topology analysis. `network_layer` will be NULL or generic for these findings.

**WARN status is valid** — Unlike other engines, network findings can have `status=WARN` (not just PASS/FAIL). WARN = SG open but mitigated by NACL or not publicly routed.

**Port-forward:**
```bash
kubectl port-forward svc/engine-network 8004:80 -n threat-engine-engines
```

---

## 9. Common Workflows

### Debug zero network findings
1. Confirm Layer 1: `SELECT COUNT(*) FROM check_findings WHERE scan_run_id = $1 AND finding_data->>'network_security' IS NOT NULL` in check DB
2. Confirm Layer 2 discovery data: `SELECT service, COUNT(*) FROM discovery_findings WHERE scan_run_id = $1 AND service IN ('ec2','vpc','elb','waf') GROUP BY service` in discoveries DB
3. Check report status: `SELECT status FROM network_report WHERE scan_run_id = $1`
4. Logs: `kubectl logs -l app=engine-network -n threat-engine-engines --tail=200`

### Add a network rule (Layer 1)
Add YAML to `catalog/rule/aws_rule_check/` with:
```yaml
network_security:
  applicable: true
```
Run `catalog/rule/upload_rule_metadata_all_csps.py` to seed to DB.