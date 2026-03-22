# Session Handover — 2026-03-21

## What was done this session

### 1. Full Pipeline Scan (orchestration: 5607457a)
- Ran all 7 engines: discovery → check+inventory → threat → compliance/iam/datasec
- Results:
  | Engine | Table | Count |
  |--------|-------|------:|
  | discovery_findings | discovery_scan_id | 2,754 |
  | check_findings | check_scan_id | 10,860 |
  | inventory_findings | inventory_scan_id | 1,259 |
  | inventory_relationships | inventory_scan_id | 53 |
  | threat_findings | threat_scan_id | 8,798 |
  | compliance_findings | compliance_scan_id | 0 (report_data has 8,798) |
  | iam_findings | iam_scan_id | 565 |
  | datasec_findings | datasec_scan_id | 0 |

### 2. Discovery Noise Cleanup
Disabled in both `rule_discoveries` DB table AND catalog YAML files:
- **Entire services disabled**: resource-explorer-2, config, osis, greengrass, resiliencehub, memorydb, mediaconnect, keyspaces
- **Specific entries disabled**: elasticbeanstalk/solution_stacks+platforms, elb/policies, backup/plans
- AWS active rules: 388 (down from 415)

### 3. Compliance Engine Fix (v-uid-fix)
- Fixed `resource_arn` → `resource_uid` in:
  - `engines/compliance/compliance_engine/storage/compliance_db_writer.py` (line 39)
  - `engines/compliance/compliance_engine/exporter/db_exporter.py` (line 297)
- Fixed `trigger_type` NOT NULL in `engines/compliance/run_scan.py` (pre-create row)
- Built, pushed, deployed: `yadavanup84/threat-engine-compliance-engine:v-uid-fix`

### 4. Wiz-Style Graph (from previous session, deployed)
- `engine-threat:v-graph-wiz` — new `/api/v1/graph/subgraph` endpoint
- `api-gateway:v-graph-wiz` — BFF uses subgraph as primary data source
- `cspm-frontend:v-graph-wiz` — Lucide icons, dark circles, risk badges

### 5. Developer Productivity Infrastructure
- **MCP Server** (`.claude/mcp-server/server.mjs`): PostgreSQL + Neo4j + Engine APIs, 8 read-only tools
- **Engine Agents** (`.claude/agents/*.md`): 9 agents with full UI→BFF→API→DB→dependencies context
- **Query Library** (`.claude/queries/`): 7 pre-built SQL/Cypher query files
- **DB Schema Dump** (`.claude/documentation/DATABASE-SCHEMA.md`): Live dump from all 9 databases
- **Memory Cleanup**: MEMORY.md trimmed from 216 → 90 lines

---

## PENDING: IAM Engine Uplift

### Goal
Transform IAM engine from simple regex-based rule matching to a full **IAM policy parser** that creates structured permission records and Neo4j graph edges for effective permissions, blast radius, and attack paths.

### What IAM engine currently does
- 57 rules that pattern-match against discovery data
- Produces `iam_findings` (565 findings last scan)
- Cross-engine: reads `threat_findings` for enrichment
- **Missing**: No policy document parsing, no effective permission computation, no IAM→Resource access edges

### What it needs to do (planned)
1. **Parse IAM policy documents** from new discovery data:
   - `get_policy_version` → managed policy JSON documents
   - `get_account_authorization_details` → inline policies + trust policies per role
   - `get_role_policy` → inline policies
   - `simulate_principal_policy` → effective permissions (optional, API-heavy)

2. **Create structured `iam_policy_statements`** table:
   | Column | Type | Description |
   |--------|------|-------------|
   | identity_arn | text | IAM role/user ARN |
   | policy_name | text | Policy name |
   | effect | text | Allow/Deny |
   | actions | text[] | s3:GetObject, ec2:*, etc. |
   | resources | text[] | ARN patterns |
   | conditions | jsonb | Condition keys |

3. **Create Neo4j `CAN_ACCESS` edges**:
   ```
   (IAMRole) -[:CAN_ACCESS {actions: ["s3:*"], effect: "Allow"}]-> (S3Bucket)
   ```

4. **Compute effective permissions**:
   Identity policies + Resource policies + Permission boundaries + SCPs - Explicit denies

### Prerequisites (discovery data needed)
Check if these IAM discovery calls are active in `rule_discoveries`:
```sql
-- Run against threat_engine_check
SELECT service, boto3_client_name, is_active,
       discoveries_data::text
FROM rule_discoveries
WHERE provider = 'aws' AND LOWER(service) = 'iam' AND is_active = true;
```

Key API calls needed:
| boto3 method | What it returns | Status |
|-------------|----------------|--------|
| `list_roles` | Role ARNs, trust policies | Should be active |
| `list_policies` | Managed policy ARNs | Should be active |
| `get_policy_version` | Policy document JSON | Check if active |
| `get_account_authorization_details` | Full IAM dump (roles + policies + groups) | Check if active |
| `list_role_policies` | Inline policy names per role | Check if active |
| `get_role_policy` | Inline policy document | Check if active |
| `list_attached_role_policies` | Managed policies attached to role | Check if active |

### Steps to implement
1. **Verify discovery data**: Check which IAM API calls are active and what data exists in discovery_findings for service='iam'
2. **Add missing discovery calls**: If `get_policy_version` or `get_account_authorization_details` aren't active, enable them
3. **Run discovery scan**: Get fresh IAM data
4. **Build IAM policy parser**: `engines/iam/iam_engine/parsers/policy_parser.py`
5. **Create `iam_policy_statements` table**: Alembic migration
6. **Create Neo4j edges**: `CAN_ACCESS`, `HAS_POLICY`, `ASSUMES`
7. **Update threat engine**: Use IAM graph edges for attack paths and blast radius

---

## PENDING: Security Graph Improvements (Threat Engine)

### Current state
- Neo4j: 20,010 nodes, ~22K relationships
- Subgraph endpoint returns 338 nodes, 39 edges (sparse)
- Internet node not appearing (EXPOSES → sgr-* not sg-*)

### What needs fixing
1. **Internet exposure**: Fix EXPOSES edge traversal (sgr → parent SG)
2. **More relationship types in subgraph**: Currently filters too aggressively
3. **Topology-first approach**: Show all resources, overlay threats (not just threatened resources)
4. **Sensitivity classification**: Tag storage resources as sensitive based on type/tags/check_findings
5. **IAM access edges**: After IAM uplift, add CAN_ACCESS edges to graph

### Layer model
```
Layer 1: TOPOLOGY (all resources + relationships from inventory)
Layer 2: SECURITY OVERLAY (threats, misconfigs, risk scores, compliance)
Layer 3: DERIVED INSIGHTS (attack paths, blast radius, toxic combos, effective permissions)
```

---

## PENDING: DataSec Engine — 0 Findings

### Issue
datasec_findings = 0 for scan 5607457a. Engine completed without errors but produced nothing.

### Investigation needed
1. Check datasec scanner logs: `kubectl logs -l job-name=datasec-scan-5607457a-f50 -n threat-engine-engines`
2. Verify it can read threat_findings (cross-DB dependency)
3. Check if datasec rules match any discovered resource types
4. May need similar fixes to compliance (column name mismatches?)

---

## PENDING: Compliance Findings Table — 0 Rows

### Issue
compliance_report has full data in `report_data` JSONB (8,798 findings, 137 controls), but `compliance_findings` table has 0 rows.

### Root cause
The `db_exporter.py` `export()` method uses the enterprise report model's `report.findings` list, which is empty. The data goes into `report_data` JSONB via `compliance_db_writer.py` but the individual findings aren't being extracted into the `compliance_findings` table.

### Fix needed
In `engines/compliance/compliance_engine/exporter/db_exporter.py`:
- The `report.findings` list is not populated by the scanner
- Need to either populate it OR extract findings from the `framework_reports` dict (like `compliance_db_writer.py` does)

---

## Current Production Image Tags (2026-03-21)
| Engine | Image |
|--------|-------|
| discoveries | `yadavanup84/engine-discoveries:v11-multicloud` |
| check | `yadavanup84/engine-check:v-resource-svc` |
| iam | `yadavanup84/engine-iam:v3-latest-scan` |
| datasec | `yadavanup84/engine-datasec:v2-latest-scan` |
| threat | `yadavanup84/engine-threat:v-graph-wiz` |
| compliance | `yadavanup84/threat-engine-compliance-engine:v-uid-fix` |
| inventory | `yadavanup84/inventory-engine:v11-blast-radius` |
| onboarding | `yadavanup84/threat-engine-onboarding-api:v-full-data` |
| secops | `yadavanup84/secops-scanner:v-uniform` |
| risk | `yadavanup84/engine-risk:v2.1-aliases` |
| frontend | `yadavanup84/cspm-frontend:v-graph-wiz` |
| gateway | `yadavanup84/threat-engine-api-gateway:v-graph-wiz` |

## Latest Orchestration
- **ID**: `5607457a-f50a-4370-8b7f-13099f63edf8`
- **Tenant**: `test-tenant-002`
- **Account**: `588989875114`
