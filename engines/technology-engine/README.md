# Technology Engine

A four-stage pipeline that discovers, normalizes, evaluates, and detects threats across **40 self-hosted technologies** in 10 categories — databases, Linux/OS, network devices, web servers, virtualization, containers, DevOps platforms, collaboration tools, data platforms, and middleware.

The technology engine is architecturally aligned with the cloud CSPM engines (same `scan_run_id` flow, same standard columns, same BFF/UI layer) and is governed by the same CIS benchmark + MITRE ATT&CK framework.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Technology Coverage Matrix](#2-technology-coverage-matrix)
3. [Sub-Engine Reference](#3-sub-engine-reference)
   - [tech-discovery](#31-tech-discovery-port-8030)
   - [tech-inventory](#32-tech-inventory-port-8031)
   - [tech-check](#33-tech-check-port-8032)
   - [tech-ciem](#34-tech-ciem-port-8033)
   - [tech-scan-agent](#35-tech-scan-agent-host-based)
4. [Pipeline Execution Flow](#4-pipeline-execution-flow)
5. [Discovery YAML Format](#5-discovery-yaml-format)
6. [Check Rule Schema](#6-check-rule-schema)
7. [CIEM Detection Rules](#7-ciem-detection-rules)
8. [CIS Rule Generation Framework](#8-cis-rule-generation-framework)
9. [Database Schema](#9-database-schema)
10. [Connector Reference](#10-connector-reference)
11. [Catalog Structure](#11-catalog-structure)
12. [Deployment & Operations](#12-deployment--operations)
13. [Onboarding a Technology Account](#13-onboarding-a-technology-account)
14. [Triggering a Scan](#14-triggering-a-scan)
15. [Seeding Rules](#15-seeding-rules)
16. [Sprint Roadmap](#16-sprint-roadmap)
17. [Adding a New Technology](#17-adding-a-new-technology)

---

## 1. Architecture Overview

```
                        ┌─────────────────────────────────────┐
                        │         Onboarding Wizard           │
                        │  (registers tech accounts in DB)    │
                        └─────────────────┬───────────────────┘
                                          │  account_id + credential_ref
                                          ▼
                        ┌─────────────────────────────────────┐
                        │      Argo WorkflowTemplate          │
                        │      tech-scan-pipeline             │
                        │   scan_run_id  account_id  tenant_id│
                        └──────────────┬──────────────────────┘
                                       │
                   ┌───────────────────▼──────────────────────┐
                   │             tech-discovery               │
                   │   Port 8030 · Image v-tech-disc-v2       │
                   │                                          │
                   │  1. Lookup credential from tech_credentials│
                   │  2. Pick category scanner (db/linux/…)   │
                   │  3. Load step6_discovery.yaml            │
                   │  4. Execute SQL/SSH/API per entry        │
                   │  5. Write → tech_discovery_findings      │
                   └───────────────────┬──────────────────────┘
                                       │
                   ┌───────────────────▼──────────────────────┐
                   │             tech-inventory               │
                   │   Port 8031 · Image v-tech-inv-v1        │
                   │                                          │
                   │  1. Read tech_discovery_findings         │
                   │  2. Deduplicate by resource_uid          │
                   │  3. Extract version / os / asset_name    │
                   │  4. Write → tech_inventory_assets        │
                   └──────────┬──────────────────┬────────────┘
                              │                  │
          ┌───────────────────▼──┐  ┌────────────▼──────────────┐
          │      tech-check      │  │         tech-ciem          │
          │  Port 8032 · v2      │  │   Port 8033 · v2           │
          │                      │  │                            │
          │  1. Load active rules │  │  1. Connect to live target │
          │     from DB          │  │  2. Pull session/log data  │
          │  2. Match by         │  │  3. Run 10 MITRE detectors │
          │     discovery_id     │  │  4. Write →                │
          │  3. Evaluate PASS/   │  │     tech_ciem_findings     │
          │     FAIL per rule    │  │                            │
          │  4. Write →          │  │    [runs in PARALLEL       │
          │  tech_check_findings │  │     with tech-check]       │
          └──────────────────────┘  └────────────────────────────┘
```

**Key design decisions:**

| Decision | Rationale |
|----------|-----------|
| Same `scan_run_id` as cloud engines | Single UUID links all engine outputs — enables cross-engine correlation in the UI |
| `provider` = `tech_type` | Mirrors CSP pattern (`provider=aws`) — same UI columns work for both |
| `region` = `host:port` | On-prem has no geo-region; host:port is the logical equivalent |
| `asset_id` = `sha256(account_id\|resource_uid)[:16]` | Stable across scans — enables drift detection in the inventory UI |
| YAML-driven discovery | Same pattern as cloud step6 YAMLs — catalog rules, not hardcoded queries |
| Separate DB (`threat_engine_tech`) | Isolates technology findings from cloud CSPM data; same RDS instance |
| CIEM connects live | Discovery reads config; CIEM reads live session logs — different data sources |

---

## 2. Technology Coverage Matrix

| Category | Technologies | Connector | Status |
|----------|-------------|-----------|--------|
| **db** | PostgreSQL, MySQL, MariaDB, Microsoft SQL Server, MongoDB, Oracle DB, Cassandra, IBM DB2 | psycopg2 / pymysql / pyodbc / pymongo / oracledb / cassandra-driver / ibm_db | Sprint 1 — DB connectors wired, YAML real SQL |
| **linux** | Ubuntu, RHEL, Debian, CentOS, SUSE, Alibaba Linux | paramiko (SSH) | Sprint 6 — stub |
| **network** | Cisco IOS, Cisco IOS-XE, Cisco NX-OS, Cisco ASA, Palo Alto, Fortinet, Juniper, F5, Check Point, Sophos | netmiko / napalm / SNMP | Sprint 7 — stub |
| **web_server** | Apache HTTP, Nginx, IIS, Tomcat, WebSphere | SSH + REST API | Sprint 8 — stub |
| **virtualization** | VMware ESXi | pyvmomi | Sprint 9 — stub |
| **container** | Docker | docker SDK | Sprint 9 — stub |
| **devops** | GitHub, GitLab | PyGithub / python-gitlab | Sprint 10 — stub |
| **collaboration** | Google Workspace, Microsoft 365 | google-auth / msal | Sprint 10 — stub |
| **data_platform** | Snowflake | snowflake-connector-python | Sprint 11 — stub |
| **middleware** | Dynamics 365, SharePoint | msal / REST | Sprint 11 — stub |

**40 technologies total across 10 categories.**

CIS Benchmarks mapped per technology:

| Technology | CIS Benchmark |
|------------|--------------|
| PostgreSQL | CIS PostgreSQL 15 |
| MySQL / MariaDB | CIS MySQL 8 |
| SQL Server | CIS SQL Server 2022 |
| MongoDB | CIS MongoDB 7 |
| Oracle DB | CIS Oracle Database 19c |
| Ubuntu | CIS Ubuntu Linux 22.04 LTS |
| RHEL | CIS Red Hat Enterprise Linux 9 |
| Cisco IOS | CIS Cisco IOS 16 |
| Nginx | CIS NGINX Benchmark |
| Apache HTTP | CIS Apache HTTP Server 2.4 |

---

## 3. Sub-Engine Reference

### 3.1 tech-discovery (Port 8030)

**Purpose:** Connect to a technology target and execute YAML-driven discovery queries. Stores raw results to `tech_discovery_findings`.

**Entry point (K8s Job):** `python run_scan.py --scan-run-id <uuid> --account-id <id>`

**FastAPI endpoints:**
```
GET  /api/v1/health/live
GET  /api/v1/health/ready
POST /api/v1/scan                      → trigger scan (enqueues Argo job)
GET  /api/v1/findings/{scan_run_id}    → list raw discovery findings
```

**Execution flow:**
```
run_scan.py
  └── TechDBManager.get_credential(account_id)
        ↓ {tech_type, tech_category, host, port, credential_ref}
  └── CATEGORY_SCANNERS[tech_category]  →  DBScanner / LinuxScanner / ...
  └── scanner.connect()                 →  opens psycopg2 / paramiko / REST
  └── scanner.discover()
        └── TechYAMLExecutor("db", "postgres").load()
              ↓ loads catalog/discovery_generator_data/db/postgres/step6_discovery.yaml
        └── for each entry in discovery[]:
              └── executor.execute_entry(entry, connector, host)
                    ├── action: query_setting  →  SHOW <param>  →  single row
                    └── action: query_table    →  SELECT ...    →  one or many rows
              └── _build_finding(discovery_id, resource_uid, resource_type, raw_data)
                    └── finding_id = sha256(discovery_id|resource_uid|scan_run_id)[:16]
  └── TechDBManager.upsert_findings(scan_run_id, findings)
```

**Image:** `yadavanup84/engine-tech-discovery:v-tech-disc-v2`

**Key files:**
- [run_scan.py](tech-discovery/run_scan.py) — K8s Job entry point
- [executor/yaml_executor.py](tech-discovery/executor/yaml_executor.py) — YAML loader + SQL dispatcher
- [providers/db/scanner.py](tech-discovery/providers/db/scanner.py) — DB category scanner
- [providers/db/connectors/db_connector.py](tech-discovery/providers/db/connectors/db_connector.py) — All DB connectors
- [providers/linux/connectors/ssh_connector.py](tech-discovery/providers/linux/connectors/ssh_connector.py) — SSH connector (paramiko)
- [common/models/connector_interface.py](tech-discovery/common/models/connector_interface.py) — `TechScanner` ABC + `TechFinding` dataclass
- [common/database/tech_db_manager.py](tech-discovery/common/database/tech_db_manager.py) — Shared DB layer

---

### 3.2 tech-inventory (Port 8031)

**Purpose:** Normalize discovery findings into stable, deduplicated asset records. Enables drift detection across scans.

**Entry point (K8s Job):** `python run_normalize.py --scan-run-id <uuid> --account-id <id>`

**FastAPI endpoints:**
```
GET  /api/v1/health/live
GET  /api/v1/health/ready
GET  /api/v1/assets?tenant_id=T[&provider=postgres]   → list assets
GET  /api/v1/assets/{asset_id}?tenant_id=T            → single asset
```

**Normalization logic:**
```
For each discovery finding (where error IS NULL):
  asset_id   = sha256(account_id|resource_uid)[:16]    ← stable across scans
  version    = raw_data.version | server_version | product_version
  os_version = raw_data.os | kernel_version | os_version
  asset_name = raw_data.hostname | display_name | instance_name | resource_uid
  metadata   = full raw_data JSONB (preserved for UI drill-down)
```

`first_seen_at` is preserved on upsert; `last_seen_at` is updated every scan — the UI can show "first detected" vs "last confirmed."

**Image:** `yadavanup84/engine-tech-inventory:v-tech-inv-v1`

**Key files:**
- [run_normalize.py](tech-inventory/run_normalize.py) — K8s Job entry point
- [app.py](tech-inventory/app.py) — FastAPI REST layer

---

### 3.3 tech-check (Port 8032)

**Purpose:** Evaluate CIS benchmark rules against discovery findings and produce PASS/FAIL/ERROR results with evidence and framework mappings.

**Entry point (K8s Job):** `python run_check.py --scan-run-id <uuid> --account-id <id>`

**FastAPI endpoints:**
```
GET  /api/v1/health/live
GET  /api/v1/health/ready
GET  /api/v1/findings/{scan_run_id}?tenant_id=T[&status=FAIL]
     → {total, fail_count, pass_count, findings[]}
```

**Evaluation flow:**
```
For each active rule in tech_rule_metadata (tech_type = X):
  ├── Find matching discovery findings by discovery_id
  ├── For each finding:
  │     raw_value = finding.raw_data[rule.rule_metadata.check.expected_key]
  │     Compare with expected_value using operator (eq|ne|in|exists|contains|gt|lt)
  │     → status = PASS | FAIL | ERROR
  └── Write tech_check_finding with:
        finding_id        = sha256(rule_id|resource_uid|scan_run_id)[:16]
        evidence          = {actual_value, expected_value, operator, raw_data}
        framework_mappings = {nist: [...], soc2: [...]}
```

**Supported operators:**

| Operator | Description | Example |
|----------|-------------|---------|
| `eq` | Exact match | `password_encryption == "scram-sha-256"` |
| `ne` | Not equal | `auth_method != "trust"` |
| `in` | Value in list | `log_statement in ["ddl", "all"]` |
| `exists` | Key is not null | `ssl_cert_path exists` |
| `contains` | Substring match | `log_line_prefix contains "%m"` |
| `gt` | Greater than | `max_connections > 0` |
| `lt` | Less than | `idle_timeout < 3600` |

**Image:** `yadavanup84/engine-tech-check:v-tech-check-v2`

**Key files:**
- [run_check.py](tech-check/run_check.py) — K8s Job entry point + rule evaluator
- [app.py](tech-check/app.py) — FastAPI REST layer

---

### 3.4 tech-ciem (Port 8033)

**Purpose:** Pull live session and audit log data from the target technology and run 10 MITRE ATT&CK-mapped behavioural anomaly detectors. Runs in **parallel** with tech-check after tech-inventory.

**Entry point (K8s Job):** `python run_ciem.py --scan-run-id <uuid> --account-id <id>`

**Environment variables:**
- `CIEM_LOOKBACK_HOURS` — analysis window in hours (default: `24`)

**FastAPI endpoints:**
```
GET  /api/v1/health/live
GET  /api/v1/health/ready
GET  /api/v1/ciem/{scan_run_id}?tenant_id=T
     → {total, critical_count, high_count, findings[]}
```

**Log sources by tech_type:**

| tech_type | Source | Data collected |
|-----------|--------|----------------|
| `postgres` | `pg_stat_activity` | Active sessions: user, IP, state, query, age |
| `postgres` | `pg_stat_database` | xact_rollback count, deadlocks, numbackends |
| `postgres` | `pg_roles` | Current superuser accounts |
| `postgres` | `pg_auth_members` | Role grants to privileged roles |
| `postgres` | pgaudit log table | Full SQL audit (if pgaudit installed + log-to-table configured) |
| `mysql` / `mariadb` | `INFORMATION_SCHEMA.PROCESSLIST` | Active sessions |
| `mysql` / `mariadb` | `performance_schema.events_statements_history_long` | Recent query history with row counts |
| `mysql` / `mariadb` | `performance_schema.accounts` | Per-account connection totals |
| others | — | Stub (empty events — Sprint 5+) |

**Image:** `yadavanup84/engine-tech-ciem:v-tech-ciem-v2`

**Key files:**
- [run_ciem.py](tech-ciem/run_ciem.py) — K8s Job entry point + all 10 detectors
- [app.py](tech-ciem/app.py) — FastAPI REST layer

---

### 3.5 tech-scan-agent (host-based)

**Purpose:** A lightweight agent deployed **on the target host** (vendor/customer server). It pulls the rule catalog from the central `tech-check` engine, runs discovery locally, evaluates rules, and pushes only PASS/FAIL findings back — no raw config data leaves the host, no inbound firewall ports required.

**When to use:** For on-premise databases, Linux OS, network devices, and web servers where the central engine cannot reach the target directly. The agent replaces direct-connect `tech-discovery` for those credentials.

**Architecture:**

```
Vendor / Customer Host
┌──────────────────────────────────────────────┐
│  tech-scan-agent  (Python, Alpine container)  │
│                                              │
│  1. GET /api/v1/tech/catalog/{tech_type}     │← pull from tech-check
│     → merged discovery entries + check rules │
│                                              │
│  2. Run discovery locally                    │
│     SQL  → psycopg2/pymysql to 127.0.0.1    │
│     SSH  → subprocess.run() (agent IS host) │
│     Docker → subprocess docker CLI          │
│     PowerShell → subprocess pwsh            │
│                                              │
│  3. Evaluate rules → PASS/FAIL               │
│                                              │
│  4. POST /api/v1/tech/findings               │→ push to tech-check
└──────────────────────────────────────────────┘
           outbound HTTPS/443 only
      ──────────────────────────────────
           Central Engine (EKS)
           tech-check :8032
```

**Usage:**

```bash
python agent.py \
  --scan-run-id  337a7425-...          \
  --account-id   acct_pg_prod_01       \
  --tech-type    postgresql            \
  --central-url  https://tech-check.threat-engine.internal \
  --token        <agent-jwt-from-onboarding>
```

**Transport matrix:**

| Transport | Tech types | How agent collects |
|-----------|-----------|-------------------|
| SQL (localhost) | postgresql, mysql, oracle_db, ibm_db2, sql_server, mariadb | Connect to 127.0.0.1 with local service account |
| SSH (local exec) | ubuntu, debian, rhel, suse, centos, apache_http, nginx, tomcat, websphere, cisco_* | `subprocess.run()` — no SSH needed, commands run in place |
| Docker socket | docker | `docker` CLI via subprocess |
| PowerShell | iis | `subprocess.run(["pwsh", "-Command", ...])` |
| REST API | check_point, microsoft_365, google_workspace, gitlab, snowflake | Central engine calls API directly — no agent needed |

**Image:** `yadavanup84/tech-scan-agent:v1`

**Key files:**
- [tech-agent/agent.py](tech-agent/agent.py) — CLI entry point
- [tech-agent/catalog_client.py](tech-agent/catalog_client.py) — GET catalog from central + local fallback
- [tech-agent/local_executor.py](tech-agent/local_executor.py) — SQL / subprocess / Docker dispatch
- [tech-agent/rule_evaluator.py](tech-agent/rule_evaluator.py) — PASS/FAIL evaluation
- [tech-agent/findings_client.py](tech-agent/findings_client.py) — POST findings to central

**K8s DaemonSet (for scanning K8s node hosts):**
```
deployment/aws/eks/engines/tech-agent-installer.yaml
```

---

## 4. Pipeline Execution Flow

### Argo DAG

```
WorkflowTemplate: tech-scan-pipeline  (namespace: argo)
Parameters: scan-run-id, account-id, tenant-id

tech-discovery  (600s timeout)
      │
      ▼
tech-inventory  (300s timeout)
      │
      ├──────────────────────┐
      ▼                      ▼
tech-check (300s)     tech-ciem (300s)
  [parallel]            [parallel]
```

### Trigger a scan manually

```bash
argo submit -n argo \
  --from workflowtemplate/tech-scan-pipeline \
  -p scan-run-id=$(python3 -c "import uuid; print(uuid.uuid4())") \
  -p account-id=<account_id> \
  -p tenant-id=<tenant_id>
```

### What each step writes

| Step | Table | Key columns written |
|------|-------|---------------------|
| tech-discovery | `tech_discovery_findings` | `finding_id`, `discovery_id`, `raw_data` (JSONB) |
| tech-inventory | `tech_inventory_assets` | `asset_id`, `version`, `os_version`, `asset_name`, `metadata` |
| tech-check | `tech_check_findings` | `rule_id`, `status`, `evidence`, `framework_mappings` |
| tech-ciem | `tech_ciem_findings` | `rule_id`, `mitre_technique`, `actor`, `source_ip`, `event_time` |

### Standard columns (all tables)

All four finding tables share the same standard columns used across the entire threat-engine platform:

```
finding_id      VARCHAR(64)    sha256(…)[:16]
scan_run_id     UUID           single identifier for this pipeline run
tenant_id       VARCHAR(255)   tenant workspace
account_id      VARCHAR(255)   registered tech account
credential_ref  VARCHAR(500)   AWS Secrets Manager ARN
credential_type VARCHAR(50)    username_password | ssh_key | api_token | …
provider        VARCHAR(50)    = tech_type  (postgres, ubuntu, cisco_ios, …)
tech_category   VARCHAR(50)    = category   (db, linux, network, …)
region          VARCHAR(255)   = host:port  (on-prem has no geo region)
resource_uid    VARCHAR(500)   unique resource identifier within the target
resource_type   VARCHAR(255)   postgres.setting | postgres.user | …
severity        VARCHAR(20)    critical | high | medium | low | info
status          VARCHAR(50)    PASS | FAIL | ERROR | open | active
first_seen_at   TIMESTAMPTZ    set on first insert, preserved on upsert
last_seen_at    TIMESTAMPTZ    updated every scan run
```

---

## 5. Discovery YAML Format

Each technology has one canonical discovery file:

```
catalog/discovery_generator_data/{category}/{tech_type}/step6_discovery.yaml
```

### File structure

```yaml
version: '1.0'
provider: technology
category: db               # category key matching CATEGORY_SCANNERS
tech_type: postgres        # tech_type key matching tech_credentials
display_name: PostgreSQL
cis_benchmark: CIS PostgreSQL 15

discovery:

  # Single-row result (settings, counts)
  - discovery_id: db.postgres.auth.password_encryption   # unique across all techs
    description: "CIS 1.1 — Ensure password_encryption uses scram-sha-256"
    resource_uid: "postgres.setting.password_encryption"  # static for singletons
    resource_type: postgres.setting
    action: query_setting        # executes SQL verbatim — used for SHOW <param>
    sql: "SHOW password_encryption"
    emit_as: single              # → one TechFinding, raw_data = first row

  # Multi-row result (users, privileges, hba rules)
  - discovery_id: db.postgres.auth.superuser_accounts
    description: "CIS 1.3 — Identify superuser accounts"
    resource_uid_template: "postgres.user.{usename}"     # .format(**row) per row
    resource_type: postgres.user
    action: query_table          # executes full SQL SELECT
    sql: >
      SELECT usename, usesuper, usecreatedb, usecreaterole,
             valuntil, (passwd IS NOT NULL) AS has_password
      FROM   pg_shadow
      WHERE  usesuper = true
    emit_as: rows                # → one TechFinding per row
```

### Action types

| `action` | What the executor does | Typical use |
|----------|----------------------|-------------|
| `query_setting` | Executes SQL as-is (e.g., `SHOW param`) via psycopg2 | Single-value config settings |
| `query_table` | Executes SQL, returns all rows | User lists, privilege tables, multi-value configs |
| `ssh_command` | Runs command string via `SSHConnector.run()` (Sprint 6) | Linux OS checks |
| `api_call` | REST API call (Sprint 7+) | Cloud management APIs |
| `cli_command` | Local CLI execution (Sprint 7+) | netmiko / napalm for network devices |

### emit_as modes

| `emit_as` | Findings produced | resource_uid |
|-----------|------------------|--------------|
| `single` | 1 finding — `raw_data = rows[0]` | From `resource_uid` field (static) |
| `rows` | N findings — one per SQL row | From `resource_uid_template.format(**row)` |

### Naming convention for `discovery_id`

```
{category}.{tech_type}.{domain}.{check_name}

Examples:
  db.postgres.auth.password_encryption
  db.postgres.logging.log_connections
  linux.ubuntu.network.iptables_rules
  network.cisco_ios.auth.enable_password
```

---

## 6. Check Rule Schema

Rules live in the `tech_rule_metadata` table (not in YAML files). Each rule references a `discovery_id` and carries an inline `check` config:

```sql
-- tech_rule_metadata row for CIS 1.1
rule_id:       'db.postgres.cis.1.1'
tech_type:     'postgres'
tech_category: 'db'
title:         'Ensure password_encryption is set to scram-sha-256'
severity:      'high'
cis_benchmark: 'CIS PostgreSQL 15 Benchmark'
cis_section:   '1.1'
nist_controls: '["IA-5", "IA-5(1)"]'
soc2_criteria: '["CC6.1", "CC6.7"]'
remediation:   'ALTER SYSTEM SET password_encryption = ''scram-sha-256''; SELECT pg_reload_conf();'
rule_metadata: '{
  "check": {
    "expected_key":   "password_encryption",   -- key inside raw_data
    "expected_value": "scram-sha-256",          -- what it must equal
    "operator":       "eq"                      -- eq | ne | in | exists | contains | gt | lt
  }
}'
```

`tech_rule_discoveries` links each rule to its YAML discovery entry:

```sql
rule_id:      'db.postgres.cis.1.1'
discovery_id: 'db.postgres.auth.password_encryption'
action_type:  'query_setting'
yaml_path:    'catalog/discovery_generator_data/db/postgres/step6_discovery.yaml'
```

**How check evaluation works:**

```
1. Load active rules for tech_type from tech_rule_metadata JOIN tech_rule_discoveries
2. For each rule:
   - Find tech_discovery_findings WHERE discovery_id = rule.discovery_id AND scan_run_id = X
   - For each finding: actual_value = finding.raw_data[rule.check.expected_key]
   - Evaluate: actual_value <operator> expected_value → PASS | FAIL | ERROR
3. Upsert to tech_check_findings with:
   - evidence: {actual_value, expected_value, operator, raw_data}
   - framework_mappings: {nist: [...], soc2: [...]}
```

### Seeded rules (PostgreSQL — CIS 15)

| Rule ID | CIS Section | Title | Severity |
|---------|------------|-------|----------|
| `db.postgres.cis.1.1` | 1.1 | password_encryption = scram-sha-256 | high |
| `db.postgres.cis.1.2` | 1.2 | No trust in pg_hba.conf | critical |
| `db.postgres.cis.1.3` | 1.3 | Only one superuser | high |
| `db.postgres.cis.3.1` | 3.1 | log_connections = on | medium |
| `db.postgres.cis.3.2` | 3.2 | log_disconnections = on | medium |
| `db.postgres.cis.3.3` | 3.3 | log_duration = on | medium |
| `db.postgres.cis.3.4` | 3.4 | log_line_prefix includes %m | medium |
| `db.postgres.cis.3.5` | 3.5 | log_statement = ddl or all | medium |
| `db.postgres.cis.pgaudit` | 3.6 | pgaudit extension installed | medium |
| `db.postgres.cis.5.1` | 5.1 | SSL = on | high |
| `db.postgres.cis.5.2` | 5.2 | ssl_min_protocol_version = TLSv1.2+ | high |
| `db.postgres.cis.6.1` | 6.1 | listen_addresses ≠ * | high |
| `db.postgres.cis.7.1` | 7.1 | idle_in_transaction_session_timeout ≠ 0 | medium |
| `db.postgres.cis.7.2` | 7.2 | statement_timeout ≠ 0 | low |

---

## 7. CIEM Detection Rules

10 built-in detectors run against live session/log data. Each detector maps to a MITRE ATT&CK technique.

| Rule ID | MITRE | Tactic | Severity | Detection Logic |
|---------|-------|--------|----------|-----------------|
| TCIEM-001 | T1110 | Credential Access | high | `xact_rollback > 50` in `pg_stat_database` OR `≥5 sessions` from same actor |
| TCIEM-002 | T1078 | Initial Access | critical | Session `client_addr` is non-RFC1918 (external IP login) |
| TCIEM-003 | T1068 | Privilege Escalation | critical | `pg_roles WHERE rolsuper=true` contains any account other than `postgres` |
| TCIEM-004 | T1078 | Persistence | high | Session `backend_start` hour is 22:00–06:00 UTC |
| TCIEM-005 | T1562 | Defense Evasion | high | `REVOKE`, `ALTER ROLE`, `DROP USER`, or `pg_hba` keyword in current session query |
| TCIEM-006 | T1552 | Credential Access | critical | `\copy`, `pg_dump`, `INTO OUTFILE`, `SELECT INTO` in session or statement history |
| TCIEM-007 | T1098 | Persistence | high | `pg_auth_members` shows non-postgres account granted a superuser/createrole role |
| TCIEM-008 | T1530 | Collection | high | MySQL `events_statements_history_long.rows_sent > 10,000` |
| TCIEM-009 | T1611 | Privilege Escalation | critical | Session user is `postgres`/`root`/`sa`/`admin` connecting from a remote IP |
| TCIEM-010 | T1490 | Impact | critical | `DROP DATABASE`, `TRUNCATE`, `shutdown`, `pg_terminate_backend` in session query |

**pgaudit bonus:** If pgaudit is installed and logs to a table (`pgaudit_log`, `audit_log`, or `pg_audit_log`), CIEM reads that table as an additional event source. Detectors TCIEM-005, 006, and 010 gain richer coverage when pgaudit is active.

---

## 8. CIS Rule Generation Framework

All 8,991 CIS check rules across 34 technologies were generated automatically from `cis_technology_compliance_rules.csv` using a Jinja2 template pipeline. This produces three artifact types per technology per CIS section.

### Generator pipeline

```
catalog/rule/cis_technology_compliance_rules.csv
         │
         ▼
catalog/rule/generate_tech_rules.py
         │
         ├── discovery YAML   →  catalog/discovery_generator_data/{cat}/{tech}/
         │     step6_section_{N}.discovery.yaml          ← loaded by TechYAMLExecutor
         │
         ├── check rule YAML  →  catalog/rule/{cat}_rule_check/{tech}/
         │     {tech}_cis_section_{N}.rules.yaml         ← loaded by tech-check
         │
         ├── CIEM rule YAML   →  catalog/rule/{cat}_rule_ciem/{tech}/
         │     {tech}_cis_section_{N}.ciem.yaml          ← MITRE-mapped log rules
         │
         └── metadata YAML    →  catalog/rule/{cat}_rule_metadata/{tech}/
               {tech}_metadata.yaml                      ← uploaded to tech_rule_metadata
```

### Jinja2 templates (`catalog/rule/tech_templates/`)

| Template | Output | Notes |
|----------|--------|-------|
| `discovery_sql.yaml.j2` | SQL discovery YAML | `query:` key; `setting_name:` quoted for `%` wildcard safety |
| `discovery_ssh.yaml.j2` | SSH discovery YAML | `command:` uses `\| tojson` to handle embedded quotes + backslashes |
| `discovery_mongo.yaml.j2` | MongoDB discovery YAML | |
| `discovery_docker.yaml.j2` | Docker API discovery YAML | |
| `discovery_rest.yaml.j2` | REST API discovery YAML | Used for cloud SaaS — no agent |
| `discovery_powershell.yaml.j2` | PowerShell discovery YAML | IIS only |
| `check_rule.yaml.j2` | Check rule YAML | `assertion.operator` mapped from `automation_type` |
| `ciem_rule.yaml.j2` | CIEM rule YAML | `mitre_technique` + `log_event_type` |
| `metadata.yaml.j2` | Rule metadata YAML | NIST / SOC2 / remediation / CIS section |

### Rule counts by sprint

| Sprint | Technologies | Rules | Transport |
|--------|-------------|-------|-----------|
| 0 | Framework only | — | Generator + validator |
| 1 | postgresql, mysql, oracle_db | 748 | SQL |
| 2 | ibm_db2, sql_server, mariadb, mongodb, cassandra | 739 | SQL + Mongo |
| 3 | ubuntu, debian, rhel | 3,386 | SSH |
| 4 | suse, centos | 1,623 | SSH |
| 5 | cisco_ios_xe, palo_alto, cisco_asa, check_point, cisco_ios_xr, cisco_nxos, fortigate, cisco_firewall | 1,168 | SSH / REST |
| 6 | apache_http, nginx, iis, tomcat, websphere | 979 | SSH / PowerShell |
| 7 | docker, vmware_esxi, gitlab, snowflake | 755 | Docker / REST / SQL |
| 8 | microsoft_365, google_workspace, sharepoint, dynamics_365 | 423 | REST API |
| **Total** | **34 technologies** | **8,991 rules** | |

### Rule ID format

```
{tech_type}.cis.{section_number}.{slug}

Examples:
  postgresql.cis.3.log_connections_are_enabled
  ubuntu.cis.1.ensure_separate_partition_for_tmp
  cisco_ios_xe.cis.2.enable_password_is_set
```

### Validator (`catalog/rule/validate_tech_rules.py`)

Eight checks run on every generated file:

| Check | What it verifies |
|-------|-----------------|
| V1 | YAML parses without error |
| V2 | `rule_id` matches `{tech}.cis.{N}.{slug}` pattern |
| V3 | CIEM rules have `rule_id` matching `{tech}.ciem.{N}.{slug}` |
| V4 | CIEM rules carry a MITRE technique ID |
| V5 | No duplicate `rule_id` within file |
| V6 | `severity` is one of critical/high/medium/low/info |
| V7 | Check rules with `automation_type=automated` have an `assertion` block |
| V8 | Manual-only rules have a `manual_procedure` field |

### Uploading rule metadata to DB

```bash
# Dry-run (count only)
python catalog/rule/upload_tech_rule_metadata.py --dry-run

# Upload all 34 techs
python catalog/rule/upload_tech_rule_metadata.py

# Upload specific category or tech
python catalog/rule/upload_tech_rule_metadata.py --category database linux
python catalog/rule/upload_tech_rule_metadata.py --tech postgresql ubuntu
```

The uploader walks `catalog/rule/{category}_rule_metadata/{tech}/{tech}_metadata.yaml` and upserts into `tech_rule_metadata` + `tech_rule_control_mapping`. All 5,025 automatable rules are loaded; the remaining 3,966 manual-only rules are represented as metadata stubs.

---

## 9. Database Schema

**Database name:** `threat_engine_tech`
**RDS instance:** `postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com:5432`

### Tables

```
tech_credentials           — registered technology accounts (ARN refs, no plaintext secrets)
tech_rule_discoveries      — discovery catalog (links YAML entries to rules)
tech_rule_metadata         — CIS check rules with inline check config
tech_rule_control_mapping  — framework cross-references (NIST, SOC2, PCI-DSS, HIPAA)
tech_scan_orchestration    — per-scan status tracking (completed engines, counts)
tech_discovery_findings    — raw JSONB results from step6_discovery.yaml queries
tech_inventory_assets      — normalized, deduplicated asset records
tech_check_findings        — PASS/FAIL per rule per resource per scan
tech_ciem_findings         — behavioural anomaly findings (MITRE-mapped)
```

### Migration

```bash
# Apply schema to threat_engine_tech DB (run from a pod with DB access)
kubectl cp shared/database/migrations/20260430_tech_engine_001_initial.sql \
  threat-engine-engines/<pod>:/tmp/tech_engine_001_initial.sql

kubectl exec -n threat-engine-engines <pod> -- \
  bash -c "PGPASSWORD=\$DB_PASSWORD psql -h \$DB_HOST -U postgres \
           -d threat_engine_tech -f /tmp/tech_engine_001_initial.sql"
```

The migration is idempotent (`CREATE TABLE IF NOT EXISTS`, `ON CONFLICT DO NOTHING`).

### ConfigMap and Secret

```yaml
# Added to threat-engine-db-config ConfigMap
TECH_DB_HOST: postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com
TECH_DB_PORT: "5432"
TECH_DB_NAME: threat_engine_tech
TECH_DB_USER: postgres

# Secret: tech-engine-db-secret
username: postgres
password: <from threat-engine-db-passwords secret>
```

---

## 10. Connector Reference

### DB Connectors (`providers/db/connectors/db_connector.py`)

| Class | tech_type | Library | Required credential fields |
|-------|-----------|---------|---------------------------|
| `PostgresConnector` | `postgres` | psycopg2 | host, port, dbname, username, password, ssl_mode (opt) |
| `MySQLConnector` | `mysql` | pymysql | host, port, dbname, username, password |
| `MariaDBConnector` | `mariadb` | pymysql | same as MySQL |
| `MSSQLConnector` | `mssql` | pyodbc | host, port, dbname, username, password, instance (opt) |
| `MongoDBConnector` | `mongodb` | pymongo | uri (mongodb://...) |
| `OracleConnector` | `oracle` | oracledb | host, port, service_name, username, password |
| `CassandraConnector` | `cassandra` | cassandra-driver | host, port, username, password |
| `IBMDB2Connector` | `ibm_db2` | ibm_db | host, port, dbname, username, password |

All connectors expose `connect()`, `execute_query(sql) → list[dict]`, `close()`.

### SSH Connector (`providers/linux/connectors/ssh_connector.py`)

```python
SSHConnector(credential)  # credential keys:
  host            str     # target hostname or IP
  port            int     # SSH port (default 22)
  username        str     # SSH username (default root)
  password        str     # password auth (mutually exclusive with ssh_private_key)
  ssh_private_key str     # PEM private key string
  sudo_required   bool    # prepend 'sudo ' to all commands

# Methods:
connector.connect()                     # raises AuthenticationError on failure
stdout, stderr, exit_code = connector.run("command", timeout=10)
connector.close()
```

**Security note:** Uses `paramiko.RejectPolicy()` — the target host key must be registered in the scanner pod's `~/.ssh/known_hosts` before connecting. Avoids automatic host key acceptance (TOFU attack vector).

### TechScanner ABC (`common/models/connector_interface.py`)

```python
class TechScanner(ABC):
    def __init__(self, scan_run_id, account_id, credential, db_manager): ...

    @abstractmethod
    async def connect(self) -> None: ...     # raise AuthenticationError on failure

    @abstractmethod
    async def discover(self) -> List[TechFinding]: ...  # raise DiscoveryError

    @abstractmethod
    async def disconnect(self) -> None: ...

    def _build_finding(self, discovery_id, resource_uid, resource_type,
                       raw_data, error_message=None) -> TechFinding:
        # Computes finding_id = sha256(discovery_id|resource_uid|scan_run_id)[:16]
        # Pre-fills all standard columns from self.credential
```

---

## 11. Catalog Structure

```
catalog/
├── discovery_generator_data/
│   ├── db/
│   │   ├── postgres/
│   │   │   ├── step6_discovery.yaml      ← canonical discovery file (real SQL)
│   │   │   ├── step6_auth.discovery.yaml     ← per-domain detail (reference)
│   │   │   ├── step6_logging.discovery.yaml
│   │   │   └── step6_access_control.discovery.yaml
│   │   ├── mysql/
│   │   ├── mariadb/
│   │   ├── mssql/
│   │   ├── mongodb/
│   │   ├── oracle/
│   │   ├── cassandra/
│   │   └── ibm_db2/
│   ├── linux/
│   │   ├── ubuntu/
│   │   ├── rhel/
│   │   ├── debian/
│   │   ├── centos/
│   │   ├── suse/
│   │   └── alibaba_linux/
│   ├── network/
│   │   ├── cisco_ios/
│   │   ├── cisco_iosxe/
│   │   ├── cisco_nxos/
│   │   ├── cisco_asa/
│   │   ├── palo_alto/
│   │   ├── fortinet/
│   │   ├── juniper/
│   │   ├── f5/
│   │   ├── check_point/
│   │   └── sophos/
│   ├── web_server/     → apache_http, nginx, iis, tomcat, websphere
│   ├── virtualization/ → vmware_esxi
│   ├── container/      → docker
│   ├── devops/         → github, gitlab
│   ├── collaboration/  → google_workspace, microsoft_365
│   ├── data_platform/  → snowflake
│   └── middleware/     → dynamics_365, sharepoint
│
└── rule/
    ├── db_rule_check/
    │   ├── postgres/   ← CIS check YAML stubs
    │   ├── mysql/
    │   └── ...
    ├── linux_rule_check/
    ├── network_rule_check/
    └── ...             (one folder per category)
```

**The authoritative discovery definition** is `step6_discovery.yaml` (loaded by `TechYAMLExecutor`). The per-domain files (`step6_auth.discovery.yaml`, etc.) are detailed references — they may be merged into `step6_discovery.yaml` or loaded as supplements in a future sprint.

---

## 12. Deployment & Operations

### Running deployments

```bash
kubectl get deployments -n threat-engine-engines | grep tech
# tech-check      1/1   Running
# tech-ciem       1/1   Running
# tech-discovery  1/1   Running
# tech-inventory  1/1   Running
```

### Current image tags

| Sub-engine | Image |
|------------|-------|
| tech-discovery | `yadavanup84/engine-tech-discovery:v-tech-disc-v2` |
| tech-inventory | `yadavanup84/engine-tech-inventory:v-tech-inv-v1` |
| tech-check | `yadavanup84/engine-tech-check:v-tech-check-v4` |
| tech-ciem | `yadavanup84/engine-tech-ciem:v-tech-ciem-v2` |
| tech-scan-agent | `yadavanup84/tech-scan-agent:v1` |

### Kubernetes manifests

```
deployment/aws/eks/engines/technology/
├── tech-discovery.yaml    (port 8030)
├── tech-inventory.yaml    (port 8031)
├── tech-check.yaml        (port 8032)
└── tech-ciem.yaml         (port 8033)

deployment/aws/eks/argo/
└── tech-pipeline.yaml     (WorkflowTemplate: tech-scan-pipeline)
```

### Build and deploy a sub-engine

```bash
# 1. Build (from repo root — context is always /)
docker build -t yadavanup84/engine-tech-discovery:v-tech-disc-v3 \
  -f engines/technology-engine/tech-discovery/Dockerfile .

# 2. Push
docker push yadavanup84/engine-tech-discovery:v-tech-disc-v3

# 3. Deploy
kubectl set image deployment/tech-discovery \
  tech-discovery=yadavanup84/engine-tech-discovery:v-tech-disc-v3 \
  -n threat-engine-engines

# 4. Verify
kubectl rollout status deployment/tech-discovery -n threat-engine-engines
kubectl logs -f -l app=tech-discovery -n threat-engine-engines --tail=50
```

### Port-forward for local testing

```bash
kubectl port-forward svc/tech-discovery 8030:80 -n threat-engine-engines &
kubectl port-forward svc/tech-inventory 8031:80 -n threat-engine-engines &
kubectl port-forward svc/tech-check     8032:80 -n threat-engine-engines &
kubectl port-forward svc/tech-ciem      8033:80 -n threat-engine-engines &

# Health check
python3 -c "import urllib.request; print(urllib.request.urlopen('http://localhost:8030/api/v1/health/live').read())"
```

### View logs

```bash
kubectl logs -f -l app=tech-discovery -n threat-engine-engines --tail=100
kubectl logs -f -l app=tech-ciem      -n threat-engine-engines --tail=100
```

### Argo Workflow

```bash
# List tech scan workflow runs
argo list -n argo | grep tech

# Trigger new scan
argo submit -n argo \
  --from workflowtemplate/tech-scan-pipeline \
  -p scan-run-id=$(python3 -c "import uuid; print(uuid.uuid4())") \
  -p account-id=<account_id> \
  -p tenant-id=<tenant_id>

# Watch progress
argo watch -n argo <workflow-name>

# View logs for a step
argo logs -n argo <workflow-name> tech-discovery
```

---

## 13. Onboarding a Technology Account

Technology accounts are onboarded through the same **Onboarding Wizard** as cloud accounts, but with a "Database" category tab.

### Via the UI

1. Open the CSPM portal → **Accounts** → **Add Account**
2. Select category: **Database** (or **Cloud** for cloud-based accounts)
3. Choose provider: `postgres`, `mysql`, `mssql`, `mongodb`, or `oracle`
4. Fill credential form:

| Provider | Required fields |
|----------|----------------|
| postgres | host, port, dbname, username, password, ssl_mode (optional) |
| mysql | host, port, dbname, username, password |
| mssql | host, port, dbname, username, password, instance (optional) |
| mongodb | uri (`mongodb://user:pass@host:port/db`) |
| oracle | host, port, service_name, username, password |

5. The wizard validates the connection by calling the provider validator
6. `account_category = "database"` is automatically set from the provider
7. The credential is stored in AWS Secrets Manager; only the ARN is saved to DB

### Via API

```bash
curl -X POST http://<gateway>/api/v1/accounts \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id":   "tenant_abc",
    "account_name": "prod-postgres",
    "provider":    "postgres",
    "credentials": {
      "host":     "10.0.1.5",
      "port":     5432,
      "dbname":   "mydb",
      "username": "monitor_user",
      "password": "secret"
    }
  }'
# Returns: {account_id: "acct_xyz", account_category: "database", ...}
```

### Via psql (direct insert for testing)

```sql
-- In threat_engine_tech DB
INSERT INTO tech_credentials
  (tenant_id, account_id, tech_type, tech_category, host, port,
   display_name, credential_type, credential_ref, status)
VALUES
  ('tenant_abc', 'acct_pg_prod', 'postgres', 'db', '10.0.1.5', 5432,
   'Production PostgreSQL', 'username_password',
   'arn:aws:secretsmanager:ap-south-1:588989875114:secret:pg-prod-cred', 'active');
```

---

## 14. Triggering a Scan

### Full pipeline (Argo)

```bash
SCAN_RUN_ID=$(python3 -c "import uuid; print(uuid.uuid4())")
ACCOUNT_ID="acct_pg_prod"
TENANT_ID="tenant_abc"

argo submit -n argo \
  --from workflowtemplate/tech-scan-pipeline \
  -p scan-run-id=$SCAN_RUN_ID \
  -p account-id=$ACCOUNT_ID \
  -p tenant-id=$TENANT_ID \
  --watch
```

### Individual step (for debugging)

```bash
# Run discovery only (in a pod with catalog access)
kubectl exec -n threat-engine-engines <tech-discovery-pod> -- \
  python run_scan.py \
    --scan-run-id $SCAN_RUN_ID \
    --account-id $ACCOUNT_ID

# Run check only (discovery must have run first)
kubectl exec -n threat-engine-engines <tech-check-pod> -- \
  python run_check.py \
    --scan-run-id $SCAN_RUN_ID \
    --account-id $ACCOUNT_ID

# Run CIEM only
kubectl exec -n threat-engine-engines <tech-ciem-pod> -- \
  python run_ciem.py \
    --scan-run-id $SCAN_RUN_ID \
    --account-id $ACCOUNT_ID
```

### Query results

```sql
-- Discovery findings
SELECT discovery_id, resource_uid, resource_type, raw_data
FROM   tech_discovery_findings
WHERE  scan_run_id = '<uuid>' AND provider = 'postgres'
ORDER  BY discovery_id;

-- Check findings (FAIL only)
SELECT rule_id, rule_title, severity, resource_uid, evidence
FROM   tech_check_findings
WHERE  scan_run_id = '<uuid>' AND status = 'FAIL'
ORDER  BY severity DESC;

-- CIEM findings
SELECT rule_id, mitre_technique, mitre_tactic, actor, source_ip, severity, evidence
FROM   tech_ciem_findings
WHERE  scan_run_id = '<uuid>'
ORDER  BY severity DESC;

-- Inventory
SELECT asset_id, asset_name, version, os_version, provider, region
FROM   tech_inventory_assets
WHERE  tenant_id = 'tenant_abc' AND provider = 'postgres';
```

---

## 15. Seeding Rules

### PostgreSQL CIS rules (already seeded)

```bash
# Verify
kubectl exec -n threat-engine-engines <any-running-pod> -- \
  bash -c "PGPASSWORD=\$TECH_DB_PASSWORD psql -h \$TECH_DB_HOST -U postgres \
           -d threat_engine_tech \
           -c 'SELECT rule_id, severity, cis_section FROM tech_rule_metadata ORDER BY cis_section'"
```

### Add rules for a new technology

1. Add rows to `tech_rule_discoveries` (maps rule to discovery YAML entry)
2. Add rows to `tech_rule_metadata` (rule definition with `rule_metadata.check` config)
3. Optionally add rows to `tech_rule_control_mapping` (NIST/SOC2/PCI cross-references)

See [scripts/seed_tech_rules_postgres.sql](../../scripts/seed_tech_rules_postgres.sql) as the reference template.

```sql
-- Minimal example for a new rule
INSERT INTO tech_rule_metadata
  (rule_id, tech_type, tech_category, title, severity,
   cis_benchmark, cis_section, remediation, rule_metadata, is_active)
VALUES (
  'db.mysql.cis.1.1', 'mysql', 'db',
  'Ensure validate_password plugin is active',
  'high', 'CIS MySQL 8 Benchmark', '1.1',
  'INSTALL PLUGIN validate_password SONAME ''validate_password.so'';',
  '{"check": {"expected_key": "plugin_status", "expected_value": "ACTIVE", "operator": "eq"}}',
  true
);
```

---

## 16. Sprint Roadmap

### Engine Sprints (sub-engine implementation)

| Sprint | Theme | Key deliverables | Status |
|--------|-------|-----------------|--------|
| 0 | Foundation | DB schema, TechDBManager, K8s manifests, Argo pipeline | ✅ done |
| 1 | Database Discovery | Real SQL dispatch via DB connectors, 14 CIS PG15 rules | ✅ done |
| 2 | Inventory | Asset normalizer with drift detection | ✅ done |
| 3 | Check Engine | Rule evaluator, all operators, framework mappings | ✅ done |
| 4 | CIEM | 10 MITRE detectors, PostgreSQL + MySQL log sources | ✅ done |
| 5 | Onboarding + Pipeline | DB provider in wizard, Argo template | ✅ done |
| 6 | Linux OS | SSH scanner, Ubuntu/RHEL/Debian, CIS Linux Benchmark | pending |
| 7 | Network Devices | netmiko/napalm, Cisco IOS/NX-OS/ASA, Palo Alto, Fortinet | pending |
| 8 | Web Servers | Apache, Nginx, IIS — SSH + config file parsing | pending |
| 9 | Virtualization + Container | pyvmomi (ESXi), Docker SDK | pending |
| 10 | DevOps + Collaboration | GitHub/GitLab APIs, Google Workspace, M365 | pending |
| 11 | Data + Middleware | Snowflake connector, Dynamics 365, SharePoint | pending |

### CIS Rule Generation Sprints (catalog population)

| Sprint | Technologies | Rules | Status |
|--------|-------------|-------|--------|
| TEC-0 | Generator framework (7 templates + validator + slug deduplicator) | — | ✅ done |
| TEC-1 | postgresql, mysql, oracle_db | 748 | ✅ done |
| TEC-2 | ibm_db2, sql_server, mariadb, mongodb, cassandra | 739 | ✅ done |
| TEC-3 | ubuntu, debian, rhel | 3,386 | ✅ done |
| TEC-4 | suse, centos | 1,623 | ✅ done |
| TEC-5 | cisco_ios_xe, palo_alto, cisco_asa, check_point, cisco_ios_xr, cisco_nxos, fortigate, cisco_firewall | 1,168 | ✅ done |
| TEC-6 | apache_http, nginx, iis, tomcat, websphere | 979 | ✅ done |
| TEC-7 | docker, vmware_esxi, gitlab, snowflake | 755 | ✅ done |
| TEC-8 | microsoft_365, google_workspace, sharepoint, dynamics_365 | 423 | ✅ done |
| TEC-9 | YAML executor multi-section glob fix + metadata uploader (5,025 rules → DB) | — | ✅ done |
| TEC-901 | tech-scan-agent — host-based scanner for SQL/SSH/Docker transports | — | ✅ done |

Story files for each sprint: [`.claude/planning/stories/TECH-*.md`](../../.claude/planning/stories/)

---

## 17. Adding a New Technology

### Checklist

**1. Add discovery YAML**
```bash
mkdir -p catalog/discovery_generator_data/<category>/<tech_type>
# Create: catalog/discovery_generator_data/<category>/<tech_type>/step6_discovery.yaml
```

Follow the format in [section 5](#5-discovery-yaml-format). Add entries for auth, logging, network, and encryption domains at minimum.

**2. Add connector** (if new category)
```python
# providers/<category>/connectors/<tech>_connector.py
class NewConnector(BaseDBConnector):
    def connect(self) -> None: ...
    def execute_query(self, sql: str) -> list[dict]: ...
```

Register in `get_db_connector()` factory.

**3. Implement scanner**
```python
# providers/<category>/scanner.py
class NewScanner(TechScanner):
    async def connect(self) -> None:
        self._connector = get_connector(self.tech_type, self.credential)
        self._connector.connect()

    async def discover(self) -> List[TechFinding]:
        executor = TechYAMLExecutor(self.tech_category, self.tech_type).load()
        findings = []
        for entry in executor.queries:
            results = executor.execute_entry(entry, self._connector, self.host)
            for item in results:
                findings.append(self._build_finding(
                    discovery_id  = entry["discovery_id"],
                    resource_uid  = item["resource_uid"],
                    resource_type = entry.get("resource_type", "config"),
                    raw_data      = item["raw_data"],
                ))
        return findings

    async def disconnect(self) -> None:
        if self._connector:
            self._connector.close()
```

Register in `CATEGORY_SCANNERS` in `run_scan.py`.

**4. Seed check rules**
```sql
-- Insert into tech_rule_discoveries + tech_rule_metadata
-- Reference: scripts/seed_tech_rules_postgres.sql
```

**5. Add CIEM log collector** (if live log source available)
```python
# In run_ciem.py — _collect_events() dispatcher
def _collect_<tech_type>(...) -> Dict[str, Any]:
    # Return {sessions: [...], stats: [...], ...}
```

Update `_collect_events()` to dispatch to the new collector.

**6. Add to onboarding wizard** (if new credential form fields needed)
- Add credential fields in `frontend/src/components/domain/OnboardingWizard.jsx`
- Add validator in `engines/onboarding/validators/`

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `TECH_DB_HOST` | PostgreSQL host for `threat_engine_tech` | from ConfigMap |
| `TECH_DB_PORT` | PostgreSQL port | `5432` |
| `TECH_DB_NAME` | Database name | `threat_engine_tech` |
| `TECH_DB_USER` | Database user | `postgres` |
| `TECH_DB_PASSWORD` | Database password | from Secret |
| `CIEM_LOOKBACK_HOURS` | CIEM analysis window | `24` |
| `CATALOG_DIR` | Override catalog root path | auto-resolved from file location |

---

## Related Documentation

| Document | Location |
|----------|----------|
| Tech Engine PRD | `.claude/planning/tech-engine-prd.md` |
| Sprint Story Files | `.claude/planning/stories/TECH-*.md` |
| DB Migration | `shared/database/migrations/20260430_tech_engine_001_initial.sql` |
| DB Schema | `shared/database/schemas/tech_engine_schema.sql` |
| CIS Rule Seed | `scripts/seed_tech_rules_postgres.sql` |
| K8s Manifests | `deployment/aws/eks/engines/technology/` |
| Argo Pipeline | `deployment/aws/eks/argo/tech-pipeline.yaml` |
| Cloud Engine README | `engines/README.md` |
