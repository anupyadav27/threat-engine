# Changes by Ajay

Tracked changes made to the threat-engine codebase during the technology engine
and compliance engine improvement sprint.

---

## 1. Tech-CIEM Engine — Full Database Coverage

**File:** `engines/technology-engine/tech-ciem/run_ciem.py`

**Problem:**
The CIEM engine only collected audit data from PostgreSQL and MySQL/MariaDB.
For all other database types (Oracle, MSSQL, MongoDB, Cassandra), the engine
silently returned 0 findings and marked the scan as "completed" — identical to
a legitimately clean scan. Admins had no way to know whether a database was
checked or simply skipped.

**Changes made:**

- Added `_collect_oracle()` — connects via `oracledb`/`cx_Oracle`, queries
  `V$SESSION`, `DBA_AUDIT_TRAIL` (failed logins), `DBA_ROLE_PRIVS` (DBA/SYSDBA
  holders), and `V$SQLAREA` (statement history).

- Added `_collect_mssql()` — connects via `pymssql`, queries
  `sys.dm_exec_sessions`, `sys.dm_os_ring_buffers` (failed logins),
  `sys.server_principals` (sysadmin members), `sys.server_role_members`, and
  `sys.dm_exec_query_stats`.

- Added `_collect_mongodb()` — connects via `pymongo`, queries `currentOp`
  (active sessions), `usersInfo` (admin role holders), and `system.profile`
  (when profiling is enabled).

- Added `_collect_cassandra()` — connects via `cassandra-driver`, queries
  `system_auth.roles` (superuser roles) and `system_auth.role_members`
  (membership in superuser roles). Sessions/statement history are not exposed
  in OSS Cassandra.

- Updated `_collect_events()` to dispatch to all 6 supported tech types.
  Returns `None` (not `{}`) for genuinely unknown types — allowing `run()` to
  distinguish "unsupported" from "clean scan with 0 events".

- Fixed `run()` — changed `if not data:` to `if data is None:` so supported
  tech types with no suspicious events in the lookback window still go through
  the full detector loop.

- Each new collector sets `_expected_superusers` in the data dict:
  Oracle → `{"SYS", "SYSTEM"}`, MSSQL → `{"sa"}`,
  MongoDB → `{"admin"}`, Cassandra → `{"cassandra"}`.

- Fixed `detect_new_superuser()` and `detect_admin_grant()` — both previously
  hardcoded `"postgres"` as the expected default superuser. Now read
  `data.get("_expected_superusers", {"postgres"})` so each tech type flags the
  right accounts.

**Coverage after change:**

| Tech | Brute Force | External IP | Superuser | Off-Hours | ACL Change | Mass Export | Admin Grant | Data Exfil | Root Session | Destructive |
|---|---|---|---|---|---|---|---|---|---|---|
| Postgres | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| MySQL/MariaDB | Yes | Yes | — | Yes | Yes | Yes | — | Yes | Yes | Yes |
| Oracle | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| MSSQL | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| MongoDB | — | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| Cassandra | — | — | Yes | — | — | — | Yes | — | — | — |

Cassandra gaps are structural — OSS Cassandra does not expose session or query
history via driver APIs.

---

## 2. Discovery YAML Generator — OS-Level Check Handling

**File:** `catalog/rule/tech_templates/render_discovery.py`

**Problem:**
The generator was producing invalid SQL placeholders for OS-level CIS checks
(e.g., `SELECT current_setting('systemd_service_files_are_enabled')`) — using
the CIS check title slug as if it were a database parameter name. These checks
require shell commands, not SQL queries.

Additionally, Oracle was incorrectly grouped with MySQL, causing it to generate
`SHOW VARIABLES LIKE '...'` (MySQL syntax) instead of Oracle-compatible SQL.

**Changes made:**

- Added `_is_os_level_check(audit_procedure, tech)` function — detects whether
  a CIS audit procedure contains extractable SQL or only shell commands.

- Added `_ORACLE_TRANSPORTS` set — Oracle now generates
  `SELECT VALUE FROM V$PARAMETER WHERE NAME = '...'` instead of MySQL syntax.

- Added `_applicable_to` field to each generated entry:
  - OS-level checks → `["self_hosted"]` (skipped for cloud-managed RDS/Azure DB)
  - SQL-queryable checks → `["cloud_managed", "self_hosted"]`

- Removed `_SHELL_PATTERN` generic clause that falsely matched prose text as
  shell commands, producing full audit procedure paragraphs as command strings.

- Added `_INLINE_DOLLAR_CMD` pattern as a precise fallback for extracting actual
  shell commands (lines starting with `$`).

- Updated `discovery_sql.yaml.j2` and `discovery_ssh.yaml.j2` templates to emit
  the `applicable_to` field in generated YAMLs.

**File:** `engines/technology-engine/tech-discovery/executor/yaml_executor.py`

- Added deployment type detection (`_detect_deployment_type`) — classifies hosts
  with RDS/Azure DB/Cloud SQL suffixes as `cloud_managed`, everything else as
  `self_hosted`.

- Added `applicable_to` filter in `execute_entry()` — skips OS-level entries
  for cloud-managed databases, skips cloud-only entries for self-hosted.

- Fixed executor dispatch bug — previously read `action` only from top-level
  entry dict, defaulting to `"query_table"`. Generated YAMLs place `action`
  inside `calls[0]`, so OS-level entries tagged `run_command` were never
  dispatched correctly. Now falls back to `calls[0].action` when top-level is
  absent.

---

## 3. Compliance Engine — P0 Bug Fixes

**File:** `engines/compliance/compliance_engine/storage/compliance_db_writer.py`

**Bug 1 — `compliance_scan_id` column does not exist:**
`save_compliance_report_to_db()` (called from `api_server.py`) was inserting
into a column `compliance_scan_id` that does not exist in the
`compliance_report` table. Every API-triggered compliance save was failing at
the DB level with a column-not-found error.

Fix: Removed `compliance_scan_id` from the INSERT statement and the matching
value tuple. `scan_run_id` is the sole primary key.

**Bug 2 — Duplicate column in `list_compliance_scans()`:**
The SELECT query fetched `scan_run_id` twice in adjacent positions. The second
occurrence was replaced with `status` (which is written by `run_scan.py` and
needed by callers of this function).

---

**File:** `engines/compliance/compliance_engine/exporter/db_exporter.py`

**Bug 3 — `resource_arn` vs `resource_uid` mismatch:**
`create_schema()` defined the column as `resource_arn TEXT` but the INSERT
statement in the same file used `resource_uid` as the column name (matching
`compliance_db_writer.py`). In any environment where `create_schema()` was
used to create the table (local dev, test), subsequent INSERT statements would
fail with "column resource_uid does not exist".

Fix: Changed `create_schema()` to use `resource_uid TEXT`. Renamed the Python
variable `resource_arn` → `resource_uid` in `export_report()` to eliminate
the naming confusion.

---

## 4. Compliance Engine — Tech Findings Now Reach Compliance

**File:** `engines/compliance/compliance_engine/loader/tech_db_loader.py` *(new)*

**Problem:**
The compliance engine only loaded findings from the cloud check engine
(`check_findings` table). The technology engine's `tech_check_findings` table
— populated by `tech-check` with CIS results for PostgreSQL, MySQL, Oracle, etc.
— was never read by the compliance engine. Database CIS findings were orphaned:
written by the tech pipeline but never contributing to any framework score.

**New file — `TechDBLoader`:**
- Connects to tech DB via `TECH_DB_*` env vars.
- Reads `tech_check_findings` for a given `scan_run_id` + `tenant_id`.
- Converts rows to the same `scan_results` dict format as `CheckDBLoader`:
  groups by `tech_category` (service) and `region`, normalises field names.
- `load_and_convert()` returns an empty results dict (not raises) when the
  tech DB is unreachable — graceful degradation for tenants with no databases.

---

**File:** `engines/compliance/run_scan.py`

- Added tech findings merge block after the CIEM merge and before
  `EnterpriseReporter.generate_report()`.
- `scan_results["results"]` now contains cloud findings + tech DB findings
  before the reporter processes them.
- Entire block is wrapped in try/except — a missing tech DB never fails the
  compliance scan for the cloud side.

**End-to-end flow after fix:**

```
tech-check writes tech_check_findings (CIS rules for each database)
          ↓
run_scan.py: CheckDBLoader  → cloud posture findings
run_scan.py: TechDBLoader   → database CIS findings   (NEW)
          ↓
scan_results = cloud_results + tech_results
          ↓
EnterpriseReporter scores both against all 13+ frameworks
          ↓
compliance_findings includes database security posture
```

---

## 5. Compliance Engine — Framework Mappings for Tech Rules

**File:** `catalog/rule/upload_tech_rule_metadata.py`

**Problem:**
The upload script created only CIS entries in `tech_rule_control_mapping`.
NIST 800-53, SOC2, PCI-DSS, and ISO 27001 columns were left empty in the
metadata YAMLs and no code was generating those mapping rows. When the
compliance engine scored tech findings against NIST or SOC2 frameworks, it
found no mappings and the database findings contributed nothing to those scores.

**Changes made:**

- Added CIS-section-to-framework cross-walk dictionaries:
  `_NIST_BY_SECTION`, `_SOC2_BY_SECTION`, `_PCI_BY_SECTION` — mapping each
  CIS section number (1–7) to the relevant framework controls.

- Added `_crosswalk_mappings()` function — reads explicit `compliance_mappings`
  from the rule YAML when present; falls back to the cross-walk tables based on
  `cis_section` when those lists are empty.

- Updated `_upsert_rules()` to call `_crosswalk_mappings()` for every rule and
  include the returned rows in the batch INSERT to `tech_rule_control_mapping`.

**Result:** Running `python upload_tech_rule_metadata.py` now populates
`tech_rule_control_mapping` with CIS + NIST 800-53 + SOC2 + PCI-DSS entries
for every tech rule across all 8 sprints (database, linux, networking,
web_server, container, virtualization, devops, data, cloud_saas).

---

---

## 6. Issue #2 — Missing DB-Internal Catalog Checks (Permanent Fix)

### MySQL — Broken SQL in 3 Catalog Entries

**Problem:**
Three MySQL CIS check entries were emitting `run_command` with an empty command
instead of the correct SQL query. The generator couldn't extract valid variable
names from those CIS audit procedures because the procedure text used the CIS
option name (e.g., `allow-suspicious-udfs`) instead of the MySQL variable name
(`allow_suspicious_udfs`), causing it to fall back to OS-level classification.

**Fix is two-layered for permanence:**

Layer 1 — YAML files corrected directly (immediate fix):
- `mysql.section_4.allow_suspicious_udfs_is_set_to_off`: changed from `run_command`/empty to `query_setting` / `SHOW VARIABLES LIKE 'allow_suspicious_udfs';`
- `mysql.section_6.log_raw_is_set_to_off`: changed from `run_command`/empty to `query_setting` / `SHOW VARIABLES LIKE 'log_raw';`
- `mysql.section_3.secure_mysql_keyring`: changed from `run_command`/empty to `query_table` / `SELECT VARIABLE_NAME, VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME LIKE 'keyring%';`

Layer 2 — Generator override dict (permanent safety net):
Added `_KNOWN_CORRECT_QUERIES` dict to `render_discovery.py`. Checked in `_augment_rows()` before any pattern extraction runs. If a discovery ID appears in this dict, the correct query is used and `_is_os_level` is forced to `False`. This means even if someone runs `generate_tech_rules.py --apply` again, the YAML will be regenerated with the correct SQL — the CSV source data no longer matters for these 3 entries.

---

### PostgreSQL — 3 New Internal Checks (Permanent, Never Overwritten)

**Problem:**
Three PostgreSQL checks that query internal catalog tables (`pg_roles`, `pg_hba_file_rules`)
cannot be generated from the CIS CSV because the CSV does not contain those SELECT
statements. If added directly to `step6_section_*.yaml` they'd be erased on the next `--apply`.

**Solution — distinct file naming + executor + generator guard:**

- **New file** `catalog/discovery_generator_data/database/postgresql/step6_internal.discovery.yaml`:
  Contains 3 manually authored entries:
  - `postgresql.internal.anonymous_user_existence` — `SELECT rolname FROM pg_roles WHERE rolname = '';`
  - `postgresql.internal.pg_hba_auth_methods` — `SELECT type, database, user_name, address, auth_method FROM pg_hba_file_rules;` (self_hosted only)
  - `postgresql.internal.superuser_assignments` — `SELECT rolname FROM pg_roles WHERE rolsuper = true AND rolname NOT IN (...);`

- **Generator guard** in `generate_tech_rules.py` `_write_yaml()`:
  Skips writing if the target filename is `step6_internal.discovery.yaml` — prints `[SKIP]` instead. The generator's glob pattern (`step6_section_*`) already avoids the file by name convention, but the guard is a hard safety net.

- **Executor update** in `yaml_executor.py` `load()`:
  After building the section file list, appends `step6_internal.discovery.yaml` if it exists. This means the 3 new PostgreSQL checks are loaded and executed automatically during any PostgreSQL tech-discovery scan.

---

## 7. Azure DB Check Rules — Broken Wiring Fixed + Coverage Expanded

**Files:** `catalog/rule/azure_rule_check/{postgresql,mysql,mariadb}/*.checks.yaml`

**Problem — Two separate issues discovered:**

**Issue A — Broken `for_each` discovery IDs (all 16 rules affected):**
The check engine resolves `for_each` via exact match on `properties->>'discovery_id'` in
`inventory_findings`. Every Azure DB check rule was using an incorrect discovery ID that
never matches any inventory record, so all 16 rules permanently returned 0 findings.

| Rule set | Wrong `for_each` | Correct `for_each` |
|---|---|---|
| PostgreSQL flexible server (6 rules) | `azure.rdbms_postgresql.servers.list` (standard) | `azure.rdbms_postgresql_flexibleservers.servers.list` |
| PostgreSQL `geo_redundant_backup` | `azure.postgresql.servers.servers_list` (no match) | `azure.rdbms_postgresql.servers.list` |
| All 8 MySQL rules | `azure.mysql.servers.servers_list` (no match) | `azure.rdbms_mysql.servers.list_by_resource_group` / `azure.rdbms_mysql_flexibleservers.servers.list` |
| MariaDB | `azure.mariadb.servers.servers_list` (no match) | `azure.rdbms_mariadb.servers.list_by_resource_group` |

**Issue B — Wrong `var` field paths:**
Azure Python SDK emits fields in `snake_case` flat structure. Several rules used CamelCase
paths nested under `properties` (e.g. `item.properties.publicNetworkAccess`,
`item.Properties.Storage.StorageProfile.GeoRedundantBackup`) which never resolve.

**Fix applied:**
- All `for_each` IDs corrected to match actual discovery operation IDs
- All `var` paths corrected to snake_case emitted field names
- PostgreSQL flexible server rules now correctly target flexible server discovery;
  standard server rules target standard server discovery as separate rule set
- Configuration parameters (log_checkpoints, log_connections, etc.) access via
  `item.configuration.*` (inventory enrichment path)

**Coverage expanded — new rules added:**

| Service | Before | After | New rules |
|---|---|---|---|
| PostgreSQL Standard | 1 rule | 6 rules | ssl_enforcement, minimal_tls, public_network_access, infra_encryption, backup_retention |
| PostgreSQL Flexible | 6 rules | 10 rules | geo_redundant_backup, backup_retention, high_availability, storage_auto_grow |
| MySQL Standard | 4 rules | 8 rules | minimal_tls, public_network_access, infra_encryption, backup_retention |
| MySQL Flexible | 4 rules | 10 rules | public_network_access, geo_redundant_backup, backup_retention, high_availability, data_encryption, storage_auto_grow |
| MariaDB | 1 rule | 5 rules | ssl_enforcement, minimal_tls, public_network_access, backup_retention |
| **Total** | **16 rules** | **39 rules** | |

New rules cover NIST 800-53 (SC-8, SC-28, CP-9), SOC2 (CC6, A1), and PCI-DSS (6.3, 9.4)
controls that were previously unmapped for Azure DB resources.

---

## Files Changed Summary

| File | Type | Issue |
|---|---|---|
| `engines/technology-engine/tech-ciem/run_ciem.py` | Modified | CIEM collectors for Oracle/MSSQL/MongoDB/Cassandra |
| `catalog/rule/tech_templates/render_discovery.py` | Modified | Generator: OS-level check handling, Oracle dialect, applicable_to; `_KNOWN_CORRECT_QUERIES` override dict |
| `catalog/rule/tech_templates/discovery_sql.yaml.j2` | Modified | Template: applicable_to field |
| `catalog/rule/tech_templates/discovery_ssh.yaml.j2` | Modified | Template: applicable_to field |
| `engines/technology-engine/tech-discovery/executor/yaml_executor.py` | Modified | Deployment detection, applicable_to filter, dispatch bug fix; loads step6_internal.discovery.yaml |
| `engines/compliance/compliance_engine/storage/compliance_db_writer.py` | Modified | Remove compliance_scan_id, fix duplicate column |
| `engines/compliance/compliance_engine/exporter/db_exporter.py` | Modified | resource_arn → resource_uid in schema and variable |
| `engines/compliance/compliance_engine/loader/tech_db_loader.py` | **New** | Loader for tech_check_findings → compliance format |
| `engines/compliance/run_scan.py` | Modified | Merge tech findings before compliance report generation |
| `catalog/rule/upload_tech_rule_metadata.py` | Modified | Cross-walk for NIST/SOC2/PCI-DSS in tech_rule_control_mapping |
| `catalog/rule/generate_tech_rules.py` | Modified | Guard: never overwrite step6_internal.discovery.yaml |
| `catalog/discovery_generator_data/database/mysql/step6_section_3.discovery.yaml` | Modified | Fix secure_mysql_keyring: run_command → query_table with keyring% SQL |
| `catalog/discovery_generator_data/database/mysql/step6_section_4.discovery.yaml` | Modified | Fix allow_suspicious_udfs: run_command → query_setting with correct var name |
| `catalog/discovery_generator_data/database/mysql/step6_section_6.discovery.yaml` | Modified | Fix log_raw: run_command → query_setting with correct var name |
| `catalog/discovery_generator_data/database/postgresql/step6_internal.discovery.yaml` | **New** | PostgreSQL internal checks: anonymous user, pg_hba auth, superuser assignments |
| `shared/common/arn.py` | Modified | Added `host_to_resource_uid()` — converts RDS endpoint to canonical ARN matching cloud engine |
| `engines/technology-engine/tech-discovery/providers/db/scanner.py` | Modified | Use `host_to_resource_uid()` so tech findings share resource_uid with cloud findings |
| `catalog/rule/azure_rule_check/postgresql/postgresql.checks.yaml` | Modified | Fix all for_each IDs + var paths; split standard/flexible; add 9 new rules |
| `catalog/rule/azure_rule_check/mysql/mysql.checks.yaml` | Modified | Fix all for_each IDs + var paths; split standard/flexible; add 11 new rules |
| `catalog/rule/azure_rule_check/mariadb/mariadb.checks.yaml` | Modified | Fix for_each ID + var path; add 4 new rules |

---

*Prepared by: Ajay*
*Date: 2026-05-08*
