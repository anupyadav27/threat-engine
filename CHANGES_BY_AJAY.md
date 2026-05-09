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

## 8. Compliance UI — Matrix, Remediation & Navigation Fixes

*Date: 2026-05-09*

### 8a. Multi-Cloud Compliance Matrix (BFF + Frontend)

**File:** `shared/api_gateway/bff/compliance.py` — new `view_compliance_matrix` endpoint
**File:** `frontend/src/app/compliance/matrix/page.jsx`
**File:** `frontend/src/lib/constants.js`

**Problem:**
The matrix page rendered 7 separate CIS rows (CIS_AWS, CIS_GCP, CIS_Azure, …) as individual
rows — a meaningless layout since rows and columns both represented cloud providers.

Clicking a matrix cell navigated to `/compliance` (frameworks list) with a filter,
forcing the user to click again to reach the actual detail page — a redundant two-step flow.

**Changes:**

- `constants.js` — collapsed 19 FRAMEWORKS entries into 12, with IDs aligned to BFF matrix keys
  (e.g. `CIS`, `NIST`, `PCI_DSS`, `SOC2`, `ISO27001`, `FedRAMP`, …)

- BFF `view_compliance_matrix` — new endpoint at `/compliance/matrix`:
  - Maps each `framework_id` from the engine to a matrix key + CSP column using
    `_classify_fw()`, `_CIS_PROVIDER`, `_REG_FW_KEY` helpers
  - CIS row: each CSP column shows its own CIS benchmark score (CIS AWS → aws column, etc.)
  - Regulatory rows: score applied to all active provider columns
  - Returns `{ matrix, frameworkIds }` — `frameworkIds[fw_key][provider]` holds the engine
    framework_id for direct navigation

- `matrix/page.jsx` — cell click now calls `router.push('/compliance/${engineId}')` directly,
  bypassing the intermediate frameworks list page entirely.

---

### 8b. Remediation Page — Empty State Fix + Column Layout

**File:** `shared/api_gateway/bff/compliance.py` — `view_compliance_remediation`
**File:** `frontend/src/app/compliance/remediation/page.jsx`

**Problem:**
Remediation page showed "No failing controls" even when 217 failing controls existed,
because `ui-data.failing_controls` was empty in the engine response.
Columns had unequal widths and long control IDs/titles overflowed.

**Changes:**

- BFF `view_compliance_remediation` — fallback path: when `failing_controls` is empty,
  picks the top 6 frameworks by `failed` count, calls their `/framework/{id}/assessment`
  endpoints in parallel, and extracts FAIL/PARTIAL controls from the families tree.

- `remediation/page.jsx` — fixed table layout:
  - `tableLayout: fixed` with explicit `<colgroup>` percentages (13/22/32/10/12/11%)
  - Control ID and Title columns: `-webkit-line-clamp: 2` with `title` attr for full text on hover

---

## 9. Compliance UI — Score Labelling, Tooltips & "Not Assessed" State

*Date: 2026-05-09*

### 9a. New Shared Tooltip Component

**File:** `frontend/src/components/shared/Tooltip.jsx` *(new)*

A reusable hover tooltip component for plain-English explanations visible to non-technical users.
- Dark floating card with arrow, appears above or below the wrapped element
- Controlled via `position` prop (`top` / `bottom`) and `maxWidth`
- Used across all compliance sub-pages

---

### 9b. Two Compliance Scores — Both Shown and Explained

**Context (Issue #1 deep-dive):**
Two endpoints compute scores with different formulas:
- `frameworks/summary` → **Assessed Score** (engine's stored value): `(PASS + 0.5×PARTIAL) / assessed_controls_only` — excludes N/A from denominator, gives partial credit
- `framework/{id}/assessment` → **Pass Rate** (strict): `PASS / all_controls` — includes N/A controls in denominator, no partial credit

For CIS AWS this produces 11.2% vs 6.4%. Both are valid but measure different things.
Showing only one without labelling is misleading.

**Fix — BFF `view_framework_detail`:**
**File:** `shared/api_gateway/bff/compliance.py`

Added a parallel call to `frameworks/summary` alongside the assessment call.
Matches the framework by ID to pull `assessed_score` (the engine's stored weighted score).
Returns `assessed_score` alongside the existing `score` (strict pass rate).
Zero added latency — both calls are concurrent via `fetch_many`.

**Fix — Framework detail page (standalone):**
**File:** `frontend/src/app/compliance/[framework]/page.jsx`

- Hero header now shows two scores side by side:
  - **Pass Rate** (large, color-coded) with ⓘ tooltip: *"out of every control in this framework … this is the number a compliance auditor would verify: X passing out of Y total controls"*
  - **Assessed Score** (smaller, blue) with ⓘ tooltip: *"of the controls we were able to test … partial credit is given for controls that are partly met"*
- `assessed_score` included in the `summary` object built from `d.assessed_score`

**Fix — Frameworks list + inline detail:**
**File:** `frontend/src/app/compliance/page.jsx`

- Top score strip renamed from "Compliance Score" to **"Overall Pass Rate"** with tooltip
- When a framework is selected (inline detail), strip shows **"Pass Rate" + "Assessed Score"** cards side by side
- `ScoreCard` component updated to accept optional `tooltip` prop — renders label with dotted underline and ⓘ icon
- Score column header: "SCORE ⓘ" with hover tooltip explaining partial credit and resource exclusion
- Findings column header: "FINDINGS ⓘ" with hover tooltip

**Fix — Matrix legend:**
**File:** `frontend/src/app/compliance/matrix/page.jsx`

- Added *"What do these scores mean? ⓘ"* link in the legend row
- Tooltip explains the Assessed Score formula and that clicking a cell opens the full control breakdown

---

### 9c. "Not Assessed" State — Distinguish No-Data from Passing

**File:** `frontend/src/app/compliance/page.jsx`

**Problem:**
Frameworks with 0 passed AND 0 failed (e.g. CIS OCI with 1977 controls, score 0%, findings 0)
showed identically to frameworks that were scanned and fully passing. Users interpreted
"0 findings" as "everything is fine" — it actually means "nothing was ever checked."

**Fix:**
- Added `hasAssessment = passed > 0 || failed > 0` flag per framework row
- Score cell: when `!hasAssessment` → dashed gray pill **"Not assessed"** replaces the 0% ring
  - Hover tooltip: *"Not assessed — no scan has run for this provider yet, or no cloud resources were found that this framework applies to. Run a scan for this cloud provider to populate results."*
- Findings cell: shows `—` instead of `0` for unassessed frameworks
- Controls cell: shows "no data" instead of green/red dot counters
- Shield icon: gray for unassessed, accent for assessed
- `totals` computation: **excludes unassessed frameworks** so the Overall Pass Rate is not
  dragged down by frameworks that have never been evaluated
- Overall Pass Rate sublabel now reads *"N of 37 frameworks assessed"* so users immediately
  see how many frameworks are excluded

---

## Files Changed Summary (additions from sessions 8–9)

| File | Type | Change |
|---|---|---|
| `shared/api_gateway/bff/compliance.py` | Modified | New matrix endpoint; remediation fallback; assessed_score in framework detail |
| `frontend/src/lib/constants.js` | Modified | Collapse FRAMEWORKS from 19 → 12; align IDs to matrix keys |
| `frontend/src/app/compliance/matrix/page.jsx` | Modified | Direct cell navigation; frameworkIds state; legend tooltip |
| `frontend/src/app/compliance/remediation/page.jsx` | Modified | Fixed column widths; 2-line clamp with title tooltip |
| `frontend/src/app/compliance/page.jsx` | Modified | Tooltip imports; ScoreCard tooltip; Pass Rate + Assessed Score strip; Not Assessed state; Overall Pass Rate excludes unassessed frameworks |
| `frontend/src/app/compliance/[framework]/page.jsx` | Modified | Pass Rate + Assessed Score hero; Tooltip imports; assessed_score in summary |
| `frontend/src/components/shared/Tooltip.jsx` | **New** | Reusable hover tooltip component |

---

## 10. Compliance UI — Global Filter Wiring

*Date: 2026-05-09*

**Problem:**
The Provider / Account / Region / Time Range filters in the top navigation bar were not
connected to two of the three compliance sub-pages. Only the remediation page (which uses
the `useViewFetch` hook) correctly re-fetched data when the filter changed. The frameworks
list and the matrix displayed stale data — always the full cross-provider view — regardless
of what the user selected in the global filter.

**Audit result (per page):**

| Page | Filter wired before fix |
|---|---|
| `/compliance` (frameworks list) | No — used raw `fetchView()` with no filter params |
| `/compliance/matrix` | No — `useEffect` dependency was `[view]` only |
| `/compliance/[framework]` (detail) | Yes — via `useViewFetch` |
| `/compliance/remediation` | Yes — via `useViewFetch` |

**Fix — Frameworks list (`frontend/src/app/compliance/page.jsx`):**

- Added `useGlobalFilter` import; destructured `gProvider`, `gAccount`, `gRegion`
- `useEffect` now depends on `[gProvider, gAccount, gRegion]` in addition to existing deps
- On scope change: passes `{ provider: gProvider, account: gAccount, region: gRegion }`
  as query params to `fetchView('compliance/frameworks')` and calls `setSelectedFw(null)`
  to clear any open inline detail panel that would now be out of scope
- Client-side provider filter: rows for CSP-specific frameworks (e.g. CIS_AWS, CIS_GCP)
  are hidden when `gProvider` is set to a different provider; multi-provider frameworks
  (NIST, SOC2, ISO 27001, etc.) always remain visible
- `totals` useMemo: respects `gProvider` filter when computing the Overall Pass Rate and
  "N of M frameworks assessed" sublabel — e.g. "9 of 12 frameworks assessed · AWS" when
  provider is selected, so the aggregate number matches the visible rows

**Fix — Matrix (`frontend/src/app/compliance/matrix/page.jsx`):**

- Added `useGlobalFilter` import; destructured `provider` as `gProvider`, `account` as `gAccount`
- `useEffect` dependency array changed from `[view]` to `[view, gProvider, gAccount]`
- Passes `provider` and `account` as query params to `fetchView('compliance/matrix', params)`
  when those filters are set — the BFF `view_compliance_matrix` handler already accepted
  and forwarded these params to the compliance engine

**Result:**
All four compliance sub-pages now respond correctly to the global Provider / Account / Region
filter. Switching provider instantly re-fetches and re-renders the relevant frameworks and
scores for that provider's scan data, with the aggregates and table rows updating in step.

---

## 11. Compliance UI — Remediation Queue: Full Data + Pagination

*Date: 2026-05-09*

### Problem

The remediation page was silently truncating results at 100 controls with no indication that
more existed. Three separate bugs caused this:

1. **Hard `limit=100` cap** — `failing_controls = failing_controls[:limit]` ran before
   `bySeverity` and `totalFailing` were computed, so the severity chips (e.g. "17 HIGH")
   and the header count ("100 failing controls") both reflected only the truncated set,
   not the real totals (217 controls in the live environment).

2. **Fallback read only top 6 frameworks** — When `ui-data` returned no `failing_controls`
   (the normal case for this deployment), the BFF fell back to reading framework assessments.
   But it capped at the 6 highest-failure frameworks via `[:6]`. Controls from the remaining
   failing frameworks were never returned at all.

3. **No pagination** — The UI just stopped at 100 rows with the toolbar showing "100 results",
   which users read as "there are only 100 failing controls".

### Fix — BFF (`shared/api_gateway/bff/compliance.py`)

- Removed `[:6]` cap on fallback framework list — all failing frameworks are now read,
  regardless of how many there are.
- Moved `bySeverity` and `totalFailing` computation to **after sorting but before the limit**
  so both always reflect the real dataset.
- Raised default `limit` from `100` to `1000` (a safety net, not a UX cap — realistic
  data volumes are well under this). `limit=0` is treated as unlimited by `if limit > 0:`.

### Fix — Frontend (`frontend/src/app/compliance/remediation/page.jsx`)

- Added `PAGE_SIZE = 25` constant and `currentPage` state.
- Renamed `displayed` → `filtered` (the full filtered dataset across all loaded controls).
- `displayed` is now `filtered.slice(pageStart, pageEnd)` — just the current page.
- `useEffect` resets `currentPage` to 1 when `severityFilter` or `searchTerm` changes,
  so filter interactions never leave the user stranded on an empty page.
- Toolbar count now shows: *"87 matching · 217 total"* when a filter is active,
  or *"217 controls"* when showing all.
- Added pagination footer (only renders when `totalPages > 1`):
  - **"Showing 26–50 of 217"** — exact range, updates on every page turn
  - **Previous / Page N of M / Next** — disabled and de-emphasised at the boundary pages
  - Previous/Next are `ChevronLeft` / `ChevronRight` icons from lucide-react

### User experience after fix

| Before | After |
|---|---|
| 100 rows, no indication more exist | All controls loaded; 25 per page |
| Severity chips show counts for 100-row slice | Chips always show real totals from engine |
| Header: "100 failing controls" | Header: "217 failing controls" (real count) |
| Controls from 7+ frameworks invisible (fallback cap) | All failing frameworks read |
| Search/filter only spans 100 loaded rows | Search/filter spans all loaded controls |

---

## Files Changed Summary (additions from session 10)

| File | Type | Change |
|---|---|---|
| `frontend/src/app/compliance/page.jsx` | Modified | Wire gProvider/gAccount/gRegion into fetch; client-side provider row filter; totals respects filter; clear selected fw on scope change |
| `frontend/src/app/compliance/matrix/page.jsx` | Modified | Wire gProvider/gAccount into fetch; useEffect dependency updated |

## Files Changed Summary (additions from session 11)

| File | Type | Change |
|---|---|---|
| `shared/api_gateway/bff/compliance.py` | Modified | Remediation: remove [:6] fallback cap; move bySeverity/totalFailing before limit; raise limit default to 1000 |
| `frontend/src/app/compliance/remediation/page.jsx` | Modified | Client-side pagination (PAGE_SIZE=25); filtered vs displayed split; reset page on filter change; pagination footer with Showing X–Y of Z |

---

## 12. Compliance UI — Table Column Alignment Fix (All 4 Tables)

*Date: 2026-05-09*

**Problem:**
All four compliance table views lacked `tableLayout: fixed` + `<colgroup>` width definitions.
Without these, browsers auto-size columns based on content — meaning long NIST control IDs
like `nist_800_53_rev5_multi_cloud_AC-16-b_0135` drove the Control ID column to 40%+ of
the table width, crushing the Control name column which should be the widest column.
Additionally, no text cells had overflow protection, so long content spilled into adjacent
cells or stretched row heights arbitrarily.

**Tables fixed:**

### `frontend/src/app/compliance/[framework]/page.jsx` — Controls Detail table

Added `tableLayout: 'fixed'` and `<colgroup>`:

| Column | Width | Before |
|---|---|---|
| Expand toggle | 36px fixed | `w-8` (Tailwind, no effect without fixed layout) |
| Control ID | 18% | auto-sized to content |
| Control name | 36% | auto-sized to content |
| Domain | 20% | auto-sized to content |
| Severity | 10% | auto-sized |
| Status | 8% | auto-sized |
| Resources | 8% | auto-sized |

Cell overflow fixes in `ControlRow`:
- **Control ID** `<code>`: `display: -webkit-box; WebkitLineClamp: 2; overflow: hidden; wordBreak: break-all` + `title` for hover
- **Control name** `<span>`: same line-clamp pattern + `title` for hover
- **Domain** `<span>`: `overflow: hidden; text-overflow: ellipsis; white-space: nowrap` + `title`; icon wrapped in a `flexShrink: 0` span so it never gets squeezed out

### `frontend/src/app/compliance/page.jsx` — Frameworks list table

Added `tableLayout: 'fixed'` and `<colgroup>`:

| Column | Width |
|---|---|
| Framework name | 38% |
| Provider | 10% |
| Score | 16% |
| Controls | 18% |
| Findings | 11% |
| → (chevron) | 7% |

Framework name cell: added `overflow: hidden; text-overflow: ellipsis; white-space: nowrap` + `title` so long names like "AWS Foundational Security Best Practices v1.0.0" never push the Provider column off-screen.

### `frontend/src/app/compliance/page.jsx` — Inline accordion controls table

Added `tableLayout: 'fixed'` and `<colgroup>`:

| Column | Width |
|---|---|
| Status icon | 6% |
| Control ID (tail) | 18% |
| Control name | 43% |
| Severity | 12% |
| Findings | 10% |
| Resources | 11% |

Removed the hardcoded `width: 50`, `width: 180`, `width: 90`, `width: 80` on individual `<td>` elements (replaced by colgroup). Added 2-line clamp + `title` to the Control name cell. Added `overflow: hidden` to every `<td>`.

### `frontend/src/app/compliance/remediation/page.jsx` — Remediation Queue table

Already had `tableLayout: fixed` and `<colgroup>` from a previous session. No changes needed.

---

## Files Changed Summary (additions from session 12)

| File | Type | Change |
|---|---|---|
| `frontend/src/app/compliance/[framework]/page.jsx` | Modified | tableLayout + colgroup; Control ID/name 2-line clamp + title; Domain ellipsis |
| `frontend/src/app/compliance/page.jsx` | Modified | Frameworks table: tableLayout + colgroup + Framework name ellipsis; Accordion table: tableLayout + colgroup + Control name 2-line clamp |

---

## 13. Compliance UI — Provider Filter Fallback (All Pages)

**Files:**
- `frontend/src/lib/global-filter-context.jsx`

**Problem:**
The "All Providers" dropdown in the GlobalFilterBar was empty when the
onboarding engine was unreachable (local dev, CI, or during fixture testing).
`providerOptions` is derived from real cloud accounts fetched from the
onboarding API at mount — if that fetch fails, the accounts list stays `[]`
and no provider options appear, making the compliance provider filter
non-functional.

**Changes made:**

- Added `STATIC_PROVIDER_OPTIONS` constant: a fixed ordered list of the 6
  supported providers (AWS, GCP, Azure, OCI, AliCloud, IBM) built from the
  existing `CLOUD_PROVIDERS` constant.

- Updated `providerOptions` memo: when `accounts.length === 0` (onboarding
  API unavailable) use the static list as fallback. When real accounts exist,
  the live-account-derived list is used exactly as before — no behaviour
  change in production.

**Result:**
Selecting GCP in the Provider dropdown now correctly hides AWS/Azure/OCI CIS
rows and keeps multi-provider framework rows (NIST, SOC 2, PCI-DSS, ISO, GDPR)
visible. Selecting AWS hides GCP/Azure/OCI CIS rows. Clearing restores all 10.

---

## 14. Compliance BFF — Remediation Severity + Total Count Fix

**File:** `shared/api_gateway/bff/compliance.py`

**Problem (3 separate bugs):**

1. `bySeverity` counts were computed *after* the `[:limit]` slice, so severity
   chips showed counts for the truncated page only, not the full dataset.

2. `totalFailing` was also computed after the slice — UI showed e.g. "100 controls"
   even when 217 were failing.

3. The fallback framework fetch used `[:6]` — only the first 6 frameworks were
   ever included in the remediation list.

4. Default `limit` was 100, capping the dataset sent to the client.

**Changes made:**

- Moved `total_failing` and `bySeverity` computation to before the `[:limit]`
  slice so both always reflect the full failing dataset.

- Removed the `[:6]` cap on the fallback framework loop.

- Raised default `limit` from 100 to 1000 so all controls reach the client
  for client-side pagination.

**Result:**
Remediation page correctly shows 217 failing controls with CRITICAL=12,
HIGH=45, MEDIUM=95, LOW=65. Severity chips count the full dataset regardless
of pagination state.

---

## Files Changed Summary (additions from sessions 13–14)

| File | Type | Change |
|---|---|---|
| `frontend/src/lib/global-filter-context.jsx` | Modified | Static provider fallback when onboarding engine unreachable |
| `shared/api_gateway/bff/compliance.py` | Modified | Remediation: bySeverity+totalFailing before limit; removed [:6] cap; limit 1000 |

---

*Prepared by: Ajay*
*Date: 2026-05-09*
