# JNY-01 Handoff — bmad-security-architect (CONSULTED, design gate CP-1)

**To:** cspm-db-engineer (R), threat-engine (R), bmad-dev (R), cspm-standards-guardian (A)
**From:** bmad-security-architect
**Re:** STRIDE design review of `mitre_technique_reference` table, BFF endpoint, threat_findings ALTER, and seed loader
**Frameworks applied:** STRIDE, MITRE ATT&CK for Cloud, D3FEND, NIST CSF 2.0 (Detect/Protect), OWASP SAMM Design

---

## 1. Verdict

**APPROVE WITH CHANGES** — directionally sound (DB-first, tenant-agnostic global ref correctly justified, bundled snapshot avoids supply-chain on cold start). Four required-pre-merge controls below must land before merge: seed integrity verification, audit row, BFF tenant-scoped query, and DoS guardrails on `affected_count`. Threat-engine specialist's schema additions (CHECK regex, `revoked`, parent self-FK, generated column) materially reduce the threat surface and I endorse them.

---

## 2. STRIDE Table

| # | STRIDE | Threat | Severity | Mitigation | Status |
|---|--------|--------|----------|------------|--------|
| 1 | **Spoofing** | Non-admin in Tenant-A queries `/views/threats/technique/T1530` and learns Tenant-B posture if `affected_count` is computed without tenant filter; or technique presence/absence enumeration leaks cluster-wide deployment. | High | (a) BFF MUST derive `tenant_id` from `AuthContext` (DI-02 helpers) — never accept it as query/path param. (b) `affected_count` SQL filter MUST include `tenant_id = :auth_tenant`. (c) Reference body (name/description/mitigations) is public MITRE — no tenant gating needed. (d) Return `affected_count = 0` for techniques with no findings in this tenant — do **not** 404 (404 leaks "technique exists but not yours" vs "unknown"; 0 is uniform). | required-pre-merge |
| 2 | **Tampering** | Compromised seed loader pod or malicious PR to bundled CSV/STIX injects falsified `mitigations`/`description` — operators read modal and apply attacker-chosen "remediation" (e.g., disable a control). Global ref → blast radius is every tenant. | **Critical** | (a) Bundled STIX file MUST have a SHA-256 manifest committed alongside (`enterprise-attack-v15.1.json.sha256`) and verified by the loader before INSERT. Fail-closed on mismatch. (b) Loader image is the same threat-engine image already in CI (no separate creds path). (c) Schema CHECK regex on `technique_id` (specialist §2) prevents pseudo-techniques like `T9999_PWN`. (d) DB role running loader has `SELECT, INSERT, UPDATE` on this table only — no GRANT to other engines' roles, no DDL. (e) Seed file checked into git, reviewed via PR (4-eyes); discourage out-of-band updates. | required-pre-merge |
| 3 | **Repudiation** | Operator cannot answer "which MITRE version was active when finding X was triaged?" or "who pushed the bad mitigation row?" Monthly cron silently overwrites. | Medium | (a) Add audit row per loader run: `(run_id, attack_version, source_sha256, rows_inserted, rows_updated, rows_skipped, started_at, finished_at, actor)` written before commit. Re-use `threat_analysis` (specialist suggested) iff schema accepts the source-hash field; else new `mitre_seed_audit`. (b) `mitre_technique_reference.version` + `last_modified` already capture per-row provenance — keep mandatory. (c) Cron actor = pod service account; capture in audit row. | required-pre-merge |
| 4 | **Information disclosure** | (a) `description`/`detection`/`mitigations` are global MITRE — non-sensitive. (b) BFF response shape might inadvertently leak internal fields. (c) Malformed `technique_id` errors could leak SQLSTATE/stack. (d) `affected_count` cached at edge could leak across tenants. | Medium | (a) BFF uses typed Pydantic response (DI-09) — whitelist columns, never `SELECT *`. (b) Exception handler returns `{"error":"invalid_technique_id"}` — no SQLSTATE. (c) `Cache-Control: private, no-store` on this endpoint. (d) Log redaction: technique_id at INFO; tenant_id at DEBUG only. | recommended |
| 5 | **DoS** | (a) GIN indexes on `tactic_ids`/`platforms`/`data_sources` JSONB — pathological (1 MB) writes bloat the index; risk lower because writes are seed-only but cron diff could be abused if upstream STIX is poisoned. (b) `affected_count` fan-out across multi-million-row `threat_findings` exhausts pool under load. (c) Recursive parent-rollup CTE if specialist's generated column is dropped. | High | (a) Cap each JSONB column: `CHECK (octet_length(col::text) < 65536)`. (b) `affected_count` MUST use new partial index `idx_threat_findings_tenant_parent_technique` — verify via EXPLAIN in CI. (c) Gateway rate-limit: 60 req/min/tenant for `/views/threats/technique/*`. (d) `SET LOCAL statement_timeout = '2s'` on the BFF connection. (e) Use generated column `mitre_parent_technique` — never `LIKE 'T1078%'` (unindexable, also matches `T10780`). | required-pre-merge |
| 6 | **Elevation of privilege** | (a) `technique_id` path param flows to SQL — without BFF validation, classic injection (`T1530'; DROP...`). (b) Schema CHECK regex protects writes, not reads. (c) Loader with elevated DB role coerced via tampered STIX → arbitrary DDL if any string-formatted SQL exists. | High | (a) BFF validates path param against `^T[0-9]{4}(\.[0-9]{3,4})?$` **before** any DB call; reject 400 otherwise. (b) Parameterized queries only (psycopg2 `%s` / asyncpg `$1`); confirmed by code-reviewer at merge. (c) Loader uses parameterized `executemany` — never f-string SQL. (d) Loader DB role: `SELECT, INSERT, UPDATE` on `mitre_technique_reference` only — no `CREATE/DROP/ALTER`. (e) The `threat_findings` ALTER (generated column + indexes) is one-shot DDL via Alembic with the migration role, not the runtime engine role. | recommended |

---

## 3. ATT&CK + D3FEND Mapping

**ATT&CK techniques this defense disrupts (when modal works):**
- **T1530 — Data from Cloud Storage Object**: modal surfaces detection guidance + impacted resources; JNY-01 unblocks today's broken lookup.
- **T1078 / T1078.004 — Valid Accounts (Cloud)**: parent+sub rollup (specialist §4) ensures rules emitting at parent (R-IAM-014) and sub (R-IAM-022) granularity converge on one investigation pane.
- **T1190 — Exploit Public-Facing Application**: kill-chain ordering via `kill_chain_phases` (specialist §2) preserves attack-path linkage initial-access → lateral-movement.
- **T1098 — Account Manipulation**: same parent-rollup logic.

**ATT&CK techniques targeting THIS feature (must defend):**
- **T1565.001 — Stored Data Manipulation** (against `mitre_technique_reference`): Mitigation #2 (SHA-256 verify + 4-eyes PR) is the primary control.
- **T1499 — Endpoint DoS**: Mitigation #5 (rate-limit + statement_timeout) addresses.
- **T1190** against the BFF: Mitigation #6 (regex + parameterized queries) addresses.

**D3FEND countermeasures invoked:**
- **D3-FH (File Hashing)** — SHA-256 manifest on bundled STIX [#2a].
- **D3-AM (Application Manifest)** — controlled seed via PR + audit log [#2e, #3].
- **D3-PA (Process Analysis)** — audit row per loader run [#3].
- **D3-IAA (Identifier Activity Analysis)** — BFF regex on `technique_id` [#6a].
- **D3-RAC (Resource Access Control)** — least-priv loader DB role [#6d].
- **D3-NTA (Network Traffic Analysis)** — gateway rate limit [#5c].

**NIST CSF 2.0:** PR.AA-05 (least privilege loader role), PR.DS-01 (seed data integrity), DE.AE-02 (audit log of loader runs), DE.CM-09 (BFF input validation).

---

## 4. Required Pre-Merge Controls (4)

1. **Seed integrity** — SHA-256 manifest committed with bundled STIX; loader verifies and fails closed on mismatch; seed file changes go through PR review (no out-of-band updates).
2. **Tenant isolation in BFF** — `tenant_id` derived from `AuthContext` only (DI-02); `affected_count` query filters on it; uniform `affected_count = 0` for absent — never 404.
3. **Seed audit row** — every loader/cron run writes `{run_id, attack_version, source_sha256, rows_inserted/updated/skipped, started_at, finished_at, actor}` before commit.
4. **DoS guardrails** — (a) JSONB `octet_length` CHECK (≤64 KiB each); (b) `statement_timeout=2s` on the BFF endpoint connection; (c) gateway rate-limit 60 req/min/tenant; (d) the partial index `idx_threat_findings_tenant_parent_technique` MUST exist before the BFF endpoint ships.

**Recommended (not blocking):**
- Typed Pydantic response (DI-09) + `Cache-Control: private, no-store`.
- Loader DB role hardened to `SELECT, INSERT, UPDATE` on the one table.
- BFF regex validation on `technique_id` mirroring the schema CHECK.

---

## 5. Open Questions for cspm-db-engineer (R)

1. **Audit table** — re-use `threat_analysis` per specialist's suggestion, or new `mitre_seed_audit`? Required field: `source_sha256`.
2. **Role separation** — can Alembic DDL run under a distinct migration role while the runtime loader runs DML-only? If the deployment uses one role for both today, flag as a separate hardening ticket (acceptable residual for JNY-01).
3. **JSONB size cap** — confirm no MITRE v15.1 row exceeds 64 KiB on `description`/`mitigations`. If any does, raise the cap rather than truncate (never truncate `mitigations`).
4. **Statement-timeout enforcement** — is `SET LOCAL statement_timeout` applied per-request in the existing BFF DB session helper, or do we need a wrapper? Required for control #4b.
5. **Revoked-technique semantics** — keep revoked rows but exclude from dropdowns; revoked techniques still count in `affected_count` if findings reference them (historical accuracy > UI cleanliness). Confirm acceptable.
6. **Response field naming** — `affected_count_exact` vs `affected_count_rollup` to prevent operator misinterpretation; confirm in BFF response schema.

---

**Bottom line:** design is sound; tenant-agnostic global ref correctly justified; specialist's additions close most obvious holes. The four pre-merge controls are non-negotiable because the table is global and a single tampered row blasts every tenant. **CP-1 design gate: PASS conditional on the four controls landing in the migration/BFF PRs.**
