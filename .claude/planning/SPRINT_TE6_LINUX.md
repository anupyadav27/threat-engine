# Sprint: TE-6 — Linux SSH Scanner (Technology Engine Sprint 6)

**Goal:** Wire the five Linux distro scanners (Ubuntu, RHEL, Debian, SUSE, CentOS) to the real paramiko SSH transport, seed rule metadata to the tech DB, and ship parallel Track 0 post-DI carryover items (selected-tenant persistence, UserAccountAccess admin UI, MITRE tactics backfill) so the platform carries zero unresolved high-priority carryover debt into the next major sprint.

**Duration:** 10 working days (2 weeks, 2026-05-06 to 2026-05-16)

**Image tag prefix:** `v-te6-linux1`

---

## Stories Table

| ID | Title | Track | Days | Depends On | Priority |
|----|-------|-------|------|------------|----------|
| T0-01 | Selected-tenant persistence via Django session | Track 0 (Platform) | 1 | — | P0 |
| T0-02 | MITRE tactics backfill + threat engine writer fix | Track 0 (Threat) | 1 | — | P0 |
| T0-03 | UserAccountAccess admin UI — grant/revoke per-user account | Track 0 (UI) | 2 | T0-01 | P1 |
| T0-04 | Empty state browser audit (DI-16) — classify all no-data panels | Track 0 (QA) | 1 | — | P1 |
| TE6-01 | LinuxScanner — integrate SSHConnector for all 5 distros | Track 1 (Discovery) | 2 | — | P0 |
| TE6-02 | Ubuntu discovery: full section 1-7 SSH dispatch + output parsing | Track 1 (Discovery) | 1 | TE6-01 | P0 |
| TE6-03 | RHEL discovery: full section 1-7 SSH dispatch + output parsing | Track 1 (Discovery) | 1 | TE6-01 | P0 |
| TE6-04 | Debian discovery: full section 1-7 SSH dispatch + output parsing | Track 1 (Discovery) | 1 | TE6-01 | P0 |
| TE6-05 | SUSE + CentOS discovery: section 1-7 SSH dispatch + output parsing | Track 1 (Discovery) | 1 | TE6-01 | P1 |
| TE6-06 | Seed linux rule metadata for all 5 distros to tech DB | Track 2 (Rules) | 1 | — | P0 |
| TE6-07 | Seed linux CIEM rules to tech_ciem_findings pipeline | Track 2 (Rules) | 1 | TE6-06 | P1 |
| TE6-08 | tech-check engine: run_check.py dispatch for linux category | Track 3 (Check) | 1 | TE6-02, TE6-06 | P0 |
| TE6-09 | SSH credential onboarding: tech_credentials schema + onboarding API | Track 4 (Onboarding) | 1.5 | — | P0 |
| TE6-10 | E2E integration test: Ubuntu SSH scan → check finding PASS/FAIL | Track 5 (QA) | 1 | TE6-02, TE6-08 | P0 |
| TE6-11 | Docker image rebuild + deploy tech-discovery v-te6-linux1 | Track 6 (Deploy) | 0.5 | TE6-05, TE6-08 | P0 |

**Total:** 15.0 developer-days across 2 engineers in parallel.

---

## Dependency Graph

```
Track 0 (parallel, no dependencies on TE6):
  T0-01 (day 1) → T0-03 (days 2-3)
  T0-02 (day 1) [independent]
  T0-04 (day 1) [independent]

Track 1 — SSH Discovery (Python engineer):
  TE6-01 (days 1-2)
    ├── TE6-02 (day 3) — Ubuntu
    ├── TE6-03 (day 3) — RHEL          [parallel with TE6-02]
    ├── TE6-04 (day 4) — Debian
    └── TE6-05 (day 4) — SUSE + CentOS

Track 2 — Rule seeding (Security analyst, parallel with Track 1):
  TE6-06 (days 1-2) → TE6-07 (days 3-4)

Track 3 — Check engine dispatch:
  TE6-02 + TE6-06 → TE6-08 (day 5)

Track 4 — Credential onboarding (Backend):
  TE6-09 (days 2-3, independent)

Track 5 — Integration test (QA, days 6-7):
  TE6-02 + TE6-08 → TE6-10

Track 6 — Deploy (day 8):
  TE6-05 + TE6-08 → TE6-11
```

**Critical path:** TE6-01 → TE6-02 → TE6-08 → TE6-10 → TE6-11 (8 working days)

---

## Per-Story Technical Notes

### T0-01: Selected-tenant persistence via Django session
`switchTenant()` in `frontend/src/lib/api.js` writes only to `sessionStorage` — page refresh loses the selected tenant. Fix: POST to `PATCH /api/auth/active-tenant/` (new Django endpoint) on every `switchTenant()` call, persisting in `request.session['active_tenant_id']`. Auth middleware reads this on next request to build `AuthContext`. Files: `frontend/src/lib/api.js`, `platform/cspm-backend/users/views.py`, `platform/cspm-backend/users/middleware.py`.

### T0-02: MITRE tactics backfill + threat engine writer fix
Two parts: (A) run `scripts/backfill_mitre_tactics.py` via `kubectl exec` on the threat pod once enrichment hits 100%; (B) patch `engines/threat/threat_engine/storage/threat_db_writer.py` to hydrate `mitre_tactics`/`mitre_techniques` from rule metadata on every new finding INSERT, so future scans self-populate without a backfill. Current enrichment: 35.5% — verify completion before running part A.

### T0-03: UserAccountAccess admin UI
Settings page at `/settings/users/[userId]/accounts` listing all `cloud_accounts` for the tenant with grant/revoke toggles. Django backend: two endpoints on `UserAccountAccess` model (from DI-03 — model exists, no API yet). RBAC gate: `require_permission("tenants:write")`. Files: `frontend/src/app/settings/users/[userId]/accounts/page.jsx` (new), `platform/cspm-backend/users/views.py`, `platform/cspm-backend/users/urls.py`.

### T0-04: Empty state browser audit (DI-16)
Manual browser walkthrough of all 30+ UI panels from the DI-16 story. Classify each as A/B/C/D. Output committed as `.claude/planning/DI-16-empty-state-audit-results.md`. Class C/D findings fixed inline; Class B filed as backlog stories. QA task — no code files for this story itself.

### TE6-01: LinuxScanner — SSHConnector integration
Replace the stub `connect()` / `discover()` / `disconnect()` in `engines/technology-engine/tech-discovery/providers/linux/scanner.py` with real paramiko calls via the existing `SSHConnector` at `providers/linux/connectors/ssh_connector.py`. Key: `SSHConnector.run()` must gain a `run_command()` alias since `TechYAMLExecutor._exec_command()` calls `connector.run_command(command)`. Raise `AuthenticationError` on paramiko exceptions.

### TE6-02: Ubuntu discovery
Wire 296 Ubuntu discovery entries (`catalog/discovery_generator_data/linux/ubuntu/step6_section_*.yaml`) through the integrated `LinuxScanner`. Add `_parse_linux_audit_result(stdout)` helper that extracts `** PASS **` / `** FAIL **` from CIS benchmark script stdout. Set `status` and `severity` on the finding dict accordingly.

### TE6-03: RHEL discovery
Same approach as TE6-02 for 249 RHEL entries (`catalog/discovery_generator_data/linux/rhel/step6_section_*.yaml`). Scripts differ (dnf, firewalld) but the PASS/FAIL sentinel is identical. `tech_type = "rhel"`.

### TE6-04: Debian discovery
192 Debian entries — `catalog/discovery_generator_data/linux/debian/step6_section_*.yaml`. Confirm section files take precedence over the legacy root `step6_discovery.yaml` via glob logic in `yaml_executor.py` line 50.

### TE6-05: SUSE + CentOS discovery
SUSE: 260 entries across 7 section files. CentOS: 5 entries in legacy single YAML (low coverage; file a backlog ticket for expansion). Both use identical PASS/FAIL stdout format.

### TE6-06: Seed linux rule metadata
Run `catalog/rule/upload_tech_rule_metadata.py --category linux` via `kubectl exec` against the tech DB. Loads 2,401 rules (ubuntu:538, rhel:607, debian:311, suse:522, centos:423). Validate: `SELECT tech_type, COUNT(*) FROM tech_rule_metadata WHERE tech_category='linux' GROUP BY tech_type`.

### TE6-07: Seed linux CIEM rules
Seed from `catalog/rule/linux_rule_ciem/` for all 7 linux variants. Verify `TechDBManager.upsert_ciem_findings()` column set in `tech_db_manager.py` lines 299-333 matches schema before seeding.

### TE6-08: tech-check linux dispatch
`engines/technology-engine/tech-check/run_check.py` — add `linux` branch to the category dispatcher mirroring the existing `db` branch. Loads rules from `tech_rule_metadata WHERE tech_type IN ('ubuntu','rhel','debian','suse','centos')`, evaluates pass/fail against `tech_discovery_findings`, writes to `tech_check_findings`.

### TE6-09: SSH credential onboarding
Add `sudo_required BOOLEAN DEFAULT false` and `ssh_private_key TEXT` columns to `tech_credentials`. SSH keys stored in AWS Secrets Manager (ARN in `credential_ref`) — never plaintext in DB or logs. New credential type `ssh_key` and `ssh_password` accepted by `POST /api/v1/onboarding/tech-account`. Migration: `shared/database/migrations/YYYYMMDD_add_ssh_credential_columns.sql`.

### TE6-10: E2E Ubuntu integration test
`tests/integration/test_tech_linux_e2e.py` — starts a Docker container (Ubuntu 22.04 + SSH), calls `run_scan.py` for `tech_type=ubuntu`, asserts >= 50 `tech_discovery_findings` rows, calls `run_check.py` for same `scan_run_id`, asserts `tech_check_findings` has PASS/FAIL rows. Uses `docker-py`. Also runs `validate_tech_rules.py --category linux` (must exit 0).

### TE6-11: Build + deploy
Add `paramiko>=3.4` to `engines/technology-engine/tech-discovery/requirements.txt`. Build `yadavanup84/engine-tech-discovery:v-te6-linux1` and `yadavanup84/engine-tech-check:v-te6-linux1`. Update image tags in `deployment/aws/eks/engines/technology/tech-discovery.yaml` and `tech-check.yaml`. Apply manifests, rollout status, health check.

---

## Definition of Done

**Track 0 — Carryover:**
- `switchTenant()` POST persists to Django; page refresh retains selected tenant
- `SELECT COUNT(*) FROM threat_detections WHERE mitre_tactics != '[]'::jsonb` > 0 for `my-tenant`
- MITRE ATT&CK tab shows non-empty tactic grid after page reload
- Future threat scans populate `mitre_tactics` without a backfill
- `/settings/users/[userId]/accounts` renders, toggles persist to DB
- DI-16 audit table complete (30+ panels classified), Class C/D items resolved

**Track 1-3 — Linux discovery + check:**
- Ubuntu, RHEL, Debian, SUSE scans each return >= 50 `tech_discovery_findings` rows
- `tech_rule_metadata` has 2,401 linux rules (SQL count validated per distro)
- `tech_check_findings` contains PASS/FAIL rows for a linux `scan_run_id`
- `validate_tech_rules.py --category linux` exits 0

**Track 4 — SSH credentials:**
- `tech_credentials` has `sudo_required` + `ssh_private_key` columns
- Onboarding API accepts `credential_type=ssh_key` and stores ARN only
- SSH key never appears in engine logs (grep verified)

**Track 5-6 — Test + deploy:**
- `test_tech_linux_e2e.py` passes
- Both tech engine images live in `threat-engine-engines` with clean rollout
- No `latest` tags in any modified K8s manifest

---

## Sprint 7 Preview (Network Devices)

Natural successor: netmiko/napalm connectors for Cisco IOS/XE/ASA/NX-OS, Palo Alto PAN-OS, FortiGate. Discovery YAMLs for 8 network device types already generated (1,168 rules in `tech_validation_report_sprint5.json`). `NetworkScanner` stub at `providers/network/scanner.py` ready for same treatment as `LinuxScanner`. Blocked on: network device credentials available in AWS Secrets Manager — confirm before scheduling.

---

## Key Files

| Story | Primary Files |
|-------|--------------|
| T0-01 | `frontend/src/lib/api.js`, `platform/cspm-backend/users/views.py` |
| T0-02 | `scripts/backfill_mitre_tactics.py`, `engines/threat/threat_engine/storage/threat_db_writer.py` |
| T0-03 | `frontend/src/app/settings/users/[userId]/accounts/page.jsx` (new), `platform/cspm-backend/users/views.py` |
| T0-04 | `.claude/planning/DI-16-empty-state-audit-results.md` (new) |
| TE6-01 | `engines/technology-engine/tech-discovery/providers/linux/scanner.py`, `connectors/ssh_connector.py` |
| TE6-02-05 | `catalog/discovery_generator_data/linux/{ubuntu,rhel,debian,suse,centos}/` (YAMLs, read-only) |
| TE6-06-07 | `catalog/rule/upload_tech_rule_metadata.py` (run, not modified) |
| TE6-08 | `engines/technology-engine/tech-check/run_check.py` |
| TE6-09 | `shared/database/migrations/YYYYMMDD_add_ssh_credential_columns.sql` (new) |
| TE6-10 | `tests/integration/test_tech_linux_e2e.py` (new) |
| TE6-11 | `engines/technology-engine/tech-discovery/requirements.txt`, both K8s manifests |