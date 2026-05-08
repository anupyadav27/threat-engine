# Sprint Story Files

Story files are the atomic handoff unit between planning and dev.
**One story = one PR = one deployable unit.**

Pass story files to `bmad-dev` to implement. Pass sprint prompt files to `bmad-security-po` to generate new stories.

---

## Active Sprints

| Sprint | Story Files | Status |
|--------|-------------|--------|
| Investigation Journey Unification (JNY-01–12) | [JNY-01](JNY-01_mitre-technique-reference-schema.md) · [JNY-02](JNY-02_inventory-blast-radius-bff-fix.md) · [JNY-03](JNY-03_ciem-sensitive-permission-grant.md) · [JNY-04](JNY-04_sprint-images-rollout.md) · [JNY-05](JNY-05_universal-finding-route.md) · [JNY-06](JNY-06_universal-finding-bff.md) · [JNY-07](JNY-07_pivot-link-primitive.md) · [JNY-08](JNY-08_pivot-link-rollout-7-engines.md) · [JNY-09](JNY-09_threat-ui-bug-fixes.md) · [JNY-10](JNY-10_ciem-stage2-actor-principal-fix.md) · [JNY-11](JNY-11_shared-engine-shell-primitives.md) · [JNY-12](JNY-12_risk-vuln-detail-routes.md) | Draft — see [SPRINT-INVESTIGATION-JOURNEY-UNIFICATION.md](../SPRINT-INVESTIGATION-JOURNEY-UNIFICATION.md) and [ADR](../../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md) |

## Completed Sprints

| Sprint | Completed | Outcome |
|--------|-----------|---------|
| TEC-901 — Tech Scan Agent | 2026-05-01 | Host-based agent (SQL/SSH/Docker/PowerShell transports); `yadavanup84/tech-scan-agent:v1` pushed; tech-check v4 deployed with catalog + findings endpoints; 5,025 rules uploaded to DB |
| TEC Sprint 9 — Engine Wire-up | 2026-05-01 | YAML executor multi-section glob load; `query`/`sql` key compat; `run_command` action; metadata uploader dry-run 5,025 rules across 34 files |
| TEC Sprint 8 — Cloud SaaS | 2026-05-01 | 423 rules (microsoft_365/google_workspace/sharepoint/dynamics_365); REST API transport; all-manual techs produce metadata stubs only |
| TEC Sprint 7 — Container/Virt/DevOps/Data | 2026-05-01 | 755 rules (docker/vmware_esxi/gitlab/snowflake); Docker API + REST transports |
| TEC Sprint 6 — Web Server | 2026-05-01 | 979 rules (apache_http/nginx/iis/tomcat/websphere); IIS PowerShell transport; legacy sample files deleted |
| TEC Sprint 5 — Networking | 2026-05-01 | 1,168 rules (cisco_ios_xe/palo_alto/cisco_asa/check_point/cisco_ios_xr/cisco_nxos/fortigate/cisco_firewall); cisco_firewall all-manual |
| TEC Sprint 4 — Linux remaining | 2026-05-01 | 1,623 rules (suse/centos); centos all-manual (EOL); legacy files deleted |
| TEC Sprint 3 — Linux primary | 2026-05-01 | 3,386 rules (ubuntu/debian/rhel); tojson fix in discovery_ssh.yaml.j2 for embedded bash script safety |
| TEC Sprint 2 — Database remaining | 2026-05-01 | 739 rules (ibm_db2/sql_server/mariadb/mongodb/cassandra); YAML `%` quoting fix in discovery_sql.yaml.j2 |
| TEC Sprint 1 — Database primary | 2026-05-01 | 748 rules (postgresql/mysql/oracle_db); MySQL SHOW VARIABLES + Oracle V$/DBA_ view fixes |
| TEC Sprint 0 — Generator Framework (TEC-001–008) | 2026-04-30 | CSV parser, 7 transport templates, check/CIEM/metadata renderers, slug deduplicator, YAML validator; PostgreSQL integration tested |
| CSPSCAN Validation (cspscan-00 → 16) | 2026-04-30 | All 6 CSPs scanned end-to-end; findings validated across check/threat/iam/network/compliance; Engine Quality Gaps sprint spun off |
| Enterprise Engine Platform Hardening (ENG-10–15) | 2026-05-01 | DataSec 8-module DSPM, DBSec 5-pillar, Container-Sec CIS K8s 7-layer, Risk FAIR+Neo4j blast radius, AI-Security MITRE ATLAS 5-pillar, CNAPP graceful degradation fix — all deployed |
| Engine Quality Gaps (ENG-16/17/18/19) | 2026-04-30 | K8s check 18,948 findings; OCI IAM 7 findings; AliCloud network 7 findings (1/layer); check_findings.finding_id schema standardized across 4 engines |
| RBAC Sprint — Role-Based Access Control Enforcement (RBAC-01–08) | 2026-05-01 | Django migrations 0008+0009 applied; 5 roles + 27 permissions seeded; require_permission() wired across all 18 engines with -rbac1 tags; BFF X-Auth-Context forwarding + cache key role isolation; frontend API-driven permissions; DEV_BYPASS_AUTH removed |
| Billing & Subscription Sprint (BILL-01–08) | 2026-05-02 | Billing DB + seed data; billing engine (Stripe Checkout); gateway subscription enforcement; Django permission extensions; platform-admin engine; billing portal frontend; grandfathering + trial hardening — `v-billing-3`, `v-padmin-2`, `v-backend-billing2` |
| UIUX Sprint 1 — Billing + Admin Dashboard (UIUX-01–05) | 2026-05-02 | Billing two-column layout + RadioTierCard + UsageMeter intelligence (75%/90% thresholds, upgrade hints); Admin engine grouping by pipeline stage + clickable MetricCard filters + ActionPopover (focus trap, 3s auto-dismiss) + 30s auto-refresh — deployed as `yadavanup84/cspm-frontend:v-uiux-sprint2` |
| Backend API Fixes (BE-01–03) | 2026-05-02 | PATCH /api/auth/me/ (name update); POST /api/auth/change-password/ (session invalidation); GET /api/users/?tenant_id= (admin-scoped listing); LogoutView cookie-clear bug fixed — `v-backend-be123` |
| Threat UI Sprint (THREAT-UI-01–04) | 2026-05-02 | Command Room scenario list + signal badges + KPI header; Scenario Detail Panel 4-chapter right drawer; Trends & Posture Delta 90-day chart; Threat Narrative Engine LLM Step 7 + chain_of_consequence in DB — `v-threat-ui-fix1`, `v-narrative-1` |
| Auth / SSO Sprint (AUTH-01–13) | 2026-05-03 | TenantIDPConfig model, OIDC/SAML/Google flows, IDP REST API, break-glass auth, Google-first login page, invite SSO, onboarding wizard (6-step), Okta migration command, audit log, workspace switcher customer_id fix — `v-auth-sprint1` + `v-auth-wizard1` |
| UI / BFF Wiring Sprint (UI-01–11b) | 2026-05-03 | useViewFetch hook, Next.js auth middleware, AI-security CSP param fix, vulnerability BFF handler, compliance remediation page, MOCK_TENANTS removed from dashboard, psycopg2 removed from BFF scans, profile + users pages wired to real APIs — `v-ui-sprint1` (frontend + gateway) |
| CSPM Agent Framework Sprint | 2026-05-03 | 27 full-context CSPM agent files (`.claude/agents/`) + 11 CSPM command skills (`.claude/commands/`) — complete coverage of all 25 engines, 3 governance docs (CSPM_CONSTITUTION, AGENT_BINDING, TESTING_QUALITY). All frontmatter validated, every engine has dedicated agent with DB schema, API endpoints, BFF calls, K8s service, and gotchas. |
| Billing Engine Sprint (BILL-S01–S11) | 2026-05-06 | Trial provisioning + Stripe checkout + scan-freq token enforcement + TrialCountdownChip + trial expiry emails + platform-admin billing oversight + Redis broker — `v-billing-adm1`, `v-padmin-billing1`, `v-billing-sprint2` |
| Data Integrity Sprint (DI-01–DI-17) | 2026-05-07 | Auth context engine_tenant_id, BFF auth helpers, tenant_id cleanup (2 batches), typed Pydantic schemas, 21/21 contract tests passing, MITRE backfill (4743/5205 rows), dashboard 7 flat-alias fields, DB gap report + migrations (threat/risk/compliance) — `v-di-sprint1` |
| Wiz-Like Security Graph Sprint (GRAPH-S1–S3, BFF-01) | 2026-05-07 | Neo4j config properties (E1), CVE nodes (E2), EXPOSES edges (E3), Argo DAG restructure (E4), graph BFF uid→id mapping + graph_capabilities flag + KEV RBAC stripping, cross-DB read users — `v-graph-sprint5` (threat) |

## Story Naming

| Work type | ID format | Example |
|-----------|-----------|---------|
| CSP enablement | `{CSP}-{NN}` | `GCP-01_vpc_layer1.md` |
| Engine work | `ENG-{NN}` | `ENG-01_network_7layer_oci.md` |
| Bug fix | `FIX-{NN}` | `FIX-01_cardinality_violation.md` |
| Shared/infra | `SHARED-{NN}` | `SHARED-01_migration_runner.md` |

---

## Minimal Story Template

```markdown
# Story: {ID} — {Title}

## Status: draft | ready | in-progress | done

## Context
What problem this solves, which engine/CSP, why now.

## Acceptance Criteria (Functional)
- [ ] specific and testable — not "works correctly"

## Acceptance Criteria (Security)
- [ ] All DB queries have tenant_id filter
- [ ] No plaintext credentials in logs
- [ ] finding_id deduplicated before INSERT (if writing findings)
- [ ] blast_radius_score = 0 in network findings (risk engine owns it)

## Technical Notes
Key files to read/modify. Image tag to increment. Pattern to follow.

## Definition of Done
- [ ] Code implemented
- [ ] docker build completes without error
- [ ] kubectl apply + rollout status clean
- [ ] bmad-security-reviewer: no BLOCKERS
- [ ] bmad-qa: all functional ACs verified
```

---

## Completed Sprints (archive reference)

| Sprint | Outcome |
|--------|---------|
| CSPSCAN Validation Sprint (2026-04-30) | Done — 6 CSPs validated end-to-end (AWS/GCP/K8s/Azure/AliCloud/OCI). Fixed: encryption SyntaxError (v-modular2), risk VARCHAR overflow + blast-radius hang (v-risk-enterprise2), dbsec URL 404. Final: AWS 45k disc→9,620 risk scenarios ($737M), GCP 233, K8s 689, Azure 40, OCI 32, AliCloud 1. Gaps: K8s check=0 (→ENG-16), OCI IAM=0 (→ENG-17), AliCloud network=1 (→ENG-18). All provisioned resources decommissioned. |
| Network Engine Full Fix (bugs + 7-layer refactor) | Done 2026-04-29 — v-net-fix11: CardinalityViolation fixed, Azure L2 fixed, all 4 non-AWS providers refactored to 7-layer; AWS 928, Azure 27, AliCloud 1, OCI 10, K8s 124 findings |
| Network Discovery Sprint (GCP/AliCloud handlers + UI multi-CSP) | Done 2026-04-29 — v-disc-net5 + v-net-fix13: GCP/AliCloud service_scanner handlers, rule_discoveries DB rows, I_p_protocol fix, UI aggregates latest scan per (provider, account_id), 4 CSPs validated: GCP 79, OCI 94, K8s 250, AliCloud 3 |
| Azure multi-CSP discovery (AZ-01 → AZ-17b) | Done — Azure working, disc=v-disc-fix15 |
| Multi-CSP pipeline (all 6 CSPs) | Done — all CSPs producing findings |
| Column standardization (2026-03-21) | Done — scan_run_id universal |