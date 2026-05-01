# Sprint Story Files

Story files are the atomic handoff unit between planning and dev.
**One story = one PR = one deployable unit.**

Pass story files to `bmad-dev` to implement. Pass sprint prompt files to `bmad-security-po` to generate new stories.

---

## Active Sprints

| Sprint | Prompt File | Status |
|--------|-------------|--------|
| Enterprise Engine Platform Hardening (DataSec/DBSec/Container/Risk/AI/CNAPP) | `../SPRINT_engine_platform_hardening.md` | stories generated, ready to implement |

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

## Enterprise Engine Platform Hardening — Story Files

| ID | File | Engine | Target Tag | Status |
|----|------|--------|------------|--------|
| ENG-10 | `ENG-10_datasec_dspm_enterprise.md` | DataSec (8-module DSPM) | `v-dspm-enterprise` | ready |
| ENG-11 | `ENG-11_dbsec_5pillar_enterprise.md` | DBSec (5-pillar) | `v-dbsec-enterprise` | ready |
| ENG-12 | `ENG-12_container_sec_cis_k8s.md` | Container-Sec (CIS K8s 7-layer) | `v-container-enterprise` | ready |
| ENG-13 | `ENG-13_risk_fair_neo4j.md` | Risk (FAIR model + Neo4j blast radius) | `v-risk-enterprise` | ready |
| ENG-14 | `ENG-14_ai_security_atlas.md` | AI-Security (MITRE ATLAS 5-pillar) | `v-ai-enterprise` | ready |
| ENG-15 | `ENG-15_cnapp_graceful_degradation.md` | CNAPP/CWPP (graceful degradation fix) | `v-cnapp-graceful` | ready |

## RBAC Sprint — Role-Based Access Control Enforcement — Story Files

### Sprint 1 — Foundation (deploy in order)

| ID | File | Component | Target | Status |
|----|------|-----------|--------|--------|
| RBAC-01 | `RBAC-01_django_rbac_schema_migration.md` | Django DB migration (roles + sessions) | No Docker — Django migrate | ready |
| RBAC-02 | `RBAC-02_seed_roles_permissions.md` | Django data migration — 5 roles, 23 perms, matrix | No Docker — Django migrate | ready |
| RBAC-03 | `RBAC-03_populate_auth_caches_login.md` | Login cache population + MeView real permissions | No Docker — Django code change | ready |

### Sprint 2 — Engine Authorization Wiring

| ID | File | Engines | Target Tags | Status |
|----|------|---------|-------------|--------|
| RBAC-04 | `RBAC-04_engine_auth_core_findings.md` | check, discoveries, threat, inventory, compliance | `*-rbac1` suffix on each | ready |
| RBAC-05 | `RBAC-05_engine_auth_security_analysis.md` | iam, ciem, network-security, risk | `*-rbac1` suffix on each | ready |
| RBAC-06 | `RBAC-06_engine_auth_enterprise_engines.md` | datasec, secops, vulnerability, ai-security, encryption, dbsec, container-sec, fix/* | `*-rbac1` suffix on each | ready |

### Sprint 3 — Gateway and Frontend

| ID | File | Component | Target Tag | Status |
|----|------|-----------|------------|--------|
| RBAC-07 | `RBAC-07_bff_auth_context_forwarding.md` | BFF auth header forwarding + cache key role isolation | `v-bff-iam-fix-rbac1` | ready |
| RBAC-08 | `RBAC-08_frontend_api_driven_permissions.md` | Frontend API-driven permissions + DEV_BYPASS removal | `v-no-mock-data-rbac1` | ready |

---

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