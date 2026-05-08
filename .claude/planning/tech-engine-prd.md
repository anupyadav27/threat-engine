# PRD: Technology Engine
## On-Premises & Self-Hosted Technology Security Posture Management

**Version:** 1.0 | **Status:** Draft | **Epic prefix:** TECH | **Date:** 2026-04-30

---

## 1. Problem Statement

The CSPM platform scans 7 cloud providers but has zero visibility into:
- Self-hosted databases (PostgreSQL, MySQL, Oracle, etc.) — CIS benchmark misconfigurations invisible
- Linux hosts — CIS Level 1/2 hardening not evaluated
- Network devices (Cisco, Palo Alto, Fortinet) — perimeter posture unscored
- SaaS platforms (M365, Google Workspace) — identity/access posture untracked
- Developer platforms (GitHub, GitLab) — source/secrets exposure undetected

Result: compliance scores exclude large portions of real asset inventory → meaningless for regulatory audit.

---

## 2. Solution — Technology Engine

4 new micro-engines extend the existing pipeline to 40 technologies across 10 categories:

```
Onboarding (8008) — register tech credentials
      ↓
tech-discovery  (8030) — YAML-driven queries → tech_discovery_findings
      ↓
tech-inventory  (8031) — normalize assets   → tech_inventory_assets
      ↓
tech-check      (8032) — CIS rule eval      → tech_check_findings
      ↓
tech-ciem       (8033) — log auth analysis  → tech_ciem_findings
      ↓
Compliance (8000) / Risk engine — consume via scan_run_id
```

---

## 3. Technology Coverage Matrix (40 technologies)

| Category | Technologies | Connection Method | CIS Benchmark |
|----------|-------------|-------------------|---------------|
| database | postgres, mysql, mariadb, mssql, mongodb, oracle, cassandra, ibm_db2 | JDBC/native connectors | CIS Postgres 14/15, MySQL 8, MariaDB 10.6, MSSQL 2019, MongoDB 6, Oracle 19c, Cassandra 4, Db2 11.5 |
| linux | ubuntu, debian, centos, redhat, suse, alibaba_linux | SSH (paramiko) | CIS Ubuntu 22.04, Debian 11, CentOS 7/8, RHEL 8/9, SUSE 15, Alibaba Linux 3 |
| network | cisco_ios, cisco_iosxe, cisco_asa, cisco_nxos, palo_alto, fortinet, f5, check_point, sophos, juniper | SSH/REST (netmiko, napalm) | CIS Cisco IOS 15, IOS XE 17, ASA 9, NX-OS 9.3, PAN-OS 10, FortiOS 7, F5 16, CP R81, Sophos 18.5, Junos 21 |
| web_server | apache_http, tomcat, nginx, iis, websphere | SSH + config parse | CIS Apache 2.4, Tomcat 10, Nginx 1.24, IIS 10, WebSphere 9 |
| virtualization | vmware_esxi | pyVmomi / vCenter REST | CIS ESXi 7.0 |
| container | docker | docker-py SDK | CIS Docker 1.6 |
| devops | github, gitlab | REST API | CIS GitHub 1.0, GitLab 15 |
| collaboration | microsoft_365, google_workspace | MSAL/Admin SDK | CIS M365 3.0, Google Workspace 1.2 |
| data_platform | snowflake | snowflake-connector | CIS Snowflake 1.0 |
| middleware | dynamics_365, sharepoint | MSAL / REST API | CIS Dynamics 365 1.0, SharePoint 2019 |

---

## 4. CIEM Detection Rules per Category

| Rule ID | Categories | MITRE | Pattern |
|---------|-----------|-------|---------|
| TCIEM-001 | all | T1110 Brute Force | ≥5 failed auth in 5 min from same IP |
| TCIEM-002 | all | T1078 Valid Accounts | Success login after ≥3 failures |
| TCIEM-003 | database | T1068 Privilege Escalation | GRANT/ALTER USER by non-DBA |
| TCIEM-004 | linux | T1078 Valid Accounts | sudo outside business hours |
| TCIEM-005 | network | T1562 Defense Evasion | ACL/firewall policy modification |
| TCIEM-006 | devops | T1552 Exfiltration | >10 repo clone/download in 60 min |
| TCIEM-007 | collaboration | T1098 Account Manipulation | New admin role assignment |
| TCIEM-008 | data_platform | T1530 Data Exfiltration | SELECT >100k rows on sensitive table |
| TCIEM-009 | container | T1611 Container Escape | Container started with --privileged |
| TCIEM-010 | virtualization | T1490 Impact | VM snapshot deletion / prod VM power-off |

---

## 5. Sprint Plan (7 sprints × 5 days)

| Sprint | Technologies | Key Deliverables |
|--------|-------------|-----------------|
| 0 | Foundation | DB schema, 4 engine scaffolds, BaseConnector, Argo template, K8s manifests |
| 1 | 8 DB engines | DB connectors, 130+ CIS rules, DB CIEM |
| 2 | 6 Linux engines | SSH connectors, 250+ CIS rules, Linux CIEM |
| 3 | 10 Network engines | netmiko/napalm connectors, 250+ rules, Network CIEM |
| 4 | web_server(5) + container + virtualization | SSH+API connectors, 200+ rules, Docker/ESXi CIEM |
| 5 | devops(2) + collaboration(2) + snowflake + middleware(2) | SaaS API connectors, 200+ rules, SaaS CIEM |
| 6 | UI/BFF integration | 5 BFF views, 5 UI pages, onboarding wizard for 10 cred types |

---

## 6. BMAD Agent Skill Matrix

| Story Type | Primary Agent | Review Agent |
|------------|--------------|--------------|
| Engine code (connector, evaluator, endpoint) | bmad-dev | bmad-architect |
| YAML catalog authoring (discovery + check + CIEM) | bmad-security-po | bmad-security-reviewer |
| DB schema + migrations | bmad-dev | bmad-architect |
| K8s manifests + Argo templates | bmad-dev | bmad-sm |
| ADRs | bmad-architect | bmad-pm |
| Compliance framework seed data | bmad-security-po | bmad-analyst |
| BFF views + Frontend pages | bmad-dev | bmad-qa |
| Pre-sprint security reviews | bmad-security-reviewer | bmad-security-architect |

---

## 7. Non-Functional Requirements

- **Credential isolation**: Secrets Manager only; no plaintext in Postgres; SSRF prevention on `host` field
- **Scan SLA**: p95 < 10 min per technology instance
- **Error tolerance**: < 5% query error rate → COMPLETED; ≥5% → PARTIAL_COMPLETE
- **Timeout**: 10s per query/command; 10 min per Argo step
- **Multi-tenancy**: `tenant_id` on all tables; row-level filtering in all queries
- **Connector security**: SSH RejectPolicy (no auto-accept), read-only catalog only, no `conf t`

---

## 8. Deferral Register

| Item | Deferred to |
|------|------------|
| Windows Server OS posture (WinRM) | v2 |
| VMware guest VM posture | v2 |
| Oracle RAC topology | v2 |
| Active Directory posture | IAM expansion feature |
| Automated remediation via SSH | Risk too high for v1 |
| PCI-DSS + HIPAA framework mapping | v2 |
| Real-time CIEM streaming | v2 (v1 = 24h batch) |
| Cross-domain attack chains (cloud → on-prem) | Threat Engine v3 |
