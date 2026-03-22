# CNAPP Gap Analysis — Threat Engine Platform

> **Date:** 2026-03-19
> **Assessed against:** Gartner 2025 CNAPP Market Guide + Wiz/Prisma Cloud/Orca feature parity

---

## Gartner's 10 CNAPP Must-Haves (2025) — Our Score

| # | Capability | Status | Engine | Gap |
|---|-----------|--------|--------|-----|
| 1 | CSPM (misconfig + compliance) | **PARTIAL** | Check + Compliance | 100+ AWS rules, 13 frameworks. Missing: real-time, cross-resource correlation, Azure/GCP rules |
| 2 | CWPP (workload vuln + runtime) | **NONE** | vulnerability/ exists | No agentless scanning, no runtime, no container image scanning |
| 3 | CIEM (identity + entitlements) | **PARTIAL** | IAM | 57 rules. Missing: effective permissions, unused perms, priv escalation paths |
| 4 | Container & K8s security | **NONE** | — | No KSPM, no container scanning, no runtime |
| 5 | IaC scanning | **FULL** | SecOps | 14 languages, 2,900 rules |
| 6 | Container image scanning | **NONE** | — | No registry scanning |
| 7 | Attack path analysis | **PARTIAL** | Threat (Neo4j) | Graph exists but shallow (sparse relationships) |
| 8 | Multi-cloud (AWS+Azure+GCP+K8s) | **PARTIAL** | Discoveries | AWS full, Azure/GCP catalog exists but check rules AWS-only |
| 9 | SIEM/SOAR integration | **NONE** | — | No connectors |
| 10 | Unified risk prioritization | **BROKEN** | Risk + Threat | All risk scores = 50 (broken inputs) |

**Score: 2/10 FULL, 4/10 PARTIAL, 4/10 NONE**

---

## Detailed Capability Matrix

### CSPM
| Capability | Status | Notes |
|-----------|--------|-------|
| Multi-cloud resource discovery | PARTIAL | AWS full (40+ services), Azure/GCP/OCI catalog exists |
| Asset classification & tagging | PARTIAL | Resource types, regions. No custom tags, no criticality |
| Shadow IT detection | NONE | |
| Misconfiguration rules (500+) | PARTIAL | 100+ AWS. Need 400+ more across clouds |
| Custom rule authoring | FULL | Rule engine with visual builder |
| Cross-resource correlation | NONE | Toxic combos are count-based only |
| Config drift detection | FULL | Inventory engine drift tracking |
| Real-time change detection | NONE | No CloudTrail event-driven |
| Exception management | PARTIAL | `is_active` flag on rules |
| Compliance frameworks (13+) | FULL | CIS, NIST, ISO, PCI, HIPAA, GDPR, SOC2, etc. |
| Compliance scoring | FULL | Per-framework, per-account |
| Compliance exports (PDF/CSV) | FULL | PDF + Excel |
| Risk scoring (0-100) | BROKEN | All scores = 50 |
| Risk trending | PARTIAL | Schema supports it, UI not showing |

### Threat Detection
| Capability | Status | Notes |
|-----------|--------|-------|
| MITRE ATT&CK mapping | FULL | Tactics + techniques on all findings |
| Attack path analysis | PARTIAL | Neo4j graph, shallow paths |
| Blast radius | BROKEN | BFS finds 0 (empty relationships) |
| Toxic combinations | NAIVE | Count-based, not curated |
| Threat intelligence | SCHEMA ONLY | Table exists, no data |
| Threat hunting | SCHEMA ONLY | Tables exist, no engine code |
| CDR (real-time) | NONE | Batch-only |

### Identity (CIEM)
| Capability | Status | Notes |
|-----------|--------|-------|
| Identity inventory | PARTIAL | IAM users, roles, policies discovered |
| Effective permissions | NONE | No policy simulation |
| Unused permissions | NONE | No CloudTrail usage analysis |
| Privilege escalation paths | NONE | |
| MFA enforcement | FULL | Checked by IAM engine |

### Data Security (DSPM)
| Capability | Status | Notes |
|-----------|--------|-------|
| Sensitive data discovery | PARTIAL | Rule-based, no actual content scanning |
| Data classification | PARTIAL | 4 levels (restricted/confidential/internal/public) |
| Data lineage | SCHEMA ONLY | Module exists, no actual tracing |
| Public data exposure | PARTIAL | Via check rules |

### Application Security
| Capability | Status | Notes |
|-----------|--------|-------|
| IaC scanning | FULL | 14 languages, 2,900 rules |
| SCA (dependency scanning) | PARTIAL | SecOps covers some |
| SAST | PARTIAL | SecOps covers some |
| Secrets detection | PARTIAL | SecOps covers some |
| CI/CD pipeline security | NONE | |
| Container image scanning | NONE | |

### Platform
| Capability | Status | Notes |
|-----------|--------|-------|
| Multi-tenant | FULL | RLS, tenant isolation |
| RBAC | FULL | Django RBAC, 56 permissions |
| API-first | FULL | FastAPI on all engines |
| Agentless | FULL | No agents needed |
| Scalability | PARTIAL | Spot nodes for scans, but single-pod |
| SIEM/SOAR integration | NONE | |
| Notification (Slack/Teams) | NONE | |
| Remediation automation | NONE | |

---

## Prioritized Roadmap Summary

| Phase | Focus | Timeline |
|-------|-------|----------|
| **Phase 1** | Fix foundation (relationships, MITRE, internet reachability, risk scores) | NOW |
| **Phase 2** | Intelligence layer (curated toxic combos, threat intel) | After Phase 1 |
| **Phase 3** | CNAPP expansion (SIEM, multi-cloud rules, notifications, remediation) | Future |
| **Phase 4** | Advanced (CDR, container scanning, CIEM, AI-SPM, EASM, runtime) | Future |

See: `PHASE3-CNAPP-EXPANSION.md` and `PHASE4-ADVANCED-CAPABILITIES.md` for detailed roadmaps.
