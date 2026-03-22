# CSPM Platform — UI Navigation & Page Hierarchy

## Base URL
```
http://<NLB>/gateway/...   (via API Gateway)
```

---

## Side Navigation (Left Sidebar)

```
┌─────────────────────────────────┐
│  CSPM Platform                  │
│                                 │
│  ▸ Dashboard                    │   ← Unified risk posture, executive view
│  ▸ Onboarding                   │   ← Multi-CSP account & credential mgmt
│     ├─ Accounts                 │
│     └─ Schedules                │
│  ▸ Scans                        │   ← Orchestration & scan pipeline
│     ├─ Run Scan                 │
│     ├─ Scan History             │
│     └─ Scan Detail              │
│  ▸ Inventory                    │   ← Asset inventory & relationships
│     ├─ Assets                   │
│     ├─ Relationships            │
│     ├─ Graph View               │
│     └─ Drift                    │
│  ▸ Threats                      │   ← Threat detection & kill-chain analysis
│     ├─ Overview                 │
│     ├─ Threat List              │
│     ├─ Threat Detail            │
│     ├─ MITRE ATT&CK Matrix      │   ← NEW: tactic/technique heat map
│     ├─ Internet Exposure        │   ← NEW: attack surface + toxic combos
│     ├─ Attack Paths             │
│     ├─ Analytics                │
│     ├─ Hunting                  │
│     └─ Intelligence             │
│  ▸ Compliance                   │   ← 13 frameworks, PDF/Excel reports
│     ├─ Dashboard                │
│     ├─ Framework Detail         │
│     ├─ Control Detail           │
│     └─ Reports                  │
│  ▸ IAM Security                 │   ← Identity & access posture (6 modules)
│     ├─ Overview                 │   ← NEW: module scorecard
│     ├─ Least Privilege          │   ← NEW: overprivileged entities
│     ├─ MFA & Credentials        │   ← NEW: MFA rate + password policy
│     └─ Role Management          │   ← NEW: role hygiene + access control
│  ▸ Data Security                │   ← Data protection, PII/PHI/PCI, GDPR
│     ├─ Overview                 │   ← NEW: data risk summary
│     ├─ Data Catalog             │   ← 21 stores with sensitivity labels
│     ├─ Classification           │   ← NEW: PII/PHI/PCI heat map
│     ├─ Data Residency           │   ← NEW: geographic compliance map
│     ├─ Data Lineage             │   ← NEW: data flow graph
│     └─ Activity & Anomalies     │   ← NEW: exfiltration detection
│  ▸ Code Security (SecOps)       │   ← IaC scanning, 14 languages
│     ├─ Run Scan                 │
│     ├─ Scan Results             │
│     └─ Rule Library             │
│  ▸ Settings                     │
│     └─ Platform Health          │
│                                 │
└─────────────────────────────────┘
```

> **NEW pages** vs original spec are marked ← NEW above. All new pages are backed by live engine APIs.

---

## Page Definitions

### 1. Dashboard (Landing)
**Route**: `/`
**Purpose**: Executive summary across all engines for the selected tenant/account.

### 2. Onboarding
**Route**: `/onboarding/*`
**Purpose**: Manage tenants, cloud accounts, credentials, and scan schedules.

### 3. Scans
**Route**: `/scans/*`
**Purpose**: Trigger orchestrated scans, view history, drill into individual scan results.

### 4. Inventory
**Route**: `/inventory/*`
**Purpose**: Browse discovered assets, visualize relationships, detect configuration drift.

### 5. Threats
**Route**: `/threats/*`
**Purpose**: Threat detection, kill-chain analysis, MITRE ATT&CK matrix, attack surface, threat hunting.

| Sub-page | Route | Description |
|----------|-------|-------------|
| Overview | `/threats` | Severity KPIs, by-service/account charts, correlation matrix |
| Threat List | `/threats/list` | Filterable table of all findings |
| Threat Detail | `/threats/:id` | Root cause, remediation, blast radius |
| MITRE ATT&CK | `/threats/mitre` | Tactic × technique heat map — kill-chain coverage |
| Internet Exposure | `/threats/exposure` | Internet-exposed resources + toxic combinations |
| Attack Paths | `/threats/attack-paths` | Multi-hop graph attack path analysis |
| Analytics | `/threats/analytics` | Trend, distribution, pattern charts |
| Hunting | `/threats/hunting` | Predefined + custom threat hunt queries |
| Intelligence | `/threats/intel` | Threat intelligence feed |

### 6. Compliance
**Route**: `/compliance/*`
**Purpose**: 13 framework dashboards (GDPR, HIPAA, PCI-DSS, CIS, NIST, SOC2 + 7 more), control drill-down, PDF/Excel report generation/download.

### 7. IAM Security
**Route**: `/iam/*`
**Purpose**: 6-module IAM posture analysis — least privilege, policy analysis, MFA enforcement, role hygiene, password policy, access control.

| Sub-page | Route | Module(s) | Description |
|----------|-------|-----------|-------------|
| Overview | `/iam` | All | Module scorecard, risk score, critical findings |
| Least Privilege | `/iam/least-privilege` | `least_privilege` + `policy_analysis` | Overprivileged entities, wildcard policies |
| MFA & Credentials | `/iam/mfa` | `mfa` + `password_policy` | MFA adoption rate, stale keys, password policy |
| Role Management | `/iam/roles` | `role_management` + `access_control` | Unused roles, trust relationships, SCPs |

### 8. Data Security
**Route**: `/datasec/*`
**Purpose**: Data store inventory (21 stores), PII/PHI/PCI classification, GDPR residency compliance, data lineage, and access anomaly detection.

| Sub-page | Route | Description |
|----------|-------|-------------|
| Overview | `/datasec` | Risk KPIs, compliance scores, data-at-risk summary |
| Data Catalog | `/datasec/catalog` | All stores with sensitivity, encryption, access status |
| Classification | `/datasec/classification` | PII/PHI/PCI detection heat map per store |
| Residency | `/datasec/residency` | Geographic map, GDPR/DPDP violation list |
| Data Lineage | `/datasec/lineage` | Flow graph — data movement between services |
| Activity | `/datasec/activity` | Access anomaly time-series, exfiltration detection |

### 9. Code Security (SecOps)
**Route**: `/secops/*`
**Purpose**: Scan git repos for vulnerabilities, view findings by severity/language, rule library.

### 10. Settings
**Route**: `/settings/*`
**Purpose**: Platform health, engine connectivity, service status.
