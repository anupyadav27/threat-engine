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
│  ▸ Dashboard                    │   ← Landing page / executive view
│  ▸ Onboarding                   │   ← Account & tenant setup
│     ├─ Tenants                  │
│     ├─ Accounts                 │
│     └─ Schedules                │
│  ▸ Scans                        │   ← Orchestration & scan management
│     ├─ Run Scan                 │
│     ├─ Scan History             │
│     └─ Scan Detail              │
│  ▸ Inventory                    │   ← Asset inventory & relationships
│     ├─ Assets                   │
│     ├─ Relationships            │
│     ├─ Graph View               │
│     └─ Drift                    │
│  ▸ Threats                      │   ← Threat detection & analysis
│     ├─ Overview                 │
│     ├─ Threat List              │
│     ├─ Threat Detail            │
│     ├─ Attack Paths             │
│     ├─ Analytics                │
│     └─ Hunting                  │
│  ▸ Compliance                   │   ← Framework compliance
│     ├─ Dashboard                │
│     ├─ Framework Detail         │
│     ├─ Control Detail           │
│     └─ Reports                  │
│  ▸ IAM Security                 │   ← Identity & access posture
│     ├─ Findings                 │
│     └─ Modules                  │
│  ▸ Data Security                │   ← Data protection & lineage
│     ├─ Catalog                  │
│     ├─ Classification           │
│     ├─ Lineage                  │
│     ├─ Residency                │
│     └─ Activity                 │
│  ▸ Code Security (SecOps)       │   ← Code scanning
│     ├─ Run Scan                 │
│     ├─ Scan Results             │
│     └─ Rule Library             │
│  ▸ Settings                     │
│     ├─ Platform Health          │
│     └─ Engine Status            │
│                                 │
└─────────────────────────────────┘
```

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
**Purpose**: View/filter threats, analyze attack paths, correlate patterns, run threat hunts.

### 6. Compliance
**Route**: `/compliance/*`
**Purpose**: Framework compliance dashboards, control drill-down, report generation/download.

### 7. IAM Security
**Route**: `/iam/*`
**Purpose**: Identity & access management findings, module-level drill-down.

### 8. Data Security
**Route**: `/datasec/*`
**Purpose**: Data catalog, classification (PII/PCI/PHI), lineage, residency, activity monitoring.

### 9. Code Security (SecOps)
**Route**: `/secops/*`
**Purpose**: Scan git repos for vulnerabilities, view findings by severity/language, rule library.

### 10. Settings
**Route**: `/settings/*`
**Purpose**: Platform health, engine connectivity, service status.
