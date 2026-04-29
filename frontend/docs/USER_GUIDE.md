# Threat Engine — User Guide
### Enterprise Cloud Security Posture Management Platform

> **Version:** 2.0 · **Audience:** Security Analysts, Compliance Officers, Cloud Administrators, Executive Stakeholders

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Getting Started](#2-getting-started)
3. [Navigation Overview](#3-navigation-overview)
4. [Global Scope Filter](#4-global-scope-filter)
5. [Dashboard](#5-dashboard)
6. [Threat Detection](#6-threat-detection)
7. [Misconfigurations](#7-misconfigurations)
8. [Compliance](#8-compliance)
9. [Inventory & Assets](#9-inventory--assets)
10. [IAM Security](#10-iam-security)
11. [Data Security](#11-data-security)
12. [Code Security (SecOps)](#12-code-security-secops)
13. [Vulnerabilities](#13-vulnerabilities)
14. [Risk Quantification](#14-risk-quantification)
15. [Scans & Orchestration](#15-scans--orchestration)
16. [Reports](#16-reports)
17. [Notifications & Alerts](#17-notifications--alerts)
18. [Settings & Administration](#18-settings--administration)
19. [Saved Filter Views](#19-saved-filter-views)
20. [Roles & Permissions](#20-roles--permissions)
21. [Glossary](#21-glossary)

---

## 1. Introduction

**Threat Engine** is an enterprise-grade Cloud Security Posture Management (CSPM) platform that gives your security team unified visibility across all cloud environments. It continuously discovers cloud resources, evaluates them against security benchmarks, detects active threats, and maps findings to compliance frameworks — all in a single pane of glass.

### What Threat Engine Does

| Capability | Description |
|---|---|
| **Discovery** | Automatically enumerates 40+ cloud services across AWS, Azure, GCP, OCI, IBM Cloud, and AliCloud |
| **Compliance** | Maps findings to 13+ frameworks: CIS, NIST 800-53, PCI-DSS, HIPAA, GDPR, ISO 27001, SOC 2 |
| **Threat Detection** | Identifies active threats using MITRE ATT&CK technique mapping with risk scoring (0–100) |
| **IAM Analysis** | Evaluates identity posture across 57 security rules — over-privilege, stale identities, MFA gaps |
| **Data Security** | Classifies data stores, monitors encryption, detects DLP violations and residency violations |
| **IaC Scanning** | Scans Infrastructure-as-Code files in 14 languages for misconfigurations before deployment |
| **Vulnerability Management** | CVE tracking and vulnerability prioritization across cloud workloads |

---

## 2. Getting Started

### 2.1 Accessing the Platform

Navigate to your Threat Engine URL in any modern browser:

```
https://<your-domain>/ui
```

You will be redirected to the login page if you are not authenticated.

### 2.2 Signing In

**Email / Password login:**

1. Enter your corporate email address
2. Enter your password
3. Check **"Stay signed in for 7 days"** to keep your session active (uses a secure HTTP-only cookie — no tokens stored in browser)
4. Click **Sign In Securely**

**SSO / SAML login (corporate identity provider):**

1. Click **Continue with SSO / SAML**
2. You will be redirected to your identity provider (Okta, Azure AD, or similar)
3. Authenticate with your corporate credentials
4. You will be redirected back to the Threat Engine dashboard automatically

> **Security note:** Threat Engine uses HTTPS-only, HTTP-only cookies. Your credentials are never stored in browser localStorage or sessionStorage. Sessions expire automatically based on your organisation's policy.

### 2.3 First Login Checklist

After your first login, complete these steps to get full value:

- [ ] Verify your assigned role and tenant in **Profile → Account Details**
- [ ] Confirm at least one cloud account appears in **Onboarding → Accounts**
- [ ] Run a discovery scan if no scan data is present: **Scans → New Scan**
- [ ] Check the **Dashboard** for the overall posture score
- [ ] Set your preferred theme (light/dark) via the toggle at the bottom of the sidebar

---

## 3. Navigation Overview

### 3.1 Sidebar

The left sidebar contains all primary navigation. It supports three interaction modes:

| Interaction | Result |
|---|---|
| **Click** on a nav item | Navigate to that section |
| **Hover** over the right edge of the sidebar | Blue pill indicator appears — drag to resize |
| **Drag** the right edge left past 120px | Sidebar collapses to icon-only mode |
| **Drag** right from collapsed mode | Sidebar expands back |
| **Click** the right edge (no drag) | Toggle collapse / expand |

### 3.2 Navigation Structure

```
Dashboard              — Security posture overview

Scans                  — Scan history and orchestration
Inventory              — Cloud asset inventory
  └─ Drift             — Configuration drift detection

Misconfigurations      — Policy violation findings

Threats                — Active threat detections
  ├─ Analytics         — Threat trends and distributions
  ├─ Threat Hunting    — IOC and intelligence matching
  ├─ Attack Paths      — Multi-hop attack chain visualisation
  ├─ Blast Radius      — Impact analysis
  ├─ Toxic Combos      — Dangerous permission combinations
  └─ Internet Exposed  — Public attack surface

Vulnerabilities        — CVE and vulnerability findings
Compliance             — Framework scoring and controls
IAM Security           — Identity and access posture
Data Security          — Data catalogue and classification
Code Security          — Infrastructure-as-Code scanning

Reports                — Report generation
Risk                   — FAIR-model risk quantification
Settings               — Platform administration
```

### 3.3 Header Bar

The top header bar provides:

| Element | Function |
|---|---|
| **Page title** | Current page name |
| **Notifications bell** | Unread alert count + quick access |
| **Tenant selector** | Switch between tenants (if multi-tenant access) |
| **Theme toggle** ☀/🌙 | Switch light/dark mode |
| **User avatar** | Profile, preferences, logout |

---

## 4. Global Scope Filter

The **Global Scope Filter bar** sits below the header and applies to every page simultaneously. It lets you narrow all findings, metrics, and charts to a specific slice of your infrastructure without navigating away.

### 4.1 Filter Dimensions

| Filter | Options | Behaviour |
|---|---|---|
| **Provider** | All Providers / AWS / Azure / GCP / OCI / IBM / AliCloud | Resets Account and Region when changed |
| **Account** | All Accounts / individual account names | Resets Region when changed; options dynamically reflect selected Provider |
| **Region** | All Regions / individual region names | Options reflect selected Provider + Account |
| **Time Range** | Last 24h / 7 days / 30 days / 90 days | Independent of other filters |

### 4.2 Filter Summary

When filters are active, a summary line appears below the title on each page:

```
Filtered to: AWS › prod-account-123 › us-east-1
```

### 4.3 Saving Filter Views ("Pinned Filters")

Frequently used filter combinations can be saved as named presets:

1. Set your desired Provider, Account, Region, and Time Range
2. Click **📌 Save View** in the filter bar
3. Type a name (e.g., `prod-aws`, `hipaa-scope`)
4. Click **Save**

Saved presets appear as **chip pills** below the filter row. Click any chip to instantly restore that filter combination. Presets are stored in your browser and persist across sessions.

To remove a preset: click the **×** on the chip.

---

## 5. Dashboard

The Dashboard provides an at-a-glance view of your cloud security posture.

### 5.1 Posture Score

The large circular gauge at the top shows your overall **Security Posture Score** (0–100):

| Score Range | Status | Meaning |
|---|---|---|
| 80–100 | 🟢 Good | Low risk; most controls passing |
| 60–79 | 🟡 Moderate | Attention needed on key areas |
| 40–59 | 🟠 Poor | Significant gaps; prioritise remediation |
| 0–39 | 🔴 Critical | Immediate action required |

### 5.2 Key Metrics Strip

Below the score, a metrics strip shows:
- **Open Findings** (critical / high / medium / low counts)
- **Compliance Score** average across all frameworks
- **Assets Monitored** total resource count
- **Active Threats** needing attention

### 5.3 Cloud Provider Health Grid

Each cloud provider shows a health card with:
- Connectivity status (✓ Connected / ✗ Error)
- Asset count discovered
- Open finding count
- Last scan time

### 5.4 Recent Activity Feed

Lists the most recent findings, scans, and compliance events with timestamps. Click any item to navigate to its detail view.

---

## 6. Threat Detection

Threat Detection is the core of Threat Engine. The system maps all findings to the **MITRE ATT&CK framework** and assigns a **risk score (0–100)** to each detected threat.

### 6.1 Threat List Page

The main `/threats` page shows all active threat findings. Key columns:

| Column | Description |
|---|---|
| **Title** | Human-readable finding description |
| **Severity** | Critical / High / Medium / Low / Info |
| **MITRE Tactic** | e.g. Credential Access, Lateral Movement, Exfiltration |
| **MITRE Technique** | e.g. T1078, T1190, T1530 |
| **Affected Assets** | Number of cloud resources impacted |
| **Risk Score** | 0–100 composite score |
| **Provider** | Cloud provider (AWS, Azure, GCP, etc.) |
| **Status** | Active / Investigating / Resolved |

**Filtering:** Use the inline filter bar to filter by severity, tactic, provider, or status.

**Sorting:** Click any column header to sort ascending/descending.

### 6.2 Threat Detail View

Click any threat row to open the detail page (`/threats/[id]`), which shows:
- Full description and remediation guidance
- Affected resources list
- MITRE mapping with tactic chain
- Timeline of detection
- Assignee and SLA status

### 6.3 Threat Analytics

The **Analytics** sub-page (`/threats/analytics`) shows:
- **Severity distribution** donut chart
- **Trend line** of findings over time (7d / 30d / 90d)
- **By tactic** bar chart — which MITRE tactics are most prevalent
- **By provider** breakdown

### 6.4 Threat Hunting

The **Threat Hunting** page (`/threats/hunting`) shows matched **Indicators of Compromise (IOCs)**:
- IP addresses, domains, file hashes matching threat intelligence feeds
- Matched cloud assets
- IOC source and confidence level

### 6.5 Attack Paths

The **Attack Paths** visualisation (`/threats/attack-paths`) shows multi-step attack chains where a compromised resource can be used as a stepping stone to reach more sensitive targets. Each path shows:
- Entry point (e.g., publicly exposed EC2)
- Intermediate hops (e.g., over-privileged IAM role)
- Target (e.g., S3 bucket with PII)

### 6.6 Blast Radius

**Blast Radius** (`/threats/blast-radius`) quantifies the potential impact if a specific resource is compromised — how many downstream resources could be affected.

### 6.7 Toxic Combinations

**Toxic Combinations** (`/threats/toxic-combinations`) identifies pairs or groups of individually-acceptable misconfigurations that, **in combination**, create a critical risk (e.g., an over-privileged role attached to a publicly accessible EC2 instance).

### 6.8 Internet-Exposed Assets

Shows all resources with a direct or indirect path to the public internet — your external attack surface.

---

## 7. Misconfigurations

The Misconfigurations page lists all policy **FAIL** findings from the check engine — resources that violate security best practices.

### 7.1 Understanding Findings

Each misconfiguration finding includes:
- **Rule ID** — e.g., `EC2-001`, `S3-014`
- **Resource** — affected cloud resource ARN/ID
- **Severity** — Critical / High / Medium / Low
- **Provider & Region**
- **First Seen / Last Seen** dates
- **Remediation steps** (click the row for detail)

### 7.2 Filtering

Use the filter bar to narrow by:
- **Provider** (AWS, Azure, GCP, etc.)
- **Severity**
- **Resource type** (EC2, S3, RDS, etc.)
- **Status** (Open, Suppressed, Resolved)

### 7.3 Exporting

Click **Export** (top-right of the table) to download findings as CSV for ticketing system integration.

---

## 8. Compliance

The Compliance module maps all findings to regulatory frameworks and standards.

### 8.1 Framework Overview

The main compliance page shows a **matrix of all accounts × frameworks**. Each cell shows the compliance percentage for that account against that framework.

**Supported frameworks:**

| Framework | Standard | Key Controls |
|---|---|---|
| CIS | CIS Benchmarks v1.4–v2.0 | 200+ controls |
| NIST 800-53 | NIST SP 800-53 Rev 5 | 1000+ controls |
| PCI DSS | PCI DSS v3.2.1 / v4.0 | 12 requirements |
| HIPAA | HIPAA Security Rule | 45 CFR Part 164 |
| GDPR | EU General Data Protection Regulation | Articles 25, 32 |
| ISO 27001 | ISO/IEC 27001:2022 | 93 controls |
| SOC 2 | AICPA TSC | Trust Service Criteria |

### 8.2 Framework Detail

Click any framework cell or navigate to `/compliance/[framework]` to see:
- Control-by-control pass/fail table
- Passing controls, failing controls, and not-applicable
- Trend over time (did compliance improve or degrade?)
- Evidence links to specific failing resources

### 8.3 Reading the Score

A framework score represents the percentage of applicable controls that are **PASSING** for a given account:

```
Score = (Passing Controls / Total Applicable Controls) × 100
```

> A score of 100% means all applicable controls in scope are passing. It does **not** mean the environment is fully compliant — manual controls (procedural, physical) are outside the scope of automated scanning.

---

## 9. Inventory & Assets

The Inventory module provides a full catalogue of all discovered cloud resources.

### 9.1 Asset List

The main inventory page (`/inventory`) shows all cloud assets discovered in your last scan. Key attributes:

| Column | Description |
|---|---|
| **Resource Name** | Display name or ID |
| **Type** | AWS service type (EC2, RDS, S3, Lambda, etc.) |
| **Provider** | Cloud provider |
| **Account** | Cloud account ID |
| **Region** | Deployment region |
| **Status** | Running / Stopped / Available / etc. |
| **Findings** | Count of open security findings |

### 9.2 Asset Detail

Click any asset to open its detail page (`/inventory/[assetId]`), which shows:
- Full resource metadata
- All associated findings (threat, check, IAM)
- Relationships to other resources
- Change history

### 9.3 Relationship Graph

The **Inventory Graph** (`/inventory/graph`) visualises relationships between cloud resources as an interactive network graph. Use it to understand blast radius and attack paths visually.

**Controls:**
- **Scroll** — zoom in/out
- **Drag** — pan the view
- **Click a node** — highlight direct relationships
- **Right-click** — open resource detail

### 9.4 Configuration Drift

**Drift Detection** (`/inventory/drift`) shows resources whose configuration has changed since the previous scan:
- What changed (property name, old value → new value)
- Who made the change (if CloudTrail is enabled)
- Whether the change introduced a new finding

---

## 10. IAM Security

IAM Security analyses your Identity and Access Management posture across 57 built-in rules.

### 10.1 Overview Tab

The IAM overview shows:
- **Over-privileged identities** — users/roles with more permissions than needed
- **No MFA** — human users without multi-factor authentication
- **Unused identities** — accounts inactive for 60+ days
- **Keys to rotate** — access keys older than 90 days
- **Policy drift** — wildcard `*` actions in IAM policies

### 10.2 Tabs

| Tab | Contents |
|---|---|
| **Overview** | KPI summary + risk score + top findings |
| **Users & Identities** | Full user table with risk level, MFA status, last login |
| **Roles** | All IAM roles with permission scope and wildcard detection |
| **Access Keys** | All access keys with age, rotation status, last used |
| **MFA Status** | MFA adoption rate by user type |
| **Privilege Analysis** | Privilege escalation paths and over-permissions |
| **Service Accounts** | Non-human identities and their permission scope |

### 10.3 Risk Levels

| Risk Level | Meaning |
|---|---|
| **Critical** | Immediate action required (e.g., root account has active access keys) |
| **High** | Address within 7 days SLA |
| **Medium** | Address within 30 days SLA |
| **Low** | Best-practice improvement; address when convenient |

---

## 11. Data Security

The Data Security module provides a complete catalogue of your data stores with classification, encryption, and access monitoring.

### 11.1 Overview Tab

Shows high-level data risk metrics:
- **Sensitive Exposed** — PII/PHI data stores with public access or no encryption
- **Unencrypted Stores** — data stores missing encryption at rest
- **DLP Violations** — data loss prevention policy breaches
- **Classification Coverage** — % of data stores with an assigned classification
- **Encryption Coverage** — % of data stores encrypted at rest

### 11.2 Data Catalog Tab

Complete inventory of all data stores discovered (RDS, S3, DynamoDB, Redshift, BigQuery, CosmosDB, Snowflake, MongoDB, etc.) with:
- Classification label (PII, PHI, PCI, Confidential, Internal, Public)
- Encryption type and key ID
- Public access flag
- Owner team
- Last scan time

### 11.3 Classification Tab

Shows how data is classified across your estate:
- Pattern types detected (SSN, credit card, email, patient ID, API keys)
- Record counts and number of locations where found
- Detection confidence (%)
- Auto-classified vs. manually labelled

### 11.4 Encryption Tab

Details of encryption at rest for each data store:
- Encryption type (KMS, SSE-S3, CMEK, None)
- Key rotation status
- Last key rotation date
- Encryption status badge (encrypted / unencrypted)

### 11.5 Data Residency Tab

Shows where sensitive data physically resides by region and the applicable compliance frameworks for each region (GDPR for EU, HIPAA for US health, PDPA for Southeast Asia).

### 11.6 DLP Tab

Lists all Data Loss Prevention policy violations detected:
- Type (Exfiltration, Unauthorized Copy, Credential Exposure)
- Affected resource
- Data type involved
- Action taken (Blocked, Alerted)

---

## 12. Code Security (SecOps)

The Code Security module scans Infrastructure-as-Code (IaC) files for misconfigurations **before they are deployed**.

### 12.1 Supported Languages

Threat Engine scans IaC in 14 languages:
`Terraform` · `CloudFormation` · `Kubernetes YAML` · `Helm` · `Ansible` · `Pulumi` · `ARM Templates` · `Bicep` · `Dockerfile` · `docker-compose` · `Kustomize` · `CDK` · `Serverless Framework` · `Crossplane`

### 12.2 Reading Scan Results

Each IaC scan finding shows:
- **File path** and line number
- **Rule violated** (e.g., `CKV_AWS_8`: Ensure IMDSv2 is required)
- **Severity**
- **Framework mapping** (which CIS / NIST control this relates to)
- **Fix suggestion** — what to change in the code

### 12.3 Scan History

The Scans list shows all historical IaC scans with:
- Repository / source path
- File count scanned
- Finding counts by severity
- Scan duration

---

## 13. Vulnerabilities

The Vulnerabilities page shows CVE (Common Vulnerability and Exposure) findings across your cloud workloads.

> This module requires the vulnerability scanner engine to be connected to your environment. Findings are based on package manifests detected during asset discovery.

### 13.1 Vulnerability Columns

| Column | Description |
|---|---|
| **CVE ID** | e.g., CVE-2024-12345 |
| **Package** | Affected software package and version |
| **Severity** | Critical / High / Medium / Low (CVSS-based) |
| **CVSS Score** | 0.0 – 10.0 |
| **Affected Resources** | Number of cloud resources running this package |
| **Fix Available** | Whether a patched version is available |
| **Published Date** | When the CVE was disclosed |

---

## 14. Risk Quantification

The Risk page provides a **FAIR (Factor Analysis of Information Risk)** model-based risk quantification — translating technical findings into business financial impact.

### 14.1 Reading the Risk Matrix

The 2×2 risk matrix plots scenarios by:
- **Y-axis** — Likelihood of occurrence (Low → High)
- **X-axis** — Financial impact (Low → High)

Scenarios in the top-right quadrant (High Likelihood + High Impact) should be prioritised first.

### 14.2 Risk Scenarios

Each risk scenario shows:
- **Risk name** — e.g., "Publicly exposed S3 bucket with PII"
- **Annualised Loss Expectancy (ALE)** — expected annual financial loss in USD
- **Loss Event Frequency** — expected occurrences per year
- **Primary Loss** — direct loss from the event
- **Secondary Loss** — indirect costs (regulatory fines, reputational damage)

---

## 15. Scans & Orchestration

The Scans module shows the history of all security scans run against your cloud accounts.

### 15.1 Scan Types

| Type | Description | Engines Involved |
|---|---|---|
| **Full Scan** | Complete discovery + check + threat + compliance | All engines |
| **Discovery** | Resource enumeration only | Discoveries engine |
| **Compliance** | Compliance scoring only | Check + Compliance engines |
| **Quick** | Critical findings only (fast) | Check engine |

### 15.2 Scan History Table

| Column | Description |
|---|---|
| **Scan Name** | Auto-generated or user-defined name |
| **Type** | Full / Discovery / Compliance / Quick |
| **Provider** | Which cloud provider was scanned |
| **Account** | Which account |
| **Status** | Running / Completed / Failed / Queued |
| **Duration** | How long the scan took |
| **Resources Scanned** | Total asset count |
| **Findings** | Critical + High finding counts |
| **Triggered By** | scheduler / manual / webhook |

### 15.3 Scan Pipeline

Click any scan to see a visual **pipeline view** showing which stages completed:

```
Discovery → Check → Inventory → Threat Detection → Compliance Scoring
```

Each stage shows status (completed ✓, running ◉, pending ○, failed ✗) and timing.

### 15.4 Running a New Scan

> Scans are typically triggered automatically by the scheduler. Contact your administrator to run an ad-hoc scan if needed.

---

## 16. Reports

The Reports module lets you generate, schedule, and download formatted security reports.

### 16.1 Report Types

| Report Type | Audience | Contents |
|---|---|---|
| **Executive Summary** | CISO, Board | Posture score, top risks, trend |
| **Compliance Report** | Compliance Officer | Framework scores, failing controls |
| **Threat Report** | Security Analyst | All active threats with MITRE mapping |
| **Vulnerability Report** | DevOps / Engineering | CVE findings, fix recommendations |
| **Inventory Report** | Cloud Admin | Full asset catalogue |
| **IAM Report** | Identity Team | Over-privileged users, stale accounts |
| **Data Security Report** | Data Officer / Privacy Team | Data classification, residency, DLP |

### 16.2 Generating a Report

1. Navigate to **Reports**
2. Click **New Report**
3. Select report type and scope (provider / account / time range)
4. Choose format: **PDF** or **CSV**
5. Click **Generate**
6. Download when status shows **Ready**

---

## 17. Notifications & Alerts

The Notifications page shows all security alerts and system events.

### 17.1 Alert Types

| Type | Trigger |
|---|---|
| **New Critical Finding** | A Critical severity finding is detected |
| **Compliance Degradation** | A framework score drops by more than 5% |
| **Scan Failure** | A scan fails to complete |
| **New Attack Path** | A new multi-step attack path is detected |
| **Stale Identity Alert** | A user account hasn't logged in for 60+ days |
| **Data Exposure Alert** | A PII/PHI store becomes publicly accessible |

### 17.2 Managing Notifications

- Click the **bell icon** in the header to see the latest 10 notifications
- Navigate to `/notifications` for the full history
- Click **Mark all as read** to clear the badge count
- Use the filter to show only Critical, Compliance, or Scan notifications

---

## 18. Settings & Administration

> **Note:** Some settings require the **Tenant Admin** or **Super Admin** role.

### 18.1 Platform Settings (`/settings`)

Shows platform health: all connected engines, their status, API version, and last heartbeat.

### 18.2 User Management (`/settings/users`)

Tenant Admins can:
- View all users in the tenant
- Invite new users (sends email invite)
- Change user roles
- Deactivate accounts

To add a user:
1. Go to **Settings → Users**
2. Click **Add User**
3. Enter email, name, and role
4. Click **Send Invite**

### 18.3 Tenant Management (`/settings/tenants`)

Super Admins can create and manage tenants (for multi-tenant deployments). Each tenant is an isolated workspace with its own cloud accounts and users.

### 18.4 Onboarding (`/onboarding`)

To connect a new cloud account:

1. Navigate to **Onboarding → Add Account**
2. Select your cloud provider
3. Follow the credential setup guide for your provider:
   - **AWS:** Enter AWS Account ID and create a cross-account IAM role with the provided policy
   - **Azure:** Enter Subscription ID and register an App Registration in Azure AD
   - **GCP:** Enter Project ID and upload a Service Account JSON key
4. Click **Validate** — Threat Engine tests connectivity
5. Once validated, click **Save** — discovery will begin on the next scheduled scan

### 18.5 Policy Management (`/policies`)

Custom policies let you define additional rules beyond the built-in rule set.

### 18.6 Rules (`/rules`)

View and manage the built-in security rules. Admins can enable/disable individual rules or adjust severity overrides.

---

## 19. Saved Filter Views

Saved Filter Views are personal **named presets** for the Global Scope Filter. They are stored in your browser's localStorage and persist across sessions.

| Action | How |
|---|---|
| **Save** | Set filters → click **📌 Save View** → type name → Save |
| **Apply** | Click the chip pill below the filter bar |
| **Delete** | Click **×** on the chip |

> Saved views are **per-browser**. They are not synced across devices or shared between users.

---

## 20. Roles & Permissions

Threat Engine uses **capability-based Role-Based Access Control (RBAC)**.

### 20.1 Built-in Roles

| Role | Description | Key Permissions |
|---|---|---|
| **Super Admin** | Full platform access | All 13 capabilities, all tenants |
| **Admin** | Tenant-wide admin | 11 capabilities, own tenant |
| **Tenant Admin** | Manage users and settings in own tenant | 10 capabilities |
| **User** | Read-only security analyst | 7 capabilities (view only) |

### 20.2 Capability Reference

| Capability | Description |
|---|---|
| `view_dashboard` | Access the main dashboard |
| `view_assets` | View inventory and asset details |
| `view_threats` | View threat findings |
| `view_compliance` | View compliance reports |
| `view_iam` | View IAM security findings |
| `view_datasec` | View data security module |
| `view_scans` | View scan history |
| `create_scans` | Trigger new scans |
| `manage_tenants` | Create and manage tenants |
| `manage_users` | Invite and manage users |
| `manage_policies` | Create and modify custom policies |
| `manage_rules` | Enable/disable security rules |
| `delete_scans` | Delete historical scan data |

---

## 21. Glossary

| Term | Definition |
|---|---|
| **CSPM** | Cloud Security Posture Management — continuous monitoring and remediation of cloud misconfigurations |
| **Finding** | A detected security issue — misconfigurations, threats, vulnerabilities, or IAM problems |
| **Posture Score** | Overall security health score (0–100); higher is better |
| **Scan Run** | A single execution of the security scanning pipeline |
| **Tenant** | An isolated workspace containing one or more cloud accounts and users |
| **MITRE ATT&CK** | A globally-accessible knowledge base of adversary tactics and techniques |
| **Tactic** | The high-level adversary goal (e.g., Initial Access, Lateral Movement) |
| **Technique** | A specific method to achieve a tactic (e.g., T1078: Valid Accounts) |
| **Risk Score** | A composite threat score (0–100) considering severity, exploitability, and blast radius |
| **SLA** | Service Level Agreement — target remediation time by severity (Critical: 24h, High: 7d) |
| **IAM** | Identity and Access Management — controls who can access what in cloud environments |
| **PII** | Personally Identifiable Information — data that can identify an individual |
| **PHI** | Protected Health Information — medical data regulated by HIPAA |
| **PCI** | Payment Card Industry — data subject to PCI-DSS standard |
| **DLP** | Data Loss Prevention — policies to prevent unauthorised data exfiltration |
| **IaC** | Infrastructure-as-Code — cloud infrastructure defined in code (Terraform, CloudFormation, etc.) |
| **FAIR** | Factor Analysis of Information Risk — a model for quantifying cyber risk in financial terms |
| **CIS** | Center for Internet Security — publisher of cloud security benchmarks |
| **CVE** | Common Vulnerabilities and Exposures — standardised vulnerability identifiers |
| **CVSS** | Common Vulnerability Scoring System — severity scoring for CVEs (0.0–10.0) |
| **IOC** | Indicator of Compromise — evidence that a system has been breached |
| **Drift** | An unintended change to a resource's configuration compared to a known-good state |
| **Blast Radius** | The scope of resources that could be affected if a given resource is compromised |
| **Toxic Combination** | Multiple individually-acceptable misconfigurations that together create a critical risk |
| **Attack Path** | A chain of vulnerabilities a threat actor could exploit to reach a sensitive target |

---

*© Threat Engine · Enterprise Cloud Security Posture Management · For support, contact your administrator or open a ticket via the support portal.*
