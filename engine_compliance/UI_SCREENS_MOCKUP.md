# Compliance Engine UI - Screen Mockups

## UI Flow & Data Mapping

---

## 🏠 Screen 1: Executive Compliance Dashboard

**URL**: `/compliance/dashboard`

**Purpose**: High-level compliance posture across all frameworks

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  COMPLIANCE OVERVIEW                 Scan: latest (2026-01-18)    │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  KEY METRICS                                                      │
│  ┌──────────────┬──────────────┬──────────────┬──────────────┐  │
│  │ 📊 78.5%     │ ✅ 3/6       │ ⚠️ 2/6       │ ❌ 1/6       │  │
│  │ Overall      │ Frameworks   │ Frameworks   │ Frameworks   │  │
│  │ Score        │ Passing      │ Partial      │ Failing      │  │
│  └──────────────┴──────────────┴──────────────┴──────────────┘  │
│                                                                   │
│  FRAMEWORK COMPLIANCE STATUS          [View All →]              │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ CIS AWS Foundations v2.0    ████████░░  85.2%  ✅ PASS   │ │
│  │ ISO 27001:2022              ███████░░░  72.1%  ⚠️ PARTIAL│ │
│  │ NIST CSF 1.1                ████████░░  81.5%  ✅ PASS   │ │
│  │ PCI DSS 4.0                 ██████░░░░  65.3%  ⚠️ PARTIAL│ │
│  │ HIPAA                        ████████░░  78.9%  ✅ PASS   │ │
│  │ GDPR                        ████░░░░░░  45.2%  ❌ FAIL   │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  TOP CRITICAL FINDINGS                    [Show All →]           │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ 🔴 CRITICAL: 67 RDS instances without encryption           │ │
│  │    Frameworks: GDPR Art.32, PCI Req.3.4, HIPAA §164.312    │ │
│  │    Controls: 12 controls failing                            │ │
│  │    [View Details] [Start Remediation]                       │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ 🔴 CRITICAL: Public S3 buckets with sensitive data         │ │
│  │    Frameworks: CIS 2.1.1, ISO A.8.3.1, NIST PR.AC-3       │ │
│  │    Controls: 8 controls failing                             │ │
│  │    [Emergency Lockdown] [View Buckets]                     │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ 🟡 HIGH: Missing CloudTrail logging                         │ │
│  │    Frameworks: CIS 3.1, ISO A.12.4.1, NIST PR.DS-3        │ │
│  │    Controls: 5 controls failing                            │ │
│  │    [Configure Logging]                                      │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  COMPLIANCE TRENDS (Last 30 Days)                                │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ [Line Chart: Overall score trend]                          │ │
│  │ 78.5% → 78.5% (No change)                                   │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  QUICK ACTIONS                                                    │
│  [📥 Export Report] [📊 Generate Enterprise Report] [⚙️ Settings]│
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// On page load
const dashboard = await fetch('/api/v1/compliance/generate?scan_id=latest&csp=aws')

// Get executive dashboard
const executive = dashboard.executive_dashboard

// Calculate metrics
const overallScore = executive.summary.overall_compliance_score
const frameworks = executive.frameworks
const criticalFindings = executive.top_critical_findings
```

---

## 📋 Screen 2: Framework Compliance Detail

**URL**: `/compliance/framework/{framework}`

**Purpose**: Detailed compliance status for a specific framework

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  ◀ Back to Dashboard                                            │
├──────────────────────────────────────────────────────────────────┤
│  📋 CIS AWS Foundations Benchmark v2.0                            │
│  Compliance Score: 85.2% ████████░░                             │
│                                                                   │
│  OVERVIEW                                                         │
│  ┌──────────────┬──────────────┬──────────────┬──────────────┐  │
│  │ 142          │ 121          │ 18           │ 3            │  │
│  │ Total        │ Passed       │ Failed       │ Not          │  │
│  │ Controls     │ Controls     │ Controls     │ Applicable   │  │
│  └──────────────┴──────────────┴──────────────┴──────────────┘  │
│                                                                   │
│  ┌─ TABS ──────────────────────────────────────────────────┐   │
│  │ [All Controls] [Failed] [Passed] [Not Applicable]       │   │
│  ├──────────────────────────────────────────────────────────┤   │
│  │ CONTROL STATUS                                            │   │
│  │                                                           │   │
│  │ ┌─────────────────────────────────────────────────────┐ │   │
│  │ │ ❌ FAIL | 2.1.1 - Ensure IAM Access Analyzer...    │ │   │
│  │ │ Category: Identity and Access Management            │ │   │
│  │ │                                                       │ │   │
│  │ │ Status: 0/3 accounts compliant                        │ │   │
│  │ │ Affected Resources: 3                                │ │   │
│  │ │ Severity: High                                       │ │   │
│  │ │                                                       │ │   │
│  │ │ Evidence:                                            │ │   │
│  │ │ • Account 155052200811: Access Analyzer not enabled │ │   │
│  │ │ • Account 194722442770: Access Analyzer not enabled │ │   │
│  │ │ • Account 588989875114: Access Analyzer not enabled │ │   │
│  │ │                                                       │ │   │
│  │ │ Remediation:                                         │ │   │
│  │ │ 1. Navigate to IAM Console                           │ │   │
│  │ │ 2. Create Access Analyzer                            │ │   │
│  │ │ 3. Enable for all regions                            │ │   │
│  │ │                                                       │ │   │
│  │ │ [View Resources] [Remediate] [Suppress]              │ │   │
│  │ └─────────────────────────────────────────────────────┘ │   │
│  │                                                           │   │
│  │ ✅ PASS | 1.1 - Maintain current contact details        │   │
│  │    Category: Identity and Access Management              │   │
│  │    Status: 3/3 accounts compliant ✅                    │   │
│  │                                                           │   │
│  │ ✅ PASS | 1.2 - Enable MFA for root account             │   │
│  │    Category: Identity and Access Management              │   │
│  │    Status: 3/3 accounts compliant ✅                    │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
│  BY CATEGORY                                                      │
│  Identity & Access: 85% | Logging: 92% | Monitoring: 78% | ...   │
│                                                                   │
│  [📥 Export Framework Report] [📊 View Trends] [🔧 Bulk Remediate]│
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// Framework from URL params
const framework = params.framework // e.g., "CIS AWS Foundations Benchmark"

// Load framework report
const report = await fetch(
  `/api/v1/compliance/framework/${encodeURIComponent(framework)}/status?scan_id=latest&csp=aws`
)

// Get controls
const controls = report.controls
const summary = report.summary

// Filter by status
const failedControls = controls.filter(c => c.status === 'FAIL')
const passedControls = controls.filter(c => c.status === 'PASS')
```

---

## 🔍 Screen 3: Control Detail View

**URL**: `/compliance/framework/{framework}/control/{control_id}`

**Purpose**: Detailed view of a specific compliance control

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  ◀ Back to Framework                                            │
├──────────────────────────────────────────────────────────────────┤
│  📋 Control: 2.1.1 - Ensure IAM Access Analyzer is enabled       │
│  Framework: CIS AWS Foundations Benchmark v2.0                    │
│  Category: Identity and Access Management                        │
│                                                                   │
│  STATUS: ❌ FAIL                                                  │
│  Compliance: 0/3 accounts (0%)                                   │
│                                                                   │
│  CONTROL DESCRIPTION                                              │
│  IAM Access Analyzer helps identify resources shared with        │
│  external entities. This control ensures Access Analyzer is       │
│  enabled for all regions.                                        │
│                                                                   │
│  REQUIREMENT                                                      │
│  • Access Analyzer must be enabled                               │
│  • Must cover all regions                                        │
│  • Must be actively analyzing resources                          │
│                                                                   │
│  AFFECTED RESOURCES (3)                    [Filter ▼] [Export →] │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Account: 155052200811 (AWS)                                │ │
│  │ Status: ❌ Access Analyzer not configured                  │ │
│  │ Region: us-east-1                                          │ │
│  │ Resource: arn:aws:iam::155052200811:analyzer/default       │ │
│  │ Evidence: {"access_analyzer_enabled": false}              │ │
│  │ [View Details] [Remediate]                                 │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ Account: 194722442770 (AWS)                                │ │
│  │ Status: ❌ Access Analyzer not configured                  │ │
│  │ Region: us-east-1                                          │ │
│  │ [View Details] [Remediate]                                 │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ Account: 588989875114 (AWS)                                │ │
│  │ Status: ❌ Access Analyzer not configured                  │ │
│  │ Region: us-east-1                                          │ │
│  │ [View Details] [Remediate]                                 │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  REMEDIATION STEPS                                                │
│  1. Navigate to IAM Console → Access Analyzer                   │
│  2. Click "Create analyzer"                                      │
│  3. Select "Organization" or "Account" scope                     │
│  4. Choose regions to analyze                                    │
│  5. Review and create                                            │
│                                                                   │
│  [📖 AWS Documentation] [▶️ Auto-Remediate] [🔕 Suppress Control] │
│                                                                   │
│  RELATED CONTROLS                                                 │
│  • 2.1.2 - Ensure Access Analyzer findings are reviewed          │
│  • ISO 27001:2022 A.8.3.0085 - Access management                │
│  • NIST CSF PR.AC-3 - Remote access management                   │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// Control ID from URL params
const controlId = params.control_id // e.g., "2.1.1"

// Get framework report and filter by control
const report = await fetch(
  `/api/v1/compliance/framework/${framework}/status?scan_id=latest&csp=aws`
)

// Find specific control
const control = report.controls.find(c => c.control_id === controlId)

// Get affected resources
const affectedResources = control.checks.filter(c => c.check_result === 'FAIL')
```

---

## 🏢 Screen 4: Account Compliance View

**URL**: `/compliance/accounts/{account_id}`

**Purpose**: Compliance status for a specific account across all frameworks

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  🏢 ACCOUNT: 155052200811 (AWS)                                   │
├──────────────────────────────────────────────────────────────────┤
│  OVERVIEW                                                         │
│  ┌──────────────┬──────────────┬──────────────┬──────────────┐  │
│  │ 75.2%        │ 450          │ 18           │ 12 Regions  │  │
│  │ Overall      │ Total        │ Failed       │ Scanned      │  │
│  │ Score        │ Controls     │ Controls     │              │  │
│  └──────────────┴──────────────┴──────────────┴──────────────┘  │
│                                                                   │
│  FRAMEWORK SCORES                                                 │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Framework                  │ Score  │ Status  │ Controls  │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ CIS AWS Foundations v2.0   │ 82.1%  │ ✅ PASS │ 142       │ │
│  │ ISO 27001:2022             │ 68.5%  │ ⚠️ PART│ 156       │ │
│  │ NIST CSF 1.1                │ 75.3%  │ ✅ PASS │ 108       │ │
│  │ PCI DSS 4.0                │ 58.2%  │ ❌ FAIL│ 89        │ │
│  │ HIPAA                       │ 72.1%  │ ⚠️ PART│ 45        │ │
│  │ GDPR                        │ 38.5%  │ ❌ FAIL│ 67        │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  FAILED CONTROLS BY FRAMEWORK            [Show All →]            │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ CIS: 18 failed controls                                    │ │
│  │ • 2.1.1 - IAM Access Analyzer (3 resources)                │ │
│  │ • 3.1 - CloudTrail enabled (5 resources)                   │ │
│  │ [View All CIS Controls →]                                  │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ ISO 27001: 45 failed controls                              │ │
│  │ • A.8.3.1 - Access control (12 resources)                  │ │
│  │ • A.12.4.1 - Logging (8 resources)                        │ │
│  │ [View All ISO Controls →]                                  │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  COMPLIANCE BY SERVICE                                            │
│  RDS: 65% | S3: 72% | IAM: 85% | EC2: 68% | ...                  │
│                                                                   │
│  REGIONAL COMPLIANCE                      [View Map →]            │
│  us-east-1: 78% | ap-south-1: 72% | eu-west-1: 65% | ...          │
│                                                                   │
│  [📥 Export Account Report] [📊 View Trends] [🔧 Remediation Plan]│
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// Account ID from URL params
const accountId = params.account_id

// Generate report filtered by account (need to filter scan results)
const report = await fetch(
  `/api/v1/compliance/generate?scan_id=latest&csp=aws`
)

// Filter results by account_id in UI or backend
// Note: May need new endpoint: /api/v1/compliance/accounts/{account_id}?scan_id=latest&csp=aws
```

---

## 🔧 Screen 5: Resource Compliance Drill-down

**URL**: `/compliance/resources/{resource_arn}`

**Purpose**: Compliance status for a specific resource across all frameworks

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  ◀ Back to Catalog                                               │
├──────────────────────────────────────────────────────────────────┤
│  📦 arn:aws:rds:ap-south-1:155052200811:db:prod-db              │
│  Service: RDS | Region: ap-south-1 | Account: 155052200811      │
│                                                                   │
│  COMPLIANCE SCORE: 68% 🟡                                        │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ ✅ 45 Passed  │  ❌ 12 Failed  │  ⚠️ 3 Warnings          │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
│  ┌─ TABS ──────────────────────────────────────────────────┐   │
│  │ [Overview] [By Framework] [Failed Controls] [Evidence]  │   │
│  ├──────────────────────────────────────────────────────────┤   │
│  │ FRAMEWORK COMPLIANCE                                      │   │
│  │                                                           │   │
│  │ CIS AWS Foundations: 72% (45/62 controls)                │   │
│  │ ISO 27001:2022: 65% (38/58 controls)                    │   │
│  │ NIST CSF: 68% (42/62 controls)                          │   │
│  │ PCI DSS: 58% (28/48 controls)                            │   │
│  │                                                           │   │
│  │ FAILED CONTROLS                                           │   │
│  │ ┌─────────────────────────────────────────────────────┐ │   │
│  │ │ ❌ CIS 3.1 - CloudTrail logging                      │ │   │
│  │ │    Status: CloudTrail not configured for this region  │ │   │
│  │ │    Evidence: {"cloudtrail_enabled": false}          │ │   │
│  │ │    [View Control] [Remediate]                        │ │   │
│  │ ├─────────────────────────────────────────────────────┤ │   │
│  │ │ ❌ ISO A.8.3.1 - Encryption at rest                  │ │   │
│  │ │    Status: Storage encryption disabled              │ │   │
│  │ │    Evidence: {"storage_encrypted": false}          │ │   │
│  │ │    [View Control] [Remediate]                       │ │   │
│  │ └─────────────────────────────────────────────────────┘ │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
│  [📥 Export Resource Report] [🔧 Remediation Plan]               │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// Resource ARN from URL params
const resourceArn = decodeURIComponent(params.resource_arn)

// Get resource drill-down
const drilldown = await fetch(
  `/api/v1/compliance/resource/drilldown?scan_id=latest&csp=aws&resource_id=${encodeURIComponent(resourceArn)}`
)

// Get compliance by framework
const byFramework = drilldown.frameworks
const failedControls = drilldown.failed_controls
```

---

## 📊 Screen 6: Compliance Trends & History

**URL**: `/compliance/trends`

**Purpose**: Historical compliance trends and improvement tracking

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  📊 COMPLIANCE TRENDS & HISTORY                                  │
├──────────────────────────────────────────────────────────────────┤
│  TIME RANGE: [Last 30 Days ▼] [Last 90 Days] [Last Year]        │
│  FRAMEWORK: [All Frameworks ▼]                                   │
│                                                                   │
│  OVERALL COMPLIANCE TREND                                         │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ [Line Chart: Score over time]                              │ │
│  │ 78.5% → 78.5% → 79.2% → 78.5%                              │ │
│  │ Jan 15    Jan 18    Jan 20    Jan 22                       │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  FRAMEWORK TRENDS                                                 │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ CIS AWS Foundations    ████████░░  85.2%  ↗ +2.1%          │ │
│  │ ISO 27001:2022        ███████░░░  72.1%  → 0%             │ │
│  │ NIST CSF 1.1          ████████░░  81.5%  ↗ +1.3%          │ │
│  │ PCI DSS 4.0           ██████░░░░  65.3%  ↘ -0.5%         │ │
│  │ HIPAA                 ████████░░  78.9%  ↗ +0.8%          │ │
│  │ GDPR                  ████░░░░░░  45.2%  → 0%             │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  IMPROVEMENTS & REGRESSIONS                                       │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ ✅ Improved: CIS AWS Foundations (+2.1%)                   │ │
│  │    Fixed: 5 controls in Identity & Access Management     │ │
│  │    Date: Jan 20, 2026                                      │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ ⚠️ Regressed: PCI DSS 4.0 (-0.5%)                        │ │
│  │    New failures: 3 controls in Encryption                 │ │
│  │    Date: Jan 22, 2026                                      │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  CONTROL STATUS CHANGES                                           │
│  • 12 controls fixed in last 30 days                             │
│  • 5 controls newly failing                                      │
│  • 3 controls marked as not applicable                           │
│                                                                   │
│  [📥 Export Trends Report] [📅 Schedule Review]                   │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// Get trends (NOTE: This endpoint may need to be created)
const trends = await fetch(
  `/api/v1/compliance/trends?csp=aws&account_id=155052200811&days=30`
)

// If endpoint doesn't exist, need to:
// 1. Store historical compliance scores
// 2. Query by date range
// 3. Calculate changes
```

---

## 🏢 Screen 7: Enterprise Report Generator

**URL**: `/compliance/enterprise/generate`

**Purpose**: Generate enterprise-grade compliance reports

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  🏢 ENTERPRISE COMPLIANCE REPORT                                  │
├──────────────────────────────────────────────────────────────────┤
│  CONFIGURATION                                                    │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Scan ID: [latest ▼]                                       │ │
│  │ CSP: [AWS ▼]                                              │ │
│  │ Tenant ID: [tenant-001]                                   │ │
│  │ Tenant Name: [Acme Corporation]                           │ │
│  │                                                             │ │
│  │ Trigger Type: [Scheduled ▼]                                │ │
│  │ Collection Mode: [Full Scan ▼]                            │ │
│  │                                                             │ │
│  │ Frameworks:                                                │ │
│  │ ☑ CIS AWS Foundations Benchmark                           │ │
│  │ ☑ ISO 27001:2022                                          │ │
│  │ ☑ NIST CSF 1.1                                            │ │
│  │ ☐ PCI DSS 4.0                                             │ │
│  │ ☐ HIPAA                                                    │ │
│  │ ☐ GDPR                                                     │ │
│  │                                                             │ │
│  │ Export Options:                                            │ │
│  │ ☑ JSON Report                                              │ │
│  │ ☑ PDF Report                                               │ │
│  │ ☑ CSV Export                                               │ │
│  │ ☐ Export to Database                                       │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  [▶️ Generate Report] [💾 Save Template] [📋 Load Template]       │
│                                                                   │
│  RECENT REPORTS                                                   │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Report ID: abc-123-def                                     │ │
│  │ Generated: Jan 18, 2026 14:30                               │ │
│  │ Status: ✅ Completed                                        │ │
│  │ [View] [Download PDF] [Download CSV]                       │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ Report ID: xyz-789-ghi                                     │ │
│  │ Generated: Jan 15, 2026 09:15                              │ │
│  │ Status: ✅ Completed                                        │ │
│  │ [View] [Download PDF] [Download CSV]                       │ │
│  └────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// Generate enterprise report
const response = await fetch('/api/v1/compliance/generate/enterprise', {
  method: 'POST',
  body: JSON.stringify({
    scan_id: 'latest',
    csp: 'aws',
    tenant_id: 'tenant-001',
    tenant_name: 'Acme Corporation',
    trigger_type: 'scheduled',
    collection_mode: 'full',
    export_to_db: false
  })
})

const { report_id, status, enterprise_report } = await response.json()

// Export report
const pdf = await fetch(
  `/api/v1/compliance/report/${report_id}/export?format=pdf`
)
```

---

## 📥 Screen 8: Report Export & Download

**URL**: `/compliance/reports/{report_id}`

**Purpose**: View and export compliance reports

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  📥 COMPLIANCE REPORT: abc-123-def                                │
├──────────────────────────────────────────────────────────────────┤
│  REPORT DETAILS                                                   │
│  Report ID: abc-123-def                                           │
│  Generated: Jan 18, 2026 14:30:00 UTC                            │
│  Scan ID: latest                                                  │
│  CSP: AWS                                                         │
│  Tenant: Acme Corporation (tenant-001)                           │
│                                                                   │
│  SUMMARY                                                          │
│  Overall Score: 78.5%                                             │
│  Frameworks: 6                                                    │
│  Total Findings: 1,423                                            │
│  Critical Findings: 67                                            │
│                                                                   │
│  EXPORT OPTIONS                                                   │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ 📄 JSON Report (Full)                                      │ │
│  │    Size: 1.2 MB                                            │ │
│  │    [Download]                                              │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ 📊 Executive Summary PDF                                    │ │
│  │    Size: 2.5 MB                                            │ │
│  │    [Download]                                              │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ 📋 Executive Summary CSV                                   │ │
│  │    Size: 145 KB                                            │ │
│  │    [Download]                                              │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ 📑 CIS Framework Report PDF                                 │ │
│  │    Size: 3.1 MB                                            │ │
│  │    [Download]                                              │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ 📑 ISO 27001 Framework Report PDF                          │ │
│  │    Size: 2.8 MB                                            │ │
│  │    [Download]                                              │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  [📥 Download All] [📧 Email Report] [🗑️ Delete Report]          │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// Get report
const report = await fetch(`/api/v1/compliance/report/${reportId}`)

// Export in different formats
const json = await fetch(`/api/v1/compliance/report/${reportId}/export?format=json`)
const pdf = await fetch(`/api/v1/compliance/report/${reportId}/export?format=pdf`)
const csv = await fetch(`/api/v1/compliance/report/${reportId}/export?format=csv`)
```

---

## 📊 Data Fields Reference

### Executive Dashboard (`/api/v1/compliance/generate`)
```json
{
  "executive_dashboard": {
    "scan_id": "latest",
    "csp": "aws",
    "account_id": "155052200811",
    "scanned_at": "2026-01-18T14:30:00Z",
    "generated_at": "2026-01-18T14:35:00Z",
    "summary": {
      "overall_compliance_score": 78.5,
      "total_frameworks": 6,
      "frameworks_passing": 3,
      "frameworks_partial": 2,
      "frameworks_failing": 1,
      "critical_findings": 67,
      "high_findings": 234,
      "medium_findings": 567,
      "low_findings": 555
    },
    "frameworks": [
      {
        "framework": "CIS AWS Foundations Benchmark",
        "version": "2.0",
        "compliance_score": 85.2,
        "status": "PASS",
        "controls_total": 142,
        "controls_passed": 121,
        "controls_failed": 18,
        "controls_not_applicable": 3
      }
    ],
    "top_critical_findings": [
      {
        "rule_id": "aws.rds.instance.storage_encrypted",
        "severity": "critical",
        "status": "FAIL",
        "affected_resources": 67,
        "frameworks": ["GDPR", "PCI DSS", "HIPAA"],
        "controls_affected": 12
      }
    ]
  }
}
```

### Framework Report (`/api/v1/compliance/framework/{framework}/status`)
```json
{
  "framework": "CIS AWS Foundations Benchmark",
  "version": "2.0",
  "compliance_score": 85.2,
  "status": "PASS",
  "summary": {
    "controls_total": 142,
    "controls_passed": 121,
    "controls_failed": 18,
    "controls_not_applicable": 3
  },
  "controls": [
    {
      "control_id": "2.1.1",
      "control_title": "Ensure IAM Access Analyzer is enabled",
      "category": "Identity and Access Management",
      "status": "FAIL",
      "compliance_percentage": 0.0,
      "checks": [
        {
          "check_result": "FAIL",
          "resource_arn": "arn:aws:iam::155052200811:analyzer/default",
          "account_id": "155052200811",
          "region": "us-east-1",
          "evidence": {"access_analyzer_enabled": false},
          "severity": "high"
        }
      ]
    }
  ]
}
```

### Resource Drill-down (`/api/v1/compliance/resource/drilldown`)
```json
{
  "resource_arn": "arn:aws:rds:ap-south-1:155052200811:db:prod-db",
  "resource_type": "rds:db",
  "service": "rds",
  "region": "ap-south-1",
  "account_id": "155052200811",
  "compliance_score": 68.0,
  "frameworks": [
    {
      "framework": "CIS AWS Foundations Benchmark",
      "compliance_score": 72.0,
      "controls_total": 62,
      "controls_passed": 45,
      "controls_failed": 12
    }
  ],
  "failed_controls": [
    {
      "framework": "CIS AWS Foundations Benchmark",
      "control_id": "3.1",
      "control_title": "Ensure CloudTrail is enabled",
      "status": "FAIL",
      "evidence": {"cloudtrail_enabled": false}
    }
  ]
}
```

### Enterprise Report (`/api/v1/compliance/generate/enterprise`)
```json
{
  "report_id": "abc-123-def",
  "tenant": {
    "tenant_id": "tenant-001",
    "tenant_name": "Acme Corporation"
  },
  "scan_context": {
    "scan_run_id": "latest",
    "trigger_type": "scheduled",
    "cloud": "aws",
    "collection_mode": "full",
    "started_at": "2026-01-18T14:00:00Z",
    "completed_at": "2026-01-18T14:30:00Z"
  },
  "findings": [
    {
      "finding_id": "stable-uuid-based-on-rule-resource",
      "rule_id": "aws.rds.instance.storage_encrypted",
      "resource_arn": "arn:aws:rds:...",
      "status": "FAIL",
      "severity": "critical",
      "first_seen_at": "2026-01-15T10:00:00Z",
      "last_seen_at": "2026-01-18T14:30:00Z",
      "evidence_id": "evidence-uuid",
      "data_ref": "s3://bucket/evidence/path.json"
    }
  ],
  "frameworks": [
    {
      "framework": "CIS AWS Foundations Benchmark",
      "version": "2.0",
      "sections": [
        {
          "section_id": "2",
          "section_title": "Identity and Access Management",
          "controls": [
            {
              "control_id": "2.1.1",
              "control_title": "Ensure IAM Access Analyzer is enabled",
              "status": "FAIL",
              "assets_passed": 0,
              "assets_failed": 3,
              "assets_total": 3,
              "finding_refs": ["finding-id-1", "finding-id-2"]
            }
          ]
        }
      ]
    }
  ],
  "asset_snapshots": [
    {
      "resource_arn": "arn:aws:rds:...",
      "resource_type": "rds:db",
      "service": "rds",
      "region": "ap-south-1",
      "account_id": "155052200811",
      "tags": {"env": "prod"},
      "metadata": {...}
    }
  ]
}
```

---

## 🎨 UI Component Library Recommendations

1. **Charts**: Recharts, Chart.js, or D3.js for trend visualization
2. **Tables**: TanStack Table (React Table v8) for control listings
3. **Progress Bars**: Custom components for compliance scores
4. **Framework**: React, Vue, or Angular
5. **State**: Redux/Zustand or React Query for API caching
6. **Export**: jsPDF or PDFKit for client-side PDF generation

---

## ✅ Implementation Checklist for Frontend

- [ ] Executive Dashboard with overall compliance score
- [ ] Framework selector and status cards
- [ ] Framework detail view with control listing
- [ ] Control detail view with affected resources
- [ ] Account compliance view
- [ ] Resource drill-down view
- [ ] Compliance trends and history chart
- [ ] Enterprise report generator form
- [ ] Report export and download
- [ ] Filtering and search functionality
- [ ] Bulk remediation actions
- [ ] Real-time updates (polling)

---

## 🔍 Missing API Endpoints to Create

Based on the UI requirements, the following endpoints may need to be added:

### 1. Account-Specific Compliance
```
GET /api/v1/compliance/accounts/{account_id}?scan_id={scan_id}&csp={csp}
```
Returns compliance status for a specific account across all frameworks.

### 2. Compliance Trends
```
GET /api/v1/compliance/trends?csp={csp}&account_id={account_id}&days={days}
```
Returns historical compliance scores and trends over time.

### 3. Control Detail
```
GET /api/v1/compliance/framework/{framework}/control/{control_id}?scan_id={scan_id}&csp={csp}
```
Returns detailed information about a specific control.

### 4. List Reports
```
GET /api/v1/compliance/reports?tenant_id={tenant_id}&limit={limit}&offset={offset}
```
Returns list of generated reports for a tenant.

### 5. Report Status
```
GET /api/v1/compliance/reports/{report_id}/status
```
Returns generation status for async report generation.

### 6. Delete Report
```
DELETE /api/v1/compliance/reports/{report_id}
```
Deletes a compliance report.

### 7. Framework List
```
GET /api/v1/compliance/frameworks?csp={csp}
```
Returns list of available compliance frameworks for a CSP.

### 8. Control Search
```
GET /api/v1/compliance/controls/search?query={query}&framework={framework}&csp={csp}
```
Search for controls across frameworks.

---

## 📝 Notes

- All existing endpoints are ready: `/api/v1/compliance/generate`, `/api/v1/compliance/framework/{framework}/status`, `/api/v1/compliance/resource/drilldown`, `/api/v1/compliance/generate/enterprise`
- Missing endpoints listed above should be implemented for full UI functionality
- Historical trend tracking requires database storage of compliance scores over time
- Account filtering may need to be added to existing endpoints or new endpoints created
