# Data Security UI - Screen Mockups

## UI Flow & Data Mapping

---

## 🏠 Screen 1: Executive Dashboard

**URL**: `/dashboard`

**Purpose**: High-level security posture overview

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  DATA SECURITY OVERVIEW                 Scan: latest (Today)     │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  KEY METRICS                                                      │
│  ┌──────────────┬──────────────┬──────────────┬──────────────┐  │
│  │ 🗄️ 117       │ ⚠️ 2,429     │ 🌍 67/117    │ 📊 72%       │  │
│  │ Data Stores  │ Findings     │ Compliant    │ Security     │  │
│  │ Discovered   │ (100% DS)    │ Regions      │ Score        │  │
│  └──────────────┴──────────────┴──────────────┴──────────────┘  │
│                                                                   │
│  FINDINGS BY MODULE                     [View Details →]         │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ 🔐 Protection/Encryption    ████████░░  1,791 (74%)       │ │
│  │ 🚪 Access Governance        ████░░░░░░    668 (28%)       │ │
│  │ 📋 Compliance               ██░░░░░░░░    360 (15%)       │ │
│  │ 📊 Activity Monitoring      █░░░░░░░░░    273 (11%)       │ │
│  │ 🌍 Data Residency          ░░░░░░░░░░    134 (6%)        │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  TOP RISKS REQUIRING ATTENTION              [Show All →]         │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ 🔴 CRITICAL: 67 RDS instances without encryption           │ │
│  │    Impact: GDPR Art.32, PCI Req.3.4, HIPAA §164.312       │ │
│  │    Accounts: 155052200811, 194722442770                    │ │
│  │    [View Details] [Start Remediation]                      │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ 🔴 CRITICAL: 25 publicly accessible S3 buckets             │ │
│  │    Contains: PII (High Confidence)                         │ │
│  │    Risk: Data breach, unauthorized access                  │ │
│  │    [Emergency Lockdown] [View Buckets]                     │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ 🟡 MEDIUM: 15 DynamoDB tables missing backup               │ │
│  │    Impact: GDPR Art.5(1)(e) - Storage limitation          │ │
│  │    [Configure Backups]                                     │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  QUICK ACTIONS                                                    │
│  [📥 Export Report] [🔧 Bulk Remediate] [⚙️ Configure Policies] │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// On page load
const summary = await fetch('/api/v1/data-security/findings?csp=aws&scan_id=latest')
const catalog = await fetch('/api/v1/data-security/catalog?csp=aws&scan_id=latest')
const residency = await fetch('/api/v1/data-security/residency?csp=aws&scan_id=latest')

// Calculate security score
const securityScore = (summary.summary.by_status.PASS / summary.summary.total_findings * 100)

// Top risks = FAIL findings with priority=high, sorted by count
const topRisks = summary.findings
  .filter(f => f.status === 'FAIL' && f.data_security_context?.priority === 'high')
  .slice(0, 5)
```

---

## 🗂️ Screen 2: Data Catalog

**URL**: `/catalog`

**Purpose**: Browse and search all data stores

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  DATA CATALOG                    🔍 [Search resources...]         │
├──────────────────────────────────────────────────────────────────┤
│  FILTERS                                                          │
│  Account: [All ▼] | Service: [All ▼] | Region: [All ▼]          │
│  Status: [All ▼] | Classification: [All ▼]                       │
│                                                                   │
│  📊 Showing 117 resources | 3 accounts | 17 regions              │
│                                                                   │
│  GROUP BY: [Account ▼]                          [🗃️ Card] [📋 List]│
│                                                                   │
│  ▼ Account: 155052200811 (AWS)                    75 resources   │
│    ├─ ▼ ap-south-1 (25 resources)                                │
│    │   ├─ 🗄️ DynamoDB Tables (21)                  [Expand ▼]   │
│    │   │   ┌──────────────────────────────────────────────────┐ │
│    │   │   │ threat-engine-accounts                           │ │
│    │   │   │ DynamoDB Table | ap-south-1                      │ │
│    │   │   │ ❌ 5 Critical  🟡 3 Medium  ✅ 12 Passed         │ │
│    │   │   │ 📊 Contains: PII | Encrypted: ✅ | Backup: ❌    │ │
│    │   │   │ [View Details →]                                 │ │
│    │   │   └──────────────────────────────────────────────────┘ │
│    │   │                                                          │
│    │   ├─ 🗃️ RDS Instances (3)                                  │
│    │   └─ 🐘 Neptune Databases (1)                              │
│    │                                                              │
│    └─ ▶ us-east-1 (6 resources)                                 │
│                                                                   │
│  ▶ Account: 194722442770 (AWS)                    35 resources   │
│  ▶ Account: 588989875114 (AWS)                     7 resources   │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// Initial load
const catalog = await fetch('/api/v1/data-security/catalog?csp=aws&scan_id=latest')

// Filter by account
const filtered = await fetch('/api/v1/data-security/catalog?csp=aws&scan_id=latest&account_id=155052200811')

// Get findings count per resource (for red/yellow/green badges)
const findings = await fetch('/api/v1/data-security/findings?csp=aws&scan_id=latest')
// Group findings by resource_id in UI
```

**Data Display**:
- Resource cards with quick status
- Filterable/searchable list
- Grouped by account/service/region
- Click → navigate to Resource Detail

---

## 🔍 Screen 3: Resource Detail

**URL**: `/resources/{resource_arn}`

**Purpose**: Complete security analysis for one resource

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  ◀ Back to Catalog                                               │
├──────────────────────────────────────────────────────────────────┤
│  📦 threat-engine-accounts                                        │
│  arn:aws:dynamodb:ap-south-1:155052200811:table/threat-engine... │
│                                                                   │
│  RESOURCE INFO                                                    │
│  Service: DynamoDB Table | Region: ap-south-1 | Account: 155...  │
│  Status: ✅ Active | Health: 🟢 Healthy | Created: 2025-12-15   │
│  Tags: env=prod, team=security, cost-center=engineering          │
│                                                                   │
│  SECURITY SCORE: 68% 🟡                                          │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ ✅ 12 Passed  │  ❌ 5 Failed  │  🟡 3 Warnings            │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
│  ┌─ TABS ──────────────────────────────────────────────────┐   │
│  │ [Overview] [Protection] [Governance] [Compliance] [...]  │   │
│  ├──────────────────────────────────────────────────────────┤   │
│  │ 🔐 PROTECTION & ENCRYPTION (5 findings)                  │   │
│  │                                                           │   │
│  │ ┌─────────────────────────────────────────────────────┐ │   │
│  │ │ ❌ FAIL | HIGH PRIORITY                              │ │   │
│  │ │ DAX Cluster Encryption Not Enabled                   │ │   │
│  │ │ Rule: aws.dynamodb.accelerator.cluster_encryption... │ │   │
│  │ │                                                       │ │   │
│  │ │ 📋 Compliance Impact:                                │ │   │
│  │ │ • GDPR Article 32 - Encryption requirement          │ │   │
│  │ │ • PCI Requirement 3.4 - Render PAN unreadable        │ │   │
│  │ │ • HIPAA §164.312(a)(2)(iv) - Encryption of ePHI     │ │   │
│  │ │                                                       │ │   │
│  │ │ 💡 Why This Matters:                                 │ │   │
│  │ │ Encryption is mandatory for resources containing:    │ │   │
│  │ │ - PII (personally identifiable information)          │ │   │
│  │ │ - PCI data (credit card information)                 │ │   │
│  │ │ - PHI (protected health information)                 │ │   │
│  │ │                                                       │ │   │
│  │ │ 🔧 REMEDIATION STEPS:                                │ │   │
│  │ │ 1. Open DynamoDB console                             │ │   │
│  │ │ 2. Select DAX cluster                                │ │   │
│  │ │ 3. Navigate to Settings > Encryption                 │ │   │
│  │ │ 4. Enable encryption at rest                         │ │   │
│  │ │ 5. Select KMS key                                    │ │   │
│  │ │                                                       │ │   │
│  │ │ [📖 AWS Docs] [▶️ Auto-Remediate] [🔕 Suppress]     │ │   │
│  │ └─────────────────────────────────────────────────────┘ │   │
│  │                                                           │   │
│  │ ✅ PASS | aws.dynamodb.table.encryption_at_rest_enabled  │   │
│  │    Server-side encryption is properly configured         │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
│  [Classification] Tab shows: PII, SENSITIVE (Confidence: 0.89)   │
│  [Residency] Tab shows: ap-south-1 ✅ Compliant                 │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// Resource ARN from URL params
const resourceArn = decodeURIComponent(params.arn)

// Load all data in parallel
const [resource, findings, classification, residency, rules] = await Promise.all([
  fetch(`/api/v1/data-security/catalog?csp=aws&scan_id=latest&resource_id=${resourceArn}`),
  fetch(`/api/v1/data-security/findings?csp=aws&scan_id=latest&resource_id=${resourceArn}`),
  fetch(`/api/v1/data-security/classification?csp=aws&scan_id=latest&resource_id=${resourceArn}`),
  fetch(`/api/v1/data-security/residency?csp=aws&scan_id=latest&resource_id=${resourceArn}`),
  // For each failing finding, get rule details
  Promise.all(
    failedFindings.map(f => 
      fetch(`/api/v1/data-security/rules/${f.rule_id}?service=${f.service}`)
    )
  )
])
```

---

## 🔐 Screen 4: Protection & Encryption Dashboard

**URL**: `/modules/protection`

**Purpose**: Focus on encryption and data protection

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  🔐 DATA PROTECTION & ENCRYPTION                                  │
├──────────────────────────────────────────────────────────────────┤
│  ENCRYPTION STATUS                                                │
│  ┌──────────────┬──────────────┬────────────────────────────┐   │
│  │ ❌ 1,100      │ ✅ 691       │ Encryption Rate: 39%       │   │
│  │ Unencrypted   │ Encrypted    │ Target: 100%               │   │
│  │ Resources     │ Resources    │ Gap: 1,100 resources       │   │
│  └──────────────┴──────────────┴────────────────────────────┘   │
│                                                                   │
│  ENCRYPTION BY SERVICE                  [Export Report ↓]        │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ RDS         ██████░░░░░░░  67 unencrypted   ❌ 39%        │ │
│  │ S3          ████████░░░░░  45 unencrypted   🟡 64%        │ │
│  │ DynamoDB    █████████░░░░  12 unencrypted   🟢 75%        │ │
│  │ Redshift    ██████████░░░   3 unencrypted   🟢 83%        │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  CRITICAL ENCRYPTION GAPS              [Filter: All ▼] [Sort ▼]  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ [Select All] 1,100 resources                               │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ ☐ RDS Security Group (default)                 ap-south-1  │ │
│  │   Account: 155052200811 | 15 instances affected           │ │
│  │   Rule: aws.rds.instance.storage_encrypted                │ │
│  │   [Remediate] [View Instances]                            │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ ☐ S3 Bucket (user-uploads)                     us-east-1  │ │
│  │   Contains: PII | Public Access: ❌                       │ │
│  │   Rule: aws.s3.bucket.default_encryption_enabled          │ │
│  │   [Enable Encryption] [View Details]                      │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  [Bulk Actions ▼] [Schedule Remediation] [Create Jira Tickets]   │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// Load encryption findings
const protection = await fetch(
  '/api/v1/data-security/findings?csp=aws&scan_id=latest&module=data_protection_encryption'
)

// Calculate encryption rate per service
const rdsFindings = await fetch(
  '/api/v1/data-security/services/rds?csp=aws&scan_id=latest'
)
const rdsEncryptionRate = rdsFindings.summary.findings_by_status.PASS / 
                          rdsFindings.summary.total_findings * 100
```

---

## 📋 Screen 5: Compliance Dashboard

**URL**: `/compliance`

**Purpose**: Track compliance across frameworks

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  📋 COMPLIANCE STATUS                                             │
├──────────────────────────────────────────────────────────────────┤
│  SELECT FRAMEWORK: [GDPR] [PCI DSS] [HIPAA] [SOC 2] [ISO 27001]  │
│                                                                   │
│  🇪🇺 GDPR COMPLIANCE                                              │
│  Overall Score: 72% ████████░░                                   │
│                                                                   │
│  BY ARTICLE                                    [View Roadmap →]  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Art. 32 (Security Measures)        45/67  ❌ 67%          │ │
│  │ ├─ Encryption at rest               45/67 compliant        │ │
│  │ ├─ Encryption in transit            67/67 compliant ✅     │ │
│  │ └─ Pseudonymization                 23/67 compliant        │ │
│  │                                                             │ │
│  │ Art. 25 (Privacy by Design)        23/50  ❌ 46%          │ │
│  │ ├─ Access controls                  23/50 compliant        │ │
│  │ └─ Data minimization                15/50 compliant        │ │
│  │                                                             │ │
│  │ Art. 30 (Records of Processing)    89/100 ✅ 89%          │ │
│  │ ├─ Audit logging                    89/100 compliant       │ │
│  │ └─ Access records                   100/100 compliant ✅   │ │
│  │                                                             │ │
│  │ Ch. V (Data Transfers)             67/117 🟡 57%          │ │
│  │ └─ Geographic restrictions          67/117 compliant       │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  FAILING CONTROLS (238 findings)           [Show All →]          │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ ❌ Art. 32: 67 resources without encryption                │ │
│  │    Affected: RDS instances across 5 regions                │ │
│  │    [View Resources] [Bulk Remediate]                       │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  [📥 Export Audit Report] [📅 Schedule Review] [📊 Trends]      │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// Load GDPR compliance
const gdpr = await fetch('/api/v1/data-security/compliance?csp=aws&scan_id=latest&framework=gdpr')

// Calculate compliance per article (group by impact.gdpr in UI)
const byArticle = {}
gdpr.findings.forEach(f => {
  const article = f.data_security_context?.impact?.gdpr
  if (article) {
    if (!byArticle[article]) byArticle[article] = {pass: 0, fail: 0}
    if (f.status === 'PASS') byArticle[article].pass++
    else byArticle[article].fail++
  }
})

// Switch framework
const pci = await fetch('/api/v1/data-security/compliance?csp=aws&scan_id=latest&framework=pci')
const hipaa = await fetch('/api/v1/data-security/compliance?csp=aws&scan_id=latest&framework=hipaa')
```

---

## 🌍 Screen 6: Data Residency Map

**URL**: `/residency`

**Purpose**: Geographic compliance and data location tracking

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  🌍 DATA RESIDENCY & GEOGRAPHIC COMPLIANCE                        │
├──────────────────────────────────────────────────────────────────┤
│  POLICY CONFIGURATION                                             │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Policy: tenant_policy                         [Edit ▼]     │ │
│  │ Allowed Regions: 🟢 us-east-1, us-west-2, ap-south-1      │ │
│  │ Restricted: 🔴 eu-*, cn-*, other regions                  │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  [Interactive World Map]                                          │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                    🗺️ WORLD MAP                           │ │
│  │                                                             │ │
│  │  North America:                                             │ │
│  │  • us-east-1    ✅ 45 resources (compliant)                │ │
│  │  • us-west-2    ✅ 22 resources (compliant)                │ │
│  │                                                             │ │
│  │  Asia Pacific:                                              │ │
│  │  • ap-south-1   ✅ 25 resources (compliant)                │ │
│  │  • ap-northeast-1  ⚪ 15 resources (no policy)             │ │
│  │                                                             │ │
│  │  Europe:                                                    │ │
│  │  • eu-central-1 ❌ 10 resources (NON-COMPLIANT)            │ │
│  │                                                             │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  COMPLIANCE SUMMARY                                               │
│  ✅ 67 Compliant  |  ❌ 50 Non-Compliant  |  ⚪ 0 Unknown        │
│                                                                   │
│  NON-COMPLIANT RESOURCES (50)          [Export List →]           │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ 🔴 eu-central-1 (10 resources)                             │ │
│  │    • arn:aws:rds:eu-central-1:...:db:prod-db-eu            │ │
│  │    • arn:aws:dynamodb:eu-central-1:...:table/user-data-eu  │ │
│  │    Action Required: Migrate to allowed region              │ │
│  │    [Start Migration Wizard] [Request Exception]            │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  CROSS-REGION REPLICATION                                         │
│  5 resources replicate to non-allowed regions                    │
│  [Review Replication Rules]                                      │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// Load residency with policy
const residency = await fetch(
  '/api/v1/data-security/residency?csp=aws&scan_id=latest&allowed_regions=us-east-1,us-west-2,ap-south-1'
)

// Group by region for map
const byRegion = {}
residency.results.forEach(r => {
  const region = r.primary_region
  if (!byRegion[region]) byRegion[region] = {compliant: 0, nonCompliant: 0, resources: []}
  if (r.compliance_status === 'compliant') byRegion[region].compliant++
  else byRegion[region].nonCompliant++
  byRegion[region].resources.push(r)
})
```

---

## 🏢 Screen 7: Account Dashboard

**URL**: `/accounts/{account_id}`

**Purpose**: Complete security view for one account

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  🏢 ACCOUNT: 155052200811 (AWS)                                   │
├──────────────────────────────────────────────────────────────────┤
│  OVERVIEW                                                         │
│  ┌──────────────┬──────────────┬──────────────┬──────────────┐  │
│  │ 75 Data      │ 1,500        │ 17 Regions   │ 4 Services   │  │
│  │ Stores       │ Findings     │ Active       │ In Use       │  │
│  └──────────────┴──────────────┴──────────────┴──────────────┘  │
│                                                                   │
│  SECURITY BY SERVICE                       [View All Services →] │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Service      │ Resources │ Critical │ High │ Medium │ Low  │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ 🗄️ DynamoDB  │    35     │    5     │  12  │   8    │  10  │ │
│  │ 🗃️ RDS       │    25     │   15     │  18  │   5    │   7  │ │
│  │ 🪣 S3        │    12     │    2     │   5  │   3    │   2  │ │
│  │ 📊 Redshift  │     3     │    0     │   2  │   1    │   0  │ │
│  └────────────────────────────────────────────────────────────┘ │
│  [Click service for details →]                                   │
│                                                                   │
│  FINDINGS BY MODULE                                               │
│  Protection: 800 | Governance: 400 | Compliance: 200 | ...       │
│                                                                   │
│  REGIONAL DISTRIBUTION                      [View Map →]          │
│  ap-south-1: 25 resources | us-east-1: 20 resources | ...        │
│                                                                   │
│  RECENT CHANGES (Last 7 days)                                    │
│  • 3 new DynamoDB tables created (2 encrypted ✅, 1 not ❌)      │
│  • 5 findings remediated                                         │
│  • Security score improved by 2.3%                               │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// Load account data
const account = await fetch('/api/v1/data-security/accounts/155052200811?csp=aws&scan_id=latest')

// Load each service
const services = account.summary.services
const serviceDetails = await Promise.all(
  services.map(svc => 
    fetch(`/api/v1/data-security/services/${svc}?csp=aws&scan_id=latest&account_id=155052200811`)
  )
)
```

---

## 🛠️ Screen 8: Service Dashboard

**URL**: `/services/{service}`

**Purpose**: Security metrics for a specific service (e.g., RDS, S3)

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  🗃️ RDS SERVICE SECURITY                                          │
├──────────────────────────────────────────────────────────────────┤
│  OVERVIEW                                                         │
│  ┌──────────────┬──────────────┬──────────────┬──────────────┐  │
│  │ 35 RDS       │ 450          │ 2 Accounts   │ 12 Regions   │  │
│  │ Instances    │ Findings     │ Using RDS    │ Deployed     │  │
│  └──────────────┴──────────────┴──────────────┴──────────────┘  │
│                                                                   │
│  COMMON MISCONFIGURATIONS                  [View All →]          │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ 1. Storage not encrypted           67 instances ❌         │ │
│  │    Impact: GDPR, PCI, HIPAA                                │ │
│  │    [Bulk Remediate]                                        │ │
│  │                                                             │ │
│  │ 2. Public access enabled           25 instances ❌         │ │
│  │    Risk: Data breach, unauthorized access                  │ │
│  │    [Block Public Access]                                   │ │
│  │                                                             │ │
│  │ 3. Backup retention < 7 days       15 instances 🟡        │ │
│  │    Impact: GDPR Art.5, data loss risk                      │ │
│  │    [Configure Backups]                                     │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  BEST/WORST PERFORMERS                                            │
│  ✅ Best:  Account 194722442770 - 95% compliant                  │
│  ❌ Worst: Account 155052200811 - 45% compliant                  │
│                                                                   │
│  FINDINGS BY ACCOUNT                      [Filter ▼] [Export →]  │
│  Account 155052200811: 250 findings (150 FAIL)                   │
│  Account 194722442770: 200 findings (50 FAIL)                    │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// Load service overview
const service = await fetch('/api/v1/data-security/services/rds?csp=aws&scan_id=latest')

// Group findings by rule_id to find common issues
const commonIssues = {}
service.findings.forEach(f => {
  if (f.status === 'FAIL') {
    if (!commonIssues[f.rule_id]) {
      commonIssues[f.rule_id] = {
        count: 0,
        rule: f.rule_id,
        priority: f.data_security_context?.priority
      }
    }
    commonIssues[f.rule_id].count++
  }
})

// Sort by count to get most common issues
const topIssues = Object.values(commonIssues).sort((a, b) => b.count - a.count)
```

---

## 📊 Data Fields Reference

### Discovery Catalog (`/catalog`)
```json
{
  "resource_id": "arn:aws:dynamodb:...",
  "resource_arn": "...",
  "resource_uid": "...",
  "resource_type": "dynamodb:table",
  "service": "dynamodb",
  "region": "ap-south-1",
  "account_id": "155052200811",
  "name": "threat-engine-accounts",
  "tags": {"env": "prod", "team": "security"},
  "lifecycle_state": "ACTIVE",
  "health_status": "Healthy"
}
```

### Findings (`/findings`)
```json
{
  "scan_run_id": "latest",
  "rule_id": "aws.rds.instance.storage_encrypted",
  "status": "FAIL",
  "resource_arn": "...",
  "service": "rds",
  "region": "ap-south-1",
  "account_id": "155052200811",
  "data_security_modules": ["data_protection_encryption"],
  "is_data_security_relevant": true,
  "data_security_context": {
    "modules": [...],
    "categories": [...],
    "priority": "high",
    "impact": {
      "gdpr": "Article 32 - Encryption requirement",
      "pci": "Requirement 3.4 - Render PAN unreadable",
      "hipaa": "§164.312(a)(2)(iv) - Encryption of ePHI"
    },
    "sensitive_data_context": "Why this matters..."
  }
}
```

### Classification (`/classification`)
```json
{
  "resource_arn": "...",
  "classification": ["PII", "SENSITIVE"],
  "confidence": 0.92,
  "matched_patterns": ["table_name:accounts", "contains:user_data"]
}
```

### Residency (`/residency`)
```json
{
  "resource_arn": "...",
  "primary_region": "ap-south-1",
  "replication_regions": [],
  "policy_name": "tenant_policy",
  "compliance_status": "compliant",
  "violations": []
}
```

---

## 🎨 UI Component Library Recommendations

1. **Charts**: Recharts, Chart.js, or D3.js
2. **Tables**: TanStack Table (React Table v8)
3. **Maps**: Leaflet or MapBox for geographic visualization
4. **Graphs**: Cytoscape.js or React Flow for lineage graphs
5. **Framework**: React, Vue, or Angular
6. **State**: Redux/Zustand or React Query for API caching

---

## ✅ Implementation Checklist for Frontend

- [ ] Executive Dashboard with metrics cards
- [ ] Data Catalog with search/filter
- [ ] Resource Detail with tabbed view
- [ ] Protection Dashboard with encryption metrics
- [ ] Governance Dashboard with access risks
- [ ] Compliance Dashboard with framework selector
- [ ] Residency Dashboard with map
- [ ] Account view with service breakdown
- [ ] Service view with common issues
- [ ] Remediation modal with steps from rule metadata
- [ ] Export functionality (PDF/CSV)
- [ ] Real-time updates (polling)

**All APIs are ready - UI can be built immediately!**

