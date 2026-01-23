# Threat Engine UI - Screen Mockups

## UI Flow & Data Mapping

---

## 🏠 Screen 1: Threat Dashboard

**URL**: `/dashboard`

**Purpose**: High-level threat overview and security posture

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  THREAT OVERVIEW                    Scan: latest (Today)        │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  KEY METRICS                                                      │
│  ┌──────────────┬──────────────┬──────────────┬──────────────┐  │
│  │ 🔴 47         │ ⚠️ 23        │ 🟡 12        │ 📊 82%       │  │
│  │ Critical      │ High         │ Medium       │ Threat       │  │
│  │ Threats       │ Threats      │ Threats      │ Coverage     │  │
│  └──────────────┴──────────────┴──────────────┴──────────────┘  │
│                                                                   │
│  THREATS BY CATEGORY                    [View Details →]         │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ 🌐 Exposure Threats          ████████░░  18 (38%)         │ │
│  │ 🔐 Identity Threats          ██████░░░░░  12 (26%)         │ │
│  │ 🔄 Lateral Movement          ████░░░░░░░   8 (17%)        │ │
│  │ 📤 Data Exfiltration          ███░░░░░░░░   5 (11%)        │ │
│  │ ⬆️  Privilege Escalation      ██░░░░░░░░░   3 (6%)         │ │
│  │ 💥 Data Breach                █░░░░░░░░░░   1 (2%)         │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  TOP CRITICAL THREATS                        [Show All →]        │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ 🔴 CRITICAL: Public S3 Bucket with Sensitive Data          │ │
│  │    Type: Data Exfiltration | Confidence: High             │ │
│  │    Affected: s3://user-data-prod (us-east-1)               │ │
│  │    Root Cause: 3 misconfig findings                         │ │
│  │    [View Details] [Start Remediation]                     │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ 🔴 CRITICAL: IAM Role with Privilege Escalation           │ │
│  │    Type: Privilege Escalation | Confidence: High           │ │
│  │    Affected: arn:aws:iam::155052200811:role/admin-role    │ │
│  │    Risk: Can create admin roles, attach policies          │ │
│  │    [View Details] [Revoke Permissions]                    │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ 🔴 CRITICAL: RDS Instance Publicly Accessible             │ │
│  │    Type: Data Breach | Confidence: High                   │ │
│  │    Affected: prod-db (ap-south-1)                         │ │
│  │    Contains: PII, PCI data                               │ │
│  │    [Emergency Lockdown] [View Details]                    │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  THREAT TREND (Last 30 Days)                                     │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  Threats                                                     │ │
│  │  50│                                                         │ │
│  │  40│     ●                                                    │ │
│  │  30│   ●   ●                                                  │ │
│  │  20│ ●     ●   ●                                              │ │
│  │  10│●         ●   ●                                           │ │
│  │   0└─────────────────────────────────────────────────────│ │
│  │     1/1  1/8  1/15 1/22 1/29                               │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  QUICK ACTIONS                                                    │
│  [📥 Export Report] [🔧 Bulk Remediate] [⚙️ Configure Detection] │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// On page load - need to generate threat report first
const report = await fetch('/api/v1/threat/generate', {
  method: 'POST',
  body: JSON.stringify({
    tenant_id: 'tenant-123',
    scan_run_id: 'latest',
    cloud: 'aws',
    trigger_type: 'manual',
    accounts: ['155052200811'],
    regions: ['us-east-1', 'ap-south-1'],
    services: [],
    started_at: '2025-01-18T00:00:00Z',
    completed_at: '2025-01-18T01:00:00Z'
  })
})

// Extract metrics from report
const summary = report.threat_summary
const criticalCount = summary.threats_by_severity.critical || 0
const highCount = summary.threats_by_severity.high || 0
const mediumCount = summary.threats_by_severity.medium || 0

// Top threats = threats sorted by severity, then by confidence
const topThreats = report.threats
  .filter(t => t.severity === 'critical')
  .sort((a, b) => {
    if (a.confidence !== b.confidence) {
      return b.confidence === 'high' ? 1 : -1
    }
    return 0
  })
  .slice(0, 5)
```

**Missing API Endpoints Needed**:
- `GET /api/v1/threat/reports/{scan_run_id}` - Get existing threat report
- `GET /api/v1/threat/summary?scan_run_id=latest` - Get just summary stats
- `GET /api/v1/threat/trend?days=30` - Get threat trend over time

---

## 🔍 Screen 2: Threat List

**URL**: `/threats`

**Purpose**: Browse and filter all detected threats

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  THREAT LIST                    🔍 [Search threats...]          │
├──────────────────────────────────────────────────────────────────┤
│  FILTERS                                                          │
│  Severity: [All ▼] | Type: [All ▼] | Status: [All ▼]            │
│  Account: [All ▼] | Region: [All ▼] | Confidence: [All ▼]       │
│                                                                   │
│  📊 Showing 82 threats | 3 accounts | 17 regions                │
│                                                                   │
│  GROUP BY: [Category ▼]                    [🗃️ Card] [📋 List] │
│                                                                   │
│  ▼ Exposure Threats (18 threats)                                 │
│    ┌──────────────────────────────────────────────────────────┐ │
│    │ ☐ 🔴 CRITICAL | High Confidence                          │ │
│    │   Public S3 Bucket with Sensitive Data                   │ │
│    │   s3://user-data-prod | us-east-1 | Account: 155052200811│ │
│    │   Root Cause: 3 misconfig findings                        │ │
│    │   First Seen: 2025-01-15 | Last Seen: 2025-01-18         │ │
│    │   [View Details] [Remediate] [Suppress]                  │ │
│    ├──────────────────────────────────────────────────────────┤ │
│    │ ☐ ⚠️ HIGH | Medium Confidence                            │ │
│    │   EC2 Security Group Allows All Traffic                  │ │
│    │   sg-12345678 | ap-south-1 | Account: 155052200811      │ │
│    │   Root Cause: 2 misconfig findings                       │ │
│    │   [View Details] [Remediate]                             │ │
│    └──────────────────────────────────────────────────────────┘ │
│                                                                   │
│  ▼ Identity Threats (12 threats)                                 │
│    ┌──────────────────────────────────────────────────────────┐ │
│    │ ☐ 🔴 CRITICAL | High Confidence                          │ │
│    │   IAM Role with Privilege Escalation                     │ │
│    │   arn:aws:iam::155052200811:role/admin-role              │ │
│    │   Can create roles, attach policies                      │ │
│    │   [View Details] [Revoke Permissions]                    │ │
│    └──────────────────────────────────────────────────────────┘ │
│                                                                   │
│  ▼ Lateral Movement (8 threats)                                  │
│  ▼ Data Exfiltration (5 threats)                                │
│  ▼ Privilege Escalation (3 threats)                             │
│  ▼ Data Breach (1 threat)                                        │
│                                                                   │
│  [Select All] [Bulk Actions ▼] [Export Selected]                │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// Load threat report
const report = await fetch('/api/v1/threat/generate', {
  method: 'POST',
  body: JSON.stringify({
    tenant_id: 'tenant-123',
    scan_run_id: 'latest',
    cloud: 'aws',
    // ... other params
  })
})

// Filter threats in UI
const filteredThreats = report.threats.filter(t => {
  if (severityFilter && t.severity !== severityFilter) return false
  if (typeFilter && t.threat_type !== typeFilter) return false
  if (statusFilter && t.status !== statusFilter) return false
  // ... more filters
  return true
})

// Group by category
const grouped = filteredThreats.reduce((acc, threat) => {
  const category = threat.threat_type
  if (!acc[category]) acc[category] = []
  acc[category].push(threat)
  return acc
}, {})
```

**Missing API Endpoints Needed**:
- `GET /api/v1/threat/list?scan_run_id=latest&severity=critical&type=exposure` - Filtered threat list
- `GET /api/v1/threat/{threat_id}` - Get single threat details
- `PATCH /api/v1/threat/{threat_id}/status` - Update threat status (resolved, suppressed, etc.)

---

## 📋 Screen 3: Threat Detail

**URL**: `/threats/{threat_id}`

**Purpose**: Detailed view of a single threat with correlations and remediation

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  ◀ Back to Threat List                                          │
├──────────────────────────────────────────────────────────────────┤
│  🔴 CRITICAL: Public S3 Bucket with Sensitive Data              │
│  Threat ID: thr_a1b2c3d4e5f6g7h8                                 │
│                                                                   │
│  THREAT INFO                                                     │
│  Type: Data Exfiltration | Severity: Critical | Confidence: High │
│  Status: Open | First Seen: 2025-01-15 | Last Seen: 2025-01-18  │
│  Account: 155052200811 | Region: us-east-1                       │
│                                                                   │
│  DESCRIPTION                                                     │
│  A publicly accessible S3 bucket contains sensitive data and     │
│  has weak logging enabled. This combination creates a high risk  │
│  of data exfiltration.                                          │
│                                                                   │
│  AFFECTED ASSETS                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ 🗄️ s3://user-data-prod                                    │   │
│  │    Resource Type: s3:bucket                               │   │
│  │    ARN: arn:aws:s3:::user-data-prod                       │   │
│  │    Region: us-east-1 | Account: 155052200811              │   │
│  │    Tags: env=prod, team=engineering, data-class=sensitive │   │
│  │    [View in AWS Console] [View Resource Details]        │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
│  ┌─ TABS ──────────────────────────────────────────────────┐   │
│  │ [Overview] [Root Causes] [Evidence] [Remediation] [...]  │   │
│  ├──────────────────────────────────────────────────────────┤   │
│  │ 🔍 ROOT CAUSE MISCONFIGURATIONS (3 findings)             │   │
│  │                                                           │   │
│  │ ┌─────────────────────────────────────────────────────┐ │   │
│  │ │ ❌ FAIL | HIGH SEVERITY                              │ │   │
│  │ │ S3 Bucket Public Access Enabled                      │ │   │
│  │ │ Rule: aws.s3.bucket.public_access_block_enabled     │ │   │
│  │ │ Finding ID: mf_abc123                                │ │   │
│  │ │                                                       │ │   │
│  │ │ Resource: s3://user-data-prod                        │ │   │
│  │ │ Account: 155052200811 | Region: us-east-1            │ │   │
│  │ │                                                       │ │   │
│  │ │ [View Finding Details] [Remediate This Issue]       │ │   │
│  │ └─────────────────────────────────────────────────────┘ │   │
│  │                                                           │   │
│  │ ┌─────────────────────────────────────────────────────┐ │   │
│  │ │ ❌ FAIL | MEDIUM SEVERITY                            │ │   │
│  │ │ S3 Bucket Logging Not Enabled                        │ │   │
│  │ │ Rule: aws.s3.bucket.logging_enabled                 │ │   │
│  │ │ Finding ID: mf_def456                                │ │   │
│  │ │                                                       │ │   │
│  │ │ [View Finding Details] [Remediate This Issue]       │ │   │
│  │ └─────────────────────────────────────────────────────┘ │   │
│  │                                                           │   │
│  │ ┌─────────────────────────────────────────────────────┐ │   │
│  │ │ ❌ FAIL | HIGH SEVERITY                             │ │   │
│  │ │ S3 Bucket Encryption Not Enabled                    │ │   │
│  │ │ Rule: aws.s3.bucket.default_encryption_enabled     │ │   │
│  │ │ Finding ID: mf_ghi789                               │ │   │
│  │ │                                                       │ │   │
│  │ │ [View Finding Details] [Remediate This Issue]      │ │   │
│  │ └─────────────────────────────────────────────────────┘ │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
│  🔧 REMEDIATION GUIDANCE                                         │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Summary: Review and remediate 3 misconfigurations to     │   │
│  │ mitigate this threat.                                     │   │
│  │                                                           │   │
│  │ Steps:                                                    │   │
│  │ 1. Review misconfig findings: mf_abc123, mf_def456, ...  │   │
│  │ 2. Enable S3 bucket public access block                  │   │
│  │ 3. Enable S3 bucket logging                              │   │
│  │ 4. Enable S3 bucket encryption                           │   │
│  │ 5. Re-scan to verify threat is resolved                  │   │
│  │                                                           │   │
│  │ [📖 AWS Documentation] [▶️ Auto-Remediate] [Create Ticket]│   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
│  THREAT STATUS                                                   │
│  [Mark as Resolved] [Suppress] [Mark as False Positive]         │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// Get threat by ID - need to load full report first
const report = await fetch('/api/v1/threat/generate', {
  method: 'POST',
  body: JSON.stringify({ /* ... */ })
})

const threat = report.threats.find(t => t.threat_id === threatId)

// Get misconfig findings referenced by threat
const misconfigFindings = report.misconfig_findings.filter(f => 
  threat.correlations.misconfig_finding_refs.includes(f.misconfig_finding_id)
)

// Get affected assets
const affectedAssets = threat.affected_assets
```

**Missing API Endpoints Needed**:
- `GET /api/v1/threat/{threat_id}` - Get single threat with full details
- `GET /api/v1/threat/{threat_id}/misconfig-findings` - Get root cause findings
- `GET /api/v1/threat/{threat_id}/assets` - Get affected assets
- `PATCH /api/v1/threat/{threat_id}` - Update threat (status, notes, etc.)

---

## 🗺️ Screen 4: Threat Map / Attack Surface

**URL**: `/threat-map`

**Purpose**: Visual representation of threats across accounts and regions

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  THREAT MAP / ATTACK SURFACE                                     │
├──────────────────────────────────────────────────────────────────┤
│  VIEW: [Geographic] [Account] [Service] [Network]               │
│                                                                   │
│  GEOGRAPHIC VIEW                                                 │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                                                             │ │
│  │                    🌍 World Map                            │ │
│  │                                                             │ │
│  │         [us-east-1] 🔴 12 threats                          │ │
│  │         [us-west-2] ⚠️  8 threats                          │ │
│  │         [ap-south-1] 🔴 15 threats                         │ │
│  │         [eu-west-1] 🟡  5 threats                          │ │
│  │                                                             │ │
│  │  Click region to filter threats                            │ │
│  │                                                             │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  ACCOUNT VIEW                                                    │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Account: 155052200811 (AWS)                                │ │
│  │ ┌──────────┬──────────┬──────────┬──────────┐           │ │
│  │ │ 🔴 12     │ ⚠️  8     │ 🟡  5     │ 📊 45%   │           │ │
│  │ │ Critical  │ High      │ Medium    │ Risk     │           │ │
│  │ └──────────┴──────────┴──────────┴──────────┘           │ │
│  │                                                             │ │
│  │ Threat Distribution by Service:                             │ │
│  │ S3         ████████░░░░░░░░░░░░  8 threats                │ │
│  │ IAM        ██████░░░░░░░░░░░░░░  6 threats                │ │
│  │ EC2        ████░░░░░░░░░░░░░░░░  4 threats                │ │
│  │ RDS        ██░░░░░░░░░░░░░░░░░░  2 threats                │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  NETWORK VIEW                                                    │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ VPC: vpc-12345678                                          │ │
│  │                                                             │ │
│  │  [Public Subnet]                                           │ │
│  │    ┌─────────────┐                                         │ │
│  │    │ EC2 Instance│ 🔴 Exposure Threat                      │ │
│  │    │ sg-abc123   │                                         │ │
│  │    └─────────────┘                                         │ │
│  │         │                                                   │ │
│  │  [Private Subnet]                                          │ │
│  │    ┌─────────────┐                                         │ │
│  │    │ RDS Instance│ 🔴 Data Breach Threat                  │ │
│  │    │ sg-def456   │                                         │ │
│  │    └─────────────┘                                         │ │
│  │                                                             │ │
│  │  [Internet Gateway]                                         │ │
│  │                                                             │ │
│  └────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// Load threat report
const report = await fetch('/api/v1/threat/generate', {
  method: 'POST',
  body: JSON.stringify({ /* ... */ })
})

// Group threats by region
const threatsByRegion = report.threats.reduce((acc, threat) => {
  const region = threat.affected_assets[0]?.region || 'unknown'
  if (!acc[region]) acc[region] = []
  acc[region].push(threat)
  return acc
}, {})

// Group threats by account
const threatsByAccount = report.threats.reduce((acc, threat) => {
  const account = threat.affected_assets[0]?.account || 'unknown'
  if (!acc[account]) acc[account] = []
  acc[account].push(threat)
  return acc
}, {})

// Group threats by service
const threatsByService = report.threats.reduce((acc, threat) => {
  const service = threat.affected_assets[0]?.resource_type?.split(':')[0] || 'unknown'
  if (!acc[service]) acc[service] = []
  acc[service].push(threat)
  return acc
}, {})
```

**Missing API Endpoints Needed**:
- `GET /api/v1/threat/map/geographic?scan_run_id=latest` - Threats grouped by region
- `GET /api/v1/threat/map/account?scan_run_id=latest` - Threats grouped by account
- `GET /api/v1/threat/map/service?scan_run_id=latest` - Threats grouped by service
- `GET /api/v1/threat/map/network?scan_run_id=latest&vpc_id=vpc-123` - Network topology with threats

---

## 📊 Screen 5: Threat Analytics

**URL**: `/analytics`

**Purpose**: Deep dive into threat patterns and trends

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  THREAT ANALYTICS                                                │
├──────────────────────────────────────────────────────────────────┤
│  TIME RANGE: [Last 7 Days ▼] [Last 30 Days] [Last 90 Days]       │
│                                                                   │
│  THREAT TRENDS                                                   │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  Threats Over Time                                          │ │
│  │  50│                                                         │ │
│  │  40│     ●                                                    │ │
│  │  30│   ●   ●                                                  │ │
│  │  20│ ●     ●   ●                                              │ │
│  │  10│●         ●   ●                                           │ │
│  │   0└─────────────────────────────────────────────────────│ │
│  │     1/1  1/8  1/15 1/22 1/29                               │ │
│  │                                                             │ │
│  │  Legend: 🔴 Critical  ⚠️ High  🟡 Medium                   │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  THREAT DISTRIBUTION                                             │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  By Category (Pie Chart)                                   │ │
│  │                                                             │ │
│  │        🌐 Exposure (38%)                                   │ │
│  │     🔐 Identity (26%)                                       │ │
│  │  🔄 Lateral Movement (17%)                                  │ │
│  │  📤 Data Exfiltration (11%)                                 │ │
│  │  ⬆️  Privilege Escalation (6%)                              │ │
│  │  💥 Data Breach (2%)                                        │ │
│  │                                                             │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  TOP THREAT PATTERNS                                             │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ 1. Public S3 + No Encryption + Weak Logging                │ │
│  │    Occurrences: 8 | Severity: Critical                     │ │
│  │    [View Pattern Details]                                   │ │
│  │                                                             │ │
│  │ 2. IAM Wildcard Policy + No MFA                            │ │
│  │    Occurrences: 6 | Severity: High                         │ │
│  │    [View Pattern Details]                                   │ │
│  │                                                             │ │
│  │ 3. Open Security Group + Public Subnet                     │ │
│  │    Occurrences: 5 | Severity: High                         │ │
│  │    [View Pattern Details]                                   │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  THREAT CORRELATION MATRIX                                       │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │        Exposure  Identity  Lateral  Exfil  Escalation      │ │
│  │ Exposure    -      0.3      0.5     0.7      0.2            │ │
│  │ Identity   0.3      -      0.4     0.3      0.8            │ │
│  │ Lateral    0.5     0.4       -      0.6      0.3            │ │
│  │ Exfil      0.7     0.3      0.6      -      0.1            │ │
│  │ Escalation 0.2     0.8      0.3     0.1       -            │ │
│  │                                                             │ │
│  │ Correlation score (0-1) showing threat co-occurrence       │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  [Export Analytics] [Schedule Report] [Create Alert Rules]        │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// Load multiple threat reports for trend analysis
const reports = await Promise.all([
  fetch('/api/v1/threat/generate', { /* scan_run_id: 'scan-1' */ }),
  fetch('/api/v1/threat/generate', { /* scan_run_id: 'scan-2' */ }),
  // ... more scans
])

// Calculate trends
const threatCountsByDate = reports.map(r => ({
  date: r.scan_context.completed_at,
  count: r.threat_summary.total_threats,
  bySeverity: r.threat_summary.threats_by_severity
}))

// Calculate threat patterns (group threats by misconfig combinations)
const threatPatterns = {}
reports.forEach(report => {
  report.threats.forEach(threat => {
    const patternKey = threat.correlations.misconfig_finding_refs
      .sort()
      .join('|')
    if (!threatPatterns[patternKey]) {
      threatPatterns[patternKey] = {
        pattern: patternKey,
        count: 0,
        threats: []
      }
    }
    threatPatterns[patternKey].count++
    threatPatterns[patternKey].threats.push(threat)
  })
})
```

**Missing API Endpoints Needed**:
- `GET /api/v1/threat/analytics/trend?days=30` - Threat trends over time
- `GET /api/v1/threat/analytics/patterns?scan_run_id=latest` - Common threat patterns
- `GET /api/v1/threat/analytics/correlation?scan_run_id=latest` - Threat correlation matrix
- `GET /api/v1/threat/analytics/distribution?scan_run_id=latest` - Threat distribution stats

---

## 🔧 Screen 6: Threat Remediation

**URL**: `/remediation`

**Purpose**: Track and manage threat remediation efforts

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  THREAT REMEDIATION                                              │
├──────────────────────────────────────────────────────────────────┤
│  FILTERS                                                          │
│  Status: [All ▼] | Priority: [All ▼] | Assignee: [All ▼]        │
│                                                                   │
│  REMEDIATION STATUS                                              │
│  ┌──────────────┬──────────────┬──────────────┬──────────────┐  │
│  │ 🔴 47         │ 🟡 23        │ ✅ 12        │ 📊 62%       │  │
│  │ Open          │ In Progress  │ Resolved     │ Completion   │  │
│  │ Threats       │ Threats      │ Threats      │ Rate         │  │
│  └──────────────┴──────────────┴──────────────┴──────────────┘  │
│                                                                   │
│  PRIORITY QUEUE                                                   │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ 🔴 CRITICAL - Public S3 Bucket with Sensitive Data        │ │
│  │    Status: Open | Assignee: Unassigned                     │ │
│  │    Due: 2025-01-20 | Days Overdue: 2                      │ │
│  │    [Assign to Me] [Start Remediation] [View Details]      │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ 🔴 CRITICAL - IAM Role with Privilege Escalation          │ │
│  │    Status: In Progress | Assignee: john@example.com        │ │
│  │    Started: 2025-01-18 | ETA: 2025-01-22                  │ │
│  │    Progress: 2/3 misconfigurations remediated             │ │
│  │    [View Progress] [Update Status]                         │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ ⚠️ HIGH - EC2 Security Group Allows All Traffic           │ │
│  │    Status: Open | Assignee: Unassigned                     │ │
│  │    Due: 2025-01-25 | Days Remaining: 5                    │ │
│  │    [Assign to Me] [Start Remediation]                      │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  REMEDIATION WORKFLOW                                            │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Threat: Public S3 Bucket with Sensitive Data               │ │
│  │                                                             │ │
│  │ Step 1: Enable S3 Public Access Block          ✅ Complete │ │
│  │   Finding: mf_abc123                                        │ │
│  │   Completed: 2025-01-18 10:30 AM by john@example.com      │ │
│  │                                                             │ │
│  │ Step 2: Enable S3 Bucket Logging              🟡 In Progress│ │
│  │   Finding: mf_def456                                        │ │
│  │   Started: 2025-01-18 11:00 AM by john@example.com        │ │
│  │   [Mark Complete] [Add Note]                                 │ │
│  │                                                             │ │
│  │ Step 3: Enable S3 Bucket Encryption          ⏳ Pending    │ │
│  │   Finding: mf_ghi789                                        │ │
│  │   [Start Step]                                             │ │
│  │                                                             │ │
│  │ [Mark Threat as Resolved] [Request Verification Scan]      │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  REMEDIATION HISTORY                                             │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ 2025-01-18 11:00 AM | john@example.com                    │ │
│  │   Started remediation for "Enable S3 Bucket Logging"       │ │
│  │                                                             │ │
│  │ 2025-01-18 10:30 AM | john@example.com                    │ │
│  │   Completed "Enable S3 Public Access Block"                │ │
│  │   Verification: Passed                                      │ │
│  └────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// Load threat report
const report = await fetch('/api/v1/threat/generate', {
  method: 'POST',
  body: JSON.stringify({ /* ... */ })
})

// Filter threats by status
const openThreats = report.threats.filter(t => t.status === 'open')
const inProgressThreats = report.threats.filter(t => t.status === 'in_progress')
const resolvedThreats = report.threats.filter(t => t.status === 'resolved')

// Get remediation status for each threat
const remediationStatus = threats.map(threat => ({
  threat_id: threat.threat_id,
  status: threat.status,
  misconfig_findings: threat.correlations.misconfig_finding_refs,
  // Need to check if findings are resolved
}))
```

**Missing API Endpoints Needed**:
- `GET /api/v1/threat/remediation/queue?status=open` - Get remediation queue
- `GET /api/v1/threat/{threat_id}/remediation` - Get remediation workflow for threat
- `POST /api/v1/threat/{threat_id}/remediation/assign` - Assign threat to user
- `POST /api/v1/threat/{threat_id}/remediation/step/{step_id}/complete` - Mark remediation step complete
- `POST /api/v1/threat/{threat_id}/remediation/verify` - Request verification scan
- `GET /api/v1/threat/remediation/history?threat_id={threat_id}` - Get remediation history

---

## 📊 Data Fields Reference

### Threat Report (`/api/v1/threat/generate`)
```json
{
  "schema_version": "cspm_threat_report.v1",
  "tenant": {
    "tenant_id": "tenant-123",
    "tenant_name": "Acme Corp"
  },
  "scan_context": {
    "scan_run_id": "scan-456",
    "trigger_type": "manual",
    "cloud": "aws",
    "accounts": ["155052200811"],
    "regions": ["us-east-1", "ap-south-1"],
    "services": ["s3", "iam", "ec2"],
    "started_at": "2025-01-18T00:00:00Z",
    "completed_at": "2025-01-18T01:00:00Z",
    "engine_version": "1.0.0"
  },
  "threat_summary": {
    "total_threats": 82,
    "threats_by_severity": {
      "critical": 47,
      "high": 23,
      "medium": 12
    },
    "threats_by_category": {
      "exposure": 18,
      "identity": 12,
      "lateral_movement": 8,
      "data_exfiltration": 5,
      "privilege_escalation": 3,
      "data_breach": 1
    },
    "threats_by_status": {
      "open": 70,
      "resolved": 10,
      "suppressed": 2
    },
    "top_threat_categories": [
      {
        "category": "exposure",
        "count": 18,
        "percentage": 21.95
      }
    ]
  },
  "threats": [
    {
      "threat_id": "thr_a1b2c3d4e5f6g7h8",
      "threat_type": "data_exfiltration",
      "title": "Public S3 Bucket with Sensitive Data",
      "description": "A publicly accessible S3 bucket contains sensitive data...",
      "severity": "critical",
      "confidence": "high",
      "status": "open",
      "first_seen_at": "2025-01-15T10:00:00Z",
      "last_seen_at": "2025-01-18T10:00:00Z",
      "correlations": {
        "misconfig_finding_refs": ["mf_abc123", "mf_def456", "mf_ghi789"],
        "affected_assets": [
          {
            "resource_uid": "arn:aws:s3:::user-data-prod",
            "resource_arn": "arn:aws:s3:::user-data-prod",
            "resource_id": "user-data-prod",
            "resource_type": "s3:bucket",
            "region": "us-east-1",
            "account": "155052200811"
          }
        ]
      },
      "affected_assets": [
        {
          "resource_uid": "arn:aws:s3:::user-data-prod",
          "resource_arn": "arn:aws:s3:::user-data-prod",
          "resource_id": "user-data-prod",
          "resource_type": "s3:bucket",
          "region": "us-east-1",
          "account": "155052200811"
        }
      ],
      "evidence_refs": ["ev_001", "ev_002"],
      "remediation": {
        "summary": "Review and remediate 3 misconfigurations...",
        "steps": [
          "Review misconfig findings: mf_abc123, mf_def456, mf_ghi789",
          "Apply recommended remediation for each finding",
          "Re-scan to verify threat is resolved"
        ]
      }
    }
  ],
  "misconfig_findings": [
    {
      "misconfig_finding_id": "mf_abc123",
      "finding_key": "aws.s3.bucket.public_access_block_enabled|arn:aws:s3:::user-data-prod|155052200811|us-east-1",
      "rule_id": "aws.s3.bucket.public_access_block_enabled",
      "severity": "high",
      "result": "FAIL",
      "account": "155052200811",
      "region": "us-east-1",
      "service": "s3",
      "resource": {
        "resource_uid": "arn:aws:s3:::user-data-prod",
        "resource_arn": "arn:aws:s3:::user-data-prod",
        "resource_id": "user-data-prod",
        "resource_type": "s3:bucket",
        "tags": {
          "env": "prod",
          "team": "engineering"
        }
      },
      "evidence_refs": [],
      "checked_fields": ["PublicAccessBlockConfiguration"],
      "first_seen_at": "2025-01-15T10:00:00Z",
      "last_seen_at": "2025-01-18T10:00:00Z"
    }
  ],
  "asset_snapshots": [
    {
      "asset_id": "arn:aws:s3:::user-data-prod",
      "provider": "aws",
      "resource_type": "s3:bucket",
      "resource_id": "user-data-prod",
      "resource_arn": "arn:aws:s3:::user-data-prod",
      "region": "us-east-1",
      "account": "155052200811",
      "tags": {
        "env": "prod",
        "team": "engineering"
      }
    }
  ],
  "evidence": [],
  "generated_at": "2025-01-18T10:00:00Z"
}
```

### Threat Types
- `exposure`: Resource is internet-reachable and has public access misconfigurations
- `identity`: Permissive IAM policies combined with privileged access or missing MFA
- `lateral_movement`: Open inbound rules combined with reachable subnets and high privileges
- `data_exfiltration`: Public storage with sensitive data and weak logging
- `privilege_escalation`: IAM policies or roles that allow privilege escalation
- `data_breach`: Misconfigurations that could lead to data breach

### Threat Severity
- `critical`: Immediate action required
- `high`: Should be addressed soon
- `medium`: Moderate risk
- `low`: Low priority
- `info`: Informational

### Threat Status
- `open`: Threat is active and not resolved
- `resolved`: Threat has been remediated
- `suppressed`: Threat is suppressed (false positive, accepted risk, etc.)
- `false_positive`: Marked as false positive

---

## 🎨 UI Component Library Recommendations

1. **Charts**: Recharts, Chart.js, or D3.js for threat trends and distributions
2. **Tables**: TanStack Table (React Table v8) for threat lists
3. **Maps**: Leaflet or MapBox for geographic threat visualization
4. **Graphs**: Cytoscape.js or React Flow for network topology and attack paths
5. **Framework**: React, Vue, or Angular
6. **State**: Redux/Zustand or React Query for API caching
7. **Timeline**: React Timeline or Vis.js for remediation workflows

---

## ✅ Implementation Checklist for Frontend

- [ ] Threat Dashboard with metrics cards
- [ ] Threat List with filtering and grouping
- [ ] Threat Detail with tabs (Overview, Root Causes, Evidence, Remediation)
- [ ] Threat Map with geographic/account/service views
- [ ] Threat Analytics with trends and patterns
- [ ] Threat Remediation with workflow tracking
- [ ] Threat status management (resolve, suppress, false positive)
- [ ] Export functionality (PDF/CSV)
- [ ] Real-time updates (polling or WebSocket)
- [ ] Threat correlation visualization
- [ ] Attack path visualization

---

## 🚨 Missing API Endpoints to Implement

### Core Threat APIs
- [ ] `GET /api/v1/threat/reports/{scan_run_id}` - Get existing threat report (cache/store reports)
- [ ] `GET /api/v1/threat/summary?scan_run_id=latest` - Get just summary stats (lightweight)
- [ ] `GET /api/v1/threat/list?scan_run_id=latest&severity=critical&type=exposure` - Filtered threat list
- [ ] `GET /api/v1/threat/{threat_id}` - Get single threat details
- [ ] `PATCH /api/v1/threat/{threat_id}` - Update threat (status, notes, assignee)
- [ ] `GET /api/v1/threat/{threat_id}/misconfig-findings` - Get root cause findings
- [ ] `GET /api/v1/threat/{threat_id}/assets` - Get affected assets

### Threat Map APIs
- [ ] `GET /api/v1/threat/map/geographic?scan_run_id=latest` - Threats grouped by region
- [ ] `GET /api/v1/threat/map/account?scan_run_id=latest` - Threats grouped by account
- [ ] `GET /api/v1/threat/map/service?scan_run_id=latest` - Threats grouped by service
- [ ] `GET /api/v1/threat/map/network?scan_run_id=latest&vpc_id=vpc-123` - Network topology with threats

### Analytics APIs
- [ ] `GET /api/v1/threat/analytics/trend?days=30` - Threat trends over time
- [ ] `GET /api/v1/threat/analytics/patterns?scan_run_id=latest` - Common threat patterns
- [ ] `GET /api/v1/threat/analytics/correlation?scan_run_id=latest` - Threat correlation matrix
- [ ] `GET /api/v1/threat/analytics/distribution?scan_run_id=latest` - Threat distribution stats

### Remediation APIs
- [ ] `GET /api/v1/threat/remediation/queue?status=open` - Get remediation queue
- [ ] `GET /api/v1/threat/{threat_id}/remediation` - Get remediation workflow for threat
- [ ] `POST /api/v1/threat/{threat_id}/remediation/assign` - Assign threat to user
- [ ] `POST /api/v1/threat/{threat_id}/remediation/step/{step_id}/complete` - Mark remediation step complete
- [ ] `POST /api/v1/threat/{threat_id}/remediation/verify` - Request verification scan
- [ ] `GET /api/v1/threat/remediation/history?threat_id={threat_id}` - Get remediation history

### Storage & Caching
- [ ] Store threat reports in database (PostgreSQL) for historical tracking
- [ ] Cache threat reports to avoid regenerating on every request
- [ ] Support querying historical threat reports for trend analysis

---

## 📝 Notes

1. **Current State**: The threat engine currently only has `POST /api/v1/threat/generate` which creates a new report each time. For UI, we need GET endpoints to retrieve existing reports.

2. **Report Storage**: Consider storing threat reports in a database (PostgreSQL) so they can be:
   - Retrieved by scan_run_id
   - Used for trend analysis
   - Tracked over time
   - Updated with status changes

3. **Threat Status Management**: Need to support updating threat status (open, resolved, suppressed, false_positive) and storing these updates.

4. **Remediation Tracking**: Need to track remediation workflows, assignees, and completion status.

5. **Integration with Compliance Engine**: Threats can be linked to compliance findings for unified reporting.

**Priority APIs to implement first**:
1. `GET /api/v1/threat/reports/{scan_run_id}` - Essential for UI
2. `GET /api/v1/threat/{threat_id}` - Essential for detail view
3. `PATCH /api/v1/threat/{threat_id}` - Essential for status management
4. `GET /api/v1/threat/summary?scan_run_id=latest` - Lightweight for dashboard



