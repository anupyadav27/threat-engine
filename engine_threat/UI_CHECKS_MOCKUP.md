# ConfigScan Check Results - UI Screen Mockups

## Overview

UI screens for viewing and analyzing ConfigScan check scan results. Focuses on raw check findings, service-level statistics, and resource-level drill-down.

**Base URL**: `/checks`

**API Base**: `http://localhost:8000/api/v1/checks`

---

## Screen 1: Check Results Dashboard

**URL**: `/checks/dashboard`

**Purpose**: Overview of all check scans with key metrics and recent activity

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  CHECK SCAN RESULTS                  Tenant: test_tenant         │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  KEY METRICS                                                      │
│  ┌──────────────┬──────────────┬──────────────┬──────────────┐  │
│  │ 70,988       │ 7,836        │ 63,152       │ 11.0%        │  │
│  │ Total Checks │ Passed       │ Failed       │ Pass Rate    │  │
│  └──────────────┴──────────────┴──────────────┴──────────────┘  │
│                                                                   │
│  TOP FAILING SERVICES                     [View All →]           │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ EC2         61,120 checks  ████░░░░░░  9.4%  5,756 passed │ │
│  │ IAM          5,050 checks  ████░░░░░░  19.0% 960 passed   │ │
│  │ S3           2,112 checks  ███░░░░░░░  28.6% 604 passed   │ │
│  │ KMS            956 checks  ██░░░░░░░░  10.9% 104 passed   │ │
│  │ Cost Exp.      630 checks  ██░░░░░░░░  11.4% 72 passed    │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  RECENT SCANS                             [Show All →]           │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ check_20260122_210506   Jan 22, 21:05   039612851381      │ │
│  │ 100 services | 70,988 checks | 11.0% pass rate            │ │
│  │ [View Details]                                             │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ check_20260122_080533   Jan 22, 08:05   039612851381      │ │
│  │ 100 services | 70,988 checks | 11.0% pass rate            │ │
│  │ [View Details]                                             │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  FILTERS                                                          │
│  [Service ▾] [Status ▾] [Account ▾] [Date Range] [Search...]    │
│                                                                   │
│  QUICK ACTIONS                                                    │
│  [📥 Export All] [🔍 Advanced Search] [📊 View Trends]           │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
const dashboard = await fetch('/api/v1/checks/dashboard?tenant_id=test_tenant');
// Response: { total_checks, passed, failed, pass_rate, top_failing_services, recent_scans }
```

---

## Screen 2: Scan Detail View

**URL**: `/checks/scans/{scan_id}`

**Purpose**: Detailed view of a specific check scan

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  ◀ Back to Dashboard                                            │
├──────────────────────────────────────────────────────────────────┤
│  SCAN: check_20260122_210506                                      │
│  Discovery Scan: discovery_20260122_080533                        │
│  Account: 039612851381 | Scanned: Jan 22, 2026 21:05             │
│                                                                   │
│  OVERALL RESULTS                                                  │
│  ┌──────────────┬──────────────┬──────────────┬──────────────┐  │
│  │ 70,988       │ 7,836        │ 63,152       │ 0            │  │
│  │ Total Checks │ Passed       │ Failed       │ Errors       │  │
│  └──────────────┴──────────────┴──────────────┴──────────────┘  │
│                                                                   │
│  SERVICES SCANNED (100 services)          [Export CSV ▾]         │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Search services...                        [Status ▾] [All] │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ Service      Total    Passed   Failed   Pass Rate   Action │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ EC2         61,120    5,756    55,364   9.4%       [View] │ │
│  │ IAM          5,050      960     4,090   19.0%      [View] │ │
│  │ S3           2,112      604     1,508   28.6%      [View] │ │
│  │ KMS            956      104       852   10.9%      [View] │ │
│  │ Lambda         244       76       168   31.1%      [View] │ │
│  │ ... (95 more services)                                     │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  FILTERS                                                          │
│  [All Services ▾] [All Status ▾] [All Rules ▾]                   │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
const scan = await fetch('/api/v1/checks/scans/check_20260122_210506?tenant_id=test_tenant');
const services = await fetch('/api/v1/checks/scans/check_20260122_210506/services?tenant_id=test_tenant');
```

---

## Screen 3: Service Detail View

**URL**: `/checks/scans/{scan_id}/services/{service}`

**Purpose**: Detailed view of check results for a specific service

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  ◀ Back to Scan                                                 │
├──────────────────────────────────────────────────────────────────┤
│  SERVICE: S3                     Scan: check_20260122_210506      │
│  Account: 039612851381 | Scanned: Jan 22, 2026 21:05             │
│                                                                   │
│  SERVICE STATISTICS                                               │
│  ┌──────────────┬──────────────┬──────────────┬──────────────┐  │
│  │ 2,112        │ 604          │ 1,508        │ 28.6%        │  │
│  │ Total Checks │ Passed       │ Failed       │ Pass Rate    │  │
│  └──────────────┴──────────────┴──────────────┴──────────────┘  │
│                                                                   │
│  │ 96           │                                               │ │
│  │ Resources    │  PASS ████░░░░░░ 28.6% | FAIL ██████░░ 71.4% │ │
│  │ Affected     │                                               │ │
│  └──────────────┴──────────────────────────────────────────────┘ │
│                                                                   │
│  TOP FAILING RULES                        [Show All Rules →]     │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Rule ID                              Findings  Pass  Fail  │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ aws.s3.bucket.versioning_enabled         96     24    72  │ │
│  │ Resources: 96 buckets affected                  [Details] │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ aws.s3.bucket.encryption_enabled         96     28    68  │ │
│  │ Resources: 96 buckets affected                  [Details] │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ aws.s3.bucket.logging_enabled            96     12    84  │ │
│  │ Resources: 96 buckets affected                  [Details] │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  AFFECTED RESOURCES                       [Export Resource List] │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Resource ARN                             Findings  Status  │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ arn:aws:s3:::aiwebsite01                   22     12P 10F │ │
│  │ [View All Findings]                                        │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ arn:aws:s3:::lgtech-website                22     8P  14F │ │
│  │ [View All Findings]                                        │ │
│  └────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
const serviceDetail = await fetch(
  '/api/v1/checks/scans/check_20260122_210506/services/s3?tenant_id=test_tenant'
);
// Response: { service, total_checks, passed, failed, pass_rate, rules, resources_affected }
```

---

## Screen 4: Finding Detail View

**URL**: `/checks/findings/{finding_id}` or `/checks/resources/{arn}`

**Purpose**: Detailed view of a single check finding or all findings for a resource

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  ◀ Back to Service                                              │
├──────────────────────────────────────────────────────────────────┤
│  FINDING DETAIL                                                   │
│                                                                   │
│  🔴 FAIL                                                           │
│  aws.s3.bucket.versioning_enabled                                │
│                                                                   │
│  RESOURCE INFORMATION                                             │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ ARN:        arn:aws:s3:::lgtech-website                    │ │
│  │ ID:         lgtech-website                                 │ │
│  │ Type:       s3 (S3 Bucket)                                 │ │
│  │ Account:    039612851381                                   │ │
│  │ Region:     global                                         │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  CHECK DETAILS                                                    │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Rule:          aws.s3.bucket.versioning_enabled            │ │
│  │ Status:        FAIL                                        │ │
│  │ Checked:       Jan 22, 2026 21:05:06                       │ │
│  │ Scan ID:       check_20260122_210506                       │ │
│  │ Discovery:     discovery_20260122_080533                   │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  EVIDENCE                                                         │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Checked Fields:                                            │ │
│  │   • Status                                                 │ │
│  │                                                            │ │
│  │ Finding Data:                                              │ │
│  │   {                                                        │ │
│  │     "rule_id": "aws.s3.bucket.versioning_enabled",         │ │
│  │     "service": "s3",                                       │ │
│  │     "discovery_id": "aws.s3.get_bucket_versioning",        │ │
│  │     "status": "FAIL"                                       │ │
│  │   }                                                        │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  RELATED FINDINGS FOR THIS RESOURCE (21 more)                    │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ aws.s3.bucket.encryption_enabled          FAIL             │ │
│  │ aws.s3.bucket.logging_enabled             FAIL             │ │
│  │ aws.s3.bucket.public_access_block         PASS             │ │
│  │ [View All 22 Findings →]                                   │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  ACTIONS                                                          │
│  [🔗 View in Console] [📋 Export Finding] [🔄 Recheck]           │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
const resource = await fetch(
  `/api/v1/checks/resources/${encodeURIComponent(arn)}?tenant_id=test_tenant`
);
// Response: { resource_arn, resource_id, resource_type, total_findings, findings[] }
```

---

## Screen 5: Search & Filter

**URL**: `/checks/search`

**Purpose**: Search and filter check results across all scans

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  SEARCH CHECK RESULTS                                            │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ 🔍  Search by ARN, Rule ID, or Service...                  │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  FILTERS                                                          │
│  Service: [All Services ▾]  Status: [All ▾]  Scan: [Latest ▾]   │
│  Account: [All Accounts ▾]  Date: [Last 30 Days ▾]              │
│                                                                   │
│  RESULTS (2,112 findings)                     Page 1 of 43       │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Resource                    Rule                    Status │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ arn:aws:s3:::aiwebsite01                                   │ │
│  │ aws.s3.bucket.versioning_enabled            🔴 FAIL        │ │
│  │ Checked: Status | Jan 22, 21:05                 [Details] │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ arn:aws:s3:::lgtech-website                                │ │
│  │ aws.s3.bucket.encryption_enabled            🔴 FAIL        │ │
│  │ Checked: ServerSideEncryptionConfiguration  [Details]     │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ arn:aws:lambda:us-east-1:588989875114:function:chatbot     │ │
│  │ aws.lambda.function.execution_role_...      ✅ PASS        │ │
│  │ Checked: Role | Jan 22, 21:05               [Details]     │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  [◀ Previous] [1] [2] [3] ... [43] [Next ▶]                     │
│                                                                   │
│  BULK ACTIONS                                                     │
│  ☑ Select All on Page    [📥 Export Selected] [📋 Generate Report] │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
const results = await fetch(
  '/api/v1/checks/findings/search?query=s3&tenant_id=test_tenant&page=1&page_size=50'
);
// Response: { findings[], total, page, page_size, total_pages }
```

---

## Screen 6: Rule Analysis

**URL**: `/checks/rules/{rule_id}`

**Purpose**: View all findings for a specific rule across resources

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  ◀ Back                                                         │
├──────────────────────────────────────────────────────────────────┤
│  RULE ANALYSIS                                                    │
│                                                                   │
│  aws.s3.bucket.versioning_enabled                                │
│  Service: S3                                                      │
│                                                                   │
│  RULE STATISTICS                                                  │
│  ┌──────────────┬──────────────┬──────────────┬──────────────┐  │
│  │ 96           │ 24           │ 72           │ 25.0%        │  │
│  │ Total        │ Passed       │ Failed       │ Pass Rate    │  │
│  └──────────────┴──────────────┴──────────────┴──────────────┘  │
│                                                                   │
│  AFFECTED RESOURCES (96 resources)        [Export List ▾]        │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Resource ARN                              Status   Checked │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ arn:aws:s3:::aiwebsite01                  FAIL   Jan 22   │ │
│  │ Versioning Status: Not Enabled                 [Details]  │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ arn:aws:s3:::lgtech-website               FAIL   Jan 22   │ │
│  │ Versioning Status: Not Enabled                 [Details]  │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ arn:aws:s3:::backup-bucket                PASS   Jan 22   │ │
│  │ Versioning Status: Enabled                     [Details]  │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  REMEDIATION GUIDANCE                                             │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Enable versioning on S3 buckets to protect against        │ │
│  │ accidental deletions and maintain object history.          │ │
│  │                                                            │ │
│  │ AWS CLI:                                                   │ │
│  │ aws s3api put-bucket-versioning \                          │ │
│  │   --bucket BUCKET_NAME \                                   │ │
│  │   --versioning-configuration Status=Enabled                │ │
│  └────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
const ruleData = await fetch(
  '/api/v1/checks/rules/aws.s3.bucket.versioning_enabled?tenant_id=test_tenant'
);
// Response: { rule_id, service, total_findings, passed, failed, findings[], resources_affected[] }
```

---

## Screen 7: Resource Timeline

**URL**: `/checks/resources/{resource_arn}/timeline`

**Purpose**: Historical view of all checks for a specific resource

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  RESOURCE TIMELINE                                               │
├──────────────────────────────────────────────────────────────────┤
│  Resource: arn:aws:s3:::lgtech-website                            │
│  Type: S3 Bucket | ID: lgtech-website                            │
│                                                                   │
│  FINDINGS SUMMARY                                                 │
│  ┌──────────────┬──────────────┬──────────────┐                  │
│  │ 22           │ 8            │ 14           │                  │
│  │ Total Checks │ Passed       │ Failed       │                  │
│  └──────────────┴──────────────┴──────────────┘                  │
│                                                                   │
│  TIMELINE                                                         │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Jan 22, 2026 21:05 - Scan: check_20260122_210506          │ │
│  │ ├─ ✅ PASS  aws.s3.bucket.public_access_block              │ │
│  │ ├─ 🔴 FAIL  aws.s3.bucket.versioning_enabled               │ │
│  │ ├─ 🔴 FAIL  aws.s3.bucket.encryption_enabled               │ │
│  │ ├─ 🔴 FAIL  aws.s3.bucket.logging_enabled                  │ │
│  │ └─ ... (18 more checks)                                    │ │
│  │                                                            │ │
│  │ Jan 22, 2026 08:05 - Scan: check_20260122_080533          │ │
│  │ ├─ ✅ PASS  aws.s3.bucket.public_access_block              │ │
│  │ ├─ 🔴 FAIL  aws.s3.bucket.versioning_enabled               │ │
│  │ └─ ... (20 more checks)                                    │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  ACTIONS                                                          │
│  [🔗 View in AWS Console] [📋 Export Timeline] [🔄 Run New Scan] │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
const resource = await fetch(
  `/api/v1/checks/resources/${encodeURIComponent(arn)}?tenant_id=test_tenant`
);
```

---

## Screen 8: Export & Reporting

**URL**: `/checks/export`

**Purpose**: Export check results in various formats

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  EXPORT CHECK RESULTS                                            │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  SELECT SCAN                                                      │
│  ○ Latest Scan (check_20260122_210506)                           │
│  ○ Specific Scan: [Select Scan ▾]                                │
│  ○ All Scans                                                      │
│                                                                   │
│  FILTERS                                                          │
│  Service:  [All Services ▾]                                      │
│  Status:   ☑ Failed  ☑ Passed  ☐ Error                          │
│  Account:  [All Accounts ▾]                                      │
│                                                                   │
│  EXPORT FORMAT                                                    │
│  ○ JSON  ○ CSV  ○ Excel  ○ PDF Report                            │
│                                                                   │
│  INCLUDE                                                          │
│  ☑ Finding Details                                               │
│  ☑ Resource Information                                          │
│  ☑ Checked Fields                                                │
│  ☑ Discovery Context                                             │
│  ☐ Full Raw Data (finding_data JSONB)                           │
│                                                                   │
│  [📥 Generate Export]                                             │
│                                                                   │
│  RECENT EXPORTS                                                   │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ check_scan_20260122_210506.csv    Jan 22, 21:15  2.4 MB   │ │
│  │ [📥 Download] [🗑️ Delete]                                   │ │
│  └────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
const exportUrl = `/api/v1/checks/scans/${scanId}/export?format=csv&service=s3&tenant_id=test_tenant`;
window.location.href = exportUrl;  // Download file
```

---

## Navigation Flow

```
Dashboard
  ├─> Scan Detail (select scan)
  │     ├─> Service Detail (select service)
  │     │     ├─> Resource Findings (select resource)
  │     │     │     └─> Finding Detail (select finding)
  │     │     └─> Rule Analysis (select rule)
  │     └─> Export (export button)
  │
  ├─> Search (search box)
  │     └─> Finding Detail (select result)
  │
  └─> Export (quick action)
```

---

## UI Components & Technologies

**Recommended Stack**:
- **Framework**: React or Vue.js
- **UI Library**: Ant Design, Material-UI, or Chakra UI
- **Charts**: Recharts or Chart.js
- **Tables**: TanStack Table (React Table) with pagination
- **State**: React Query for API caching
- **Export**: xlsx library for Excel, jsPDF for PDF

---

## API Endpoint Summary

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/checks/dashboard` | GET | Dashboard statistics |
| `/api/v1/checks/scans` | GET | List scans (paginated) |
| `/api/v1/checks/scans/{id}` | GET | Scan summary |
| `/api/v1/checks/scans/{id}/services` | GET | Service breakdown |
| `/api/v1/checks/scans/{id}/services/{svc}` | GET | Service detail |
| `/api/v1/checks/scans/{id}/findings` | GET | Scan findings (paginated) |
| `/api/v1/checks/findings/search` | GET | Search findings |
| `/api/v1/checks/resources/{arn}` | GET | Resource findings |
| `/api/v1/checks/rules/{rule_id}` | GET | Rule findings |
| `/api/v1/checks/stats` | GET | Aggregated statistics |
| `/api/v1/checks/scans/{id}/export` | GET | Export scan results |

---

## Data Flow Example

### 1. User Opens Dashboard
```
UI → GET /api/v1/checks/dashboard?tenant_id=X
API → Query check_results (aggregations)
DB → Return stats
API → Format response
UI → Display dashboard
```

### 2. User Drills into Service
```
UI → GET /api/v1/checks/scans/{id}/services/s3?tenant_id=X
API → Query check_results WHERE resource_type='s3'
DB → Return S3 findings
API → Aggregate rules, resources
UI → Display service detail
```

### 3. User Views Resource
```
UI → GET /api/v1/checks/resources/arn:aws:s3:::bucket?tenant_id=X
API → Query check_results WHERE resource_arn='...'
DB → Return all findings for resource
UI → Display timeline
```

---

## Mobile Responsive Views

**Dashboard (Mobile)**:
```
┌────────────────────┐
│ ☰ Menu   Checks    │
├────────────────────┤
│ KEY METRICS        │
│ ┌────────┬────────┐│
│ │ 70,988 │ 11.0%  ││
│ │ Checks │ Pass   ││
│ └────────┴────────┘│
│                    │
│ TOP FAILING        │
│ ┌────────────────┐ │
│ │ EC2   61K  9%  │ │
│ │ IAM    5K  19% │ │
│ │ S3     2K  29% │ │
│ └────────────────┘ │
│                    │
│ [View All →]       │
└────────────────────┘
```

---

## Integration Points

### With Threat Engine
- Link from check findings to threat detections
- Check results feed into threat analysis
- Shared tenant/customer context

### With Compliance Engine
- Rule IDs can map to compliance controls
- Check results feed compliance scores
- Shared scan context

### With Discovery Engine
- Discovery scan ID links
- Resource enrichment from discovery data
- Traceability to source API calls

---

## Future Enhancements

1. **Trend Analysis** - Pass/fail trends over time per service/rule
2. **Bulk Remediation** - Select multiple findings and trigger remediation
3. **Custom Rules** - UI for creating custom check rules
4. **Notifications** - Alert on new failures or degrading pass rates
5. **Comparison** - Compare two scans to see changes
6. **Filters Presets** - Save commonly used filter combinations
7. **Real-time Updates** - WebSocket for live scan progress
8. **AI Insights** - Suggest remediation based on finding patterns

---

## Performance Considerations

- Use PostgreSQL indexes for fast queries
- Paginate all list endpoints (default 50 items)
- Cache dashboard aggregations (5-minute TTL)
- Use JSONB operators for efficient finding_data queries
- Limit export sizes (max 100K findings)

---

## Security

- Multi-tenant isolation enforced at API level
- All queries filter by tenant_id
- Resource ARN validation before queries
- Rate limiting on search/export endpoints
- CORS configured for specific origins only
