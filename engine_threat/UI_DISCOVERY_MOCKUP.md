# ConfigScan Discovery Results - UI Screen Mockups

## Overview

UI screens for viewing and analyzing ConfigScan discovery scan results. Focuses on discovered resources, service-level breakdown, and resource-level drill-down.

**Base URL**: `/discoveries`

**API Base**: `http://localhost:8000/api/v1/discoveries`

---

## Screen 1: Discovery Dashboard

**URL**: `/discoveries/dashboard`

**Purpose**: Overview of all discovery scans with key metrics and recent activity

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  DISCOVERY SCAN RESULTS              Tenant: test_tenant         │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  KEY METRICS                                                      │
│  ┌──────────────┬──────────────┬──────────────┬──────────────┐  │
│  │ 50,000       │ 12,000       │ 100          │ 27           │  │
│  │ Discoveries  │ Resources    │ Services     │ Regions       │  │
│  └──────────────┴──────────────┴──────────────┴──────────────┘  │
│                                                                   │
│  TOP SERVICES BY DISCOVERIES              [View All →]           │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ EC2         30,000 discoveries  12,000 resources  27 regions│ │
│  │ IAM          8,000 discoveries   5,000 resources  global    │ │
│  │ S3           2,000 discoveries   2,000 resources  global    │ │
│  │ KMS          1,500 discoveries   1,200 resources  27 regions │ │
│  │ Lambda         800 discoveries     500 resources  27 regions│ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  RECENT SCANS                             [Show All →]           │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ discovery_20260122_080533   Jan 22, 08:05   039612851381   │ │
│  │ 100 services | 50,000 discoveries | 12,000 resources        │ │
│  │ [View Details]                                             │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ discovery_20260121_211958   Jan 21, 21:19   039612851381   │ │
│  │ 100 services | 48,000 discoveries | 11,500 resources       │ │
│  │ [View Details]                                             │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  FILTERS                                                          │
│  [Service ▾] [Region ▾] [Account ▾] [Date Range] [Search...]    │
│                                                                   │
│  QUICK ACTIONS                                                    │
│  [📥 Export All] [🔍 Advanced Search] [📊 View Trends]           │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
const dashboard = await fetch('/api/v1/discoveries/dashboard?tenant_id=test_tenant');
// Response: { total_discoveries, unique_resources, services_scanned, top_services, recent_scans }
```

---

## Screen 2: Scan Detail View

**URL**: `/discoveries/scans/{scan_id}`

**Purpose**: Detailed view of a specific discovery scan

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  ◀ Back to Dashboard                                            │
├──────────────────────────────────────────────────────────────────┤
│  SCAN: discovery_20260122_080533                                  │
│  Account: 039612851381 | Scanned: Jan 22, 2026 08:05             │
│                                                                   │
│  OVERALL RESULTS                                                  │
│  ┌──────────────┬──────────────┬──────────────┬──────────────┐  │
│  │ 50,000       │ 12,000       │ 100          │ 27           │  │
│  │ Discoveries  │ Resources    │ Services     │ Regions       │  │
│  └──────────────┴──────────────┴──────────────┴──────────────┘  │
│                                                                   │
│  SERVICES SCANNED (100 services)          [Export CSV ▾]         │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Search services...                        [Region ▾] [All] │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ Service      Discoveries  Resources  Regions      Action   │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ EC2         30,000       12,000     27          [View]    │ │
│  │ IAM          8,000        5,000     global     [View]    │ │
│  │ S3           2,000        2,000     global     [View]    │ │
│  │ KMS          1,500        1,200     27          [View]    │ │
│  │ Lambda         800          500     27          [View]    │ │
│  │ ... (95 more services)                                     │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  FILTERS                                                          │
│  [All Services ▾] [All Regions ▾] [All Discovery Functions ▾]  │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
const scan = await fetch('/api/v1/discoveries/scans/discovery_20260122_080533?tenant_id=test_tenant');
const services = await fetch('/api/v1/discoveries/scans/discovery_20260122_080533/services?tenant_id=test_tenant');
```

---

## Screen 3: Service Detail View

**URL**: `/discoveries/scans/{scan_id}/services/{service}`

**Purpose**: Detailed view of discovery results for a specific service

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  ◀ Back to Scan                                                 │
├──────────────────────────────────────────────────────────────────┤
│  SERVICE: S3                     Scan: discovery_20260122_080533  │
│  Account: 039612851381 | Scanned: Jan 22, 2026 08:05             │
│                                                                   │
│  SERVICE STATISTICS                                               │
│  ┌──────────────┬──────────────┬──────────────┬──────────────┐  │
│  │ 2,000        │ 2,000        │ global       │ 15           │  │
│  │ Discoveries  │ Resources    │ Region       │ Functions    │  │
│  └──────────────┴──────────────┴──────────────┴──────────────┘  │
│                                                                   │
│  DISCOVERY FUNCTIONS                      [Show All Functions →]│
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Discovery Function                    Records  Resources   │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ aws.s3.list_buckets                     96       96       │ │
│  │ Resources: 96 buckets discovered                [Details]  │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ aws.s3.get_bucket_versioning             96       96       │ │
│  │ Resources: 96 buckets with versioning data        [Details] │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ aws.s3.get_bucket_encryption              96       96       │ │
│  │ Resources: 96 buckets with encryption data        [Details] │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  DISCOVERED RESOURCES                     [Export Resource List] │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Resource ARN                             Discoveries       │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ arn:aws:s3:::aiwebsite01                   15             │ │
│  │ [View All Discoveries]                                    │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ arn:aws:s3:::lgtech-website                15             │ │
│  │ [View All Discoveries]                                    │ │
│  └────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
const serviceDetail = await fetch(
  '/api/v1/discoveries/scans/discovery_20260122_080533/services/s3?tenant_id=test_tenant'
);
// Response: { service, total_discoveries, unique_resources, regions, discovery_functions }
```

---

## Screen 4: Discovery Detail View

**URL**: `/discoveries/discoveries/{id}` or `/discoveries/resources/{arn}`

**Purpose**: Detailed view of a single discovery record or all discoveries for a resource

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  ◀ Back to Service                                              │
├──────────────────────────────────────────────────────────────────┤
│  DISCOVERY DETAIL                                                 │
│                                                                   │
│  📋 aws.s3.get_bucket_versioning                                  │
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
│  DISCOVERY DETAILS                                                │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Function:   aws.s3.get_bucket_versioning                   │ │
│  │ Service:    s3                                             │ │
│  │ Discovered: Jan 22, 2026 08:05:33                          │ │
│  │ Scan ID:    discovery_20260122_080533                      │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  EMITTED FIELDS                                                   │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ {                                                           │ │
│  │   "Status": "Enabled",                                      │ │
│  │   "MfaDelete": "Disabled"                                   │ │
│  │ }                                                           │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  RAW API RESPONSE                                                 │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ {                                                           │ │
│  │   "Status": "Enabled",                                      │ │
│  │   "MfaDelete": "Disabled",                                  │ │
│  │   "ResponseMetadata": {...}                                 │ │
│  │ }                                                           │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  RELATED DISCOVERIES FOR THIS RESOURCE (14 more)                 │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ aws.s3.get_bucket_encryption                                │ │
│  │ aws.s3.get_bucket_logging                                   │ │
│  │ aws.s3.get_bucket_policy                                    │ │
│  │ [View All 15 Discoveries →]                                │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  ACTIONS                                                          │
│  [🔗 View in Console] [📋 Export Discovery] [🔄 Re-discover]     │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
const resource = await fetch(
  `/api/v1/discoveries/resources/${encodeURIComponent(arn)}?tenant_id=test_tenant`
);
// Response: { resource_arn, resource_id, resource_type, total_discoveries, discoveries[] }
```

---

## Screen 5: Search & Filter

**URL**: `/discoveries/search`

**Purpose**: Search and filter discovery results across all scans

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  SEARCH DISCOVERY RESULTS                                        │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ 🔍  Search by ARN, Discovery ID, or Service...              │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  FILTERS                                                          │
│  Service: [All Services ▾]  Region: [All ▾]  Scan: [Latest ▾]  │
│  Account: [All Accounts ▾]  Date: [Last 30 Days ▾]              │
│                                                                   │
│  RESULTS (2,000 discoveries)                  Page 1 of 40       │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Resource                    Discovery Function      Service │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ arn:aws:s3:::aiwebsite01                                   │ │
│  │ aws.s3.get_bucket_versioning            s3                 │ │
│  │ Discovered: Jan 22, 08:05                 [Details]        │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ arn:aws:s3:::lgtech-website                                │ │
│  │ aws.s3.get_bucket_encryption            s3                 │ │
│  │ Discovered: Jan 22, 08:05                 [Details]        │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ arn:aws:ec2:us-east-1:588989875114:instance/i-12345       │ │
│  │ aws.ec2.describe_instances              ec2                │ │
│  │ Discovered: Jan 22, 08:05                 [Details]        │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  [◀ Previous] [1] [2] [3] ... [40] [Next ▶]                     │
│                                                                   │
│  BULK ACTIONS                                                     │
│  ☑ Select All on Page    [📥 Export Selected] [📋 Generate Report] │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
const results = await fetch(
  '/api/v1/discoveries/discoveries/search?query=s3&tenant_id=test_tenant&page=1&page_size=50'
);
// Response: { discoveries[], total, page, page_size, total_pages }
```

---

## Screen 6: Discovery Function Analysis

**URL**: `/discoveries/functions/{discovery_id}`

**Purpose**: View all discoveries for a specific discovery function across resources

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  ◀ Back                                                         │
├──────────────────────────────────────────────────────────────────┤
│  DISCOVERY FUNCTION ANALYSIS                                      │
│                                                                   │
│  aws.s3.list_buckets                                              │
│  Service: S3                                                      │
│                                                                   │
│  FUNCTION STATISTICS                                              │
│  ┌──────────────┬──────────────┬──────────────┐                  │
│  │ 96           │ 96           │ global       │                  │
│  │ Discoveries  │ Resources    │ Region       │                  │
│  └──────────────┴──────────────┴──────────────┘                  │
│                                                                   │
│  DISCOVERED RESOURCES (96 resources)        [Export List ▾]      │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Resource ARN                              Discovered       │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ arn:aws:s3:::aiwebsite01                  Jan 22, 08:05   │ │
│  │ Bucket Name: aiwebsite01                       [Details]  │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ arn:aws:s3:::lgtech-website               Jan 22, 08:05   │ │
│  │ Bucket Name: lgtech-website                    [Details]  │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ arn:aws:s3:::backup-bucket                Jan 22, 08:05   │ │
│  │ Bucket Name: backup-bucket                     [Details]  │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  SAMPLE DISCOVERY DATA                                            │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ {                                                           │ │
│  │   "Name": "aiwebsite01",                                    │ │
│  │   "CreationDate": "2024-01-15T10:30:00Z"                    │ │
│  │ }                                                           │ │
│  └────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
const functionData = await fetch(
  '/api/v1/discoveries/functions/aws.s3.list_buckets?tenant_id=test_tenant'
);
// Response: { discovery_id, service, total_discoveries, resources_discovered[], discoveries[] }
```

---

## Screen 7: Resource Timeline

**URL**: `/discoveries/resources/{resource_arn}/timeline`

**Purpose**: Historical view of all discoveries for a specific resource

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  RESOURCE DISCOVERY TIMELINE                                     │
├──────────────────────────────────────────────────────────────────┤
│  Resource: arn:aws:s3:::lgtech-website                            │
│  Type: S3 Bucket | ID: lgtech-website                            │
│                                                                   │
│  DISCOVERIES SUMMARY                                               │
│  ┌──────────────┬──────────────┬──────────────┐                  │
│  │ 15           │ 15           │ 5             │                  │
│  │ Total        │ Functions    │ Scans        │                  │
│  └──────────────┴──────────────┴──────────────┘                  │
│                                                                   │
│  TIMELINE                                                         │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Jan 22, 2026 08:05 - Scan: discovery_20260122_080533       │ │
│  │ ├─ 📋 aws.s3.list_buckets                                  │ │
│  │ ├─ 📋 aws.s3.get_bucket_versioning                         │ │
│  │ ├─ 📋 aws.s3.get_bucket_encryption                          │ │
│  │ ├─ 📋 aws.s3.get_bucket_logging                            │ │
│  │ └─ ... (11 more discoveries)                              │ │
│  │                                                            │ │
│  │ Jan 21, 2026 21:19 - Scan: discovery_20260121_211958       │ │
│  │ ├─ 📋 aws.s3.list_buckets                                  │ │
│  │ ├─ 📋 aws.s3.get_bucket_versioning                         │ │
│  │ └─ ... (13 more discoveries)                               │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  ACTIONS                                                          │
│  [🔗 View in AWS Console] [📋 Export Timeline] [🔄 Run New Scan] │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
const resource = await fetch(
  `/api/v1/discoveries/resources/${encodeURIComponent(arn)}?tenant_id=test_tenant`
);
```

---

## Screen 8: Export & Reporting

**URL**: `/discoveries/export`

**Purpose**: Export discovery results in various formats

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  EXPORT DISCOVERY RESULTS                                        │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  SELECT SCAN                                                      │
│  ○ Latest Scan (discovery_20260122_080533)                       │
│  ○ Specific Scan: [Select Scan ▾]                                │
│  ○ All Scans                                                      │
│                                                                   │
│  FILTERS                                                          │
│  Service:  [All Services ▾]                                      │
│  Region:   [All Regions ▾]                                       │
│  Account:  [All Accounts ▾]                                      │
│                                                                   │
│  EXPORT FORMAT                                                    │
│  ○ JSON  ○ CSV  ○ Excel  ○ PDF Report                            │
│                                                                   │
│  INCLUDE                                                          │
│  ☑ Discovery Details                                              │
│  ☑ Resource Information                                           │
│  ☑ Emitted Fields                                                 │
│  ☑ Raw API Response                                               │
│  ☐ Configuration Hash                                             │
│                                                                   │
│  [📥 Generate Export]                                             │
│                                                                   │
│  RECENT EXPORTS                                                   │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ discovery_scan_20260122_080533.csv    Jan 22, 08:15  5.2 MB│ │
│  │ [📥 Download] [🗑️ Delete]                                   │ │
│  └────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
const exportUrl = `/api/v1/discoveries/scans/${scanId}/export?format=csv&service=s3&tenant_id=test_tenant`;
window.location.href = exportUrl;  // Download file
```

---

## Navigation Flow

```
Dashboard
  ├─> Scan Detail (select scan)
  │     ├─> Service Detail (select service)
  │     │     ├─> Resource Discoveries (select resource)
  │     │     │     └─> Discovery Detail (select discovery)
  │     │     └─> Discovery Function (select function)
  │     └─> Export (export button)
  │
  ├─> Search (search box)
  │     └─> Discovery Detail (select result)
  │
  └─> Export (quick action)
```

---

## API Endpoint Summary

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/discoveries/dashboard` | GET | Dashboard statistics |
| `/api/v1/discoveries/scans` | GET | List scans (paginated) |
| `/api/v1/discoveries/scans/{id}` | GET | Scan summary |
| `/api/v1/discoveries/scans/{id}/services` | GET | Service breakdown |
| `/api/v1/discoveries/scans/{id}/services/{svc}` | GET | Service detail |
| `/api/v1/discoveries/scans/{id}/discoveries` | GET | Scan discoveries (paginated, filterable) |
| `/api/v1/discoveries/discoveries/search` | GET | Search discoveries globally |
| `/api/v1/discoveries/resources/{arn}` | GET | All discoveries for resource |
| `/api/v1/discoveries/functions/{discovery_id}` | GET | All discoveries for function |
| `/api/v1/discoveries/scans/{id}/export` | GET | Export (JSON/CSV) |

---

## Integration with Check Results

**Link from Discovery to Checks:**
- Discovery detail → "View Check Results" button
- Resource discoveries → "View Compliance Status" button
- Service detail → "Run Checks" button

**Link from Checks to Discovery:**
- Check finding → "View Discovery Data" button
- Resource findings → "View All Discoveries" button

---

## Data Flow Example

### 1. User Opens Dashboard
```
UI → GET /api/v1/discoveries/dashboard?tenant_id=X
API → Query discoveries (aggregations)
DB → Return stats
API → Format response
UI → Display dashboard
```

### 2. User Drills into Service
```
UI → GET /api/v1/discoveries/scans/{id}/services/s3?tenant_id=X
API → Query discoveries WHERE service='s3'
DB → Return S3 discoveries
API → Aggregate discovery functions, resources
UI → Display service detail
```

### 3. User Views Resource
```
UI → GET /api/v1/discoveries/resources/arn:aws:s3:::bucket?tenant_id=X
API → Query discoveries WHERE resource_arn='...'
DB → Return all discoveries for resource
UI → Display timeline
```

---

## Mobile Responsive Views

**Dashboard (Mobile)**:
```
┌────────────────────┐
│ ☰ Menu  Discoveries│
├────────────────────┤
│ KEY METRICS        │
│ ┌────────┬────────┐│
│ │ 50,000 │ 12,000 ││
│ │ Discov │ Resrcs ││
│ └────────┴────────┘│
│                    │
│ TOP SERVICES       │
│ ┌────────────────┐ │
│ │ EC2   30K  12K │ │
│ │ IAM    8K   5K │ │
│ │ S3     2K   2K │ │
│ └────────────────┘ │
│                    │
│ [View All →]       │
└────────────────────┘
```

---

## Future Enhancements

1. **Drift Detection** - Show configuration changes over time
2. **Resource Relationships** - Visualize resource dependencies
3. **Bulk Operations** - Select multiple resources and run checks
4. **Custom Discovery** - UI for creating custom discovery functions
5. **Notifications** - Alert on new resources or configuration changes
6. **Comparison** - Compare two scans to see changes
7. **Filters Presets** - Save commonly used filter combinations
8. **Real-time Updates** - WebSocket for live scan progress

---

## Performance Considerations

- Use PostgreSQL indexes for fast queries
- Paginate all list endpoints (default 50 items)
- Cache dashboard aggregations (5-minute TTL)
- Use JSONB operators for efficient raw_response/emitted_fields queries
- Limit export sizes (max 100K discoveries)

---

## Security

- Multi-tenant isolation enforced at API level
- All queries filter by tenant_id
- Resource ARN validation before queries
- Rate limiting on search/export endpoints
- CORS configured for specific origins only
