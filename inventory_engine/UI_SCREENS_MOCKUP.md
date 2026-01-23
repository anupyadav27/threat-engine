# Inventory Engine UI - Screen Mockups

## UI Flow & Data Mapping

---

## 🏠 Screen 1: Executive Dashboard

**URL**: `/dashboard`

**Purpose**: High-level inventory overview and scan status

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  INVENTORY OVERVIEW                  Scan: latest (2 hours ago)  │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  KEY METRICS                                                      │
│  ┌──────────────┬──────────────┬──────────────┬──────────────┐  │
│  │ 📦 15,247    │ 🔗 28,934    │ 🌍 45        │ ☁️ 3         │  │
│  │ Assets       │ Relationships │ Regions      │ Providers    │  │
│  │ Discovered   │ (Graph Edges) │ Active       │ Connected    │  │
│  └──────────────┴──────────────┴──────────────┴──────────────┘  │
│                                                                   │
│  ASSETS BY PROVIDER                    [View Details →]          │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ AWS         ████████████████░░  12,450 (82%)              │ │
│  │ Azure       ████░░░░░░░░░░░░░   2,100 (14%)              │ │
│  │ GCP         ██░░░░░░░░░░░░░░░     697 (4%)                │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  TOP RESOURCE TYPES                        [View All →]          │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ 🪣 S3 Buckets                   4,523 resources           │ │
│  │ 💻 EC2 Instances                3,245 resources           │ │
│  │ 🗄️ DynamoDB Tables              2,891 resources           │ │
│  │ 🗃️ RDS Instances                1,567 resources           │ │
│  │ 🔐 IAM Roles                    1,234 resources           │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  RECENT DRIFT DETECTED (Last Scan)        [View Drift Report →]  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ ➕ 23 New Assets Added                                     │ │
│  │    • 12 EC2 instances in us-east-1                        │ │
│  │    • 8 S3 buckets                                          │ │
│  │    • 3 RDS instances                                       │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ ➖ 5 Assets Removed                                        │ │
│  │    • 3 terminated EC2 instances                           │ │
│  │    • 2 deleted S3 buckets                                 │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ 🔄 147 Assets Changed                                      │ │
│  │    • 89 tag modifications                                 │ │
│  │    • 45 configuration changes                             │ │
│  │    • 13 relationship changes                              │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  QUICK ACTIONS                                                    │
│  [🔄 Run New Scan] [📥 Export Inventory] [📊 View Graph]        │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// On page load
const summary = await fetch('/api/v1/inventory/runs/latest/summary?tenant_id=155052200811')
const drift = await fetch('/api/v1/inventory/runs/latest/drift?tenant_id=155052200811&limit=10')

// Calculate metrics from summary
const totalAssets = summary.total_assets
const totalRelationships = summary.total_relationships
const assetsByProvider = summary.assets_by_provider
const assetsByResourceType = summary.assets_by_resource_type

// Get top resource types (sort by count)
const topTypes = Object.entries(summary.assets_by_resource_type)
  .sort((a, b) => b[1] - a[1])
  .slice(0, 5)
```

---

## 📦 Screen 2: Asset Catalog

**URL**: `/catalog`

**Purpose**: Browse and search all discovered assets

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  ASSET CATALOG                     🔍 [Search assets...]         │
├──────────────────────────────────────────────────────────────────┤
│  FILTERS                                                          │
│  Provider: [All ▼] | Account: [All ▼] | Region: [All ▼]         │
│  Resource Type: [All ▼] | Tags: [All ▼]                          │
│                                                                   │
│  📊 Showing 15,247 assets | 3 providers | 8 accounts | 45 regions│
│                                                                   │
│  GROUP BY: [Provider ▼]                    [🗃️ Card] [📋 List]  │
│                                                                   │
│  ▼ AWS (12,450 assets)                                           │
│    ├─ ▼ Account: 155052200811 (5,200 assets)                    │
│    │   ├─ ▼ ap-south-1 (1,856 assets)                           │
│    │   │   ├─ 🪣 S3 Buckets (423)                  [Expand ▼]   │
│    │   │   │   ┌──────────────────────────────────────────────────┐ │
│    │   │   │   │ my-prod-bucket                                   │ │
│    │   │   │   │ S3 Bucket | ap-south-1                           │ │
│    │   │   │   │ Account: 155052200811                            │ │
│    │   │   │   │ Tags: env=prod, team=security                    │ │
│    │   │   │   │ Relationships: 5 (1 KMS key, 2 IAM roles, ...) │ │
│    │   │   │   │ [View Details →] [View Graph →]                 │ │
│    │   │   │   └──────────────────────────────────────────────────┘ │
│    │   │   │                                                          │
│    │   │   ├─ 💻 EC2 Instances (567)                               │
│    │   │   ├─ 🗄️ DynamoDB Tables (234)                             │
│    │   │   ├─ 🗃️ RDS Instances (156)                               │
│    │   │   └─ 🔐 IAM Roles (476)                                   │
│    │   │                                                              │
│    │   └─ ▶ us-east-1 (2,344 assets)                               │
│    │                                                                  │
│    └─ ▶ Account: 194722442770 (7,250 assets)                        │
│                                                                      │
│  ▼ Azure (2,100 assets)                                             │
│  ▼ GCP (697 assets)                                                 │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// Initial load with filters
const assets = await fetch('/api/v1/inventory/assets?tenant_id=155052200811&provider=aws&limit=100')

// Filter by account
const filtered = await fetch('/api/v1/inventory/assets?tenant_id=155052200811&account_id=155052200811&region=ap-south-1&resource_type=s3.bucket')

// Get relationships count per asset (may need aggregation endpoint)
const relationships = await fetch('/api/v1/inventory/relationships?tenant_id=155052200811&resource_uid={uid}')
```

**Data Display**:
- Asset cards with key metadata
- Filterable/searchable list
- Grouped by provider/account/region/service
- Relationship count per asset
- Click → navigate to Asset Detail

---

## 🔍 Screen 3: Asset Detail

**URL**: `/assets/{resource_uid}`

**Purpose**: Complete view of one asset with relationships and metadata

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  ◀ Back to Catalog                                               │
├──────────────────────────────────────────────────────────────────┤
│  📦 my-prod-bucket                                                │
│  arn:aws:s3:::my-prod-bucket                                      │
│                                                                   │
│  ASSET INFO                                                       │
│  Provider: AWS | Account: 155052200811 | Region: ap-south-1      │
│  Resource Type: s3.bucket | Status: Active                        │
│  Created: 2025-10-15 10:30:00 UTC                                 │
│  Last Scanned: 2026-01-18 08:00:00 UTC                            │
│  Tags: env=prod, team=security, cost-center=engineering           │
│                                                                   │
│  METADATA                                                          │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Versioning: Enabled                                       │   │
│  │ Encryption: AES256 (Server-side)                         │   │
│  │ Public Access: Blocked                                   │   │
│  │ Lifecycle Rules: 2 configured                           │   │
│  │ Notification Configs: 1 SQS queue                       │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
│  ┌─ TABS ──────────────────────────────────────────────────┐   │
│  │ [Overview] [Relationships] [Drift History] [Raw Data]   │   │
│  ├──────────────────────────────────────────────────────────┤   │
│  │ 🔗 RELATIONSHIPS (5 connections)                         │   │
│  │                                                           │   │
│  │ ┌─────────────────────────────────────────────────────┐ │   │
│  │ │ 🔐 ENCRYPTED_BY                                     │ │   │
│  │ │ ┌──────────────────────────────────────────────┐   │ │   │
│  │ │ │ arn:aws:kms:ap-south-1:155052200811:key/abc │   │ │   │
│  │ │ │ KMS Key | ap-south-1                         │   │ │   │
│  │ │ │ [View Asset →]                               │   │ │   │
│  │ │ └──────────────────────────────────────────────┘   │ │   │
│  │ └─────────────────────────────────────────────────────┘ │   │
│  │                                                           │   │
│  │ ┌─────────────────────────────────────────────────────┐ │   │
│  │ │ 👤 CONTROLLED_BY                                    │ │   │
│  │ │ ┌──────────────────────────────────────────────┐   │ │   │
│  │ │ │ arn:aws:iam::155052200811:role/s3-access-role│   │ │   │
│  │ │ │ IAM Role | global                            │   │ │   │
│  │ │ │ [View Asset →]                               │   │ │   │
│  │ │ └──────────────────────────────────────────────┘   │ │   │
│  │ └─────────────────────────────────────────────────────┘ │   │
│  │                                                           │   │
│  │ [View Graph Visualization →]                             │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
│  DRIFT HISTORY                                                    │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ 2026-01-18: Asset changed (tags.env: dev → prod)          │ │
│  │ 2026-01-15: Relationship added (encrypted_by → KMS key)   │ │
│  │ 2025-12-01: Asset first discovered                       │ │
│  └────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// Resource UID from URL params
const resourceUid = decodeURIComponent(params.resource_uid)

// Load all data in parallel
const [asset, relationships, driftHistory] = await Promise.all([
  fetch(`/api/v1/inventory/assets/${resourceUid}?tenant_id=155052200811`),
  fetch(`/api/v1/inventory/assets/${resourceUid}/relationships?tenant_id=155052200811&depth=2`),
  fetch(`/api/v1/inventory/assets/${resourceUid}/drift?tenant_id=155052200811&limit=20`)
])

// Group relationships by type
const byType = {}
relationships.forEach(rel => {
  if (!byType[rel.relation_type]) byType[rel.relation_type] = []
  byType[rel.relation_type].push(rel)
})
```

---

## 🕸️ Screen 4: Relationship Graph

**URL**: `/graph`

**Purpose**: Interactive graph visualization of asset relationships

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  🕸️ ASSET RELATIONSHIP GRAPH                                      │
├──────────────────────────────────────────────────────────────────┤
│  FILTERS                                                          │
│  Start Asset: [Search...] | Depth: [2 ▼] | Relation Types: [All] │
│                                                                   │
│  [Interactive Graph Canvas]                                       │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                                                             │ │
│  │                    [KMS Key]                               │ │
│  │                         │                                  │ │
│  │                         │ encrypted_by                     │ │
│  │                         ↓                                  │ │
│  │              [S3 Bucket]─────┐                             │ │
│  │                  │           │                             │ │
│  │                  │           │                             │ │
│  │        controlled_by    connected_to                       │ │
│  │                  │           │                             │ │
│  │                  ↓           ↓                             │ │
│  │           [IAM Role]    [Lambda Function]                  │ │
│  │                  │           │                             │ │
│  │                  │           │ attached_to                 │ │
│  │                  └───────────┘                             │ │
│  │                           │                                │ │
│  │                           ↓                                │ │
│  │                    [VPC]                                   │ │
│  │                                                             │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  LEGEND                                                           │
│  [🪣 S3] [💻 EC2] [🗄️ DynamoDB] [🔐 IAM] [🔑 KMS] [🌐 VPC]      │
│                                                                   │
│  RELATIONSHIP TYPES                                               │
│  ──── encrypted_by  ━━━ controlled_by  ═══ connected_to          │
│                                                                   │
│  [Center Graph] [Export PNG] [Export JSON] [Share Link]          │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// Start from a specific asset
const assetUid = params.resource_uid || null
const depth = params.depth || 2

if (assetUid) {
  // Get subgraph from this asset
  const graph = await fetch(`/api/v1/inventory/graph?tenant_id=155052200811&resource_uid=${assetUid}&depth=${depth}`)
} else {
  // Get overview graph (top connected assets)
  const graph = await fetch(`/api/v1/inventory/graph?tenant_id=155052200811&limit=100`)
}

// Graph response format
// {
//   "nodes": [
//     {"id": "arn:...", "type": "s3.bucket", "name": "my-bucket", ...}
//   ],
//   "edges": [
//     {"from": "arn:...", "to": "arn:...", "type": "encrypted_by", ...}
//   ]
// }
```

---

## 📊 Screen 5: Drift Dashboard

**URL**: `/drift`

**Purpose**: Track changes and drift between scans

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  📊 DRIFT & CHANGE DETECTION                                      │
├──────────────────────────────────────────────────────────────────┤
│  COMPARE SCANS                                                    │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Baseline: [latest ▼]                                       │ │
│  │ Compare:  [20260118_080000 ▼]                              │ │
│  │ Time Range: Last 30 days                                   │ │
│  │ [Compare →]                                                 │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  DRIFT SUMMARY                                                    │
│  ┌──────────────┬──────────────┬──────────────┬──────────────┐  │
│  │ ➕ 23        │ ➖ 5         │ 🔄 147       │ ✅ 14,819    │  │
│  │ Added        │ Removed      │ Changed      │ Unchanged    │  │
│  │ Assets       │ Assets       │ Assets       │ Assets       │  │
│  └──────────────┴──────────────┴──────────────┴──────────────┘  │
│                                                                   │
│  CHANGES BY TYPE                            [Filter: All ▼]      │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ ➕ Asset Added                   23 changes                │ │
│  │    • 12 EC2 instances in us-east-1                        │ │
│  │    • 8 S3 buckets                                          │ │
│  │    • 3 RDS instances                                       │ │
│  │    [View All →]                                            │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ ➖ Asset Removed                 5 changes                 │ │
│  │    • 3 terminated EC2 instances                           │ │
│  │    • 2 deleted S3 buckets                                 │ │
│  │    [View All →]                                            │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ 🔄 Asset Changed                  147 changes              │ │
│  │    • 89 tag modifications                                 │ │
│  │    • 45 configuration changes                             │ │
│  │    • 13 metadata updates                                  │ │
│  │    [View All →]                                            │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ 🔗 Relationship Changed           18 changes               │ │
│  │    • 12 edges added                                        │ │
│  │    • 6 edges removed                                       │ │
│  │    [View All →]                                            │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  CHANGES BY PROVIDER                  [View Trends →]            │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ AWS         ████████████░░  158 changes (90%)             │ │
│  │ Azure       ███░░░░░░░░░░   12 changes (7%)               │ │
│  │ GCP         █░░░░░░░░░░░░    5 changes (3%)               │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  RECENT CHANGES TIMELINE            [Export Report ↓]            │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ 2026-01-18 08:00  |  ➕ 5 new assets                       │ │
│  │ 2026-01-17 20:00  |  🔄 23 assets changed                 │ │
│  │ 2026-01-17 08:00  |  ➖ 2 assets removed                   │ │
│  │ 2026-01-16 08:00  |  ➕ 12 new assets                      │ │
│  └────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// Get drift between two scans
const drift = await fetch(
  '/api/v1/inventory/drift?tenant_id=155052200811&baseline_scan=latest&compare_scan=20260118_080000'
)

// Get drift for specific asset
const assetDrift = await fetch(
  '/api/v1/inventory/assets/{resource_uid}/drift?tenant_id=155052200811&limit=50'
)

// Group by change type
const byType = {
  added: drift.filter(d => d.change_type === 'asset_added'),
  removed: drift.filter(d => d.change_type === 'asset_removed'),
  changed: drift.filter(d => d.change_type === 'asset_changed')
}

// Group by provider
const byProvider = {}
drift.forEach(d => {
  const provider = d.provider || 'unknown'
  if (!byProvider[provider]) byProvider[provider] = 0
  byProvider[provider]++
})
```

---

## 🏢 Screen 6: Account Dashboard

**URL**: `/accounts/{account_id}`

**Purpose**: Complete inventory view for one account

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  🏢 ACCOUNT: 155052200811 (AWS)                                   │
├──────────────────────────────────────────────────────────────────┤
│  OVERVIEW                                                         │
│  ┌──────────────┬──────────────┬──────────────┬──────────────┐  │
│  │ 5,200        │ 12,450       │ 17           │ 12           │  │
│  │ Assets       │ Relationships │ Regions      │ Services     │  │
│  │ Discovered   │ (Graph Edges) │ Active       │ In Use       │  │
│  └──────────────┴──────────────┴──────────────┴──────────────┘  │
│                                                                   │
│  ASSETS BY SERVICE                       [View All Services →]   │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Service      │ Assets │ Relationships │ Regions │ Status   │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ 🪣 S3        │ 1,856  │ 3,234         │ 12      │ ✅ Active │ │
│  │ 💻 EC2       │ 1,234  │ 4,567         │ 15      │ ✅ Active │ │
│  │ 🗄️ DynamoDB  │   567  │ 1,123         │  8      │ ✅ Active │ │
│  │ 🗃️ RDS       │   456  │   890         │ 10      │ ✅ Active │ │
│  │ 🔐 IAM       │ 1,087  │ 2,636         │  1      │ ✅ Active │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  REGIONAL DISTRIBUTION                      [View Map →]          │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ ap-south-1    ████████████████░░  1,856 assets (36%)      │ │
│  │ us-east-1     ████████████░░░░░░  1,234 assets (24%)      │ │
│  │ us-west-2     ████████░░░░░░░░░░    890 assets (17%)      │ │
│  │ eu-west-1     ██████░░░░░░░░░░░░    678 assets (13%)      │ │
│  │ ap-northeast-1█████░░░░░░░░░░░░░    542 assets (10%)      │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  RESOURCE TYPE BREAKDOWN                                          │
│  S3 Buckets: 1,856 | EC2 Instances: 1,234 | DynamoDB: 567 | ...  │
│                                                                   │
│  RECENT CHANGES (Last Scan)                                       │
│  • 5 new EC2 instances created                                   │
│  • 3 S3 buckets deleted                                          │
│  • 12 assets had tag changes                                     │
│  • 8 new relationships discovered                                │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// Load account summary
const account = await fetch('/api/v1/inventory/accounts/155052200811?tenant_id=155052200811&scan_id=latest')

// Load assets by service
const services = await fetch('/api/v1/inventory/assets?tenant_id=155052200811&account_id=155052200811&group_by=service')

// Load regional distribution
const regions = await fetch('/api/v1/inventory/assets?tenant_id=155052200811&account_id=155052200811&group_by=region')

// Recent drift for this account
const drift = await fetch('/api/v1/inventory/drift?tenant_id=155052200811&account_id=155052200811&limit=10')
```

---

## 🔧 Screen 7: Service Dashboard

**URL**: `/services/{service}`

**Purpose**: View all assets of a specific service type (e.g., S3, EC2)

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  🪣 S3 SERVICE INVENTORY                                          │
├──────────────────────────────────────────────────────────────────┤
│  OVERVIEW                                                         │
│  ┌──────────────┬──────────────┬──────────────┬──────────────┐  │
│  │ 4,523        │ 12,234       │ 8            │ 45           │  │
│  │ S3 Buckets   │ Relationships │ Accounts     │ Regions      │  │
│  │ Discovered   │ (Graph Edges) │ Using S3     │ Deployed     │  │
│  └──────────────┴──────────────┴──────────────┴──────────────┘  │
│                                                                   │
│  BUCKETS BY ACCOUNT                       [View All →]           │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Account        │ Buckets │ Public │ Encrypted │ With Tags │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ 155052200811   │ 1,856   │ 23     │ 1,523     │ 1,234     │ │
│  │ 194722442770   │ 1,567   │ 45     │ 1,234     │ 987       │ │
│  │ 588989875114   │ 1,100   │ 12     │ 890       │ 756       │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  REGIONAL DISTRIBUTION                                            │
│  us-east-1: 1,234 | us-west-2: 890 | ap-south-1: 756 | ...       │
│                                                                   │
│  COMMON CONFIGURATIONS                                            │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Versioning Enabled:          3,456 buckets (76%)          │ │
│  │ Encryption Enabled:          3,647 buckets (81%)          │ │
│  │ Public Access Blocked:       4,234 buckets (94%)          │ │
│  │ Lifecycle Rules:             1,234 buckets (27%)          │ │
│  │ Notification Configs:          567 buckets (13%)          │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  BUCKET LIST                      [Filter ▼] [Search...] [Export]│
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ ☐ my-prod-bucket              ap-south-1 | 155052200811    │ │
│  │    Encrypted: ✅ | Public: ❌ | Versioning: ✅             │ │
│  │    [View Details →]                                        │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ ☐ user-uploads              us-east-1 | 155052200811       │ │
│  │    Encrypted: ❌ | Public: ⚠️ | Versioning: ❌             │ │
│  │    [View Details →]                                        │ │
│  └────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// Load service overview
const service = await fetch('/api/v1/inventory/services/s3?tenant_id=155052200811&scan_id=latest')

// Get all assets of this service type
const assets = await fetch('/api/v1/inventory/assets?tenant_id=155052200811&resource_type=s3.bucket&limit=100')

// Group by account
const byAccount = await fetch('/api/v1/inventory/assets?tenant_id=155052200811&resource_type=s3.bucket&group_by=account_id')

// Get configuration stats (requires metadata parsing)
// May need to aggregate from asset metadata
```

---

## ☁️ Screen 8: Multi-Cloud Dashboard

**URL**: `/providers`

**Purpose**: Compare inventory across cloud providers

**Layout**:
```
┌──────────────────────────────────────────────────────────────────┐
│  ☁️ MULTI-CLOUD INVENTORY                                         │
├──────────────────────────────────────────────────────────────────┤
│  PROVIDER COMPARISON                                              │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Provider │ Assets │ Accounts │ Regions │ Services │ Graph  │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ ☁️ AWS   │ 12,450 │ 5        │ 45      │ 25       │ 28K    │ │
│  │          │        │          │         │          │ edges  │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ 🔷 Azure │  2,100 │ 3        │ 12      │ 18       │ 4.2K   │ │
│  │          │        │          │         │          │ edges  │ │
│  ├────────────────────────────────────────────────────────────┤ │
│  │ 🟢 GCP   │    697 │ 2        │  8      │ 12       │ 1.5K   │ │
│  │          │        │          │         │          │ edges  │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  COMMON RESOURCE TYPES ACROSS PROVIDERS                          │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Storage Buckets                                             │ │
│  │ AWS S3: 4,523 | Azure Blob: 567 | GCP Cloud Storage: 234   │ │
│  │                                                             │ │
│  │ Compute Instances                                           │ │
│  │ AWS EC2: 3,245 | Azure VMs: 890 | GCP Compute: 234         │ │
│  │                                                             │ │
│  │ Databases                                                   │ │
│  │ AWS RDS: 1,567 | Azure SQL: 456 | GCP Cloud SQL: 123       │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  CROSS-CLOUD RELATIONSHIPS                                        │
│  0 cross-cloud relationships detected                            │
│  (Note: Cross-cloud relationships require external integration)  │
│                                                                   │
│  [View AWS →] [View Azure →] [View GCP →]                       │
└──────────────────────────────────────────────────────────────────┘
```

**API Calls**:
```javascript
// Load summary for all providers
const summary = await fetch('/api/v1/inventory/runs/latest/summary?tenant_id=155052200811')

// Group by provider
const byProvider = summary.assets_by_provider

// Get common resource types across providers
const aws = await fetch('/api/v1/inventory/assets?tenant_id=155052200811&provider=aws&group_by=resource_type')
const azure = await fetch('/api/v1/inventory/assets?tenant_id=155052200811&provider=azure&group_by=resource_type')
const gcp = await fetch('/api/v1/inventory/assets?tenant_id=155052200811&provider=gcp&group_by=resource_type')
```

---

## 📊 Data Fields Reference

### Asset (`/assets`)
```json
{
  "schema_version": "cspm_asset.v1",
  "tenant_id": "155052200811",
  "scan_run_id": "inv_20260118_080000",
  "provider": "aws",
  "account_id": "155052200811",
  "region": "ap-south-1",
  "scope": "regional",
  "resource_type": "s3.bucket",
  "resource_id": "my-prod-bucket",
  "resource_uid": "arn:aws:s3:::my-prod-bucket",
  "name": "my-prod-bucket",
  "tags": {
    "env": "prod",
    "team": "security"
  },
  "metadata": {
    "created_at": "2025-10-01T10:12:00Z",
    "versioning": true,
    "encryption": "AES256",
    "public_access_blocked": true,
    "raw_refs": [
      "s3://.../raw/aws/155052200811/ap-south-1/s3.json"
    ]
  },
  "hash_sha256": "abc123..."
}
```

### Relationship (`/relationships`)
```json
{
  "schema_version": "cspm_relationship.v1",
  "tenant_id": "155052200811",
  "scan_run_id": "inv_20260118_080000",
  "provider": "aws",
  "account_id": "155052200811",
  "region": "ap-south-1",
  "relation_type": "encrypted_by",
  "from_uid": "arn:aws:s3:::my-prod-bucket",
  "to_uid": "arn:aws:kms:ap-south-1:155052200811:key/abc123",
  "properties": {
    "encryption_type": "KMS",
    "key_id": "abc123"
  }
}
```

### Drift Record (`/drift`)
```json
{
  "schema_version": "cspm_drift.v1",
  "tenant_id": "155052200811",
  "scan_run_id": "inv_20260118_080000",
  "change_type": "asset_changed",
  "resource_uid": "arn:aws:s3:::my-prod-bucket",
  "diff": {
    "path": "tags.env",
    "before": "dev",
    "after": "prod"
  },
  "detected_at": "2026-01-18T08:00:00Z"
}
```

### Scan Summary (`/summary`)
```json
{
  "scan_run_id": "inv_20260118_080000",
  "tenant_id": "155052200811",
  "started_at": "2026-01-18T08:00:00Z",
  "completed_at": "2026-01-18T09:30:00Z",
  "status": "completed",
  "total_assets": 15247,
  "total_relationships": 28934,
  "assets_by_provider": {
    "aws": 12450,
    "azure": 2100,
    "gcp": 697
  },
  "assets_by_resource_type": {
    "s3.bucket": 4523,
    "ec2.instance": 3245,
    "dynamodb.table": 2891
  },
  "assets_by_region": {
    "ap-south-1": 1856,
    "us-east-1": 1234
  },
  "providers_scanned": ["aws", "azure", "gcp"],
  "accounts_scanned": ["155052200811", "194722442770"],
  "regions_scanned": ["ap-south-1", "us-east-1", ...],
  "errors_count": 0
}
```

---

## 🎨 UI Component Library Recommendations

1. **Graph Visualization**: Cytoscape.js, React Flow, or D3.js for relationship graphs
2. **Charts**: Recharts, Chart.js, or Apache ECharts
3. **Tables**: TanStack Table (React Table v8) with virtualization
4. **Maps**: Leaflet or MapBox for regional visualization
5. **Framework**: React, Vue, or Angular
6. **State**: Redux/Zustand or React Query for API caching
7. **Search**: Elasticsearch/OpenSearch for asset search (if needed)

---

## ✅ Implementation Checklist for Frontend

- [ ] Executive Dashboard with metrics cards
- [ ] Asset Catalog with search/filter/group
- [ ] Asset Detail with tabs (overview, relationships, drift, raw)
- [ ] Relationship Graph with interactive visualization
- [ ] Drift Dashboard with change comparison
- [ ] Account view with service breakdown
- [ ] Service view with configuration stats
- [ ] Multi-cloud provider comparison
- [ ] Export functionality (CSV/JSON/PDF)
- [ ] Real-time scan status updates
- [ ] Graph export (PNG/SVG/JSON)

---

## 🔌 Missing API Endpoints (To Be Implemented)

### Critical APIs Needed:

1. **GET `/api/v1/inventory/assets`** ✅ (Partially implemented, needs completion)
   - ✅ Basic filtering (provider, region, resource_type)
   - ❌ Grouping (group_by parameter)
   - ❌ Pagination with cursor
   - ❌ Search functionality
   - ❌ Relationship count aggregation

2. **GET `/api/v1/inventory/assets/{resource_uid}`** ✅ (Partially implemented)
   - ❌ Full asset details with metadata
   - ❌ Historical data lookup

3. **GET `/api/v1/inventory/assets/{resource_uid}/relationships`** ✅ (Partially implemented)
   - ❌ Depth-based traversal
   - ❌ Filter by relation_type
   - ❌ Direction (inbound/outbound)

4. **GET `/api/v1/inventory/graph`** ❌ (Not implemented)
   - Graph visualization endpoint
   - Returns nodes and edges for visualization library
   - Support for depth, filters, and limits

5. **GET `/api/v1/inventory/drift`** ❌ (Not implemented)
   - Compare two scans
   - Filter by account, provider, resource_type
   - Group by change_type

6. **GET `/api/v1/inventory/assets/{resource_uid}/drift`** ❌ (Not implemented)
   - Drift history for specific asset
   - Timeline view

7. **GET `/api/v1/inventory/accounts/{account_id}`** ❌ (Not implemented)
   - Account summary
   - Service breakdown
   - Regional distribution

8. **GET `/api/v1/inventory/services/{service}`** ❌ (Not implemented)
   - Service-specific summary
   - Configuration statistics
   - Account distribution

9. **GET `/api/v1/inventory/runs/{scan_run_id}/drift`** ❌ (Not implemented)
   - Drift records for a scan run

10. **GET `/api/v1/inventory/relationships`** ❌ (Not implemented)
    - List relationships with filters
    - Aggregation endpoints

### Nice-to-Have APIs:

11. **POST `/api/v1/inventory/scan`** ✅ (Already implemented)
    - Consider async job queue for long scans
    - WebSocket/SSE for progress updates

12. **GET `/api/v1/inventory/search`** ❌ (Not implemented)
    - Full-text search across assets
    - Tag-based search
    - Metadata search

13. **GET `/api/v1/inventory/stats`** ❌ (Not implemented)
    - Aggregate statistics
    - Trend analysis
    - Growth metrics

**All critical APIs need to be implemented before UI can be fully functional!**



