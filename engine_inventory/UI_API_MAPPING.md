# Inventory Engine UI - API Mapping & Database Queries

## Database Backend

**All UI endpoints query:**
- `threat_engine_inventory.asset_index_latest` TABLE (287 assets)
- `threat_engine_inventory.relationship_index_latest` TABLE (97 relationships)
- `threat_engine_inventory.inventory_run_index` TABLE (scan summaries)

---

## UI Screens & API Endpoints

### 1. Asset Inventory Dashboard
**URL**: `/inventory/dashboard`

**API Endpoint**:
```
GET /api/v1/inventory/runs/latest/summary?tenant_id=test-tenant
```

**Response**:
```json
{
  "scan_run_id": "inv_20260130_034909_6339",
  "total_assets": 266,
  "total_relationships": 97,
  "assets_by_resource_type": {
    "iam.role": 136,
    "iam.attached-policy": 54,
    "s3.bucket": 21,
    "ec2.security-group": 18
  },
  "assets_by_region": {
    "global": 240,
    "us-east-1": 26
  },
  "started_at": "2026-01-30T03:49:09Z",
  "completed_at": "2026-01-30T03:49:27Z"
}
```

**Database Query**:
```sql
SELECT * FROM inventory_run_index
WHERE tenant_id = 'test-tenant'
ORDER BY completed_at DESC
LIMIT 1;
```

---

### 2. Asset List View
**URL**: `/inventory/assets`

**API Endpoint**:
```
GET /api/v1/inventory/assets?tenant_id=test-tenant&resource_type=iam.role&limit=50
```

**Response**:
```json
{
  "assets": [
    {
      "resource_uid": "arn:aws:iam::123:role/RoleName",
      "resource_type": "iam.role",
      "account_id": "588989875114",
      "region": "global",
      "name": null,
      "tags": {},
      "scan_run_id": "inv_20260130_034909_6339"
    }
  ],
  "total": 136,
  "limit": 50,
  "offset": 0,
  "has_more": true
}
```

**Database Query**:
```sql
SELECT * FROM asset_index_latest
WHERE tenant_id = 'test-tenant'
  AND resource_type = 'iam.role'
ORDER BY resource_uid
LIMIT 50;
```

**Filters**:
- `resource_type`: iam.role, s3.bucket, ec2.security-group, etc.
- `provider`: aws, azure, gcp
- `region`: us-east-1, global, etc.
- `account_id`: specific account

---

### 3. Asset Detail View
**URL**: `/inventory/assets/{resource_uid}`

**API Endpoint**:
```
GET /api/v1/inventory/assets/{resource_uid}?tenant_id=test-tenant
```

**Response**:
```json
{
  "resource_uid": "arn:aws:s3:::cspm-lgtech",
  "resource_type": "s3.bucket",
  "account_id": "588989875114",
  "region": "global",
  "provider": "aws",
  "name": null,
  "tags": {},
  "scan_run_id": "inv_20260130_034909_6339",
  "metadata": {}
}
```

**Database Query**:
```sql
SELECT * FROM asset_index_latest
WHERE resource_uid = 'arn:aws:s3:::cspm-lgtech'
  AND tenant_id = 'test-tenant';
```

---

### 4. Asset Relationships View
**URL**: `/inventory/assets/{resource_uid}/relationships`

**API Endpoint**:
```
GET /api/v1/inventory/assets/{resource_uid}/relationships?tenant_id=test-tenant&depth=1
```

**Response**:
```json
{
  "resource_uid": "arn:aws:ec2:us-east-1:123:security-group/sg-123",
  "relationships": [
    {
      "relation_type": "attached_to",
      "from_uid": "arn:aws:ec2:...:security-group/sg-123",
      "to_uid": "arn:aws:ec2:...:vpc/vpc-456",
      "properties": {"source_field_value": "vpc-456"}
    }
  ],
  "by_type": {
    "attached_to": [...]
  },
  "total": 2
}
```

**Database Query**:
```sql
SELECT * FROM relationship_index_latest
WHERE (from_uid = 'arn:aws:ec2:...:security-group/sg-123'
   OR to_uid = 'arn:aws:ec2:...:security-group/sg-123')
  AND tenant_id = 'test-tenant';
```

---

### 5. Relationship Graph View
**URL**: `/inventory/relationships`

**API Endpoint**:
```
GET /api/v1/inventory/relationships?tenant_id=test-tenant&relation_type=attached_to&limit=100
```

**Response**:
```json
{
  "relationships": [
    {
      "from_uid": "arn:aws:ec2:...:sg/sg-123",
      "to_uid": "arn:aws:ec2:...:vpc/vpc-456",
      "relation_type": "attached_to",
      "account_id": "588989875114"
    }
  ],
  "total": 97,
  "limit": 100
}
```

**Database Query**:
```sql
SELECT * FROM relationship_index_latest
WHERE tenant_id = 'test-tenant'
  AND relation_type = 'attached_to'
ORDER BY from_uid
LIMIT 100;
```

**Relationship Types**:
- `attached_to` (36 relationships)
- `contained_by` (26)
- `member_of` (18)
- `uses` (5)
- `encrypted_by` (3)
- `controlled_by`, `backs_up_to`, `has_policy`, `replicates_to`

---

### 6. Drift History View
**URL**: `/inventory/drift`

**API Endpoint**:
```
GET /api/v1/inventory/drift?tenant_id=test-tenant&scan_run_id=inv_latest
```

**Database Query**:
```sql
-- Note: Drift detection not yet implemented in inventory
-- Would query discovered_drift or similar table
```

---

## Inventory Engine API Summary

### Asset Queries:
- `GET /api/v1/inventory/assets` - List assets (filterable)
- `GET /api/v1/inventory/assets/{resource_uid}` - Asset detail
- `GET /api/v1/inventory/runs/latest/summary` - Latest scan summary

### Relationship Queries:
- `GET /api/v1/inventory/relationships` - List relationships
- `GET /api/v1/inventory/assets/{resource_uid}/relationships` - Asset relationships

### Scans:
- `POST /api/v1/inventory/scan/async` - Run inventory scan
- `GET /api/v1/inventory/jobs/{job_id}` - Check scan status
- `GET /api/v1/inventory/scans` - List scans

---

## Database Views for Inventory UI

**Create these views for UI dashboards**:

### Assets by Type (for pie chart):
```sql
CREATE VIEW assets_by_type AS
SELECT 
    resource_type,
    COUNT(*) as count
FROM asset_index_latest
WHERE tenant_id = 'test-tenant'
GROUP BY resource_type
ORDER BY count DESC;
```

### Assets by Region (for map):
```sql
CREATE VIEW assets_by_region AS
SELECT 
    region,
    COUNT(*) as count,
    COUNT(DISTINCT resource_type) as resource_types
FROM asset_index_latest
WHERE tenant_id = 'test-tenant'
GROUP BY region;
```

### Relationship Summary:
```sql
CREATE VIEW relationship_summary AS
SELECT 
    relation_type,
    COUNT(*) as count
FROM relationship_index_latest
WHERE tenant_id = 'test-tenant'
GROUP BY relation_type;
```

---

## Testing Inventory UI APIs

```bash
kubectl -n threat-engine-local port-forward svc/inventory-service 8022:8022 &

# Dashboard
curl "http://localhost:8022/api/v1/inventory/runs/latest/summary?tenant_id=test-tenant" | jq

# List S3 buckets
curl "http://localhost:8022/api/v1/inventory/assets?tenant_id=test-tenant&resource_type=s3.bucket" | jq

# Asset detail
curl "http://localhost:8022/api/v1/inventory/assets/arn:aws:s3:::cspm-lgtech?tenant_id=test-tenant" | jq

# Relationships
curl "http://localhost:8022/api/v1/inventory/relationships?tenant_id=test-tenant&limit=10" | jq
```

---

## Files Created

- `engine_inventory/UI_API_MAPPING.md` (this file)
- All endpoints query database tables (no file dependencies)

**Next**: Check/Discovery engine UI mapping
