# Inventory Enrichment Implementation

## Overview
Upgraded inventory creation to automatically enrich independent discovery results with data from dependent discoveries. This provides richer inventory data without changing checks or scan collection logic.

## What Changed

### 1. New Enrichment Function
- **Function**: `_enrich_inventory_with_dependent_discoveries()`
- **Location**: `engine/service_scanner.py` (lines 1779-1880)
- **Purpose**: Merges dependent discovery results into independent discovery items

### 2. Integration Points
- Integrated into `run_global_service()` (line ~2832)
- Integrated into `run_regional_service()` (line ~3515)
- Runs in **PHASE 2: BUILD INVENTORY** (after discoveries, before checks)

### 3. What Remains Unchanged
- ✅ **Checks logic**: No changes to check execution or evaluation
- ✅ **Scan collection**: No changes to discovery execution
- ✅ **Standard template fields**: Protected from overwriting
- ✅ **Backward compatibility**: Existing inventory structure preserved

## How It Works

### Independent Discoveries (Base Inventory)
- Create base inventory items with standard template fields:
  - `resource_arn`, `resource_id`, `resource_type`, `resource_name`, `resource_uid`, `name`, `tags`
- Examples:
  - `aws.s3.list_buckets` → Creates bucket inventory items
  - `aws.ec2.describe_instances` → Creates instance inventory items

### Dependent Discoveries (Enrichment)
- Enrich base items by adding their fields:
  - `aws.s3.get_bucket_versioning` → Adds `Status`, `MFADelete` to buckets
  - `aws.s3.get_bucket_abac` → Adds `Status` (ABAC) to buckets
  - `aws.s3.get_public_access_block` → Adds `BlockPublicAcls`, etc. to buckets

### Matching Logic
- Matches dependent items to independent items using common keys:
  - `Name`, `name`, `resource_id`, `Bucket`, `ResourceId`, `InstanceId`, etc.
- Protects standard template fields from overwriting
- Skips `None` values to keep inventory clean

## Example: S3 Bucket Enrichment

### Before (Independent Only)
```json
{
  "resource_arn": "arn:aws:s3:::my-bucket",
  "resource_id": "my-bucket",
  "resource_type": "s3:bucket",
  "name": "my-bucket",
  "Name": "my-bucket",
  "CreationDate": "2024-01-01T00:00:00Z"
}
```

### After (Enriched)
```json
{
  "resource_arn": "arn:aws:s3:::my-bucket",
  "resource_id": "my-bucket",
  "resource_type": "s3:bucket",
  "name": "my-bucket",
  "Name": "my-bucket",
  "CreationDate": "2024-01-01T00:00:00Z",
  
  // Enriched fields from dependent discoveries:
  "Status": "Enabled",                    // from get_bucket_versioning
  "MFADelete": "Disabled",                // from get_bucket_versioning
  "IsPublic": false,                      // from get_bucket_policy_status
  "BlockPublicAcls": true,                // from get_public_access_block
  "IgnorePublicAcls": true,               // from get_public_access_block
  "BlockPublicPolicy": true,              // from get_public_access_block
  "RestrictPublicBuckets": true,          // from get_public_access_block
  "TargetBucket": "logs-bucket",          // from get_bucket_logging
  
  "_enriched_from": [                     // Tracking field
    "aws.s3.get_bucket_versioning",
    "aws.s3.get_bucket_policy_status",
    "aws.s3.get_public_access_block",
    "aws.s3.get_bucket_logging"
  ]
}
```

## Protected Fields
These fields are **never overwritten** by dependent discoveries:
- `resource_arn`
- `resource_id`
- `resource_type`
- `resource_name`
- `resource_uid`
- `name`
- `tags`
- `Name` (matching key)

## Output Structure

### File Organization
```
output/
  scan_20260119_143000/
    ├── inventory.ndjson                    # Combined (all accounts/regions/services)
    ├── inventory_588989875114_ap-south-1.ndjson  # Per account+region
    ├── inventory_588989875114_us-east-1.ndjson
    └── summary.json
```

### Format
- **NDJSON**: One JSON object per line
- **Multi-dimensional**: Each record includes `account_id`, `region`, `service`
- **Enriched**: Dependent discovery fields merged into base items

## Benefits

1. **Richer Inventory**: More complete resource information
2. **No Breaking Changes**: Standard template fields preserved
3. **Automatic**: Works for all services with dependent discoveries
4. **Queryable**: Enriched fields available for filtering/analysis
5. **Trackable**: `_enriched_from` field shows which discoveries enriched each item

## Testing

To verify enrichment is working:

1. Run a scan with services that have dependent discoveries (e.g., S3)
2. Check inventory files for enriched fields
3. Verify standard template fields are preserved
4. Check `_enriched_from` field shows dependent discovery IDs

Example query:
```bash
# Check if S3 buckets have versioning status (enriched field)
grep '"service":"s3"' inventory.ndjson | grep '"Status":"Enabled"'
```

## Notes

- Enrichment happens **after** all discoveries complete
- Enrichment happens **before** checks run (checks can use enriched data)
- If enrichment fails, it logs a warning but continues (non-blocking)
- Only enriches inventory resources (filtered by `is_cspm_inventory_resource()`)

