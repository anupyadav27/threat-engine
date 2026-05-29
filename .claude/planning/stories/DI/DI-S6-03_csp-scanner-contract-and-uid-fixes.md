# DI-S6-03 — CSP Scanner Contract Fix + UID Fixes (Azure / GCP / AliCloud)
**Sprint**: DI-S6 | **Type**: Bug Fix | **Status**: Planned → Implementing
**Points**: 5 | **Priority**: Critical (Azure/GCP/AliCloud write 0 rows)

---

## Root Cause Per CSP

### Azure — scan_service() contract mismatch
`_scan_one()` expects every scanner to return `(items_list, metadata_dict)`.
AWS/GCP/OCI return a 2-tuple. Azure returns a bare `List[Dict]`.
Unpacking `[]` into `items, _` → `ValueError: not enough values to unpack (expected 2, got 0)`.
All 1947 Azure service×region tasks fail with this error → 0 rows written.

**Fix**: Normalize in `_scan_one()` before unpacking.

### GCP — uid_template '{item.name}' produces non-canonical value
GCS bucket selfLink = `https://www.googleapis.com/storage/v1/b/my-bucket` → canonical.
But `uid_template='{item.name}'` → `"my-bucket"` → not canonical (doesn't start with `projects/`
or `https://www.googleapis.com/`). Strategy 1 fails silently, Strategy 2 checks `selfLink` but
`CANONICAL_PREFIXES` for GCP was missing `https://storage.googleapis.com/` as an alternative prefix.
Fix: add storage prefix + fix uid_template to use `{item.selfLink}` for storage service.

### AliCloud — heuristic misses CSP-specific ID fields
`_CSP_FIELD_CANDIDATES["alicloud"] = ("id", "ResourceId", "InstanceId")` — none of these match:
- RAM roles: have `Arn` field → `acs:ram::123456:role/my-role` (already canonical, just not checked)
- RAM users: have `UserId` (numeric, not canonical) → need uid_template
- VPC: have `VpcId` (e.g. `vpc-xxx`, not canonical) → need uid_template

---

## Code Fixes

### 1. enumerator.py `_scan_one()` — normalize return type (fixes Azure)
```python
# Before (breaks on Azure):
items, _ = await scanner.scan_service(service=service, region=region,
                                      config=config, skip_dependents=False)

# After (handles both List and (List, dict)):
result = await scanner.scan_service(service=service, region=region,
                                    config=config, skip_dependents=False)
if isinstance(result, tuple):
    items = result[0] if result else []
else:
    items = result or []
```

### 2. uid_builder.py — GCP canonical prefixes + AliCloud field candidates
```python
CANONICAL_PREFIXES = {
    ...
    "gcp": ("projects/", "https://www.googleapis.com/", "https://storage.googleapis.com/"),
    ...
}

_CSP_FIELD_CANDIDATES = {
    ...
    "alicloud": ("Arn", "id", "ResourceId", "InstanceId", "BucketName"),
    ...
}
```

## SQL Fixes (check DB)

### GCP — fix storage uid_template
```sql
UPDATE rule_discoveries
SET    uid_template = '{item.selfLink}'
WHERE  provider = 'gcp' AND service = 'storage'
  AND  uid_template = '{item.name}';
```

### AliCloud — add uid_templates for RAM users and VPC
```sql
UPDATE rule_discoveries
SET    uid_template = 'acs:ram::{context.account_id}:user/{item.UserName}'
WHERE  provider = 'alicloud' AND service = 'ram'
  AND  discoveries_data::text LIKE '%UserName%'
  AND  discoveries_data::text NOT LIKE '%RoleName%';

UPDATE rule_discoveries
SET    uid_template = 'acs:vpc:{context.region}:{context.account_id}:vpc/{item.VpcId}'
WHERE  provider = 'alicloud' AND service = 'vpc'
  AND  uid_template IS NULL;
```

---

## Acceptance Criteria
- [ ] Azure scan writes rows (no ValueError in di_scan_errors)
- [ ] GCP storage rows have `resource_uid` starting with `https://www.googleapis.com/` or `https://storage.googleapis.com/`
- [ ] AliCloud RAM role rows have `resource_uid` starting with `acs:`
- [ ] AliCloud RAM user rows have `resource_uid = acs:ram::account:user/name`
- [ ] AliCloud VPC rows have `resource_uid = acs:vpc:region:account:vpc/id`
- [ ] Zero ResourceIdMissingError for storage (GCP) and ram/vpc (AliCloud)