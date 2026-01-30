# Fields Without Operations - Analysis Summary

## Overview

Analysis of the **21.3% (7,598 fields)** that have no `operations` field listed in `direct_vars.json`.

## Key Findings

### Summary

- **Total fields without operations**: 7,598
- **In dependency_index.json**: 7,598 (100.0%) ✅
- **From READ operations**: 6,858 (90.3%) ✅ **KEEP**
- **From WRITE operations**: 740 (9.7%) ❌ **REMOVE**

### Recommendation

**✅ KEEP 90.3% (6,858 fields)** - These are from read operations
- These fields should have their `operations` field populated
- They are valid for CSPM read-only use cases
- They can be discovered through read operations

**❌ REMOVE 9.7% (740 fields)** - These are from write operations
- These fields are produced by write operations (Create, Update, etc.)
- Not needed for CSPM read-only use cases
- Should be removed when filtering to read-only

## Breakdown

```
Fields Without Operations: 7,598
├─ ✅ From READ operations: 6,858 (90.3%) → KEEP
└─ ❌ From WRITE operations: 740 (9.7%) → REMOVE
```

## Top Services

### Fields from READ Operations (Should Keep - Add Operations)

| Service | Count | Notes |
|---------|-------|-------|
| sagemaker | 258 | Should add operations to these fields |
| eip | 245 | Should add operations to these fields |
| vpcflowlogs | 245 | Should add operations to these fields |
| ebs | 243 | Should add operations to these fields |
| ec2 | 243 | Should add operations to these fields |
| vpc | 243 | Should add operations to these fields |
| iotsitewise | 122 | Should add operations to these fields |
| iot | 98 | Should add operations to these fields |
| glue | 88 | Should add operations to these fields |

### Fields from WRITE Operations (Should Remove)

| Service | Count | Notes |
|---------|-------|-------|
| datazone | 43 | Remove - from write operations |
| lex-models | 22 | Remove - from write operations |
| pinpoint | 20 | Remove - from write operations |
| bedrock-agentcore-control | 18 | Remove - from write operations |
| medialive | 17 | Remove - from write operations |

## Examples

### ✅ Fields from READ Operations (Keep)

**Service: accessanalyzer**
- Field: `accessPreview`
- Entity: `accessanalyzer.access_preview`
- Read Operations: `ListAccessPreviews`, `GetAccessPreview`
- **Action**: Keep, add operations to field definition

**Service: account**
- Field: `AccountCreatedDate`
- Entity: `account.account_created_date`
- Read Operations: `GetAccountInformation`
- **Action**: Keep, add operations to field definition

### ❌ Fields from WRITE Operations (Remove)

**Service: acm-pca**
- Field: `S3Key`
- Entity: `acm-pca.audit_report_id_s3_key`
- Write Operations: `CreateCertificateAuthorityAuditReport`
- **Action**: Remove - from write operation

**Service: amplifybackend**
- Field: `ChallengeCode`
- Entity: `amplifybackend.app_id_challenge_code`
- Write Operations: `CreateToken`
- **Action**: Remove - from write operation

## Handling Strategy

### Current Filter Script Behavior

The current `filter_direct_vars_read_only.py` script keeps all fields without operations by default. This needs to be updated to:

1. **Check dependency_index.json** for fields without operations
2. **Determine if they're from read or write operations**
3. **Keep if from read operations**
4. **Remove if from write operations**

### Updated Filtering Logic

```python
# For fields without operations:
1. Get dependency_index_entity
2. Look up entity in dependency_index.json
3. Get operations that produce the entity
4. Check if operations are read operations
5. Keep if read operations exist
6. Remove if only write operations
```

## Impact on Filtering

When filtering `direct_vars.json` to read-only operations:

- **Original total fields**: 35,749
- **Fields with operations (read)**: ~27,707 (kept)
- **Fields without operations (from read)**: 6,858 (keep) ✅
- **Fields without operations (from write)**: 740 (remove) ❌
- **Fields with operations (write)**: ~444 (remove) ❌

**Final count after filtering**: ~34,565 fields (96.7% kept)

## Next Steps

1. ✅ **Update filter script** to check dependency_index.json for fields without operations
2. ✅ **Keep 6,858 fields** that trace to read operations
3. ✅ **Remove 740 fields** that trace to write operations
4. ⚠️ **Consider adding operations** to the 6,858 kept fields for clarity (optional)

## Files Generated

- `analyze_fields_without_operations.py` - Analysis script
- `fields_without_operations_analysis.json` - Detailed results
- `FIELDS_WITHOUT_OPERATIONS_ANALYSIS.md` - This document

