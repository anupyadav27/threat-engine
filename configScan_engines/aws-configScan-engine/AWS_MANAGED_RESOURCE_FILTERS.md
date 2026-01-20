# AWS-Managed Resource Filters

## Summary

AWS creates thousands of default/system resources in every account/region. Scanning these wastes time and inflates inventory.

### Impact
- **Default resources per region:** ~45-60 items
- **Across 5 accounts × 17 regions:** ~4,250 items
- **Performance impact:** 30-50% of scan time
- **Expected gain:** Reduce scan from 2.2 hours to 1.2-1.5 hours

## Filters Applied

### 1. IAM Policies ✅
**Filter:** `Scope: Local`
- Before: 1000+ policies (mostly AWS-managed)
- After: ~10-50 customer-managed policies
- **Impact:** 20-100x faster

### 2. SSM Documents ✅
**Filter:** `Owner: Self`
- Before: 500+ documents (AWS-* documents)
- After: ~5-10 customer documents
- **Impact:** 50-100x faster

### 3. SSM Patch Baselines ✅
**Filter:** `Owner: Self`
- Before: ~15 AWS baselines
- After: ~1-3 customer baselines
- **Impact:** 5-15x faster

### 4. CloudFormation Stacks ✅
**Filter:** Active status only
- Filters out deleted/failed stacks
- Reduces noise

### 5. Config Rules ✅
**Added:** MaxResults for pagination
- Most rules are customer-managed
- AWS service-linked rules are minimal

## Additional Candidates

### High Priority (not yet implemented)

**6. ECR Repositories**
- Already scoped to account (no AWS-managed repos)
- ✅ No filter needed

**7. Lambda Layers**
- Some layers are AWS-published
- Can filter by Owner if needed

**8. EventBridge Event Buses**
- Skip 'default' event bus (exists in all regions)
- Only scan custom event buses

**9. Athena Workgroups**
- Skip 'primary' workgroup (AWS default)
- Only scan custom workgroups

**10. Keyspaces**
- Skip system_* keyspaces
- Only scan customer keyspaces

**11. KMS Aliases**
- Skip alias/aws/* (AWS-managed)
- Only scan customer aliases

**12. Secrets Manager**
- Skip aws/* and rds!* prefixes
- Only scan customer secrets

### Medium Priority

**13. CloudWatch**
- Log groups: Skip /aws/* prefixes
- Dashboards: Usually customer-managed

**14. Systems Manager Parameters**
- Skip /aws/* paths
- Only scan customer parameters

## Implementation Status

✅ **Implemented:**
1. IAM policies (Scope: Local)
2. SSM documents (Owner: Self)
3. SSM patch baselines (Owner: Self)
4. CloudFormation stacks (Active status filter)
5. Config rules (pagination added)

⏳ **To Implement:**
- EventBridge (skip default)
- Athena (skip primary)
- Keyspaces (skip system_*)
- KMS (skip alias/aws/*)
- Lambda layers (if needed)
- Secrets Manager (skip aws/*)
- CloudWatch logs (skip /aws/*)
- SSM Parameters (skip /aws/*)

## Expected Results

### Before Filters
- Total inventory: ~10,000-15,000 items
- Default resources: ~4,250 items (30-40%)
- Scan time: 2.2 hours

### After Filters
- Total inventory: ~6,000-8,000 items
- Default resources: Minimal
- **Scan time: 1.2-1.5 hours**
- **Improvement: ~40% faster**

## Next Steps

1. Test current filters in next scan
2. Monitor performance improvement
3. Add remaining filters if needed
4. Consider making it configurable via env var

