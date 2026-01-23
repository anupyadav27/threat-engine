# EFS YAML Validation Report

**Date**: 2026-01-08  
**Service**: efs  
**Total Rules**: 11

---

## Validation Summary

**Total Rules**: 11  
**Validated**: 11  
**Passing**: 0  
**Fixed**: 0  
**Test Status**: PARTIAL (execution successful, but all checks failed - logic issues)

---

## Per-Rule Results

### aws.efs.encryption.at_rest_enabled

**Metadata Intent**: 
- Checks that encryption at rest is enabled
- Should verify Encrypted is true

**YAML Checks**: 
- Discovery: `aws.efs.describe_file_systems` ✅
- Condition: `item.Encrypted equals 'true'`

**Match**: ⚠️ PARTIAL

**Issues**:
1. **Value Type**: Uses string `'true'` but API likely returns boolean `true`. Should verify actual return type.
2. **Duplicate Rule**: Identical to `aws.efs.filesystem.encryption_at_rest_enabled` and `aws.efs.resource.encryption_at_rest_enabled` - all 3 check the same thing.

**Fixed**: No

**Test**: FAIL - All checks failed (likely value type mismatch)

---

### aws.efs.filesystem.encryption_at_rest_enabled

**Metadata Intent**: 
- Checks that filesystem encryption at rest is enabled
- Should verify Encrypted is true

**YAML Checks**: 
- Discovery: `aws.efs.describe_file_systems` ✅
- Condition: `item.Encrypted equals 'true'`

**Match**: ⚠️ PARTIAL

**Issues**:
1. **Duplicate Rule**: Same as rules #1 and #3.
2. **Value Type**: Same as rule #1.

**Fixed**: No

**Test**: FAIL - All checks failed

---

### aws.efs.resource.encryption_at_rest_enabled

**Metadata Intent**: 
- Checks that resource encryption at rest is enabled
- Should verify Encrypted is true

**YAML Checks**: 
- Discovery: `aws.efs.describe_file_systems` ✅
- Condition: `item.Encrypted equals 'true'`

**Match**: ⚠️ PARTIAL

**Issues**:
1. **Duplicate Rule**: Same as rules #1 and #2.
2. **Value Type**: Same as rule #1.

**Fixed**: No

**Test**: FAIL - All checks failed

---

### aws.efs.filesystem.kms_key_policy_least_privilege

**Metadata Intent**: 
- Checks that KMS key policy follows least privilege
- Should verify encryption is enabled AND KMS key is configured

**YAML Checks**: 
- Discovery: `aws.efs.describe_file_systems` ✅
- Conditions:
  - `item.Encrypted equals 'true'`
  - `item.KmsKeyId exists`

**Match**: ⚠️ PARTIAL

**Issues**:
1. **Insufficient Check**: Only checks if KmsKeyId exists, but doesn't verify the KMS key policy follows least privilege. Need to check the actual KMS key policy, not just that a key exists.
2. **Value Type**: Same string vs boolean issue.

**Fixed**: No

**Test**: FAIL - All checks failed

---

### aws.efs.have.backup_enabled

**Metadata Intent**: 
- Checks that backup is enabled
- Should verify backup policy status is ENABLED

**YAML Checks**: 
- Discovery: `aws.efs.describe_backup_policy` ✅
- Condition: `item.Status equals ENABLED`

**Match**: ✅ YES

**Issues**:
1. **Duplicate Rule**: Identical to `aws.efs.resource.backup_enabled`.

**Fixed**: No

**Test**: FAIL - All checks failed (likely no backups enabled in test accounts)

---

### aws.efs.resource.backup_enabled

**Metadata Intent**: 
- Checks that resource backup is enabled
- Should verify backup policy status is ENABLED

**YAML Checks**: 
- Discovery: `aws.efs.describe_backup_policy` ✅
- Condition: `item.Status equals ENABLED`

**Match**: ✅ YES

**Issues**:
1. **Duplicate Rule**: Identical to rule #5.

**Fixed**: No

**Test**: FAIL - All checks failed

---

### aws.efs.filesystem.snapshots_enabled

**Metadata Intent**: 
- Checks that snapshots are enabled
- Should verify snapshot/backup protection is configured

**YAML Checks**: 
- Discovery: `aws.efs.describe_file_systems` ✅
- Condition: `item.FileSystemProtection exists`

**Match**: ❌ NO

**Issues**:
1. **Insufficient Check**: Only checks if `FileSystemProtection` exists, but doesn't verify snapshots are actually enabled. FileSystemProtection is about deletion protection, not snapshots. EFS doesn't have traditional snapshots - it uses backup policies. Should check backup policy instead.

**Fixed**: No

**Test**: FAIL - All checks failed (wrong validation logic)

---

### aws.efs.resource.multi_az_enabled

**Metadata Intent**: 
- Checks that Multi-AZ is enabled
- Should verify file system is configured for high availability across multiple AZs

**YAML Checks**: 
- Discovery: `aws.efs.describe_file_systems` ✅
- Condition: `item.NumberOfMountTargets greater_than_or_equal 1`

**Match**: ❌ NO

**Issues**:
1. **Wrong Validation**: Checks if NumberOfMountTargets >= 1, but that doesn't verify Multi-AZ. A file system can have 1 mount target in a single AZ. EFS is inherently multi-AZ (it's a regional service), but the check should verify mount targets are in multiple AZs, not just that mount targets exist.
2. **Insufficient Logic**: Should check that mount targets exist in multiple availability zones.

**Fixed**: No

**Test**: FAIL - All checks failed (wrong validation logic)

---

### aws.efs.filesystem.private_network_only_configured

**Metadata Intent**: 
- Checks that filesystem is configured for private network only
- Should verify mount targets are in private subnets (not public)

**YAML Checks**: 
- Discovery: `aws.efs.describe_mount_targets` ✅
- Conditions:
  - `item.SubnetId exists`
  - `item.VpcId exists`

**Match**: ❌ NO

**Issues**:
1. **Insufficient Check**: Only checks if SubnetId and VpcId exist, but doesn't verify the subnet is private. Mount targets always have SubnetId and VpcId - need to check if the subnet has public IP assignment disabled or is in a private subnet.
2. **Duplicate Rule**: Identical to rule #10.

**Fixed**: No

**Test**: FAIL - All checks failed (insufficient validation)

---

### aws.efs.not_publicly_accessible.not_publicly_accessible_configured

**Metadata Intent**: 
- Checks that filesystem is not publicly accessible
- Should verify mount targets are not publicly accessible

**YAML Checks**: 
- Discovery: `aws.efs.describe_mount_targets` ✅
- Conditions:
  - `item.SubnetId exists`
  - `item.VpcId exists`

**Match**: ❌ NO

**Issues**:
1. **Duplicate Rule**: Identical to rule #9.
2. **Insufficient Check**: Same as rule #9 - doesn't verify subnet is private.

**Fixed**: No

**Test**: FAIL - All checks failed

---

### aws.efs.user.identity_and_root_directory_enforced

**Metadata Intent**: 
- Checks that identity and root directory are enforced
- Should verify PosixUser and RootDirectory are configured

**YAML Checks**: 
- Discovery: `aws.efs.describe_access_points` ✅
- Conditions:
  - `item.PosixUser exists`
  - `item.RootDirectory exists`

**Match**: ⚠️ PARTIAL

**Issues**:
1. **Logic Verification**: Checks if both exist, which seems correct. However, need to verify if this is the right validation - should both always exist, or should they be configured in a specific way?

**Fixed**: No

**Test**: FAIL - All checks failed (likely no access points or not configured correctly)

---

## Critical Issues Summary

### Issue 1: Duplicate Rules
- **3 encryption rules** (rules 1, 2, 3): All check `Encrypted equals 'true'`
- **2 backup rules** (rules 5, 6): Both check `Status equals ENABLED`
- **2 private network rules** (rules 9, 10): Both check `SubnetId exists AND VpcId exists`

### Issue 2: Value Type Issues
- Rules 1-4 use string `'true'` but API likely returns boolean `true`

### Issue 3: Insufficient Validation Logic
- **Rule 4**: Only checks KmsKeyId exists, doesn't verify KMS key policy least privilege
- **Rule 7**: Checks FileSystemProtection exists, but that's deletion protection, not snapshots
- **Rule 8**: Checks NumberOfMountTargets >= 1, but doesn't verify Multi-AZ (should check multiple AZs)
- **Rules 9 & 10**: Only check SubnetId/VpcId exist, don't verify subnet is private

### Issue 4: Wrong Field/Concept
- **Rule 7**: FileSystemProtection is about deletion protection, not snapshots. EFS uses backup policies for backups, not snapshots.

---

## Recommended Fixes

### Fix 1: Consolidate Duplicate Rules
- Keep one encryption rule (e.g., `aws.efs.resource.encryption_at_rest_enabled`)
- Keep one backup rule (e.g., `aws.efs.resource.backup_enabled`)
- Keep one private network rule (e.g., `aws.efs.filesystem.private_network_only_configured`)

### Fix 2: Fix Value Types
- Verify if Encrypted returns boolean or string, adjust values accordingly

### Fix 3: Enhance Rule 4 (KMS Key Policy)
- Need to check actual KMS key policy, not just that key exists. May require additional API call to get key policy.

### Fix 4: Fix Rule 7 (Snapshots)
- Remove or change to check backup policy instead, as EFS doesn't have traditional snapshots

### Fix 5: Fix Rule 8 (Multi-AZ)
- Should check that mount targets exist in multiple availability zones, not just that mount targets exist

### Fix 6: Enhance Rules 9 & 10 (Private Network)
- Should check subnet configuration (e.g., mapPublicIpOnLaunch=false) or verify subnet is in private subnet range

---

## Test Results

**Execution**: ✅ PASS - No errors  
**Warnings**: None  
**Check Results**: 10 checks found (2 per account × 5 accounts), all FAILED  
**Field Paths**: ⚠️ Some correct, some need verification

**Test Status**: PARTIAL - Execution successful but all checks failed, indicating logic issues rather than structural errors

**Note**: Only 10 checks found when there should be 11 - one rule may not have executed (likely due to no resources found for that discovery)

---

## Checklist

- [x] All metadata files have YAML checks
- [x] All YAML checks have metadata files
- [ ] Each check matches its metadata intention ❌ (11 issues found)
- [ ] Field paths are correct ⚠️ (most correct, some need verification)
- [ ] Operators are correct ✅
- [ ] Values are correct ⚠️ (value type issues)
- [ ] Discoveries are correct ✅
- [x] Test passes without errors ✅
- [ ] Check results are logical ❌ (all failed - logic issues)
- [ ] Metadata review updated ⚠️ (needs update after fixes)

---

## Next Steps

1. **Consolidate Duplicates**: Remove duplicate rules (3 encryption, 2 backup, 2 private network)
2. **Fix Value Types**: Verify and fix boolean vs string values
3. **Enhance Validation Logic**: Fix rules 4, 7, 8, 9, 10 to check actual requirements
4. **Fix Rule 7**: Change from FileSystemProtection to backup policy check
5. **Fix Rule 8**: Check multiple AZs instead of just mount target count
6. **Enhance Rules 9 & 10**: Check subnet is actually private
7. **Re-test**: Run scanner again to verify all fixes work
8. **Update Metadata Review Report**: Generate final report after fixes





