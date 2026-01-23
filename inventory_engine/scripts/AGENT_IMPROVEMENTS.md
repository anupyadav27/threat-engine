# Agent Improvements Based on Generated Relationships

## Analysis of 40 Services Processed

### Patterns Found

#### 1. Cross-Service Type Confusion (FIXED ✅)
**Issue:** Agent generated `service.key`, `service.role`, `service.topic` instead of `kms.key`, `iam.role`, `sns.topic`

**Examples:**
- `backup.key` → `kms.key` ✅ (auto-fixed)
- `emr.role` → `iam.role` ✅ (auto-fixed)
- `autoscaling.topic` → `sns.topic` ✅ (auto-fixed)
- `config.topic` → `sns.topic` ✅ (auto-fixed)

**Fix Applied:** ✅ Added explicit cross-service rules to prompt

#### 2. Invalid Resource Types (NEEDS AGENT FIX)
**Issue:** Agent generates resource types that don't exist in classification index

**Examples:**
- `eks.cluster`, `eks.nodegroup`, `eks.fargate_profile` - Need to check actual normalized types
- `cognito.group`, `cognito.user_pool` - Should be `cognito-idp.*` or different
- `cloudwatch.entry` - Doesn't exist (2 instances)
- `codeartifact.repository` - Check actual normalized type
- `eip.instance` - Should be `ec2.instance`

**Root Cause:** Agent not strictly following SERVICE RESOURCE TYPES list

**Fix Needed:** ✅ Already added to prompt: "If a resource type doesn't exist in SERVICE RESOURCE TYPES, DO NOT create relationships for it"

#### 3. Service Prefix Issues (FIXED ✅)
**Issue:** Wrong service prefixes in target types

**Examples:**
- `aws.organizations.organization` → Should be `organizations.organization`
- `glue.catalog` - May need verification

**Fix Applied:** ✅ Added explicit cross-service rules

#### 4. EC2 Resource Type Validation (NEEDS FIX)
**Issue:** Some services reference `ec2.vpc`, `ec2.instance` but validation fails

**Examples:**
- `directconnect.resource` → `ec2.vpc` (marked invalid but should be valid)
- `kafka.cluster` → `ec2.vpc` (marked invalid but should be valid)
- `keyspaces.resource` → `ec2.vpc` (marked invalid but should be valid)

**Root Cause:** Validation script may have issues, or these types need to be checked

**Action:** Review validation logic - these should be valid

## Key Learnings

### What Works Well ✅
1. **ARN pattern generation** - Agent correctly constructs ARN patterns with placeholders
2. **Relation type selection** - Appropriate relation types chosen
3. **Cross-service identification** - Agent identifies relationships to IAM, KMS, EC2, SNS
4. **Array handling** - Correctly uses `source_field_item` for arrays
5. **Nested field paths** - Handles nested fields like `NotificationConfiguration.TopicArn`

### What Needs Improvement ⚠️
1. **Strict resource type adherence** - Agent sometimes creates types not in the list
2. **EC2 type validation** - Need to verify `ec2.vpc`, `ec2.instance` are in classification index
3. **Service prefix consistency** - Some services use wrong prefixes (e.g., `aws.organizations`)

## Recommended Prompt Enhancements

### Already Added ✅
1. CRITICAL RULES section with cross-service mappings
2. Explicit instruction to use only resource types from SERVICE RESOURCE TYPES list
3. Don't create relationships for non-existent resource types

### Additional Recommendations
1. **Add validation examples** - Show examples of invalid vs valid resource types
2. **Emphasize EC2 types** - Explicitly list common EC2 types: `ec2.vpc`, `ec2.subnet`, `ec2.security-group`, `ec2.instance`
3. **Service prefix guidance** - Clarify that service prefixes should match SERVICE RESOURCE TYPES exactly

## Statistics

- **Total relationships generated:** 164
- **Auto-fixed:** 11 (cross-service type corrections)
- **Invalid (needs review):** 16 (resource type mismatches)
- **Valid and merged:** 164 (all valid ones merged into CORE_RELATION_MAP)

## Next Steps for Remaining Services

1. ✅ **Continue with improved prompt** - Should reduce issues
2. ⏳ **Fix validation script** - Check why `ec2.vpc` etc. are marked invalid
3. ⏳ **Review invalid relationships** - Manually fix EKS, Cognito, etc.
4. ⏳ **Batch process remaining** - ~29 services left
