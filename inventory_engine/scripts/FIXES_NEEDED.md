# Fixes Needed - Auto-Fixable vs Agent Correction

## Status
- ✅ **40 services processed**
- ⏳ **29 services remaining**
- ✅ **Prompt improved** with critical cross-service rules

## What Can Be Auto-Fixed Later (Post-Processing)

### 1. Cross-Service Type Corrections (Easy Auto-Fix)
These patterns can be automatically corrected:
- `*.key` → `kms.key` (when target_uid_pattern contains "kms")
- `*.role` → `iam.role` (when target_uid_pattern contains "iam" or "arn:aws:iam")
- `*.topic` → `sns.topic` (when target_uid_pattern contains "sns" or "arn:aws:sns")
- `*.policy` → `iam.policy` (when target_uid_pattern contains "iam" or "arn:aws:iam")

**Examples:**
- `backup.key` → `kms.key` ✅
- `config.topic` → `sns.topic` ✅
- `elasticache.topic` → `sns.topic` ✅
- `emr.role` → `iam.role` ✅
- `bedrock.role` → `iam.role` ✅
- `guardduty.key` → `kms.key` ✅

### 2. ARN Pattern Corrections (Easy Auto-Fix)
- Fix `cloudwatch.log-group` → `logs.group` (when pattern contains logs)
- Fix service name mismatches in ARN patterns

## What Needs Agent/Prompt Correction

### 1. Invalid Resource Types (Agent Issue)
These are generated because resource types don't exist in classification index:
- `cognito.group` → Should check actual normalized type (might be `cognito-idp.group`)
- `cognito.user_pool` → Should check actual normalized type (might be `cognito-idp.user-pool`)
- `cloudwatch.entry` → Doesn't exist, agent should not generate this
- `codeartifact.repository` → Check actual normalized type

**Fix:** ✅ **DONE** - Added to prompt: "If a resource type doesn't exist in SERVICE RESOURCE TYPES, DO NOT create relationships for it"

### 2. EKS Resource Type Mismatches (Agent Issue)
- Agent generates: `eks.cluster`, `eks.nodegroup`, `eks.fargate_profile`, `eks.addon`
- Need to check actual normalized types from classification index

**Fix:** ✅ **DONE** - Added to prompt: "Use EXACT resource types from SERVICE RESOURCE TYPES list"

### 3. Wrong Service Prefixes (Agent Issue - Now Fixed)
- `aws.organizations.organization` → Should be `organizations.organization`
- `glue.catalog` → Check if correct (might be `glue.catalog` or different)

**Fix:** ✅ **DONE** - Added explicit cross-service rules to prompt

## Prompt Improvements Made

✅ Added CRITICAL RULES section:
- Use EXACT resource types from SERVICE RESOURCE TYPES
- Explicit cross-service mapping rules (IAM, KMS, SNS, EC2, CloudWatch Logs)
- Don't create relationships for non-existent resource types

## Auto-Fix Script Plan

After all services are processed, create script to:
1. Load all generated relationship files
2. Apply cross-service type corrections
3. Validate against classification index
4. Generate corrected versions
5. Report what couldn't be auto-fixed

## Recommendation

✅ **Continue processing** - The improved prompt should reduce issues for remaining 29 services
✅ **Fix in batch later** - Most issues are auto-fixable
✅ **Manual review** - Only needed for edge cases (EKS, Cognito resource types)
