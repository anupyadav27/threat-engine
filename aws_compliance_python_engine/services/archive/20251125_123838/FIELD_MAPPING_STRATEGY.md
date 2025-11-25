# Field Mapping Analysis & Quality Improvement Plan

## 📊 Current Status

### Coverage Metrics
- ✅ **Services**: 102/102 (100%)
- ✅ **Checks**: 1,932 (100%)
- ⚠️  **Field Validation**: 586/1,932 (30.3% clean)
- ⚠️  **Field Issues**: 1,346/1,932 (69.7% need field fixes)

### Clean Services (6)
Only 5.9% of services have perfect field mappings:
- `datasync`
- `firehose`
- `mq`
- `servicecatalog`
- `transfer`
- `vpcflowlogs`

## 🔍 Issue Analysis

### Problem: Missing Fields

**Root Cause**: Pattern-based generation uses generic field names that don't match actual AWS API responses.

**Example Issues:**

| Service | Check | Required Field | Issue |
|---------|-------|---------------|-------|
| EC2 | Security group public | `is_public` | Field not in AWS API response |
| IAM | Password policy | `is_public` | Wrong field for IAM checks |
| S3 | Encryption | `encryption_enabled` | Should be `sse_algorithm` |
| CloudWatch | Logging | `logging_enabled` | Too generic |

### Top Services Needing Fixes

| Service | Checks | Issues | Issue Rate |
|---------|--------|--------|------------|
| IAM | 105 | 105 | 100.0% |
| EC2 | 175 | 115 | 65.7% |
| CloudWatch | 86 | 85 | 98.8% |
| Glue | 97 | 84 | 86.6% |
| SageMaker | 83 | 73 | 88.0% |
| Backup | 66 | 61 | 92.4% |
| RDS | 62 | 48 | 77.4% |
| VPC | 53 | 53 | 100.0% |
| Redshift | 51 | 37 | 72.5% |
| CloudTrail | 42 | 41 | 97.6% |

## 📋 Detailed Mapping Needed

For each check, we need to validate:

### 1. Discovery Step Requirements
```yaml
discovery_id: aws.{service}.{resource}_{config_type}
```
**Must provide:**
- ✅ Resource ID/Name
- ✅ Actual config field names from AWS API
- ✅ Proper data transformation (nested fields, array access, etc.)

### 2. AWS API Call Validation
```yaml
calls:
  - client: {service}
    action: {actual_boto3_method}  # Must be real Boto3 method
    params: {...}  # Must match method signature
    save_as: {variable}
```

**Need to validate:**
- ✅ `client` name matches Boto3 service
- ✅ `action` is a real Boto3 method for that service
- ✅ `params` match method signature
- ✅ Response structure matches field extraction

### 3. Field Extraction
```yaml
emit:
  item:
    field_name: '{{ response.ActualPath.To.Field }}'
```

**Must match:**
- ✅ AWS API response structure
- ✅ Field data types (string, bool, number, array, etc.)
- ✅ Handling of optional/missing fields
- ✅ Proper Jinja2 template syntax

### 4. Check Conditions
```yaml
conditions:
  var: resource.actual_field_name  # Must match emitted field
  op: equals|exists|gt|contains
  value: expected_value
```

**Must validate:**
- ✅ `var` references field from discovery
- ✅ Operator matches field type
- ✅ Expected value is realistic

## 🛠️ Solution Approaches

### Option 1: Manual Fix (High Quality, Slow)
**Process:**
1. For each service, consult Boto3 documentation
2. Update discovery API calls with real methods
3. Map actual AWS API response fields
4. Update check conditions to use correct fields
5. Test with real AWS account

**Pros:**
- ✅ Highest quality
- ✅ Production-ready
- ✅ Fully tested

**Cons:**
- ❌ Very slow (1-2 hours per service)
- ❌ Requires deep AWS expertise
- ❌ ~200 hours for all 102 services

**Recommended for**: Top 10-20 critical services

### Option 2: AWS Boto3 Documentation Scraping (Automated)
**Process:**
1. Parse Boto3 documentation
2. Extract method signatures and response structures
3. Auto-generate discovery with real field names
4. Validate against schemas

**Pros:**
- ✅ Faster (can process all services)
- ✅ Accurate to Boto3 spec
- ✅ Repeatable

**Cons:**
- ⚠️  Requires Boto3 docs parsing
- ⚠️  May miss edge cases
- ⚠️  Still needs testing

**Estimated time**: 10-20 hours development + validation

### Option 3: AI-Powered Fix with Real AWS Docs (Hybrid)
**Process:**
1. For each service, feed metadata + AWS docs to AI
2. AI generates discovery with real API calls
3. Auto-validate against Boto3
4. Human review for critical services

**Pros:**
- ✅ Good quality
- ✅ Relatively fast
- ✅ Scales to all services

**Cons:**
- ⚠️  Requires working AI API
- ⚠️  Still needs validation
- ⚠️  May have errors

**Estimated time**: 20-40 hours (if AI available)

### Option 4: Progressive Testing (Pragmatic)
**Process:**
1. Use current implementation as baseline
2. Run against real AWS accounts
3. Fix services based on actual failures
4. Iterate until acceptable quality

**Pros:**
- ✅ Focuses on real issues
- ✅ Prioritizes by usage
- ✅ Practical approach

**Cons:**
- ⚠️  Requires AWS access
- ⚠️  Takes time to find all issues
- ⚠️  May miss unused checks

**Recommended for**: Production deployment strategy

## 🎯 Recommended Implementation Plan

### Phase 1: Critical Services (Manual) - 2-3 days
Fix top 10 services manually with real AWS API calls:
1. **S3** (64 checks) - 27 issues
2. **EC2** (175 checks) - 115 issues
3. **IAM** (105 checks) - 105 issues
4. **RDS** (62 checks) - 48 issues
5. **Lambda** (36 checks) - 25 issues
6. **VPC** (53 checks) - 53 issues
7. **CloudTrail** (42 checks) - 41 issues
8. **KMS** (24 checks) - 24 issues
9. **EKS** (78 checks) - 24 issues
10. **CloudWatch** (86 checks) - 85 issues

**Coverage**: 725/1,932 checks (37.5%)

### Phase 2: Boto3 Schema Validation - 1 week
1. Create Boto3 documentation parser
2. Extract all service methods and response schemas
3. Auto-validate current discovery against schemas
4. Auto-fix where possible
5. Flag remaining issues

**Coverage**: All 102 services validated

### Phase 3: Real AWS Testing - Ongoing
1. Set up test AWS account
2. Run checks service by service
3. Fix failures based on actual API responses
4. Create test suite for regression prevention

### Phase 4: AI-Assisted Refinement - Optional
If AI becomes available:
1. Feed service metadata + Boto3 docs
2. Generate improved discovery steps
3. Validate and merge improvements

## 📦 Deliverables from Analysis

### 1. FIELD_MAPPING_ANALYSIS.json
Complete technical analysis:
- All services, checks, discovery steps
- Required vs provided fields
- Field coverage percentages
- Specific issues per check

### 2. AWS_API_MAPPING.json
Mapping of AWS APIs used:
- 813 total API calls across services
- Categorized by type (list_, get_, describe_, other)
- Per-service API inventory

### 3. FIELD_VALIDATION_REPORT.md
Human-readable report:
- Summary statistics
- Top issues by service
- Recommendations

### 4. This Strategy Document
Comprehensive plan for improvement.

## ✅ Immediate Next Steps

1. **Review Analysis Files**
   - Check FIELD_VALIDATION_REPORT.md for specific issues
   - Review AWS_API_MAPPING.json to validate APIs

2. **Choose Approach**
   - **Quick Win**: Fix top 5-10 services manually
   - **Scalable**: Build Boto3 validation tool
   - **Pragmatic**: Start testing with AWS

3. **Validate with AWS**
   - Fix credentials
   - Run checks on test account
   - Document actual vs expected behavior

## 🎓 Your Question Answered

> "this will help use to validate all rules with less chance of error, right?"

**Answer: YES! ✅**

This analysis provides:
1. ✅ **Clear visibility** into what fields each check needs
2. ✅ **Validation** of discovery providing required fields
3. ✅ **Mapping** of AWS API calls to check requirements
4. ✅ **Prioritization** of which services need the most work
5. ✅ **Structured approach** to fix issues systematically

**Current Quality**: 30.3% of checks have correct field mappings
**Target Quality**: 95%+ after fixes

The mapping shows us exactly what needs to be fixed, reducing trial-and-error and ensuring systematic improvement.

---

**Next Action**: Choose which phase to start with based on your priorities and constraints.

