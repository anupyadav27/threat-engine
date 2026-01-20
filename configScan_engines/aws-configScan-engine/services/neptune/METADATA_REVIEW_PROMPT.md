# neptune Metadata Review and Consolidation Prompt

You are an expert AWS compliance engineer reviewing metadata mappings and metadata files for the **neptune** service. Your task is to analyze and provide actionable suggestions for consolidations and cross-service placements.

## Service Context

**Service Name**: `neptune`  
**Service Path**: `/Users/apple/Desktop/threat-engine/aws_compliance_python_engine/services/neptune/`

## Files to Review

### 1. Metadata Mapping
**File**: `metadata_mapping.json`

Contains technical check specifications with:
- `rule_id`: Unique identifier for the rule
- `python_method`: boto3 method name
- `response_path`: Path to data in API response
- `logical_operator`: "all", "any", or null
- `nested_field`: Array of field checks with paths, expected values, and operators

### 2. Metadata YAML Files
**Directory**: `metadata/*.yaml`

Each file contains:
- rule_id, service, resource, requirement
- title, description, rationale
- compliance standards (cis, iso27001, nist, etc.)
- severity, scope, domain

### 3. Replacement Plan (if exists)
**File**: `replacement_plan.json`

Contains existing consolidation and placement suggestions.

### 4. Reference: boto3 Dependencies
**Path**: `/Users/apple/Desktop/threat-engine/pythonsdk-database/aws/neptune/boto3_dependencies_with_python_names_fully_enriched.json`

Contains actual AWS API method specifications to validate method ownership.

## Your Task

Analyze the neptune service and provide:

1. **Consolidation Suggestions**: Find duplicate rules and suggest removals/replacements
2. **Cross-Service Analysis**: Identify rules that should be moved to other services
3. **Compliance Optimization**: Suggest compliance standard merging

## Review Criteria

### A. Consolidation Opportunities

1. **Duplicate Checks**
   - Normalize check signatures: `python_method` + `response_path` + `logical_operator` + sorted `nested_field`
   - Identify rules with identical normalized signatures
   - Prioritize keeping rules with:
     - **More compliance standards** attached
     - **More comprehensive field checks** (superset of another rule)
     - **Better naming/convention**
   - Suggest removal of duplicates with confidence score (0-100%)

2. **Similar Checks (Field Subset/Superset)**
   - Find rules checking overlapping fields
   - If Rule A checks all fields that Rule B checks (and more), suggest keeping A
   - Provide confidence score for merge (85-94% for subset relationships)

3. **Compliance Merging**
   - When consolidating, ensure all compliance standards from removed rules are merged
   - List all compliance IDs that need to be merged

### B. Cross-Service Placements

1. **API Method Ownership Check**
   - For each rule, check which service the `python_method` belongs to
   - If method belongs to a different service, flag for placement suggestion
   - Common cross-service patterns:
     - Rules using **IAM** methods (get_role, list_policies, get_policy)
     - Rules using **S3** methods (get_bucket_*, list_buckets)
     - Rules using **KMS** methods (describe_key, get_key_rotation_status)
     - Rules using **CloudWatch** methods (get_metric, describe_alarm)
     - Rules using **CloudTrail** methods (describe_trails, get_trail)
     - Rules using **ACM** methods (describe_certificate, list_certificates)

2. **Service Context Validation**
   - Check if rule_id prefix matches method's service
   - If `aws.{service_name}.*` rule uses `{service_name}` method → NOT cross-service
   - If `aws.{service_name}.*` rule uses different service method → Likely cross-service

3. **Method Ambiguity**
   - If method exists in multiple services, flag as ambiguous
   - Lower confidence score for ambiguous methods (75-84%)
   - Note `service_count_for_method` in suggestion

## Output Format

Provide your review in JSON format:

```json
{{
  "service": "neptune",
  "review_date": "2024-01-XX",
  "review_summary": {{
    "total_rules": 50,
    "rules_reviewed": 50,
    "consolidation_opportunities": 3,
    "cross_service_suggestions": 2
  }},
  "consolidation_suggestions": {{
    "duplicates": [
      {{
        "keep": {{
          "rule_id": "aws.neptune.resource.check_complete",
          "metadata_file": "aws.neptune.resource.check_complete.yaml",
          "reason": "More comprehensive (checks all fields)",
          "compliance_count": 5,
          "compliance": ["cis_1", "iso_1", "nist_1", "soc2_1", "gdpr_1"]
        }},
        "remove": [
          {{
            "rule_id": "aws.neptune.resource.check_basic",
            "metadata_file": "aws.neptune.resource.check_basic.yaml",
            "replaced_by": "aws.neptune.resource.check_complete",
            "reason": "Subset of check_complete - checks only 2 of 3 fields",
            "compliance_count": 2,
            "compliance": ["cis_1", "iso_1"],
            "confidence_percentage": 95.0,
            "review_needed": "none",
            "action": "merge_compliance_to_kept_rule",
            "compliance_merged": false
          }}
        ]
      }}
    ]
  }},
  "cross_service_suggestions": [
    {{
      "rule_id": "aws.neptune.resource.check_name",
      "metadata_file": "aws.neptune.resource.check_name.yaml",
      "current_service": "neptune",
      "suggested_service": "target_service",
      "reason": "Uses target_service API methods (describe_trails is CloudTrail method)",
      "python_method": "describe_trails",
      "confidence_percentage": 95.0,
      "review_needed": "none",
      "has_compliance": true,
      "compliance_count": 3,
      "compliance": ["cis_1", "iso_1", "nist_1"],
      "is_common_dependency": true,
      "method_ambiguous": false,
      "service_count_for_method": 1
    }}
  ],
  "confidence_scores": {{
    "consolidation_opportunities": 85.5,
    "cross_service_placement": 90.0
  }},
  "recommendations": [
    {{
      "priority": "high",
      "action": "consolidate",
      "rule_ids": ["rule1", "rule2"],
      "description": "Merge 2 duplicate rules checking same fields",
      "impact": "Reduces duplicate rules, improves maintainability"
    }},
    {{
      "priority": "medium",
      "action": "move",
      "rule_ids": ["rule3"],
      "description": "Move rule to cloudtrail service - uses CloudTrail API",
      "impact": "Better service organization"
    }}
  ]
}}
```

## Confidence Scoring Guidelines

### Consolidation Suggestions
- **≥90%**: Exact duplicate (identical normalized check signature)
- **85-89%**: Field subset/superset relationship (one rule checks all fields of another + more)
- **75-84%**: Similar checks with some overlap, may need review
- **<75%**: Different checks, not recommended for consolidation

### Cross-Service Placements
- **≥90%**: Clear API method mismatch, common dependency service (IAM, S3, KMS, CloudWatch, CloudTrail)
- **85-89%**: Method belongs to different service, but not common dependency
- **75-84%**: Ambiguous - method exists in multiple services
- **<75%**: Unclear ownership, needs investigation

### Review Needed Flags
- **"none"**: Confidence ≥90% - Safe to automate
- **"optional"**: Confidence 75-89% - Recommended manual/AI review
- **"required"**: Confidence <75% - Must review before applying

## Special Considerations

1. **Normalize Check Signatures**
   - Sort `nested_field` by `field_path` for comparison
   - Include all parts: method + path + operator + sorted fields

2. **Service Prefix Matching**
   - Extract service from rule_id: `aws.neptune.{{resource}}.{{check}}`
   - If extracted service matches method's service → NOT cross-service
   - If extracted service differs from method's service → Potential cross-service

3. **Compliance Preservation**
   - When consolidating, merge ALL compliance standards
   - Never lose compliance coverage
   - Mark `compliance_merged: false` until actually merged

4. **Method Ambiguity Detection**
   - Check if `python_method` appears in multiple boto3 dependency files
   - Flag with `method_ambiguous: true` if count > 1
   - Include `service_count_for_method` in output

## Example Scenarios

### Scenario 1: Exact Duplicate
```json
Rule A: {{
  "python_method": "get_bucket_encryption",
  "response_path": "ServerSideEncryptionConfiguration",
  "nested_field": [{{"field_path": "Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm", "expected_value": "aws:kms", "operator": "equals"}}],
  "compliance": ["cis_1", "iso_1", "nist_1"]
}}

Rule B: {{
  "python_method": "get_bucket_encryption",
  "response_path": "ServerSideEncryptionConfiguration",
  "nested_field": [{{"field_path": "Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm", "expected_value": "aws:kms", "operator": "equals"}}],
  "compliance": ["cis_1"]
}}
```
**Result**: Keep Rule A, Remove Rule B, Merge compliance, Confidence: 95%

### Scenario 2: Field Subset
```json
Rule A: Checks ["Field1", "Field2", "Field3"] - 5 compliance
Rule B: Checks ["Field1", "Field2"] - 2 compliance
```
**Result**: Keep Rule A, Remove Rule B, Merge compliance, Confidence: 88%

### Scenario 3: Cross-Service
```json
{{
  "rule_id": "aws.timestream.resource.cloudtrail_logging_enabled",
  "python_method": "describe_trails",
  "service": "timestream"
}}
```
**Result**: Move to cloudtrail service, Confidence: 95%

## Instructions

1. **Load all files** for neptune service
2. **Normalize all check signatures** for comparison
3. **Group rules** by normalized signature to find duplicates
4. **Check method ownership** using boto3 dependencies
5. **Generate suggestions** with confidence scores
6. **Output JSON** following the format above

---

**Begin Review**: Analyze the neptune service files and generate comprehensive review JSON.
