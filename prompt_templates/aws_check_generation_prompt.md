# AWS Compliance Check Generation Prompt Template

## Context
You are a compliance engineer tasked with creating security and compliance checks for AWS infrastructure. You need to generate YAML rule definitions that can be executed by our AWS compliance engine to validate infrastructure against security best practices.

## AWS Engine Capabilities

### Scope Options
- **`regional`**: Scans resources within a specific AWS region
- **`global`**: Scans account-level or cross-region resources

### Discovery Actions
Uses AWS API calls through boto3:
- **EC2**: `describe_instances`, `describe_security_groups`, `describe_volumes`
- **IAM**: `list_users`, `list_roles`, `list_policies`
- **S3**: `list_buckets`, `get_bucket_encryption`
- **RDS**: `describe_db_instances`, `describe_db_snapshots`
- **CloudTrail**: `describe_trails`, `get_trail_status`
- **Config**: `describe_config_rules`, `get_compliance_details_by_config_rule`

### Field Paths
JSONPath-like syntax for navigating AWS API responses:
- **Array Access**: `SecurityGroups[].IpPermissions[].IpRanges[].CidrIp`
- **Nested Objects**: `Reservations[].Instances[].MetadataOptions.HttpTokens`
- **Direct Fields**: `EbsEncryptionByDefault`

### Operators
- `equals`: Exact value match
- `contains`: Field contains the expected value
- `not_contains`: Field does not contain the expected value
- `exists`: Field exists and has a value
- `not_exists`: Field does not exist or is null/empty

### Multi-Step Checks
Supports complex validation logic:
```yaml
multi_step: true
logic: AND  # or OR
calls:
  - action: describe_security_groups
    fields:
      - path: SecurityGroups[].IpPermissions[].IpRanges[].CidrIp
        operator: contains
        expected: 0.0.0.0/0
      - path: SecurityGroups[].IpPermissions[].FromPort
        operator: contains
        expected: 22
```

## Prompt Template

```
Generate an AWS compliance check to validate [COMPLIANCE_REQUIREMENT].

**Compliance Standard**: [STANDARD_NAME] - [REQUIREMENT_ID]
**Requirement**: [DETAILED_DESCRIPTION]
**Severity**: [HIGH/MEDIUM/LOW]
**Scope**: [regional/global]

**Target Resources**: [RESOURCE_TYPE] (e.g., EC2 instances, Security Groups, S3 buckets, IAM users)

**Expected Behavior**: [WHAT_SHOULD_BE_TRUE/FALSE]

**Current Infrastructure Context**:
- [ANY_SPECIFIC_INFRASTRUCTURE_DETAILS]
- [EXISTING_RESOURCES_OR_PATTERNS]
- [REGIONAL_OR_GLOBAL_SCOPE_NEEDS]

**Additional Requirements**:
- [ANY_SPECIFIC_OPERATORS_OR_LOGIC_NEEDED]
- [MULTI_STEP_CHECK_REQUIREMENTS]
- [ERROR_HANDLING_PREFERENCES]

Please generate the complete YAML rule including:
1. Discovery section with appropriate AWS API calls
2. Check section with proper field paths and operators
3. Appropriate scope setting (regional/global)
4. Any special handling needed for AWS-specific resources
```

## Example Prompts

### EC2 Security Group Example
```
Generate an AWS compliance check to validate Security Group SSH restrictions.

**Compliance Standard**: CIS AWS Foundations 1.4 - 4.1
**Requirement**: Ensure Security Groups do not allow SSH (port 22) from 0.0.0.0/0
**Severity**: HIGH
**Scope**: regional

**Target Resources**: EC2 Security Groups

**Expected Behavior**: Security Groups should not allow inbound SSH access from anywhere (0.0.0.0/0)

**Current Infrastructure Context**:
- Using EC2 instances with Security Groups
- Need to check both CIDR ranges and port configurations
- Regional scope for Security Group scanning

Please generate the complete YAML rule including discovery and check sections.
```

### S3 Encryption Example
```
Generate an AWS compliance check to validate S3 bucket encryption.

**Compliance Standard**: CIS AWS Foundations 1.4 - 2.1.1
**Requirement**: Ensure S3 buckets have default encryption enabled
**Severity**: HIGH
**Scope**: global

**Target Resources**: S3 buckets

**Expected Behavior**: All S3 buckets should have default encryption enabled

**Current Infrastructure Context**:
- Multiple S3 buckets across the account
- Need to check encryption settings
- Global scope for S3 bucket listing

Please generate the complete YAML rule including discovery and check sections.
```

## Response Format

When responding to these prompts, provide:

1. **Complete YAML Rule**: The full rule definition ready to be placed in the appropriate AWS service file
2. **Explanation**: Brief explanation of how the rule works
3. **Field Mapping**: Explanation of the AWS API response structure and field paths
4. **Scope Considerations**: Why the chosen scope (regional/global) is appropriate
5. **Testing Notes**: Any considerations for testing the rule with AWS resources

## Common AWS Patterns

### Security Group Validation
```yaml
- check_id: sg_no_ssh_from_anywhere
  for_each: list_security_groups
  param: GroupIds
  multi_step: true
  logic: AND
  calls:
    - action: describe_security_groups
      fields:
        - path: SecurityGroups[].IpPermissions[].IpRanges[].CidrIp
          operator: contains
          expected: 0.0.0.0/0
        - path: SecurityGroups[].IpPermissions[].FromPort
          operator: contains
          expected: 22
```

### Instance Configuration Check
```yaml
- check_id: ec2_imdsv2_enabled
  for_each: list_instances
  param: InstanceIds
  calls:
    - action: describe_instances
      fields:
        - path: Reservations[].Instances[].MetadataOptions.HttpTokens
          operator: equals
          expected: required
```

### Account-Level Setting Check
```yaml
- check_id: ebs_encryption_by_default
  calls:
    - action: get_ebs_encryption_by_default
      fields:
        - path: EbsEncryptionByDefault
          operator: equals
          expected: true
```

This template ensures consistent, effective AWS compliance checks that integrate seamlessly with your existing AWS compliance engine.
