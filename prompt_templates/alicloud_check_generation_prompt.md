# AliCloud Compliance Check Generation Prompt Template

## Context
You are a compliance engineer tasked with creating **security and compliance checks** for Alibaba Cloud (AliCloud) infrastructure. These checks will be used by our AliCloud compliance engine to validate infrastructure against security best practices and compliance standards.

## Purpose
Generate YAML rule definitions that can be executed by the AliCloud compliance engine to validate infrastructure configurations, security settings, and compliance requirements.

---

## AliCloud Engine Capabilities

### Scope Options
- **`regional`**: Scans resources within a specific AliCloud region
- **`global`**: Scans account-level or cross-region resources

### Discovery Actions
Uses AliCloud SDK for Python (`aliyunsdkcore`):
- **ECS (Elastic Compute Service)**: `DescribeInstances`, `DescribeSecurityGroups`, `DescribeDisks`
- **OSS (Object Storage Service)**: `ListBuckets`, `GetBucketACL`, `GetBucketEncryption`
- **RDS (Relational Database Service)**: `DescribeDBInstances`, `DescribeDBInstanceSSL`
- **RAM (Resource Access Management)**: `ListUsers`, `ListPolicies`, `ListRoles`
- **VPC (Virtual Private Cloud)**: `DescribeVpcs`, `DescribeVSwitches`, `DescribeNatGateways`
- **ActionTrail**: `DescribeTrails`, `GetTrailStatus`
- **ACK (Container Service for Kubernetes)**: `DescribeClusters`, `DescribeClusterDetail`

### Field Paths
Dot notation for navigating AliCloud resource properties:
- **Direct Fields**: `PublicIpAddress.IpAddress`, `Status`, `RegionId`
- **Nested Objects**: `SecurityGroupIds.SecurityGroupId[]`, `VpcAttributes.VpcId`
- **Arrays**: `Tags.Tag[]`, `Instances.Instance[]`
- **Special**: `__self__` for the entire resource object

### Operators
- `equals`: Exact value match
- `not_equals`: Field does not equal expected value
- `contains`: Field contains the expected value
- `not_contains`: Field does not contain the expected value
- `exists`: Field exists and has a value
- `not_exists`: Field does not exist or is null/empty
- `gt`: Greater than (for numerical comparisons)
- `lt`: Less than (for numerical comparisons)
- `in`: Value is in a list of expected values
- `not_in`: Value is not in a list of expected values

### Actions
- **`identity`**: Object reference for resource evaluation
- **`eval`**: Direct field evaluation
- **`list`**: Resource listing operations
- **`get`**: Retrieve detailed resource information

### Multi-Step Checks
Supports complex validation logic:
```yaml
multi_step: true
logic: AND  # or OR
calls:
  - action: identity
    params: {}
    fields:
      - path: PublicIpAddress.IpAddress
        operator: not_exists
        expected: null
      - path: VpcAttributes.VpcId
        operator: exists
        expected: null
```

---

## Prompt Template for Compliance Check Generation

```
Generate an AliCloud compliance check to validate [COMPLIANCE_REQUIREMENT].

**Compliance Standard**: [STANDARD_NAME] - [REQUIREMENT_ID]
**Requirement**: [DETAILED_DESCRIPTION]
**Severity**: [CRITICAL/HIGH/MEDIUM/LOW]
**Scope**: [regional/global]

**Target Resources**: [RESOURCE_TYPE] (e.g., ECS Instances, OSS Buckets, RDS Instances, RAM Users, VPCs)

**Expected Behavior**: [WHAT_SHOULD_BE_TRUE/FALSE]

**Current Infrastructure Context**:
- [ANY_SPECIFIC_INFRASTRUCTURE_DETAILS]
- [EXISTING_RESOURCES_OR_PATTERNS]
- [REGIONAL_OR_GLOBAL_SCOPE_NEEDS]
- [PAGINATION_OR_ITERATION_REQUIREMENTS]

**Additional Requirements**:
- [ANY_SPECIFIC_OPERATORS_OR_LOGIC_NEEDED]
- [MULTI_STEP_CHECK_REQUIREMENTS]
- [MULTIPLE_REGIONS_OR_ACCOUNTS]

Please generate the complete YAML rule including:
1. Discovery section with appropriate AliCloud SDK calls
2. Check section with proper field paths and operators
3. Appropriate scope setting (regional/global)
4. Any special handling needed for AliCloud-specific resources
```

---

## Example Prompts

### ECS Security Example
```
Generate an AliCloud compliance check to validate ECS instance public IP restrictions.

**Compliance Standard**: AliCloud Security Baseline - 1.1
**Requirement**: Ensure ECS instances do not have public IP addresses directly attached
**Severity**: HIGH
**Scope**: regional

**Target Resources**: AliCloud ECS Instances

**Expected Behavior**: ECS instances should not have public IP addresses (PublicIpAddress.IpAddress should not exist)

**Current Infrastructure Context**:
- Multiple ECS instances across different regions
- Need to check both PublicIpAddress and EipAddress fields
- Regional scope for instance scanning

Please generate the complete YAML rule including discovery and check sections.
```

### OSS Encryption Example
```
Generate an AliCloud compliance check to validate OSS bucket encryption.

**Compliance Standard**: AliCloud Security Baseline - 2.3
**Requirement**: Ensure OSS buckets are encrypted at rest
**Severity**: HIGH
**Scope**: global

**Target Resources**: AliCloud OSS Buckets

**Expected Behavior**: OSS buckets should have encryption enabled (ServerSideEncryptionRule should exist)

**Current Infrastructure Context**:
- Multiple OSS buckets across the account
- Need to check bucket-level encryption settings
- Global scope for bucket listing

Please generate the complete YAML rule including discovery and check sections.
```

### RDS Security Example
```
Generate an AliCloud compliance check to validate RDS SSL enforcement.

**Compliance Standard**: AliCloud Security Baseline - 3.2
**Requirement**: Ensure RDS instances enforce SSL/TLS connections
**Severity**: HIGH
**Scope**: regional

**Target Resources**: AliCloud RDS Instances

**Expected Behavior**: RDS instances should have SSL enabled (SSLEnabled should be true)

**Current Infrastructure Context**:
- Multiple RDS instances across regions
- Need to check SSL configuration
- Regional scope for RDS scanning

Please generate the complete YAML rule including discovery and check sections.
```

### RAM Policy Example
```
Generate an AliCloud compliance check to validate RAM user MFA.

**Compliance Standard**: AliCloud Security Baseline - 4.1
**Requirement**: Ensure all RAM users have MFA enabled
**Severity**: CRITICAL
**Scope**: global

**Target Resources**: AliCloud RAM Users

**Expected Behavior**: All RAM users should have MFA enabled (MFADevice should exist)

**Current Infrastructure Context**:
- Multiple RAM users in the account
- Need to check MFA device status
- Global scope for user listing

Please generate the complete YAML rule including discovery and check sections.
```

---

## Response Format

When responding to these prompts, provide:

1. **Complete YAML Rule**: The full rule definition ready to be placed in the appropriate AliCloud service file
2. **Explanation**: Brief explanation of how the rule works
3. **Field Mapping**: Explanation of the AliCloud resource structure and field paths
4. **Scope Considerations**: Why the chosen scope (regional/global) is appropriate
5. **Action Strategy**: Whether to use `identity`, `eval`, or other actions
6. **Testing Notes**: Any considerations for testing the rule with AliCloud resources

---

## Common AliCloud Patterns

### ECS Instance Security Check
```yaml
- check_id: ecs_instance_no_public_ip
  name: ECS Instance No Public IP
  severity: HIGH
  for_each: instances
  param: instance
  calls:
    - action: identity
      params: {}
      fields:
        - path: PublicIpAddress.IpAddress
          operator: not_exists
          expected: null
  multi_step: false
  logic: AND
  errors_as_fail: []
```

### OSS Bucket Encryption Check
```yaml
- check_id: oss_bucket_encryption_enabled
  name: OSS Bucket Encryption Enabled
  severity: HIGH
  for_each: buckets
  param: bucket
  calls:
    - action: identity
      params: {}
      fields:
        - path: ServerSideEncryptionRule
          operator: exists
          expected: null
  multi_step: false
  logic: AND
  errors_as_fail: []
```

### Security Group Restriction Check
```yaml
- check_id: ecs_security_group_no_unrestricted_ingress
  name: ECS Security Group No Unrestricted Ingress
  severity: HIGH
  for_each: security_groups
  param: sg
  multi_step: true
  logic: AND
  calls:
    - action: identity
      params: {}
      fields:
        - path: Permissions.Permission[].SourceCidrIp
          operator: not_equals
          expected: "0.0.0.0/0"
        - path: Permissions.Permission[].PortRange
          operator: not_equals
          expected: "-1/-1"
  errors_as_fail: []
```

### Multi-Step VPC Configuration Check
```yaml
- check_id: ecs_instance_in_vpc_with_encryption
  name: ECS Instance In VPC With Encryption
  severity: HIGH
  for_each: instances
  param: instance
  multi_step: true
  logic: AND
  calls:
    - action: identity
      params: {}
      fields:
        - path: VpcAttributes.VpcId
          operator: exists
          expected: null
        - path: DataDisks.DataDisk[].Encrypted
          operator: equals
          expected: true
  errors_as_fail: []
```

---

## AliCloud-Specific Considerations

### Regional vs Global Resources
- **Regional Resources**: ECS, RDS, VPC, SLB (Server Load Balancer)
- **Global Resources**: OSS, RAM, ActionTrail, CDN

### Response Structure
AliCloud APIs often wrap results in specific tags:
- **List Operations**: `Instances.Instance[]`, `Buckets.Bucket[]`
- **Single Resource**: Direct object access
- **Pagination**: Use `PageNumber` and `PageSize` parameters

### Common Field Patterns
- **IDs**: `InstanceId`, `BucketName`, `VpcId`
- **Status**: `Status`, `State`
- **Arrays**: `SecurityGroupIds.SecurityGroupId[]`, `Tags.Tag[]`
- **Nested**: `VpcAttributes.VpcId`, `PublicIpAddress.IpAddress`

### Security Group Rules
Security group permissions have specific structures:
- `SourceCidrIp`: Source IP range
- `PortRange`: Port range (e.g., "22/22", "80/80", "-1/-1" for all)
- `IpProtocol`: Protocol type (tcp, udp, icmp, all)
- `Policy`: Allow or Drop

### Encryption Fields
- **ECS Disks**: `Encrypted` (boolean)
- **OSS Buckets**: `ServerSideEncryptionRule.SSEAlgorithm`
- **RDS**: `SSLEnabled`, `TDEStatus`

---

## Best Practices

1. **Understand AliCloud API Structure**: AliCloud APIs have unique response formats
2. **Use Appropriate Scope**: Regional for ECS/RDS/VPC, Global for OSS/RAM
3. **Handle Pagination**: Large resource lists may require pagination
4. **Test Field Paths**: Verify field paths with actual API responses
5. **Consider Multi-Region**: Use appropriate region iteration when needed
6. **Error Handling**: Use `errors_as_fail` for specific error codes
7. **Performance**: Batch operations when possible to reduce API calls

---

## Integration with Metadata

Each check should have a corresponding metadata file with:
- **rule_id**: Unique identifier (e.g., `alicloud.ecs.instance.no_public_ip`)
- **title**: Human-readable title
- **description**: Detailed explanation
- **severity**: Risk level
- **domain**: Security domain (e.g., "Network Security")
- **subcategory**: Specific category
- **references**: AliCloud documentation links
- **compliance**: Framework mappings

This template ensures consistent, effective AliCloud compliance checks that integrate seamlessly with your existing AliCloud compliance engine.

