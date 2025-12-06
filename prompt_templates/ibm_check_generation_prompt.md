# IBM Cloud Compliance Check Generation Prompt Template

## Context
You are a compliance engineer tasked with creating **security and compliance checks** for IBM Cloud infrastructure. These checks will be used by our IBM Cloud compliance engine to validate infrastructure against security best practices and compliance standards.

## Purpose
Generate YAML rule definitions that can be executed by the IBM Cloud compliance engine to validate infrastructure configurations, security settings, and compliance requirements.

---

## IBM Cloud Engine Capabilities

### Scope Options
- **`regional`**: Scans resources within a specific IBM Cloud region
- **`account`**: Scans account-level resources
- **`resource_group`**: Scans resources within a specific resource group
- **`global`**: Scans global resources across the account

### Discovery Actions
Uses IBM Cloud SDK for Python (`ibm-cloud-sdk-core`, `ibm-platform-services`):
- **VPC**: `list_instances`, `list_security_groups`, `list_subnets`, `list_vpcs`
- **IAM**: `list_users`, `list_service_ids`, `list_access_policies`, `list_api_keys`
- **Key Protect**: `list_keys`, `get_key_metadata`, `list_key_policies`
- **Databases**: `list_deployments`, `get_deployment`, `list_database_users`
- **Containers**: `list_clusters`, `get_cluster`, `list_worker_pools`
- **Cloud Object Storage (COS)**: `list_buckets`, `get_bucket_config`, `get_bucket_encryption`
- **Security Advisor**: `list_findings`, `list_providers`
- **Resource Controller**: `list_resource_instances`, `list_resource_groups`

### Field Paths
Dot notation for navigating IBM Cloud resource properties:
- **Direct Fields**: `state`, `name`, `region`, `crn`
- **Nested Objects**: `profile.name`, `network_interfaces[].primary_ipv4_address`
- **Arrays**: `security_groups[]`, `tags[]`
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
- `gte`: Greater than or equal
- `lte`: Less than or equal
- `in`: Value is in a list of expected values
- `not_in`: Value is not in a list of expected values
- `regex`: Match against regular expression

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
      - path: network_interfaces[].primary_ipv4_address
        operator: not_exists
        expected: null
      - path: vpc.name
        operator: exists
        expected: null
```

---

## Prompt Template for Compliance Check Generation

```
Generate an IBM Cloud compliance check to validate [COMPLIANCE_REQUIREMENT].

**Compliance Standard**: [STANDARD_NAME] - [REQUIREMENT_ID]
**Requirement**: [DETAILED_DESCRIPTION]
**Severity**: [CRITICAL/HIGH/MEDIUM/LOW]
**Scope**: [regional/account/resource_group/global]

**Target Resources**: [RESOURCE_TYPE] (e.g., VPC Instances, Databases, Key Protect Keys, IAM Users, Kubernetes Clusters)

**Expected Behavior**: [WHAT_SHOULD_BE_TRUE/FALSE]

**Current Infrastructure Context**:
- [ANY_SPECIFIC_INFRASTRUCTURE_DETAILS]
- [EXISTING_RESOURCES_OR_PATTERNS]
- [RESOURCE_GROUP_OR_ACCOUNT_SCOPE_NEEDS]
- [PAGINATION_OR_ITERATION_REQUIREMENTS]

**Additional Requirements**:
- [ANY_SPECIFIC_OPERATORS_OR_LOGIC_NEEDED]
- [MULTI_STEP_CHECK_REQUIREMENTS]
- [MULTIPLE_REGIONS_OR_RESOURCE_GROUPS]

Please generate the complete YAML rule including:
1. Discovery section with appropriate IBM Cloud SDK calls
2. Check section with proper field paths and operators
3. Appropriate scope setting (regional/account/resource_group/global)
4. Any special handling needed for IBM Cloud-specific resources
```

---

## Example Prompts

### VPC Security Example
```
Generate an IBM Cloud compliance check to validate VPC instance public IP restrictions.

**Compliance Standard**: IBM Cloud Security Baseline - 1.1
**Requirement**: Ensure VPC instances do not have public floating IPs attached
**Severity**: HIGH
**Scope**: regional

**Target Resources**: IBM Cloud VPC Instances

**Expected Behavior**: VPC instances should not have floating IPs attached (floating_ips should be empty or not exist)

**Current Infrastructure Context**:
- Multiple VPC instances across different resource groups
- Need to check network interface configurations
- Regional scope for instance scanning

Please generate the complete YAML rule including discovery and check sections.
```

### Key Protect Example
```
Generate an IBM Cloud compliance check to validate Key Protect key rotation.

**Compliance Standard**: IBM Cloud Security Baseline - 2.3
**Requirement**: Ensure Key Protect keys have rotation policies enabled
**Severity**: HIGH
**Scope**: account

**Target Resources**: IBM Cloud Key Protect Keys

**Expected Behavior**: Key Protect keys should have automatic rotation enabled (rotation_policy should exist)

**Current Infrastructure Context**:
- Multiple Key Protect instances across resource groups
- Need to check key rotation policies
- Account scope for key listing

Please generate the complete YAML rule including discovery and check sections.
```

### Database Security Example
```
Generate an IBM Cloud compliance check to validate Database encryption.

**Compliance Standard**: IBM Cloud Security Baseline - 3.2
**Requirement**: Ensure Databases are encrypted with customer-managed keys
**Severity**: HIGH
**Scope**: account

**Target Resources**: IBM Cloud Databases

**Expected Behavior**: Databases should use BYOK (Bring Your Own Key) for encryption (key_protect_key should exist)

**Current Infrastructure Context**:
- Multiple database deployments across resource groups
- Need to check encryption configuration
- Account scope for database scanning

Please generate the complete YAML rule including discovery and check sections.
```

### IAM Policy Example
```
Generate an IBM Cloud compliance check to validate IAM user MFA enforcement.

**Compliance Standard**: IBM Cloud Security Baseline - 4.1
**Requirement**: Ensure all IAM users have MFA enabled
**Severity**: CRITICAL
**Scope**: account

**Target Resources**: IBM Cloud IAM Users

**Expected Behavior**: All IAM users should have MFA enabled (mfa_enabled should be true)

**Current Infrastructure Context**:
- Multiple IAM users in the account
- Need to check MFA status
- Account scope for user listing

Please generate the complete YAML rule including discovery and check sections.
```

---

## Response Format

When responding to these prompts, provide:

1. **Complete YAML Rule**: The full rule definition ready to be placed in the appropriate IBM Cloud service file
2. **Explanation**: Brief explanation of how the rule works
3. **Field Mapping**: Explanation of the IBM Cloud resource structure and field paths
4. **Scope Considerations**: Why the chosen scope (regional/account/resource_group/global) is appropriate
5. **Action Strategy**: Whether to use `identity`, `eval`, or other actions
6. **Testing Notes**: Any considerations for testing the rule with IBM Cloud resources

---

## Common IBM Cloud Patterns

### VPC Instance Public IP Check
```yaml
- check_id: vpc_instance_no_floating_ip
  name: VPC Instance No Floating IP
  severity: HIGH
  for_each: instances
  param: instance
  calls:
    - action: identity
      params: {}
      fields:
        - path: floating_ips
          operator: not_exists
          expected: null
  multi_step: false
  logic: AND
  errors_as_fail: []
```

### Key Protect Rotation Check
```yaml
- check_id: key_protect_rotation_enabled
  name: Key Protect Rotation Enabled
  severity: HIGH
  for_each: keys
  param: key
  calls:
    - action: identity
      params: {}
      fields:
        - path: rotation_policy
          operator: exists
          expected: null
  multi_step: false
  logic: AND
  errors_as_fail: []
```

### Security Group Unrestricted Access Check
```yaml
- check_id: vpc_security_group_no_unrestricted_ssh
  name: VPC Security Group No Unrestricted SSH
  severity: HIGH
  for_each: security_groups
  param: security_group
  multi_step: true
  logic: AND
  calls:
    - action: identity
      params: {}
      fields:
        - path: rules[].remote.cidr_block
          operator: not_equals
          expected: "0.0.0.0/0"
        - path: rules[].port_min
          operator: not_equals
          expected: 22
  errors_as_fail: []
```

### Multi-Step Database Configuration Check
```yaml
- check_id: database_encrypted_with_backup
  name: Database Encrypted With Backup
  severity: HIGH
  for_each: databases
  param: database
  multi_step: true
  logic: AND
  calls:
    - action: identity
      params: {}
      fields:
        - path: key_protect_key
          operator: exists
          expected: null
        - path: backup.enabled
          operator: equals
          expected: true
        - path: backup.retention_days
          operator: gte
          expected: 7
  errors_as_fail: []
```

---

## IBM Cloud-Specific Considerations

### Resource Groups
- **Purpose**: Logical organization of resources
- **Scope**: Resources belong to one resource group
- **Access Control**: IAM policies can target resource groups
- **Cross-Resource Group**: Some checks may need to iterate across groups

### Regional vs Global Resources
- **Regional Resources**: VPC, VSI (Virtual Server Instances), Load Balancers
- **Global Resources**: IAM, COS (Cloud Object Storage), Key Protect, Resource Controller

### CRN (Cloud Resource Name)
IBM Cloud uses CRNs to uniquely identify resources:
```
crn:v1:bluemix:public:service-name:location:account-id:resource-type:resource-id::
```
- **Components**: Version, Cloud, Public/Dedicated, Service, Location, Account, Resource Type, Resource ID
- **Usage**: For precise resource identification and policy targeting

### Response Structure
IBM Cloud SDKs return objects with specific structures:
- **List Operations**: Return arrays of resource objects
- **Get Operations**: Return single resource object
- **Pagination**: Use `limit` and `start` parameters

### Common Field Patterns
- **IDs**: `id`, `crn`, `resource_id`, `resource_group_id`
- **State**: `state`, `status`, `lifecycle_state`
- **Tags**: `tags[]`, `user_tags[]`, `access_tags[]`
- **Networking**: `vpc`, `subnet`, `primary_ipv4_address`, `floating_ips`

### Security Group Rules
Security group rules have specific structures:
- **Direction**: inbound, outbound
- **Remote**: IP address, CIDR block, security group
- **Protocol**: tcp, udp, icmp, all
- **Port Range**: `port_min` and `port_max`

### Encryption Options
- **Platform-Managed**: Default encryption by IBM
- **Customer-Managed (BYOK)**: Keys in Key Protect or Hyper Protect Crypto Services
- **Field**: `key_protect_key` or `key_protect_instance` indicates BYOK

### IAM Policies
- **Policy Types**: Access policies, Authorization policies
- **Subjects**: Users, Service IDs, Access Groups
- **Roles**: Viewer, Operator, Editor, Administrator, Manager
- **Resources**: Service instances, resource groups, account

### COS (Cloud Object Storage)
- **Buckets**: Regional, Cross-Region, Single Site
- **Access Control**: IAM policies, Bucket policies, Access Control Lists
- **Encryption**: SSE-C (customer-provided), SSE-KP (Key Protect)

---

## Best Practices

1. **Understand Resource Groups**: IBM Cloud's resource organization model
2. **Use Appropriate Scope**: Regional for VPC/compute, Account for IAM/COS
3. **Handle Pagination**: Use SDK pagination for large result sets
4. **Test Field Paths**: Verify attribute names with actual SDK responses
5. **Consider Multi-Resource-Group**: Iterate when needed
6. **Error Handling**: Use `errors_as_fail` for specific error codes
7. **Performance**: Batch operations and use resource controller for queries
8. **CRN Parsing**: Use CRN components for resource categorization
9. **State Checking**: Filter by `state` to avoid deleted/failed resources

---

## Integration with Metadata

Each check should have a corresponding metadata file with:
- **rule_id**: Unique identifier (e.g., `ibm.vpc.instance.no_floating_ip`)
- **title**: Human-readable title
- **description**: Detailed explanation
- **severity**: Risk level
- **domain**: Security domain (e.g., "Network Security")
- **subcategory**: Specific category
- **references**: IBM Cloud documentation links
- **compliance**: Framework mappings (CIS, PCI-DSS, etc.)

---

## IBM Cloud SDK Code Patterns

### Basic Resource Listing
```python
from ibm_vpc import VpcV1
vpc_service = VpcV1(authenticator=authenticator)
instances = vpc_service.list_instances().get_result()
for instance in instances['instances']:
    # Check instance properties
```

### Pagination
```python
start = None
all_instances = []
while True:
    response = vpc_service.list_instances(start=start, limit=50).get_result()
    all_instances.extend(response['instances'])
    if 'next' in response and response['next']:
        start = response['next']['href'].split('start=')[1]
    else:
        break
```

### Resource Controller Query
```python
from ibm_platform_services import ResourceControllerV2
rc_service = ResourceControllerV2(authenticator=authenticator)
resources = rc_service.list_resource_instances(
    resource_group_id=resource_group_id
).get_result()
```

### Key Protect Operations
```python
from ibm_key_protect_api import IbmKeyProtectApiV2
kp_service = IbmKeyProtectApiV2(authenticator=authenticator)
keys = kp_service.list_keys(
    bluemix_instance=instance_id
).get_result()
```

---

## IBM Cloud Service Categories

### Compute
- **Virtual Servers**: VPC VSI, Classic VSI
- **Bare Metal**: Dedicated servers
- **VMware**: VMware Solutions

### Containers
- **IKS**: IBM Kubernetes Service
- **Red Hat OpenShift**: Managed OpenShift clusters

### Databases
- **Databases for PostgreSQL, MySQL, MongoDB, etc.**
- **Db2**: SQL database
- **Cloudant**: NoSQL database

### Storage
- **COS**: Cloud Object Storage
- **Block Storage**: VPC Block Storage
- **File Storage**: NFS-based storage

### Networking
- **VPC**: Virtual Private Cloud
- **Load Balancers**: Application and Network Load Balancers
- **Direct Link**: Private connectivity
- **CDN**: Content Delivery Network

### Security
- **IAM**: Identity and Access Management
- **Key Protect**: Key management service
- **Hyper Protect Crypto Services**: HSM-based key management
- **Security Advisor**: Security findings and insights
- **Secrets Manager**: Secrets lifecycle management

This template ensures consistent, effective IBM Cloud compliance checks that integrate seamlessly with your existing IBM Cloud compliance engine.

