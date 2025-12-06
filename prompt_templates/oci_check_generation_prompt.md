# OCI (Oracle Cloud Infrastructure) Compliance Check Generation Prompt Template

## Context
You are a compliance engineer tasked with creating **security and compliance checks** for Oracle Cloud Infrastructure (OCI). These checks will be used by our OCI compliance engine to validate infrastructure against security best practices and compliance standards.

## Purpose
Generate YAML rule definitions that can be executed by the OCI compliance engine to validate infrastructure configurations, security settings, and compliance requirements.

---

## OCI Engine Capabilities

### Scope Options
- **`regional`**: Scans resources within a specific OCI region
- **`compartment`**: Scans resources within a specific compartment
- **`tenancy`**: Scans tenancy-level or cross-compartment resources

### Discovery Actions
Uses OCI SDK for Python (`oci`):
- **Compute**: `list_instances`, `list_boot_volumes`, `list_volume_attachments`
- **Identity**: `list_users`, `list_groups`, `list_policies`, `list_compartments`
- **Database**: `list_autonomous_databases`, `list_db_systems`
- **Object Storage**: `list_buckets`, `get_bucket`, `get_bucket_encryption`
- **Virtual Network**: `list_vcns`, `list_security_lists`, `list_network_security_groups`
- **Cloud Guard**: `list_detector_recipes`, `list_responder_recipes`, `list_targets`
- **Monitoring**: `list_alarms`, `list_alarm_history`
- **Vault**: `list_vaults`, `list_keys`

### Field Paths
Dot notation for navigating OCI resource properties:
- **Direct Fields**: `lifecycle_state`, `display_name`, `time_created`
- **Nested Objects**: `defined_tags.Operations.CostCenter`, `metadata.ssh_authorized_keys`
- **Arrays**: `freeform_tags`, `capabilities[]`
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
      - path: is_public
        operator: equals
        expected: false
      - path: kms_key_id
        operator: exists
        expected: null
```

---

## Prompt Template for Compliance Check Generation

```
Generate an OCI compliance check to validate [COMPLIANCE_REQUIREMENT].

**Compliance Standard**: [STANDARD_NAME] - [REQUIREMENT_ID]
**Requirement**: [DETAILED_DESCRIPTION]
**Severity**: [CRITICAL/HIGH/MEDIUM/LOW]
**Scope**: [regional/compartment/tenancy]

**Target Resources**: [RESOURCE_TYPE] (e.g., Compute Instances, Databases, Buckets, Users, VCNs)

**Expected Behavior**: [WHAT_SHOULD_BE_TRUE/FALSE]

**Current Infrastructure Context**:
- [ANY_SPECIFIC_INFRASTRUCTURE_DETAILS]
- [EXISTING_RESOURCES_OR_PATTERNS]
- [COMPARTMENT_OR_TENANCY_SCOPE_NEEDS]
- [PAGINATION_OR_ITERATION_REQUIREMENTS]

**Additional Requirements**:
- [ANY_SPECIFIC_OPERATORS_OR_LOGIC_NEEDED]
- [MULTI_STEP_CHECK_REQUIREMENTS]
- [MULTIPLE_COMPARTMENTS_OR_REGIONS]

Please generate the complete YAML rule including:
1. Discovery section with appropriate OCI SDK calls
2. Check section with proper field paths and operators
3. Appropriate scope setting (regional/compartment/tenancy)
4. Any special handling needed for OCI-specific resources
```

---

## Example Prompts

### Compute Security Example
```
Generate an OCI compliance check to validate Compute instance public IP restrictions.

**Compliance Standard**: OCI Security Baseline - 1.1
**Requirement**: Ensure Compute instances do not have public IP addresses directly attached
**Severity**: HIGH
**Scope**: compartment

**Target Resources**: OCI Compute Instances

**Expected Behavior**: Compute instances should not have public IP addresses assigned to VNICs

**Current Infrastructure Context**:
- Multiple compute instances across different compartments
- Need to check VNIC attachments and public IP assignments
- Compartment scope for instance scanning

Please generate the complete YAML rule including discovery and check sections.
```

### Object Storage Example
```
Generate an OCI compliance check to validate Object Storage bucket encryption.

**Compliance Standard**: OCI Security Baseline - 2.3
**Requirement**: Ensure Object Storage buckets are encrypted with customer-managed keys
**Severity**: HIGH
**Scope**: compartment

**Target Resources**: OCI Object Storage Buckets

**Expected Behavior**: Object Storage buckets should have KMS encryption enabled (kms_key_id should exist)

**Current Infrastructure Context**:
- Multiple buckets across compartments
- Need to check encryption configuration
- Compartment scope for bucket listing

Please generate the complete YAML rule including discovery and check sections.
```

### Database Security Example
```
Generate an OCI compliance check to validate Autonomous Database public access.

**Compliance Standard**: OCI Security Baseline - 3.2
**Requirement**: Ensure Autonomous Databases are not publicly accessible
**Severity**: CRITICAL
**Scope**: compartment

**Target Resources**: OCI Autonomous Databases

**Expected Behavior**: Autonomous Databases should not be publicly accessible (is_dedicated and private_endpoint_ip should be configured)

**Current Infrastructure Context**:
- Multiple autonomous databases across compartments
- Need to check public access settings
- Compartment scope for database scanning

Please generate the complete YAML rule including discovery and check sections.
```

### IAM Policy Example
```
Generate an OCI compliance check to validate IAM user MFA enforcement.

**Compliance Standard**: OCI Security Baseline - 4.1
**Requirement**: Ensure all IAM users have MFA enabled
**Severity**: CRITICAL
**Scope**: tenancy

**Target Resources**: OCI IAM Users

**Expected Behavior**: All IAM users should have MFA devices enabled (is_mfa_activated should be true)

**Current Infrastructure Context**:
- Multiple IAM users in the tenancy
- Need to check MFA status
- Tenancy scope for user listing

Please generate the complete YAML rule including discovery and check sections.
```

---

## Response Format

When responding to these prompts, provide:

1. **Complete YAML Rule**: The full rule definition ready to be placed in the appropriate OCI service file
2. **Explanation**: Brief explanation of how the rule works
3. **Field Mapping**: Explanation of the OCI resource structure and field paths
4. **Scope Considerations**: Why the chosen scope (regional/compartment/tenancy) is appropriate
5. **Action Strategy**: Whether to use `identity`, `eval`, or other actions
6. **Testing Notes**: Any considerations for testing the rule with OCI resources

---

## Common OCI Patterns

### Compute Instance Public IP Check
```yaml
- check_id: compute_instance_no_public_ip
  name: Compute Instance No Public IP
  severity: HIGH
  for_each: instances
  param: instance
  calls:
    - action: identity
      params: {}
      fields:
        - path: public_ip
          operator: not_exists
          expected: null
  multi_step: false
  logic: AND
  errors_as_fail: []
```

### Object Storage Encryption Check
```yaml
- check_id: object_storage_bucket_cmk_encryption
  name: Object Storage Bucket CMK Encryption
  severity: HIGH
  for_each: buckets
  param: bucket
  calls:
    - action: identity
      params: {}
      fields:
        - path: kms_key_id
          operator: exists
          expected: null
  multi_step: false
  logic: AND
  errors_as_fail: []
```

### Security List Unrestricted Access Check
```yaml
- check_id: vcn_security_list_no_unrestricted_ssh
  name: VCN Security List No Unrestricted SSH
  severity: HIGH
  for_each: security_lists
  param: security_list
  multi_step: true
  logic: AND
  calls:
    - action: identity
      params: {}
      fields:
        - path: ingress_security_rules[].source
          operator: not_equals
          expected: "0.0.0.0/0"
        - path: ingress_security_rules[].tcp_options.destination_port_range.min
          operator: not_equals
          expected: 22
  errors_as_fail: []
```

### Multi-Step Database Configuration Check
```yaml
- check_id: autonomous_database_private_with_backup
  name: Autonomous Database Private With Backup
  severity: HIGH
  for_each: autonomous_databases
  param: database
  multi_step: true
  logic: AND
  calls:
    - action: identity
      params: {}
      fields:
        - path: is_dedicated
          operator: equals
          expected: true
        - path: private_endpoint_ip
          operator: exists
          expected: null
        - path: is_auto_scaling_enabled
          operator: equals
          expected: true
  errors_as_fail: []
```

---

## OCI-Specific Considerations

### Compartment Hierarchy
- **Root Compartment**: Tenancy OCID
- **Sub-Compartments**: Nested structure for organization
- **Cross-Compartment Access**: May require specific IAM policies
- **Scope Selection**: Use `compartment` for resource-specific, `tenancy` for account-wide

### Regional vs Tenancy Resources
- **Regional Resources**: Compute, VCN, Database, Load Balancer
- **Tenancy Resources**: IAM, Tagging, Policies, Audit logs

### Response Structure
OCI SDK returns Python objects with attributes:
- **Direct Access**: `instance.display_name`, `bucket.kms_key_id`
- **Lists**: Use list comprehensions or iterate
- **Pagination**: Use `list_call_get_all_results()` helper

### Common Field Patterns
- **OCIDs**: `id`, `compartment_id`, `kms_key_id`
- **State**: `lifecycle_state` (AVAILABLE, TERMINATED, etc.)
- **Tags**: `defined_tags`, `freeform_tags`
- **Networking**: `vcn_id`, `subnet_id`, `private_ip`, `public_ip`

### Security List vs NSG
OCI has two firewall mechanisms:
- **Security Lists**: Legacy, subnet-level rules
- **Network Security Groups (NSGs)**: Modern, instance-level rules
- Check both for comprehensive security validation

### Encryption Options
- **Platform-Managed Keys**: Default encryption
- **Customer-Managed Keys (CMK)**: Keys stored in Vault
- **Field**: `kms_key_id` indicates CMK usage

### IAM Policies
- **Policy Format**: `Allow group <group> to <verb> <resource> in compartment <compartment>`
- **Verbs**: inspect, read, use, manage
- **Resources**: all-resources, instance-family, bucket, etc.

---

## Best Practices

1. **Understand Compartments**: OCI's compartment hierarchy is key to resource organization
2. **Use Appropriate Scope**: Compartment for most resources, Tenancy for IAM/Audit
3. **Handle Pagination**: Use SDK pagination helpers for large result sets
4. **Test Field Paths**: Verify attribute names with actual SDK responses
5. **Consider Multi-Compartment**: Iterate across compartments when needed
6. **Error Handling**: Use `errors_as_fail` for specific error codes
7. **Performance**: Use resource search for cross-compartment queries
8. **Lifecycle States**: Check `lifecycle_state` to avoid terminated resources

---

## Integration with Metadata

Each check should have a corresponding metadata file with:
- **rule_id**: Unique identifier (e.g., `oci.compute.instance.no_public_ip`)
- **title**: Human-readable title
- **description**: Detailed explanation
- **severity**: Risk level
- **domain**: Security domain (e.g., "Network Security")
- **subcategory**: Specific category
- **references**: OCI documentation links
- **compliance**: Framework mappings (CIS OCI, PCI-DSS, etc.)

---

## OCI SDK Code Patterns

### Basic Resource Listing
```python
compute_client = oci.core.ComputeClient(config)
instances = compute_client.list_instances(compartment_id=compartment_id)
for instance in instances.data:
    # Check instance properties
```

### Pagination
```python
from oci.pagination import list_call_get_all_results
all_instances = list_call_get_all_results(
    compute_client.list_instances,
    compartment_id=compartment_id
)
```

### Cross-Compartment Search
```python
search_client = oci.resource_search.ResourceSearchClient(config)
query = "query instance resources"
results = search_client.search_resources(query)
```

This template ensures consistent, effective OCI compliance checks that integrate seamlessly with your existing OCI compliance engine.

