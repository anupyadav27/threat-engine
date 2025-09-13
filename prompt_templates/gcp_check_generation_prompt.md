# GCP Compliance Check Generation Prompt Template

## Context
You are a compliance engineer tasked with creating security and compliance checks for Google Cloud Platform (GCP) infrastructure. You need to generate YAML rule definitions that can be executed by our GCP compliance engine to validate infrastructure against security best practices.

## GCP Engine Capabilities

### Scope Options
- **`regional`**: Scans resources within a specific GCP region/zone
- **`global`**: Scans project-level or cross-region resources

### Discovery Actions
Uses Google Cloud SDK for Python:
- **Compute**: `aggregated_list_instances`, `list_firewalls`, `list_networks`
- **Storage**: `list_buckets`, `get_bucket_iam_policy`
- **IAM**: `list_service_accounts`, `list_roles`, `list_policies`
- **Security**: `list_findings`, `list_sources`
- **Monitoring**: `list_alert_policies`, `list_notification_channels`

### Field Paths
Dot notation for navigating GCP resource properties:
- **Direct Fields**: `has_external_ip`, `shielded_secure_boot`
- **Nested Objects**: `metadata.serial_port_enabled`
- **Arrays**: `source_ranges[]`, `allowed_tcp_ports[]`
- **Special**: `__self__` for the entire resource object

### Operators
- `equals`: Exact value match
- `contains`: Field contains the expected value
- `not_contains`: Field does not contain the expected value
- `exists`: Field exists and has a value
- `not_exists`: Field does not exist or is null/empty

### Actions
- **`eval`**: Direct field evaluation (most common)
- **`identity`**: Object reference for complex operations
- **`list`**: Resource listing operations

### Multi-Step Checks
Supports complex validation logic:
```yaml
multi_step: true
logic: AND  # or OR
calls:
  - action: eval
    fields:
      - path: source_ranges[]
        operator: contains
        expected: 0.0.0.0/0
      - path: allowed_tcp_ports[]
        operator: contains
        expected: "22"
```

## Prompt Template

```
Generate a GCP compliance check to validate [COMPLIANCE_REQUIREMENT].

**Compliance Standard**: [STANDARD_NAME] - [REQUIREMENT_ID]
**Requirement**: [DETAILED_DESCRIPTION]
**Severity**: [HIGH/MEDIUM/LOW]
**Scope**: [regional/global]

**Target Resources**: [RESOURCE_TYPE] (e.g., Compute instances, Firewalls, Storage buckets, IAM service accounts)

**Expected Behavior**: [WHAT_SHOULD_BE_TRUE/FALSE]

**Current Infrastructure Context**:
- [ANY_SPECIFIC_INFRASTRUCTURE_DETAILS]
- [EXISTING_RESOURCES_OR_PATTERNS]
- [REGIONAL_OR_GLOBAL_SCOPE_NEEDS]
- [ZONE_OR_REGION_SPECIFIC_REQUIREMENTS]

**Additional Requirements**:
- [ANY_SPECIFIC_OPERATORS_OR_LOGIC_NEEDED]
- [MULTI_STEP_CHECK_REQUIREMENTS]
- [AGGREGATED_RESOURCE_LISTING_NEEDS]

Please generate the complete YAML rule including:
1. Discovery section with appropriate GCP API calls
2. Check section with proper field paths and operators
3. Appropriate scope setting (regional/global)
4. Any special handling needed for GCP-specific resources
```

## Example Prompts

### Compute Security Example
```
Generate a GCP compliance check to validate Compute instance external IP restrictions.

**Compliance Standard**: CIS GCP Foundations 1.3 - 4.1
**Requirement**: Ensure Compute instances do not have external IP addresses
**Severity**: HIGH
**Scope**: regional

**Target Resources**: GCP Compute instances

**Expected Behavior**: Compute instances should not have external IP addresses (has_external_ip should be false)

**Current Infrastructure Context**:
- Multiple Compute instances across different zones
- Using aggregated instance listing across all zones
- Need to check the has_external_ip field

Please generate the complete YAML rule including discovery and check sections.
```

### Firewall Security Example
```
Generate a GCP compliance check to validate Firewall SSH restrictions.

**Compliance Standard**: CIS GCP Foundations 1.3 - 4.2
**Requirement**: Ensure Firewalls do not allow SSH (port 22) from 0.0.0.0/0
**Severity**: HIGH
**Scope**: regional

**Target Resources**: GCP Firewall rules

**Expected Behavior**: Firewall rules should not allow inbound SSH access from anywhere (0.0.0.0/0)

**Current Infrastructure Context**:
- Multiple firewall rules across the project
- Need to check both source ranges and allowed ports
- Regional scope for firewall scanning

Please generate the complete YAML rule including discovery and check sections.
```

### Storage Security Example
```
Generate a GCP compliance check to validate Storage bucket public access.

**Compliance Standard**: CIS GCP Foundations 1.3 - 3.1
**Requirement**: Ensure Storage buckets are not publicly accessible
**Severity**: HIGH
**Scope**: global

**Target Resources**: GCP Storage buckets

**Expected Behavior**: Storage buckets should not have public read access

**Current Infrastructure Context**:
- Multiple storage buckets across the project
- Need to check IAM policies and public access settings
- Global scope for bucket listing

Please generate the complete YAML rule including discovery and check sections.
```

## Response Format

When responding to these prompts, provide:

1. **Complete YAML Rule**: The full rule definition ready to be placed in the appropriate GCP service file
2. **Explanation**: Brief explanation of how the rule works
3. **Field Mapping**: Explanation of the GCP resource structure and field paths
4. **Scope Considerations**: Why the chosen scope (regional/global) is appropriate
5. **Action Strategy**: Whether to use `eval`, `identity`, or other actions
6. **Testing Notes**: Any considerations for testing the rule with GCP resources

## Common GCP Patterns

### Compute Instance Security Check
```yaml
- check_id: compute_instance_no_external_ip
  for_each: instances
  param: instance
  calls:
    - action: eval
      fields:
        - path: has_external_ip
          operator: equals
          expected: false
  multi_step: false
  logic: AND
  errors_as_fail: []
```

### Firewall Security Check
```yaml
- check_id: compute_firewall_no_ssh_from_anywhere
  for_each: firewalls
  param: firewall
  multi_step: true
  logic: AND
  calls:
    - action: eval
      fields:
        - path: source_ranges[]
          operator: contains
          expected: 0.0.0.0/0
        - path: allowed_tcp_ports[]
          operator: contains
          expected: "22"
  errors_as_fail: []
```

### Instance Configuration Check
```yaml
- check_id: compute_instance_shielded_secure_boot
  for_each: instances
  param: instance
  calls:
    - action: eval
      fields:
        - path: shielded_secure_boot
          operator: equals
          expected: true
  multi_step: false
  logic: AND
  errors_as_fail: []
```

### Metadata Configuration Check
```yaml
- check_id: compute_instance_serial_port_disabled
  for_each: instances
  param: instance
  calls:
    - action: eval
      fields:
        - path: metadata.serial_port_enabled
          operator: equals
          expected: false
  multi_step: false
  logic: AND
  errors_as_fail: []
```

## GCP-Specific Considerations

### Aggregated Resource Listing
For Compute instances, use `aggregated_list_instances` to scan across all zones:
```yaml
discovery:
  - discovery_id: instances
    calls:
      - action: aggregated_list_instances
```

### Firewall Rule Analysis
Firewall rules in GCP have specific structures:
- `source_ranges[]`: Array of CIDR blocks
- `allowed_tcp_ports[]`: Array of allowed TCP ports
- `direction`: INGRESS or EGRESS

### Storage Bucket IAM
Storage bucket security involves checking IAM policies:
- Public access through IAM bindings
- Uniform bucket-level access settings
- Object-level permissions

This template ensures consistent, effective GCP compliance checks that integrate seamlessly with your existing GCP compliance engine.
