# Azure Compliance Check Generation Prompt Template

## Context
You are a compliance engineer tasked with creating security and compliance checks for Azure infrastructure. You need to generate YAML rule definitions that can be executed by our Azure compliance engine to validate infrastructure against security best practices.

## Azure Engine Capabilities

### Scope Options
- **`tenant`**: Scans tenant-level resources (Microsoft Graph API)
- **`management_group`**: Scans management group level resources
- **`subscription`**: Scans subscription-level resources
- **`regional`**: Scans region-specific resources
- **`global`**: Scans global resources

### Discovery Actions
Uses Azure SDK for Python:
- **Compute**: `virtual_machines.list`, `disks.list_by_resource_group`
- **Storage**: `storage_accounts.list`, `storage_accounts.list_by_resource_group`
- **Network**: `network_security_groups.list`, `network_watchers.list`
- **Policy**: `policy_definitions.list`, `policy_assignments.list`
- **Management Groups**: `management_groups.list`
- **Microsoft Graph**: `applications.list`, `users.list`

### Field Paths
Dot notation for navigating Azure resource properties:
- **Direct Fields**: `encryption.type`, `storage_profile.os_disk.managed_disk`
- **Nested Objects**: `encryption.key_vault_properties.key_uri`
- **Arrays**: `network_profile.network_interfaces[].id`
- **Special**: `__self__` for the entire resource object

### Operators
- `equals`: Exact value match
- `contains`: Field contains the expected value
- `not_contains`: Field does not contain the expected value
- `exists`: Field exists and has a value
- `not_exists`: Field does not exist or is null/empty

### Resource Group Iteration
Supports scanning across multiple resource groups:
```yaml
scope: subscription
iterate_resource_groups: true
discovery:
  - discovery_id: vms
    resource_group_param: resource_group_name
    calls:
      - action: virtual_machines.list
        resource_group_param: resource_group_name
```

## Prompt Template

```
Generate an Azure compliance check to validate [COMPLIANCE_REQUIREMENT].

**Compliance Standard**: [STANDARD_NAME] - [REQUIREMENT_ID]
**Requirement**: [DETAILED_DESCRIPTION]
**Severity**: [HIGH/MEDIUM/LOW]
**Scope**: [tenant/management_group/subscription/regional/global]

**Target Resources**: [RESOURCE_TYPE] (e.g., Virtual Machines, Storage Accounts, Network Security Groups, Policy Definitions)

**Expected Behavior**: [WHAT_SHOULD_BE_TRUE/FALSE]

**Current Infrastructure Context**:
- [ANY_SPECIFIC_INFRASTRUCTURE_DETAILS]
- [EXISTING_RESOURCES_OR_PATTERNS]
- [SCOPE_LEVEL_NEEDS]
- [RESOURCE_GROUP_ITERATION_REQUIREMENTS]

**Additional Requirements**:
- [ANY_SPECIFIC_OPERATORS_OR_LOGIC_NEEDED]
- [RESOURCE_GROUP_TRAVERSAL_NEEDS]
- [MANAGEMENT_GROUP_OR_TENANT_LEVEL_ACCESS]

Please generate the complete YAML rule including:
1. Discovery section with appropriate Azure SDK calls
2. Check section with proper field paths and operators
3. Appropriate scope setting and resource group iteration
4. Any special handling needed for Azure-specific resources
```

## Example Prompts

### VM Security Example
```
Generate an Azure compliance check to validate VM public IP restrictions.

**Compliance Standard**: Azure Security Benchmark - NS-1
**Requirement**: Ensure Virtual Machines do not have public IP addresses directly attached
**Severity**: HIGH
**Scope**: subscription

**Target Resources**: Azure Virtual Machines

**Expected Behavior**: VMs should not have public IP addresses (network_profile.network_interfaces should not contain publicIPAddresses)

**Current Infrastructure Context**:
- Multiple VMs across different resource groups
- Need to iterate through all resource groups
- Check network interface configurations

Please generate the complete YAML rule including discovery and check sections.
```

### Storage Encryption Example
```
Generate an Azure compliance check to validate Storage Account CMK encryption.

**Compliance Standard**: Azure Security Benchmark - DP-5
**Requirement**: Ensure Storage accounts are encrypted with Customer Managed Keys
**Severity**: HIGH
**Scope**: subscription

**Target Resources**: Azure Storage Accounts

**Expected Behavior**: Storage accounts should use CMK encryption (encryption.key_source should be Microsoft.Keyvault)

**Current Infrastructure Context**:
- Multiple storage accounts across resource groups
- Need to check encryption settings and key vault properties
- Iterate through resource groups for discovery

Please generate the complete YAML rule including discovery and check sections.
```

### Management Group Policy Example
```
Generate an Azure compliance check to validate Management Group policy assignments.

**Compliance Standard**: Azure Security Benchmark - PL-1
**Requirement**: Ensure Management Groups have policy assignments configured
**Severity**: MEDIUM
**Scope**: management_group

**Target Resources**: Azure Policy Assignments at Management Group level

**Expected Behavior**: Management Groups should have at least one policy assignment

**Current Infrastructure Context**:
- Multiple management groups in the tenant
- Need to check policy assignments at MG level
- Management group scope scanning

Please generate the complete YAML rule including discovery and check sections.
```

## Response Format

When responding to these prompts, provide:

1. **Complete YAML Rule**: The full rule definition ready to be placed in the appropriate Azure service file
2. **Explanation**: Brief explanation of how the rule works
3. **Field Mapping**: Explanation of the Azure resource structure and field paths
4. **Scope Considerations**: Why the chosen scope is appropriate
5. **Resource Group Strategy**: Whether and how resource group iteration is used
6. **Testing Notes**: Any considerations for testing the rule with Azure resources

## Common Azure Patterns

### VM Configuration Check
```yaml
- check_id: vm_managed_disks
  title: Ensure VMs use managed disks
  severity: medium
  for_each: vms
  param: vm
  calls:
    - action: self
      fields:
        - path: storage_profile.os_disk.managed_disk
          operator: exists
          expected: true
```

### Storage Account Security Check
```yaml
- check_id: storage_https_only
  title: Ensure Storage accounts require HTTPS
  severity: high
  for_each: accounts
  param: account
  calls:
    - action: self
      fields:
        - path: enable_https_traffic_only
          operator: equals
          expected: true
```

### Network Security Group Check
```yaml
- check_id: nsg_no_ssh_from_any
  title: Ensure NSGs do not allow SSH from anywhere
  severity: high
  for_each: nsgs
  param: nsg
  calls:
    - action: self
      fields:
        - path: security_rules[].source_address_prefix
          operator: not_contains
          expected: "*"
        - path: security_rules[].destination_port_range
          operator: not_contains
          expected: "22"
```

### Management Group Policy Check
```yaml
- check_id: mg_has_policy_assignments
  title: Ensure Management Groups have policy assignments
  severity: medium
  for_each: mg_policy_assignments
  param: assignment
  calls:
    - action: self
      fields:
        - path: name
          operator: exists
          expected: true
```

This template ensures consistent, effective Azure compliance checks that integrate seamlessly with your existing Azure compliance engine.
