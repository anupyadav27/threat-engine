# Azure Compliance Check and Metadata Generation Prompt Template

## Context
You are a compliance engineer tasked with creating **security and compliance checks** and their corresponding **metadata files** for Azure infrastructure. These checks and metadata files will be used by our Azure compliance engine to validate infrastructure against security best practices and compliance standards.

## Purpose
- **Compliance Checks**: Define YAML rules to validate Azure resources against security requirements.
- **Metadata Files**: Provide rich context for compliance checks, including categorization, compliance mapping, risk assessment, and remediation guidance.

---

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

---

## Prompt Template for Compliance Check Generation

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

---

## Prompt Template for Metadata Generation

```
Generate a CSP metadata file for the following Azure compliance check:

**Rule ID**: azure.<service>.<category>.<check_name>
**Title**: <Human Readable Title>
**Description**: <What the check validates and why it matters>

**Check Details**:
- **Service**: <service_name> (e.g., compute, storage, network, policy)
- **Resource Type**: <resource_type> (e.g., virtual_machines, storage_accounts, network_security_groups)
- **Severity**: <low|medium|high|critical>
- **Scope**: <tenant|management_group|subscription|regional|global>

**Compliance Standard**: [STANDARD_NAME] - [REQUIREMENT_ID]
- Framework: <CIS|NIST|SOC2|HIPAA|PCI-DSS|GDPR>
- Control ID: <control_id> (e.g., CIS-2.1.1, NIST-SC-13)
- Control Title: <control_title>
- Version: <framework_version> (e.g., CIS-1.4, NIST-800-53-rev5)

**CSP Categorization**:
- **Primary Category**: <data_security|entitlement|network_security|compute_security|secrets_management|compliance_governance|monitoring_detection|infrastructure_security>
- **Subcategory**: <specific_subcategory>
- **Security Domain**: <corresponding_security_domain>

**Risk Assessment**:
- **Impact**: <low|medium|high|critical> - <why this matters>
- **Likelihood**: <low|medium|high> - <explanation>
- **Risk Score**: <0-100> - <calculation rationale>

**Detection**:
- **Evidence Type**: <config_read|api_call|log_analysis|scan_result>
- **Detection Method**: <static|runtime|continuous>
- **Detection Capability**: <automated|manual|semi-automated>
- **Recommended Frequency**: <continuous|daily|weekly|monthly>

**Remediation**:
- **Automated**: <true|false>
- **Remediation Type**: <config_change|policy_update|permission_change|delete|isolate>
- **Estimated Time**: <minutes|hours|days>
- **Complexity**: <low|medium|high>
- **Steps**: <detailed remediation steps>

**Context**:
- **Business Justification**: <Why this control is important for the business>
- **Attack Scenario**: <How this could be exploited if not implemented>
- **Not Applicable When**: <conditions when this check doesn't apply>

**Additional Context**:
- [ANY_SPECIFIC_DETAILS_ABOUT_THE_CHECK]
- [CATEGORY_SPECIFIC_FIELDS] (e.g., data_classification for data_security, access_type for entitlement)

Please generate the complete CSP metadata file following the `azure_csp_metadata_template.yaml` structure.
```

---

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

### Metadata Example
```
Generate a CSP metadata file for the following Azure compliance check:

**Rule ID**: azure.storage.data_security.encryption_at_rest
**Title**: Ensure Storage Accounts are encrypted at rest
**Description**: Validate that all Azure Storage Accounts have encryption enabled to protect data at rest.

**Check Details**:
- **Service**: storage
- **Resource Type**: storage_accounts
- **Severity**: high
- **Scope**: subscription

**Compliance Standard**: Azure Security Benchmark - DP-5
- Framework: CIS
- Control ID: CIS-2.1.1
- Control Title: Ensure Storage Account encryption is enabled
- Version: CIS-1.4

**CSP Categorization**:
- **Primary Category**: data_security
- **Subcategory**: data_encryption_at_rest
- **Security Domain**: data_security

**Risk Assessment**:
- **Impact**: high - Unencrypted data exposes sensitive information
- **Likelihood**: high - Misconfigured storage accounts are common
- **Risk Score**: 85 - High impact data exposure × high likelihood of misconfiguration

**Detection**:
- **Evidence Type**: config_read
- **Detection Method**: static
- **Detection Capability**: automated
- **Recommended Frequency**: continuous

**Remediation**:
- **Automated**: true
- **Remediation Type**: config_change
- **Estimated Time**: minutes
- **Complexity**: low
- **Steps**: 
  1. Enable encryption on the storage account using Azure CLI
  2. Verify encryption settings in the Azure portal

**Context**:
- **Business Justification**: Protects sensitive customer data and meets compliance requirements (HIPAA, PCI-DSS, GDPR)
- **Attack Scenario**: Attacker gains access to unencrypted storage account, exfiltrates sensitive data
- **Not Applicable When**: no_storage_accounts

Please generate the complete CSP metadata file.
```

This template ensures consistent, effective Azure compliance checks and metadata files that integrate seamlessly with your existing Azure compliance engine.
