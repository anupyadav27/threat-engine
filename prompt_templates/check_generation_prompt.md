# Compliance Check Generation Prompt Template

## Overview
This is the main template for generating compliance check functions across different cloud engines. For detailed, cloud-specific templates, see the individual files below.

## Quick Reference
- **AWS**: [aws_check_generation_prompt.md](aws_check_generation_prompt.md)
- **Azure**: [azure_check_generation_prompt.md](azure_check_generation_prompt.md)  
- **GCP**: [gcp_check_generation_prompt.md](gcp_check_generation_prompt.md)
- **Kubernetes**: [kubernetes_check_generation_prompt.md](kubernetes_check_generation_prompt.md)

## Common Architecture Patterns

All engines follow similar patterns but with cloud-specific implementations:

### 1. Discovery Phase
- **AWS**: Uses boto3 API calls (e.g., `describe_security_groups`)
- **Azure**: Uses Azure SDK calls (e.g., `virtual_machines.list`)
- **GCP**: Uses Google Cloud SDK calls (e.g., `aggregated_list_instances`)
- **K8s**: Uses Kubernetes API calls (e.g., `list_pods`)

### 2. Check Phase
- **Field Paths**: JSONPath-like syntax (AWS) vs dot notation (Azure/GCP/K8s)
- **Operators**: Common set (`equals`, `contains`, `exists`) with cloud-specific additions
- **Multi-step Logic**: AND/OR combinations for complex validations

### 3. Scope Management
- **AWS**: `regional` vs `global`
- **Azure**: `tenant`, `management_group`, `subscription`, `regional`, `global`
- **GCP**: `regional` vs `global`
- **K8s**: `cluster` vs `namespace`

## Universal Prompt Structure

```
Generate a [CLOUD_PROVIDER] compliance check to validate [COMPLIANCE_REQUIREMENT].

**Compliance Standard**: [STANDARD_NAME] - [REQUIREMENT_ID]
**Requirement**: [DETAILED_DESCRIPTION]
**Severity**: [HIGH/MEDIUM/LOW]
**Scope**: [APPROPRIATE_SCOPE_FOR_CLOUD]

**Target Resources**: [RESOURCE_TYPE]

**Expected Behavior**: [WHAT_SHOULD_BE_TRUE/FALSE]

**Current Infrastructure Context**:
- [INFRASTRUCTURE_DETAILS]
- [SCOPE_AND_ITERATION_NEEDS]

**Additional Requirements**:
- [SPECIFIC_OPERATORS_OR_LOGIC]
- [MULTI_STEP_NEEDS]

Please generate the complete YAML rule including discovery and check sections.
```

## When to Use Each Template

- **Use AWS template** for: EC2, S3, IAM, Security Groups, RDS, CloudTrail
- **Use Azure template** for: VMs, Storage Accounts, NSGs, Policy, Management Groups, Entra ID
- **Use GCP template** for: Compute instances, Firewalls, Storage buckets, IAM
- **Use K8s template** for: Pods, Deployments, RBAC, Network Policies, Security Contexts

## Common Compliance Standards

- **CIS Benchmarks**: CIS AWS, Azure, GCP, Kubernetes
- **Azure Security Benchmark**: Microsoft's security recommendations
- **NIST**: National Institute of Standards and Technology
- **ISO 27001**: Information security management
- **SOC 2**: Service Organization Control 2

## Best Practices

1. **Start with the specific template** for your cloud provider
2. **Understand the scope** before writing the rule
3. **Test field paths** with actual API responses
4. **Use appropriate operators** for the validation logic
5. **Consider multi-step checks** for complex validations
6. **Document the rule purpose** clearly

## Getting Started

1. Choose your cloud provider template
2. Fill in the prompt structure with your requirements
3. Generate the YAML rule
4. Test with your compliance engine
5. Iterate and refine as needed

For detailed examples and cloud-specific patterns, refer to the individual template files above.
