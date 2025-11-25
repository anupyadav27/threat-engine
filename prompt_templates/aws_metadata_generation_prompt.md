# AWS CSP Metadata Generation Prompt Template

## Context
You are a compliance engineer tasked with creating **Cloud Security Posture (CSP) metadata files** for AWS compliance checks. These metadata files provide rich context for CSPM (Cloud Security Posture Management) tool integration, enabling proper security categorization, compliance mapping, risk assessment, and remediation guidance.

## Purpose
Metadata files are **required** for each compliance check. They provide:
- **CSP categorization** for dashboard organization and filtering
- **Compliance framework mapping** (CIS, NIST, SOC2, HIPAA, PCI-DSS, GDPR)
- **Risk assessment** with numeric scores for prioritization
- **Remediation guidance** with step-by-step instructions
- **Detection capabilities** and evidence types

## Metadata Template Reference
For the complete metadata structure, refer to: **`aws_csp_metadata_template.yaml`**

## File Location
- **Metadata File**: `services/<service_name>/metadata/<rule_id>.yaml`
- **Corresponding Rule**: `services/<service_name>/rules/<service_name>.yaml`

---

## CSP Categorization

### Primary CSPM Categories (Choose ONE)

1. **`data_security`** - Data protection and encryption
   - Subcategories: `data_encryption_at_rest`, `data_encryption_in_transit`, `data_classification`, `data_backup`, `data_retention`, `data_loss_prevention`
   - Use when: Check validates encryption, backup, data classification, or data protection
   - Examples: S3 encryption, RDS encryption, EBS volume encryption, data backup

2. **`entitlement`** - Identity & Access Management (IAM)
   - Subcategories: `access_control`, `authentication`, `authorization`, `privilege_management`, `service_accounts`, `role_management`, `policy_management`, `mfa_enforcement`, `session_management`, `least_privilege`, `access_reviews`, `temporary_access`
   - Use when: Check validates IAM policies, permissions, roles, MFA, or access controls
   - Examples: IAM user MFA, role least privilege, access key rotation, permission boundaries

3. **`network_security`** - Network perimeter and segmentation
   - Subcategories: `firewall_rules`, `network_segmentation`, `vpc_configuration`, `network_monitoring`, `dns_security`, `load_balancer_security`, `vpn_security`, `network_access_control`, `subnet_segmentation`, `security_groups`, `nacl_rules`
   - Use when: Check validates security groups, VPC configs, firewall rules, or network access
   - Examples: Security group SSH restrictions, VPC flow logs, network ACLs, load balancer security

4. **`compute_security`** - Virtual machines, containers, serverless
   - Subcategories: `instance_security`, `container_security`, `serverless_security`, `image_security`, `runtime_protection`, `metadata_service`, `instance_monitoring`, `container_scanning`
   - Use when: Check validates EC2, Lambda, ECS, or container configurations
   - Examples: EC2 IMDSv2 enforcement, Lambda function security, ECS container security, AMI hardening

5. **`secrets_management`** - Cryptographic keys and secrets
   - Subcategories: `key_rotation`, `key_management`, `secret_storage`, `certificate_management`, `kms_configuration`, `secrets_encryption`, `key_access_control`
   - Use when: Check validates KMS, Secrets Manager, certificates, or key rotation
   - Examples: KMS key rotation, Secrets Manager encryption, certificate auto-renewal, key access policies

6. **`compliance_governance`** - Audit, compliance, policy enforcement
   - Subcategories: `audit_logging`, `compliance_monitoring`, `policy_enforcement`, `configuration_management`, `drift_detection`, `resource_tagging`, `compliance_reporting`
   - Use when: Check validates CloudTrail, Config, compliance monitoring, or policy enforcement
   - Examples: CloudTrail logging, AWS Config compliance, resource tagging policy, drift detection

7. **`monitoring_detection`** - Security monitoring and threat detection
   - Subcategories: `log_management`, `threat_detection`, `anomaly_detection`, `incident_response`, `security_monitoring`, `alerting`, `siem_integration`
   - Use when: Check validates GuardDuty, Security Hub, CloudWatch, or threat detection
   - Examples: GuardDuty enabled, Security Hub findings, CloudWatch logging, anomaly detection

8. **`infrastructure_security`** - Platform hardening and vulnerability management
   - Subcategories: `platform_hardening`, `patch_management`, `vulnerability_management`, `endpoint_protection`, `infrastructure_monitoring`, `security_updates`
   - Use when: Check validates patch management, vulnerability scanning, or infrastructure hardening
   - Examples: EC2 patch management, System Manager patching, vulnerability scanning, infrastructure hardening

### Security Domains
Map to the corresponding security domain:
- `data_security` → `data_security`
- `entitlement` → `identity_access`
- `network_security` → `network_security`
- `compute_security` → `compute_security`
- `secrets_management` → `secrets_management`
- `compliance_governance` → `compliance_governance`
- `monitoring_detection` → `monitoring_detection`
- `infrastructure_security` → `infrastructure_security`

---

## Prompt Template for Metadata Generation

```
Generate a CSP metadata file for the following AWS compliance check:

**Rule ID**: aws.<service>.<category>.<check_name>
**Title**: <Human Readable Title>
**Description**: <What the check validates and why it matters>

**Check Details**:
- **Service**: <service_name> (e.g., s3, iam, ec2, rds)
- **Resource Type**: <resource_type> (e.g., storage.bucket, identity.user, compute.vm)
- **Severity**: <low|medium|high|critical>
- **Scope**: <account|region|resource>

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

Please generate the complete CSP metadata file following the `aws_csp_metadata_template.yaml` structure.
```

---

## Required Metadata Fields

### Core Identification (Required)
- `rule_id`: aws.<service>.<category>.<check_name>
- `title`: Human-readable title
- `description`: Detailed description of what the check validates

### CSP Categorization (Required)
- `cspm_category`: One of the 8 primary categories
- `cspm_subcategory`: Specific subcategory from the category list
- `security_domain`: Corresponding security domain
- `cspm_tags`: Array of tags for filtering (e.g., ["encryption", "s3", "compliance"])

### Compliance Framework Mapping (Required)
- `assertion_id`: Framework domain.control identifier
- `compliance_frameworks`: Array of framework mappings
  - `framework`: Framework name (CIS, NIST, SOC2, etc.)
  - `control_id`: Framework-specific control ID
  - `control_title`: Control title from framework
  - `mapping_type`: direct|partial|related
  - `version`: Framework version

### Service & Resource (Required)
- `service`: AWS service name
- `resource_type`: Resource type (e.g., storage.bucket, identity.user)
- `resource_scope`: account|region|resource
- `adapter`: aws.<service>.<adapter>

### Risk Assessment (Required)
- `severity`: low|medium|high|critical
- `risk_score`: 0-100 (see scoring guidelines below)
- `impact`: low|medium|high|critical
- `likelihood`: low|medium|high

### Detection & Evidence (Required)
- `evidence_type`: config_read|api_call|log_analysis|scan_result
- `detection_method`: static|runtime|continuous
- `detection_capability`: automated|manual|semi-automated
- `recommended_frequency`: continuous|daily|weekly|monthly

### Remediation (Required)
- `remediation.description`: Step-by-step remediation guidance
- `remediation.automated`: true|false
- `remediation.remediation_type`: config_change|policy_update|permission_change|delete|isolate
- `remediation.remediation_steps`: Array of step-by-step actions
- `remediation.estimated_time`: minutes|hours|days
- `remediation.complexity`: low|medium|high

### Context & Rationale (Required)
- `rationale`: Why this control is important
- `business_justification`: Business reason for implementing
- `attack_scenario`: Example of exploitation if not implemented
- `not_applicable_when`: Conditions when check doesn't apply

### Additional Fields (Category-Specific)
- **For data_security**: `data_classification`, `pii_handling`, `data_residency`
- **For entitlement**: `access_type`, `privilege_level`, `network_scope`
- **For network_security**: `network_scope`, `traffic_direction`, `protocol`
- **For all**: `notes`, `reference_url`, `aws_well_architected_pillar`, `alert_priority`, `auto_remediation_enabled`, `suppression_allowed`

---

## Risk Scoring Guidelines

Calculate `risk_score` (0-100) based on:

### Critical (90-100)
- Data exposure or breach
- Authentication bypass vulnerabilities
- Public access to sensitive resources
- Privilege escalation paths

### High (70-89)
- Encryption disabled on sensitive data
- Missing MFA for privileged accounts
- Excessive IAM permissions
- Unrestricted network access rules
- Missing security logging

### Medium (50-69)
- Missing CloudTrail logging
- Outdated security policies
- Suboptimal configuration
- Missing monitoring or alerts
- Resource tagging violations

### Low (0-49)
- Resource tagging recommendations
- Cost optimization suggestions
- Best practice improvements
- Optimization recommendations
- Non-critical configuration issues

**Formula**: Base score on impact × likelihood, with adjustment for severity

---

## Compliance Framework Mapping

### Mapping Types
- **`direct`**: Check directly implements the framework control
- **`partial`**: Check partially covers the framework control
- **`related`**: Check is contextually related but not a direct implementation

### Common Framework Mappings

**CIS AWS Foundations**:
- Encryption checks → CIS-2.x (Storage Security)
- IAM checks → CIS-1.x (Identity and Access Management)
- Network checks → CIS-4.x (Networking)
- Logging checks → CIS-3.x (Logging)

**NIST 800-53**:
- Encryption → SC-13 (Cryptographic Protection)
- Access Control → AC-1 through AC-25
- Audit → AU-1 through AU-16

**SOC 2**:
- Security → CC6.x (Logical Access Controls)
- Availability → CC7.x (System Operations)
- Confidentiality → CC6.x (Encryption)

---

## Category-Specific Guidance

### Data Security Metadata
Include:
- `data_classification`: public|internal|confidential|restricted
- `pii_handling`: true|false
- `data_residency`: region_specific|global

Example tags: `["encryption", "data-protection", "s3", "compliance"]`

### Entitlement Metadata
Include:
- `access_type`: read|write|delete|admin|full_control
- `privilege_level`: readonly|standard|elevated|administrative
- `network_scope`: vpc|public|private|cross_account|internet

Example tags: `["iam", "entitlement", "access-control", "mfa"]`

### Network Security Metadata
Include:
- `network_scope`: vpc|public|private|cross_account|internet|peered
- `traffic_direction`: ingress|egress|both
- `protocol`: tcp|udp|icmp|all

Example tags: `["network", "firewall", "security-group", "vpc"]`

---

## Example Metadata Generation Prompt

```
Generate a CSP metadata file for the following AWS compliance check:

**Rule ID**: aws.s3.bucket_encryption.default_encryption_enabled
**Title**: S3 Bucket Default Encryption Enabled
**Description**: Ensure all S3 buckets have default encryption enabled to protect data at rest from unauthorized access

**Check Details**:
- **Service**: s3
- **Resource Type**: storage.bucket
- **Severity**: high
- **Scope**: account

**Compliance Standard**: CIS AWS Foundations 1.4 - 2.1.1
- Framework: CIS
- Control ID: CIS-2.1.1
- Control Title: Ensure S3 bucket encryption is enabled
- Version: CIS-1.4

**CSP Categorization**:
- **Primary Category**: data_security
- **Subcategory**: data_encryption_at_rest
- **Security Domain**: data_security

**Risk Assessment**:
- **Impact**: high - Unencrypted data exposes sensitive information
- **Likelihood**: high - Public buckets or misconfigured policies are common
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
  1. Enable default encryption on bucket using AWS CLI
  2. Choose KMS or S3-managed encryption key
  3. Verify encryption is applied

**Context**:
- **Business Justification**: Protects sensitive customer data and meets compliance requirements (HIPAA, PCI-DSS, GDPR)
- **Attack Scenario**: Attacker gains access to unencrypted S3 bucket through misconfigured bucket policy, exfiltrates sensitive customer data
- **Not Applicable When**: no_s3_buckets

**Additional Context**:
- Data classification: confidential
- PII handling: true
- AWS Well-Architected Pillar: security

Please generate the complete CSP metadata file.
```

---

## Expected Response Format

Your response should include:

1. **Complete Metadata YAML**: Full metadata file following `aws_csp_metadata_template.yaml` structure
2. **Categorization Rationale**: Explanation of why you chose the specific CSP category and subcategory
3. **Risk Score Calculation**: Breakdown of how the risk score was calculated (impact × likelihood + adjustments)
4. **Compliance Mapping Explanation**: Why the framework mappings are direct/partial/related
5. **Remediation Approach**: Justification for automated vs manual remediation

---

## Related Files
- **Rule Generation**: See `aws_check_generation_prompt.md` for generating the corresponding YAML rule
- **Metadata Template**: See `aws_csp_metadata_template.yaml` for complete structure reference

