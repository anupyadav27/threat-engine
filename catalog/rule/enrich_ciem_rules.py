#!/usr/bin/env python3
"""
enrich_ciem_rules.py

Adds rationale, remediation, references, and compliance_frameworks fields
to all CIEM rule YAML files in:
  - catalog/rule/azure_rule_ciem/
  - catalog/rule/aws_rule_ciem/

Lookup hierarchy (first match wins):
  1. rule_id exact override
  2. primary MITRE technique (mitre_techniques[0])
  3. parent technique (e.g. T1098 for T1098.003)
  4. threat_category fallback

Usage:
    python3 enrich_ciem_rules.py                    # both catalogs
    python3 enrich_ciem_rules.py --aws-only
    python3 enrich_ciem_rules.py --azure-only
    python3 enrich_ciem_rules.py --dry-run          # print, don't write
    python3 enrich_ciem_rules.py --force            # overwrite existing fields
"""

import argparse
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent.parent
AZURE_CIEM_DIR = ROOT / "catalog" / "rule" / "azure_rule_ciem"
AWS_CIEM_DIR   = ROOT / "catalog" / "rule" / "aws_rule_ciem"

# ─────────────────────────────────────────────────────────────────────────────
# MITRE technique enrichment data
# Keys: exact technique ID (e.g. "T1098.003") or parent (e.g. "T1098")
# ─────────────────────────────────────────────────────────────────────────────

TECHNIQUE: dict[str, dict[str, Any]] = {
    # ── Account Manipulation ──────────────────────────────────────────────────
    "T1098": {
        "rationale": (
            "Account manipulation events indicate an adversary modifying account settings, "
            "credentials, or permissions to maintain access or escalate privileges."
        ),
        "remediation": (
            "1. Immediately review the modified account and revert unauthorized changes.\n"
            "2. Audit recent actions by the actor principal.\n"
            "3. Enable alerts for all account modification operations.\n"
            "4. Enforce change-control processes for privileged account modifications."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1098/"],
    },
    "T1098.001": {
        "rationale": (
            "Adding credentials to accounts enables persistence and lateral movement using "
            "existing trusted identities, potentially bypassing MFA and conditional access policies."
        ),
        "remediation": (
            "1. Revoke the newly added credential immediately.\n"
            "2. Review all credentials associated with the account.\n"
            "3. Investigate the actor's session for additional malicious activity.\n"
            "4. Enforce MFA and conditional access policies for all credential operations.\n"
            "5. Use Privileged Identity Management (PIM) for just-in-time access."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1098/001/",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
        ],
    },
    "T1098.003": {
        "rationale": (
            "Granting additional cloud roles enables privilege escalation and persistence, "
            "especially when targeting high-privilege roles such as Owner or Global Administrator."
        ),
        "remediation": (
            "1. Remove the unauthorized role assignment immediately.\n"
            "2. Review all role assignments for the affected principal.\n"
            "3. Enable just-in-time privileged access using PIM / AWS IAM Identity Center.\n"
            "4. Require approval workflows for Owner/Contributor/privileged role assignments.\n"
            "5. Alert on all role assignments at subscription or tenant scope."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1098/003/",
            "https://learn.microsoft.com/en-us/azure/role-based-access-control/overview",
            "https://learn.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-configure",
        ],
    },
    "T1098.005": {
        "rationale": (
            "Registering or modifying device identities in cloud directories can enable attackers "
            "to bypass device-based Conditional Access policies and establish persistent access."
        ),
        "remediation": (
            "1. Review and remove unauthorized device registrations.\n"
            "2. Enable device registration restrictions in Entra ID.\n"
            "3. Require device compliance via Intune for resource access.\n"
            "4. Monitor device registration events in Entra audit logs."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1098/005/",
            "https://learn.microsoft.com/en-us/azure/active-directory/devices/manage-device-identities",
        ],
    },
    "T1098.006": {
        "rationale": (
            "Adding credentials to service principals or managed identities allows attackers to "
            "authenticate as the identity and access all resources within its permission scope."
        ),
        "remediation": (
            "1. Immediately delete the unauthorized credential from the service principal.\n"
            "2. Rotate all existing credentials for the affected identity.\n"
            "3. Review the service principal's permission scope and reduce if excessive.\n"
            "4. Require approved change management for credential operations.\n"
            "5. Use Managed Identities instead of explicit credentials where possible."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1098/006/",
            "https://learn.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal",
            "https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-overview",
        ],
    },
    # ── Valid Accounts ────────────────────────────────────────────────────────
    "T1078": {
        "rationale": (
            "Use of valid compromised accounts allows attackers to blend with normal operations, "
            "bypassing detection systems that rely on signature-based approaches."
        ),
        "remediation": (
            "1. Force password reset and revoke all active sessions.\n"
            "2. Enable MFA and Conditional Access policies for the account.\n"
            "3. Review and limit account permissions following least-privilege principles.\n"
            "4. Implement anomaly detection for unusual sign-in patterns."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1078/"],
    },
    "T1078.004": {
        "rationale": (
            "Cloud account compromise enables access to all resources within the account's "
            "permission scope. Attackers leverage valid credentials to avoid detection and pivot "
            "across cloud services."
        ),
        "remediation": (
            "1. Immediately suspend the compromised account and revoke active sessions.\n"
            "2. Reset credentials and enforce MFA enrollment.\n"
            "3. Review all API calls and resource accesses made by the account.\n"
            "4. Investigate sign-in logs for source IP and geolocation anomalies.\n"
            "5. Enable Microsoft Entra ID Protection / AWS GuardDuty credential anomaly alerts."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1078/004/",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
            "https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/overview-identity-protection",
        ],
    },
    # ── Create Account ────────────────────────────────────────────────────────
    "T1136": {
        "rationale": (
            "New account creation can establish persistence by creating backdoor accounts that "
            "survive credential rotation of existing accounts."
        ),
        "remediation": (
            "1. Disable and review the newly created account immediately.\n"
            "2. Verify business justification with the account requestor.\n"
            "3. Enforce account creation approval processes.\n"
            "4. Alert on all account creation events outside approved provisioning workflows."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1136/"],
    },
    "T1136.003": {
        "rationale": (
            "Creating cloud accounts enables adversaries to establish persistence that survives "
            "compromised-account remediation, as the new account may not be immediately visible "
            "or associated with a known identity."
        ),
        "remediation": (
            "1. Disable and investigate the new cloud account immediately.\n"
            "2. Require MFA and business justification for all cloud account creation.\n"
            "3. Integrate account provisioning with HR/ITSM systems for lifecycle control.\n"
            "4. Enable alerts for account creation across all cloud tenants and sub-accounts."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1136/003/",
            "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts.html",
            "https://learn.microsoft.com/en-us/azure/active-directory/fundamentals/add-users-azure-active-directory",
        ],
    },
    # ── Privilege Escalation ──────────────────────────────────────────────────
    "T1548": {
        "rationale": (
            "Abuse of elevation mechanisms allows attackers to gain higher privileges than "
            "initially granted, potentially achieving administrative control over cloud resources."
        ),
        "remediation": (
            "1. Revoke the elevated permissions immediately.\n"
            "2. Enable Privileged Identity Management with approval workflows.\n"
            "3. Audit all elevation events and correlate with other suspicious activity.\n"
            "4. Enforce time-limited privilege elevations with justification requirements."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1548/"],
    },
    "T1548.005": {
        "rationale": (
            "Temporary elevated credentials or role chaining in cloud environments can grant "
            "administrative access without leaving obvious audit trails in standard IAM logs."
        ),
        "remediation": (
            "1. Review and revoke temporary elevated credentials.\n"
            "2. Implement SCP / Azure Policy guardrails to prevent unauthorized role chaining.\n"
            "3. Enable session recording for all privileged access sessions.\n"
            "4. Alert on all AssumeRole / elevateAccess API calls."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1548/005/",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use.html",
        ],
    },
    # ── Defense Evasion ───────────────────────────────────────────────────────
    "T1562": {
        "rationale": (
            "Impairing defenses prevents detection and response to malicious activity, enabling "
            "attackers to operate undetected for extended periods."
        ),
        "remediation": (
            "1. Immediately re-enable all disabled security controls.\n"
            "2. Investigate the actor's recent activity for follow-on attacks.\n"
            "3. Apply RBAC restrictions to prevent unauthorized modification of security services.\n"
            "4. Set up alerting that does not depend on the targeted service."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1562/"],
    },
    "T1562.001": {
        "rationale": (
            "Disabling security tools such as GuardDuty, Security Hub, or Microsoft Defender "
            "allows attackers to proceed with subsequent attack phases without triggering alerts."
        ),
        "remediation": (
            "1. Re-enable the security tool immediately.\n"
            "2. Apply SCPs / Azure Policies to prevent disabling security services.\n"
            "3. Enable Config rules to detect and auto-remediate disabled security tools.\n"
            "4. Alert via secondary channel (CloudWatch Events, Azure Event Grid) independent of the disabled service."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1562/001/",
            "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_managing_access.html",
            "https://learn.microsoft.com/en-us/azure/defender-for-cloud/enable-enhanced-security",
        ],
    },
    "T1562.004": {
        "rationale": (
            "Disabling network-level security controls (NSG rules, firewall rules, WAF) removes "
            "barriers for lateral movement and exfiltration, exposing internal resources to attack."
        ),
        "remediation": (
            "1. Revert the network security rule changes immediately.\n"
            "2. Use Azure Policy / AWS Config to enforce baseline network security rules.\n"
            "3. Implement change management approval for all network security modifications.\n"
            "4. Enable VPC Flow Logs / NSG Flow Logs to audit network traffic."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1562/004/",
            "https://learn.microsoft.com/en-us/azure/network-watcher/nsg-flow-logs-overview",
            "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html",
        ],
    },
    "T1562.007": {
        "rationale": (
            "Weakening or disabling cloud security policies reduces the enforcement surface for "
            "compliance controls and may allow prohibited actions to succeed silently."
        ),
        "remediation": (
            "1. Restore disabled policy assignments and investigate the actor.\n"
            "2. Apply RBAC restrictions so only authorized principals can modify security policies.\n"
            "3. Enable activity log alerts for all policy assignment changes.\n"
            "4. Use Azure Policy / AWS Config mandatory enforcement modes."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1562/007/",
            "https://learn.microsoft.com/en-us/azure/governance/policy/overview",
        ],
    },
    "T1562.008": {
        "rationale": (
            "Disabling or modifying cloud audit logs (CloudTrail, Azure Diagnostic Settings) "
            "removes the forensic record needed for incident investigation and may mask subsequent attacks."
        ),
        "remediation": (
            "1. Immediately restore the logging configuration.\n"
            "2. Lock CloudTrail S3 buckets with Object Lock; use immutable Azure Monitor storage.\n"
            "3. Apply SCPs / Azure Policy to prevent logging disruption.\n"
            "4. Configure out-of-band alerting (AWS EventBridge → SNS / Azure Event Grid) for logging changes."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1562/008/",
            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html",
            "https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings",
        ],
    },
    # ── Credential Access ─────────────────────────────────────────────────────
    "T1552": {
        "rationale": (
            "Obtaining stored credentials enables attackers to access additional systems and "
            "services without triggering authentication anomaly detectors."
        ),
        "remediation": (
            "1. Rotate all potentially compromised credentials immediately.\n"
            "2. Audit access to credential stores and secrets vaults.\n"
            "3. Use managed identities and secrets managers instead of static credentials.\n"
            "4. Enable alerts on all credential access operations."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1552/"],
    },
    "T1552.001": {
        "rationale": (
            "Credentials stored in files, environment variables, or cloud storage are frequent "
            "targets; exfiltration enables persistent access to downstream systems."
        ),
        "remediation": (
            "1. Rotate all credentials that may have been exposed.\n"
            "2. Use AWS Secrets Manager / Azure Key Vault for all credential storage.\n"
            "3. Scan repositories and container images for embedded credentials.\n"
            "4. Implement DLP policies to prevent credential file exfiltration."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1552/001/",
            "https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html",
            "https://learn.microsoft.com/en-us/azure/key-vault/general/best-practices",
        ],
    },
    "T1552.004": {
        "rationale": (
            "Private keys embedded in code repositories, CI/CD pipelines, or cloud storage "
            "can be harvested to authenticate as services or users."
        ),
        "remediation": (
            "1. Rotate all affected private keys immediately.\n"
            "2. Scan source code and build artifacts for private key patterns.\n"
            "3. Use HSM-backed key storage (AWS KMS / Azure Key Vault HSM).\n"
            "4. Enforce automated secret scanning in all CI/CD pipelines."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1552/004/",
            "https://docs.aws.amazon.com/kms/latest/developerguide/overview.html",
        ],
    },
    "T1552.005": {
        "rationale": (
            "Cloud instance metadata endpoints provide temporary credentials; accessing them "
            "from an SSRF vulnerability or compromised workload yields credentials to the cloud account."
        ),
        "remediation": (
            "1. Enforce IMDSv2 (AWS) / restrict IMDS access (Azure) to prevent credential theft.\n"
            "2. Alert on metadata service calls from unexpected sources.\n"
            "3. Apply network-level restrictions to limit IMDS reachability.\n"
            "4. Investigate the source of any metadata endpoint request."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1552/005/",
            "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
        ],
    },
    "T1552.007": {
        "rationale": (
            "Container secrets, Kubernetes secrets, and environment variables can expose "
            "sensitive credentials to any process with read access to the container environment."
        ),
        "remediation": (
            "1. Remove sensitive data from container environment variables.\n"
            "2. Use Kubernetes Secrets Store CSI Driver or Vault Agent for secrets injection.\n"
            "3. Enable encryption for Kubernetes Secrets at rest.\n"
            "4. Restrict access to secrets using Kubernetes RBAC least-privilege policies."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1552/007/",
            "https://kubernetes.io/docs/concepts/configuration/secret/",
        ],
    },
    # ── Modify Authentication Process ─────────────────────────────────────────
    "T1556": {
        "rationale": (
            "Modifying authentication processes enables attackers to bypass MFA, establish "
            "rogue identity providers, or create persistent authentication backdoors."
        ),
        "remediation": (
            "1. Revert authentication configuration changes immediately.\n"
            "2. Audit all changes to authentication methods and providers.\n"
            "3. Require change management approval for authentication configuration changes.\n"
            "4. Monitor identity provider federation settings continuously."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1556/"],
    },
    "T1556.006": {
        "rationale": (
            "MFA bypass or manipulation allows attackers to authenticate without the second "
            "factor, significantly reducing authentication security for targeted accounts."
        ),
        "remediation": (
            "1. Investigate and revert MFA method changes for all affected accounts.\n"
            "2. Force re-enrollment of MFA for affected accounts.\n"
            "3. Enable Conditional Access policies requiring phishing-resistant MFA (FIDO2).\n"
            "4. Alert on all MFA method changes, especially for privileged accounts."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1556/006/",
            "https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-mfa-howitworks",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html",
        ],
    },
    "T1556.007": {
        "rationale": (
            "Updating domain federation settings to a rogue identity provider (Golden SAML) "
            "enables persistent tenant-wide authentication bypass without requiring valid credentials."
        ),
        "remediation": (
            "1. Immediately revert the federation change and remove the rogue IdP.\n"
            "2. Revoke all SAML tokens issued via the rogue IdP.\n"
            "3. Restrict domain federation changes to break-glass accounts with approval workflows.\n"
            "4. Enable Microsoft Sentinel detection rules for federation changes.\n"
            "5. Implement PIM with approval for all federation management operations."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1556/007/",
            "https://learn.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-introduction",
            "https://www.microsoft.com/en-us/security/blog/2020/12/21/advice-for-incident-responders-on-recovery-from-systemic-identity-compromises/",
        ],
    },
    # ── Event-Triggered Persistence ───────────────────────────────────────────
    "T1546": {
        "rationale": (
            "Event-triggered execution via cloud automation rules can establish persistent "
            "code execution that activates on specific events, surviving credential rotation."
        ),
        "remediation": (
            "1. Review and remove unauthorized automation rules or event subscriptions.\n"
            "2. Restrict creation of automation rules to authorized principals.\n"
            "3. Audit all event-triggered execution configurations regularly.\n"
            "4. Enable alerts on automation rule creation and modification."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1546/"],
    },
    "T1546.004": {
        "rationale": (
            "Bash/shell profile modifications on cloud instances persist across reboots and "
            "user logins, executing attacker code automatically on each login."
        ),
        "remediation": (
            "1. Inspect and restore shell profile files to a known-good state.\n"
            "2. Use immutable infrastructure patterns to prevent runtime file modifications.\n"
            "3. Enable file integrity monitoring on critical system files.\n"
            "4. Restrict SSH access and use cloud session managers for instance access."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1546/004/"],
    },
    # ── Domain Policy Modification ────────────────────────────────────────────
    "T1484": {
        "rationale": (
            "Domain policy modifications can weaken security boundaries, disable MFA "
            "enforcement, or broaden access permissions at scale across the entire tenant."
        ),
        "remediation": (
            "1. Revert unauthorized policy changes immediately.\n"
            "2. Apply RBAC restrictions to limit who can modify domain or tenant policies.\n"
            "3. Require approval workflows for all global security policy changes.\n"
            "4. Monitor policy change events in audit logs with high-priority alerting."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1484/"],
    },
    "T1484.001": {
        "rationale": (
            "Group Policy modifications can disable security controls, deploy malware, or "
            "modify access rights across all systems in an organizational unit simultaneously."
        ),
        "remediation": (
            "1. Identify and revert unauthorized GPO changes.\n"
            "2. Restrict GPO modification rights to domain admin accounts with approval workflows.\n"
            "3. Enable audit logging for all Group Policy changes.\n"
            "4. Use Microsoft Defender for Identity to detect GPO tampering."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1484/001/",
            "https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-group-policy",
        ],
    },
    "T1484.002": {
        "rationale": (
            "Modifying cloud trust relationships (AWS Organizations trust policies, Azure AD "
            "B2B settings) can expand the attack surface by allowing external identity providers "
            "to authenticate to tenant resources."
        ),
        "remediation": (
            "1. Review and revert unauthorized trust relationship changes.\n"
            "2. Require multi-party approval for cross-tenant trust modifications.\n"
            "3. Audit external collaboration settings in Azure AD / AWS Organizations regularly.\n"
            "4. Alert on all federation or cross-account trust policy changes."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1484/002/",
            "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html",
        ],
    },
    # ── Impact ────────────────────────────────────────────────────────────────
    "T1485": {
        "rationale": (
            "Data destruction attacks cause irreversible data loss and service disruption; "
            "early detection and response is critical to minimizing recovery scope."
        ),
        "remediation": (
            "1. Immediately quarantine the actor's credentials and halt further destructive operations.\n"
            "2. Initiate incident response and activate backup/recovery procedures.\n"
            "3. Enable S3 Object Lock / Azure Blob immutable storage to protect backups.\n"
            "4. Require MFA for bucket/storage account deletion operations."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1485/",
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html",
            "https://learn.microsoft.com/en-us/azure/storage/blobs/immutable-storage-overview",
        ],
    },
    "T1486": {
        "rationale": (
            "Ransomware attacks encrypt cloud storage or databases for extortion; early "
            "detection limits the scope of encryption before a ransom demand is issued."
        ),
        "remediation": (
            "1. Isolate the affected resources and revoke attacker credentials immediately.\n"
            "2. Activate backup recovery procedures from clean snapshots.\n"
            "3. Enable versioning and soft-delete for all storage resources.\n"
            "4. Use Defender for Cloud / AWS Macie to detect mass encryption events."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1486/",
            "https://learn.microsoft.com/en-us/azure/storage/blobs/versioning-overview",
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html",
        ],
    },
    "T1489": {
        "rationale": (
            "Service disruption attacks stop critical cloud services, causing availability "
            "incidents; attackers may use this to create leverage or cover their tracks."
        ),
        "remediation": (
            "1. Restart affected services and investigate the root cause.\n"
            "2. Restrict service modification/deletion permissions via RBAC.\n"
            "3. Use resource locks on critical services to prevent accidental or malicious deletion.\n"
            "4. Enable auto-remediation via AWS Config / Azure Policy for critical service states."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1489/"],
    },
    "T1496": {
        "rationale": (
            "Resource hijacking (cryptomining, botnet hosting) causes unexpected cloud costs "
            "and may indicate a broader compromise of cloud credentials or workloads."
        ),
        "remediation": (
            "1. Terminate the unauthorized workloads immediately.\n"
            "2. Revoke compromised credentials used to launch the resources.\n"
            "3. Enable budget alerts and anomaly detection for unexpected spend spikes.\n"
            "4. Use AWS Cost Anomaly Detection / Azure Cost Management alerts."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1496/",
            "https://docs.aws.amazon.com/cost-management/latest/userguide/getting-started-ad.html",
        ],
    },
    "T1498": {
        "rationale": (
            "Network denial-of-service from or via cloud resources can indicate compromise "
            "of cloud assets being weaponized for DDoS campaigns against external targets."
        ),
        "remediation": (
            "1. Revoke credentials used to create DDoS-capable resources.\n"
            "2. Enable AWS Shield Advanced / Azure DDoS Protection with alerting.\n"
            "3. Alert on creation of high-bandwidth resources by non-standard principals."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1498/",
            "https://learn.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview",
        ],
    },
    "T1529": {
        "rationale": (
            "System shutdown/reboot attacks cause availability loss and may be used to delete "
            "evidence, force service restarts, or trigger incident response procedures."
        ),
        "remediation": (
            "1. Revoke credentials of the actor and restore affected systems.\n"
            "2. Apply RBAC restrictions on instance stop/terminate/reboot operations.\n"
            "3. Use resource locks where appropriate to prevent unauthorized termination."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1529/"],
    },
    "T1531": {
        "rationale": (
            "Account access removal (deleting users, removing MFA) blocks legitimate users "
            "from accessing resources and can be used to seize control of cloud accounts."
        ),
        "remediation": (
            "1. Restore removed accounts or access immediately from a break-glass account.\n"
            "2. Review and audit all actions taken by the responsible actor.\n"
            "3. Implement role-based approvals for account deletion and access revocation.\n"
            "4. Maintain break-glass emergency access accounts with separate credential paths."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1531/",
            "https://learn.microsoft.com/en-us/azure/active-directory/roles/security-emergency-access",
        ],
    },
    # ── Discovery ─────────────────────────────────────────────────────────────
    "T1046": {
        "rationale": (
            "Network service scanning maps the cloud environment's attack surface; early "
            "detection of reconnaissance activity can preempt follow-on attacks."
        ),
        "remediation": (
            "1. Investigate the source IP and principal performing the scan.\n"
            "2. Apply NSG/security group rules to limit service scan visibility.\n"
            "3. Enable VPC Flow Logs / NSG Flow Logs to detect scanning patterns.\n"
            "4. Block or throttle API calls from suspicious scan sources."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1046/"],
    },
    "T1070": {
        "rationale": (
            "Indicator removal techniques (log deletion, history clearing) obstruct forensic "
            "investigation by destroying evidence of attacker activity."
        ),
        "remediation": (
            "1. Enable log immutability (S3 Object Lock, Azure Immutable Blob Storage).\n"
            "2. Ship logs to a separate, write-protected security account in real time.\n"
            "3. Alert on log deletion or purge operations immediately.\n"
            "4. Investigate all log deletion events as potential incident indicators."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1070/",
            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html",
        ],
    },
    "T1082": {
        "rationale": (
            "System information discovery collects environment details (OS, software, "
            "configurations) used to identify vulnerabilities and plan further attack steps."
        ),
        "remediation": (
            "1. Restrict instance metadata access to only necessary services.\n"
            "2. Monitor for unusual volumes of DescribeInstances / VM metadata API calls.\n"
            "3. Enable IMDSv2 (AWS) to prevent SSRF-based metadata access."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1082/"],
    },
    "T1083": {
        "rationale": (
            "File and directory discovery operations map available data stores, identifying "
            "high-value targets for subsequent collection and exfiltration."
        ),
        "remediation": (
            "1. Apply least-privilege RBAC on all storage access.\n"
            "2. Enable storage access logging and alert on unusual enumeration patterns.\n"
            "3. Use bucket/container policies to restrict list operations to authorized roles."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1083/"],
    },
    "T1087": {
        "rationale": (
            "Account discovery enumerates cloud identities to identify targets for credential "
            "attacks, privilege escalation, or social engineering."
        ),
        "remediation": (
            "1. Restrict IAM/directory listing permissions to least-privilege roles.\n"
            "2. Enable alerts on bulk directory enumeration API calls.\n"
            "3. Use Conditional Access to limit enumeration from suspicious locations."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1087/"],
    },
    "T1087.004": {
        "rationale": (
            "Cloud account enumeration identifies IAM users, service principals, and roles "
            "that can be targeted for credential attacks or privilege escalation."
        ),
        "remediation": (
            "1. Apply IAM permission restrictions on ListUsers/ListRoles/ListServicePrincipals.\n"
            "2. Alert on unexpected enumeration API call patterns.\n"
            "3. Use AWS Organizations SCPs / Azure Policy to limit who can enumerate identities."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1087/004/",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples_iam_limited-identities.html",
        ],
    },
    "T1580": {
        "rationale": (
            "Cloud infrastructure discovery enumerates running resources, network configurations, "
            "and security controls to plan further attacks within the cloud environment."
        ),
        "remediation": (
            "1. Restrict describe/list API permissions to only authorized roles.\n"
            "2. Monitor for unusual enumeration activity in CloudTrail / Activity Log.\n"
            "3. Apply resource-level permissions to prevent unauthorized resource discovery."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1580/",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_actions-resources-contextkeys.html",
        ],
    },
    "T1590": {
        "rationale": (
            "Gathering cloud target information (account IDs, domain names, IP ranges) "
            "enables more targeted and stealthy follow-on attacks."
        ),
        "remediation": (
            "1. Minimize public exposure of cloud account IDs and infrastructure details.\n"
            "2. Monitor for reconnaissance patterns in public-facing API endpoints.\n"
            "3. Use AWS Shield Advanced / Azure DDoS Protection for reconnaissance detection."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1590/"],
    },
    "T1590.002": {
        "rationale": (
            "DNS enumeration reveals cloud service hostnames and IP addresses, enabling "
            "targeted attack infrastructure mapping and phishing campaign preparation."
        ),
        "remediation": (
            "1. Review DNS zone transfer settings and restrict access.\n"
            "2. Enable DNS query logging and alert on enumeration patterns.\n"
            "3. Apply DNSSEC on all externally resolvable domains."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1590/002/"],
    },
    "T1595": {
        "rationale": (
            "Active scanning of cloud endpoints reveals open ports, services, and API "
            "endpoints that can be exploited for initial access or lateral movement."
        ),
        "remediation": (
            "1. Apply WAF rules and security groups to minimize service exposure.\n"
            "2. Enable AWS Shield / Azure DDoS Protection.\n"
            "3. Alert on network scanning patterns in VPC / NSG flow logs."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1595/"],
    },
    "T1595.001": {
        "rationale": (
            "Scanning for exposed IP ranges and hostnames enables attackers to map the cloud "
            "attack surface for vulnerability research and targeted exploitation."
        ),
        "remediation": (
            "1. Minimize the number of publicly routable cloud resources.\n"
            "2. Use private endpoints for cloud services where possible.\n"
            "3. Enable network flow logging and alert on scanning activity."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1595/001/"],
    },
    "T1595.002": {
        "rationale": (
            "Vulnerability scanning of cloud endpoints identifies exploitable weaknesses "
            "that can be used for initial access or follow-on exploitation."
        ),
        "remediation": (
            "1. Apply security patches promptly for all cloud-exposed services.\n"
            "2. Enable Defender for Cloud / Amazon Inspector for vulnerability detection.\n"
            "3. Alert on unusual port scanning activity in network flow logs."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1595/002/"],
    },
    # ── Lateral Movement ──────────────────────────────────────────────────────
    "T1021": {
        "rationale": (
            "Lateral movement via remote services enables attackers to spread within the "
            "cloud environment, accessing additional resources and escalating attack impact."
        ),
        "remediation": (
            "1. Restrict remote service access using network security groups.\n"
            "2. Require MFA for all remote access sessions.\n"
            "3. Enable session monitoring and recording for all privileged access."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1021/"],
    },
    "T1021.001": {
        "rationale": (
            "RDP access to cloud VMs enables interactive lateral movement; unauthorized "
            "RDP sessions may indicate credential theft or instance compromise."
        ),
        "remediation": (
            "1. Disable public RDP access; use Azure Bastion / AWS Systems Manager Session Manager.\n"
            "2. Apply NSG rules to restrict RDP to authorized management IPs only.\n"
            "3. Enable JIT VM access in Defender for Cloud."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1021/001/",
            "https://learn.microsoft.com/en-us/azure/bastion/bastion-overview",
        ],
    },
    "T1021.004": {
        "rationale": (
            "SSH access to cloud instances enables lateral movement and interactive control; "
            "compromise may spread via SSH key reuse across multiple instances."
        ),
        "remediation": (
            "1. Use EC2 Instance Connect / Azure Bastion instead of static SSH keys.\n"
            "2. Restrict SSH access via security groups to known management IPs only.\n"
            "3. Use AWS Systems Manager / Azure Bastion to eliminate direct SSH exposure."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1021/004/",
            "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-connect-methods.html",
        ],
    },
    "T1021.007": {
        "rationale": (
            "Cloud service lateral movement via VPC peering, service-to-service calls, or "
            "shared credentials enables attackers to pivot between cloud accounts and regions."
        ),
        "remediation": (
            "1. Review all VPC/VNet peering connections and remove unauthorized peerings.\n"
            "2. Apply network ACLs to restrict cross-VPC traffic to required flows only.\n"
            "3. Use AWS Transit Gateway / Azure Virtual WAN with strict routing policies.\n"
            "4. Enable VPC Flow Logs / NSG Flow Logs to detect lateral movement patterns."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1021/007/",
            "https://docs.aws.amazon.com/vpc/latest/peering/what-is-vpc-peering.html",
        ],
    },
    # ── Collection ────────────────────────────────────────────────────────────
    "T1005": {
        "rationale": (
            "Collecting data from cloud resources before exfiltration indicates active data "
            "theft; early detection limits data loss volume."
        ),
        "remediation": (
            "1. Restrict data access permissions to least-privilege roles.\n"
            "2. Enable CloudTrail data events / Storage analytics logging.\n"
            "3. Apply DLP policies to detect bulk data access patterns."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1005/"],
    },
    "T1530": {
        "rationale": (
            "Data from cloud storage (S3, Azure Blob) is a primary exfiltration target; "
            "bulk download or cross-account access indicates potential data theft."
        ),
        "remediation": (
            "1. Enable server-side access logging for all storage buckets and containers.\n"
            "2. Alert on high-volume GetObject/BlobRead operations by single principals.\n"
            "3. Apply bucket policies to restrict GetObject to authorized principals only.\n"
            "4. Enable Macie / Defender for Storage for sensitive data detection and alerting."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1530/",
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/logging-with-S3.html",
            "https://learn.microsoft.com/en-us/azure/storage/common/storage-analytics-logging",
        ],
    },
    "T1537": {
        "rationale": (
            "Transferring data to an attacker-controlled cloud account bypasses traditional "
            "egress monitoring by using trusted cloud provider channels that appear legitimate."
        ),
        "remediation": (
            "1. Block cross-account data replication/copy operations via SCPs / Azure Policy.\n"
            "2. Monitor for S3 replication rule changes or storage account copy operations.\n"
            "3. Alert on cross-tenant storage access and replication events.\n"
            "4. Apply data residency policies via Azure Policy / AWS Config."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1537/",
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication.html",
        ],
    },
    # ── Exfiltration ──────────────────────────────────────────────────────────
    "T1041": {
        "rationale": (
            "Exfiltration over C2 channel conceals data theft within existing command-and-control "
            "communication, making it harder to detect via standard DLP tools."
        ),
        "remediation": (
            "1. Apply egress filtering and network flow monitoring.\n"
            "2. Enable DLP policies to inspect outbound traffic.\n"
            "3. Alert on unusual outbound data volumes from cloud resources."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1041/"],
    },
    "T1048": {
        "rationale": (
            "Exfiltration over alternative protocols bypasses DLP solutions that only inspect "
            "standard channels, enabling data theft via DNS, HTTPS, or custom protocols."
        ),
        "remediation": (
            "1. Apply protocol-level egress filtering (default-deny).\n"
            "2. Enable DNS query logging and alert on DNS tunneling patterns.\n"
            "3. Use a cloud-native CASB solution to inspect all outbound traffic."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1048/"],
    },
    "T1048.003": {
        "rationale": (
            "Exfiltration via unencrypted protocols is detectable via network inspection; "
            "early detection enables intervention before data is fully exfiltrated."
        ),
        "remediation": (
            "1. Apply protocol-level egress restrictions (block outbound non-HTTPS traffic).\n"
            "2. Enable network flow analysis to detect unencrypted data transfers.\n"
            "3. Apply DLP policies on all outbound traffic."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1048/003/"],
    },
    "T1567": {
        "rationale": (
            "Exfiltration to cloud storage services (OneDrive, S3 buckets in attacker accounts) "
            "uses trusted channels that bypass traditional DLP controls."
        ),
        "remediation": (
            "1. Apply CASB policies to restrict file uploads to unauthorized cloud storage.\n"
            "2. Block access to non-corporate cloud storage domains at the network perimeter.\n"
            "3. Enable Cloud App Security / Defender for Cloud Apps policies."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1567/"],
    },
    # ── Command and Control ───────────────────────────────────────────────────
    "T1071.004": {
        "rationale": (
            "DNS-based C2 uses a protocol commonly allowed through firewalls; early detection "
            "prevents ongoing command-and-control communication from persisting."
        ),
        "remediation": (
            "1. Enable DNS query logging and anomaly detection on all resolvers.\n"
            "2. Block known malicious DNS servers via cloud DNS firewall policies.\n"
            "3. Apply recursive DNS restrictions for cloud instances."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1071/004/"],
    },
    "T1090": {
        "rationale": (
            "Proxied connections through cloud infrastructure conceal the true origin of attacks "
            "and bypass IP-based blocking measures."
        ),
        "remediation": (
            "1. Monitor for unusual outbound connection patterns from cloud resources.\n"
            "2. Restrict outbound internet access via security groups (default-deny egress).\n"
            "3. Apply CASB policies to detect and block proxy usage."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1090/"],
    },
    "T1090.003": {
        "rationale": (
            "Multi-hop proxies (Tor, cloud relays) make it difficult to trace the origin "
            "of attacks while maintaining C2 communications to compromised cloud workloads."
        ),
        "remediation": (
            "1. Block Tor exit node IPs via security group deny rules.\n"
            "2. Enable VPC endpoint policies to restrict outbound traffic destinations.\n"
            "3. Use cloud-native threat intelligence feeds to block known proxy infrastructure."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1090/003/"],
    },
    "T1572": {
        "rationale": (
            "Protocol tunneling encapsulates C2 traffic within legitimate protocols, bypassing "
            "firewall rules that allow standard protocols (HTTP, DNS, HTTPS)."
        ),
        "remediation": (
            "1. Apply deep packet inspection at all network egress points.\n"
            "2. Monitor for unusual traffic patterns in VPC Flow Logs / NSG Flow Logs.\n"
            "3. Restrict outbound traffic to required protocols and destinations only."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1572/"],
    },
    "T1573": {
        "rationale": (
            "Encrypted C2 channels prevent traffic inspection; detection relies on behavioral "
            "analysis of connection patterns and destination reputation."
        ),
        "remediation": (
            "1. Enable TLS inspection at network egress using cloud-native inspection.\n"
            "2. Alert on connections to domains with poor reputation or unknown certificates.\n"
            "3. Apply CASB solutions for cloud egress inspection and control."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1573/"],
    },
    # ── Execution ─────────────────────────────────────────────────────────────
    "T1059.007": {
        "rationale": (
            "JavaScript-based execution via cloud functions or Lambda can run malicious code "
            "without requiring server-level access or traditional deploy pipelines."
        ),
        "remediation": (
            "1. Restrict Lambda/Function App deployment permissions to authorized principals.\n"
            "2. Enable static analysis and code signing for function deployments.\n"
            "3. Monitor function invocation patterns for behavioral anomalies."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1059/007/"],
    },
    "T1059.013": {
        "rationale": (
            "Cloud API execution via CLIs (AWS CLI, Azure CLI, kubectl) can automate malicious "
            "operations at scale within cloud environments without requiring UI access."
        ),
        "remediation": (
            "1. Enable CloudTrail / Activity Log monitoring for all API calls.\n"
            "2. Apply RBAC restrictions to limit the scope of all API call permissions.\n"
            "3. Alert on anomalous API usage patterns (unusual regions, APIs, or timing)."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1059/013/",
            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html",
        ],
    },
    "T1651": {
        "rationale": (
            "Cloud administration commands (Run Command, VM extensions, Lambda invocations) "
            "allow remote code execution within cloud environments without traditional exploit techniques."
        ),
        "remediation": (
            "1. Restrict Systems Manager Run Command / VM extension write permissions via RBAC.\n"
            "2. Enable logging for all Run Command executions and VM extension deployments.\n"
            "3. Use approved patch management instead of ad-hoc run commands.\n"
            "4. Alert on Run Command / RunShellScript executions by non-standard principals."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1651/",
            "https://docs.aws.amazon.com/systems-manager/latest/userguide/run-command.html",
            "https://learn.microsoft.com/en-us/azure/virtual-machines/extensions/overview",
        ],
    },
    "T1072": {
        "rationale": (
            "Software deployment tool abuse enables attackers to deploy malicious software "
            "across multiple systems via CI/CD pipelines or deployment platforms."
        ),
        "remediation": (
            "1. Restrict deployment tool access to authorized principals with MFA enforcement.\n"
            "2. Require code signing and approval workflows for all deployments.\n"
            "3. Enable audit logging for all software deployment operations."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1072/"],
    },
    "T1648": {
        "rationale": (
            "Serverless execution abuse leverages cloud-native compute functions to run malicious "
            "workloads without infrastructure management overhead, making attribution difficult."
        ),
        "remediation": (
            "1. Apply least-privilege IAM roles to all Lambda / Azure Functions.\n"
            "2. Enable function-level access logging and behavioral monitoring.\n"
            "3. Use VPC endpoint policies to restrict function outbound network access."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1648/"],
    },
    # ── Cloud Infrastructure Modification ─────────────────────────────────────
    "T1578": {
        "rationale": (
            "Modifying cloud compute infrastructure enables attackers to implant backdoors, "
            "create snapshots for data theft, or revert security hardening on workloads."
        ),
        "remediation": (
            "1. Restrict compute resource modification permissions to authorized change management roles.\n"
            "2. Alert on compute resource modifications by non-standard principals.\n"
            "3. Enable encryption and access controls for all snapshots and images."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1578/"],
    },
    "T1578.001": {
        "rationale": (
            "Creating new cloud instances in a backdoored image allows persistent access via "
            "VM images that survive standard reimaging procedures."
        ),
        "remediation": (
            "1. Enforce golden image policies requiring only approved base images.\n"
            "2. Restrict CreateImage / image write permissions to CI/CD pipeline roles.\n"
            "3. Enable CSPM image scanning via Defender for Servers / Amazon Inspector."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1578/001/"],
    },
    "T1578.002": {
        "rationale": (
            "Creating VM/container snapshots can be used to exfiltrate data or establish "
            "persistent access to a copy of the original workload outside security boundaries."
        ),
        "remediation": (
            "1. Restrict snapshot creation permissions to authorized backup roles.\n"
            "2. Alert on snapshot exports or cross-account snapshot copy operations.\n"
            "3. Enable encryption for all EBS / managed disk snapshots."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1578/002/"],
    },
    "T1578.003": {
        "rationale": (
            "Reverting instances to older snapshots can undo security patches or configuration "
            "hardening, re-introducing known vulnerabilities into production workloads."
        ),
        "remediation": (
            "1. Restrict revert/restore operations to formal change management workflows.\n"
            "2. Alert on unauthorized instance restoration events.\n"
            "3. Require MFA and approval for snapshot restoration to production."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1578/003/"],
    },
    "T1578.004": {
        "rationale": (
            "Moving cloud resources between accounts can transfer sensitive data to "
            "attacker-controlled accounts while appearing as a legitimate cloud operation."
        ),
        "remediation": (
            "1. Apply SCPs / Azure Policy to prevent cross-account resource moves.\n"
            "2. Alert on resource moves to non-standard or external accounts.\n"
            "3. Require explicit management approval for cross-account resource transfers."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1578/004/"],
    },
    "T1525": {
        "rationale": (
            "Implanting malicious code in cloud images or container registries establishes "
            "persistent backdoors in every instance launched from the tampered image."
        ),
        "remediation": (
            "1. Enforce image signing and provenance verification (AWS Signer / ACR content trust).\n"
            "2. Scan all images with vulnerability and malware scanners before production use.\n"
            "3. Restrict push permissions to container registries to authorized CI/CD pipelines only."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1525/",
            "https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html",
            "https://learn.microsoft.com/en-us/azure/container-registry/container-registry-intro",
        ],
    },
    "T1610": {
        "rationale": (
            "Deploying unauthorized containers enables execution of arbitrary workloads within "
            "the cloud environment, potentially accessing internal network resources or data stores."
        ),
        "remediation": (
            "1. Restrict container deployment permissions via Kubernetes RBAC / Azure Policy.\n"
            "2. Enable admission controllers (OPA Gatekeeper / Azure Policy for AKS).\n"
            "3. Alert on privileged container deployments.\n"
            "4. Enforce container image signing and verification policies."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1610/",
            "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
        ],
    },
    "T1611": {
        "rationale": (
            "Container escape to host enables attackers to break out of container isolation "
            "and compromise the underlying node, affecting all co-located workloads."
        ),
        "remediation": (
            "1. Prevent privileged container execution via admission controllers.\n"
            "2. Enable read-only root filesystems for all container workloads.\n"
            "3. Apply Pod Security Standards (restricted profile) cluster-wide.\n"
            "4. Use gVisor or Kata Containers for additional hardware-level isolation."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1611/",
            "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
        ],
    },
    # ── Token / Auth Material ─────────────────────────────────────────────────
    "T1528": {
        "rationale": (
            "Stealing OAuth access tokens enables impersonation of users or services without "
            "requiring their passwords, bypassing MFA in many configurations."
        ),
        "remediation": (
            "1. Revoke stolen tokens immediately via token revocation endpoints.\n"
            "2. Enable Conditional Access policies with token binding.\n"
            "3. Use FIDO2/Passwordless authentication to prevent token theft.\n"
            "4. Enable Continuous Access Evaluation for all critical resources."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1528/",
            "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/overview",
        ],
    },
    "T1550.001": {
        "rationale": (
            "OAuth token abuse allows attackers to access cloud resources as the token owner "
            "for extended periods without needing credentials, until token expiry."
        ),
        "remediation": (
            "1. Revoke the compromised application token immediately.\n"
            "2. Audit all OAuth consent grants and remove unauthorized application registrations.\n"
            "3. Enable Microsoft Entra ID risky sign-in detection.\n"
            "4. Reduce token lifetimes for high-privilege applications."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1550/001/",
            "https://learn.microsoft.com/en-us/azure/active-directory/develop/access-tokens",
        ],
    },
    "T1606.002": {
        "rationale": (
            "Forging SAML tokens (Golden SAML attack) enables long-term, tenant-wide authentication "
            "as any user including administrators, without triggering MFA or password checks."
        ),
        "remediation": (
            "1. Rotate all SAML signing certificates immediately.\n"
            "2. Enable sign-in risk detection and Conditional Access for suspicious tokens.\n"
            "3. Monitor for unusual service usage patterns from federated accounts.\n"
            "4. Consider migrating to OIDC/OAuth2 from SAML where possible."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1606/002/",
            "https://www.microsoft.com/en-us/security/blog/2020/12/21/advice-for-incident-responders-on-recovery-from-systemic-identity-compromises/",
        ],
    },
    # ── Brute Force ───────────────────────────────────────────────────────────
    "T1110.001": {
        "rationale": (
            "Password guessing attacks can compromise accounts with weak passwords; detection "
            "enables account lockout before successful compromise occurs."
        ),
        "remediation": (
            "1. Enforce account lockout policies after consecutive failed attempts.\n"
            "2. Require strong password complexity and minimum length.\n"
            "3. Enable MFA to prevent successful login even if password is guessed.\n"
            "4. Block sign-ins from high-risk IP ranges using Conditional Access policies."
        ),
        "refs": [
            "https://attack.mitre.org/techniques/T1110/001/",
            "https://learn.microsoft.com/en-us/azure/active-directory/authentication/tutorial-enable-azure-mfa",
        ],
    },
    # ── MITM ──────────────────────────────────────────────────────────────────
    "T1557": {
        "rationale": (
            "MITM attacks on cloud communication channels can intercept credentials, session "
            "tokens, or sensitive data in transit between cloud services."
        ),
        "remediation": (
            "1. Enforce TLS/HTTPS for all cloud API communications.\n"
            "2. Enable HSTS and consider certificate pinning for critical services.\n"
            "3. Apply network-level controls to prevent ARP spoofing within VNets/VPCs."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1557/"],
    },
    # ── DNS / Network C2 ──────────────────────────────────────────────────────
    "T1568.001": {
        "rationale": (
            "Fast flux DNS techniques are used by botnets and C2 infrastructure to evade "
            "IP-based blocking by constantly rotating IP addresses for malicious domains."
        ),
        "remediation": (
            "1. Enable DNS threat intelligence feeds in your security tooling.\n"
            "2. Block connections to domains with abnormally short DNS TTLs.\n"
            "3. Use cloud DNS filtering services with threat intelligence integration."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1568/001/"],
    },
    "T1571": {
        "rationale": (
            "Non-standard port communications bypass firewall rules configured for standard "
            "ports, enabling C2 communication over unexpected and less-monitored channels."
        ),
        "remediation": (
            "1. Apply default-deny egress security groups (allow only required outbound ports).\n"
            "2. Enable network flow analysis to detect non-standard port usage.\n"
            "3. Restrict outbound traffic to approved destination ports only."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1571/"],
    },
    "T1600": {
        "rationale": (
            "Weakening encryption on cloud network communications enables interception of "
            "otherwise protected data in transit between services."
        ),
        "remediation": (
            "1. Enforce TLS 1.2+ for all connections; disable TLS 1.0 and 1.1.\n"
            "2. Apply Azure Policy / AWS Config rules to enforce minimum TLS settings.\n"
            "3. Use Certificate Manager / Key Vault for automated certificate lifecycle management."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1600/"],
    },
    # ── Resource Development ──────────────────────────────────────────────────
    "T1583.003": {
        "rationale": (
            "Attackers acquiring virtual private servers in cloud environments use them as "
            "attack infrastructure, C2 servers, or anonymizing proxies."
        ),
        "remediation": (
            "1. Monitor for unusual compute provisioning in all cloud accounts.\n"
            "2. Alert on EC2/VM launches in unexpected regions or with non-standard configurations.\n"
            "3. Apply budget controls to detect unauthorized resource provisioning."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1583/003/"],
    },
    "T1584.002": {
        "rationale": (
            "Compromising DNS infrastructure enables domain hijacking, allowing phishing or "
            "traffic redirection attacks against legitimate services."
        ),
        "remediation": (
            "1. Apply MFA to all DNS management accounts.\n"
            "2. Enable DNSSEC on all critical domains.\n"
            "3. Alert on all DNS zone or record modifications."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1584/002/"],
    },
    "T1585.002": {
        "rationale": (
            "Creating cloud email or cloud accounts for attack purposes enables phishing and "
            "social engineering attacks appearing to come from legitimate cloud providers."
        ),
        "remediation": (
            "1. Monitor for new cloud account creation events outside approved provisioning.\n"
            "2. Apply email filtering to detect phishing from cloud provider addresses.\n"
            "3. Enable DMARC/DKIM/SPF for all owned domains."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1585/002/"],
    },
    "T1587.001": {
        "rationale": (
            "Custom malware developed specifically for cloud environments evades generic "
            "detection tools that rely on known-bad signatures."
        ),
        "remediation": (
            "1. Enable behavioral analysis in cloud security tools (Defender for Cloud, GuardDuty).\n"
            "2. Apply application allowlisting for critical workloads.\n"
            "3. Enable Defender for Cloud / GuardDuty behavioral threat detection."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1587/001/"],
    },
    # ── Initial Access ────────────────────────────────────────────────────────
    "T1133": {
        "rationale": (
            "External remote service access (VPN, Citrix, cloud portals) is a common initial "
            "access vector; unexpected access may indicate compromised credentials."
        ),
        "remediation": (
            "1. Apply Conditional Access policies to require MFA for all external access.\n"
            "2. Enable sign-in risk detection and session controls.\n"
            "3. Monitor for unusual remote access patterns (new location, device, timing)."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1133/"],
    },
    "T1190": {
        "rationale": (
            "Public-facing application exploitation can provide initial foothold in cloud "
            "environments; early detection limits attacker dwell time significantly."
        ),
        "remediation": (
            "1. Apply WAF rules to detect and block exploitation attempts.\n"
            "2. Enable vulnerability scanning for all public-facing services.\n"
            "3. Apply security patches promptly for all known CVEs."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1190/"],
    },
    "T1566.001": {
        "rationale": (
            "Spear phishing with attachments targets cloud users with malicious files that "
            "can capture credentials or establish persistent cloud account access."
        ),
        "remediation": (
            "1. Enable Microsoft Defender for Office 365 / AWS SES email filtering.\n"
            "2. Apply email attachment sandboxing and safe links protection.\n"
            "3. Conduct regular phishing awareness training for all users."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1566/001/"],
    },
    "T1563.001": {
        "rationale": (
            "Hijacking SSH sessions enables an attacker to take over an existing authenticated "
            "session without re-authenticating, gaining access to all open connections."
        ),
        "remediation": (
            "1. Use ControlMaster restrictions to prevent SSH session multiplexing.\n"
            "2. Enable SSH session logging and session monitoring.\n"
            "3. Use certificate-based authentication with short-lived certificates."
        ),
        "refs": ["https://attack.mitre.org/techniques/T1563/001/"],
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# Compliance frameworks per threat_category
# ─────────────────────────────────────────────────────────────────────────────

CATEGORY_COMPLIANCE: dict[str, dict[str, list[str]]] = {
    "privilege_escalation": {
        "cis_aws_v3":      ["1.1", "1.16", "1.17"],
        "cis_azure_v2":    ["1.1", "2.1", "3.1"],
        "nist_800_53_r5":  ["AC-2", "AC-3", "AC-6", "IA-2"],
        "pci_dss_v4":      ["7.1", "7.2", "8.2"],
        "iso_27001_2022":  ["A.5.18", "A.8.2", "A.8.3"],
    },
    "defense_evasion": {
        "cis_aws_v3":      ["3.1", "3.2", "3.3", "3.4"],
        "cis_azure_v2":    ["5.1", "5.2", "5.3"],
        "nist_800_53_r5":  ["AU-2", "AU-6", "AU-12", "SI-4"],
        "pci_dss_v4":      ["10.1", "10.2", "10.3"],
        "iso_27001_2022":  ["A.8.15", "A.8.16", "A.5.28"],
    },
    "credential_access": {
        "cis_aws_v3":      ["1.14", "1.19", "2.1"],
        "cis_azure_v2":    ["1.3", "1.4", "8.1"],
        "nist_800_53_r5":  ["IA-5", "IA-8", "SC-28"],
        "pci_dss_v4":      ["8.2", "8.3", "8.6"],
        "iso_27001_2022":  ["A.8.5", "A.9.4", "A.9.2"],
    },
    "persistence": {
        "cis_aws_v3":      ["1.1", "1.4", "1.16"],
        "cis_azure_v2":    ["1.1", "2.1", "2.9"],
        "nist_800_53_r5":  ["AC-2", "AC-6", "IA-2", "SC-7"],
        "pci_dss_v4":      ["7.1", "8.2", "10.2"],
        "iso_27001_2022":  ["A.8.2", "A.9.2", "A.5.18"],
    },
    "data_destruction": {
        "cis_aws_v3":      ["2.1", "2.6", "3.1"],
        "cis_azure_v2":    ["3.1", "7.5"],
        "nist_800_53_r5":  ["CP-9", "CP-10", "SI-12"],
        "pci_dss_v4":      ["3.2", "3.3", "12.3"],
        "iso_27001_2022":  ["A.8.13", "A.8.14", "A.5.33"],
    },
    "data_exfiltration": {
        "cis_aws_v3":      ["2.7", "3.7"],
        "cis_azure_v2":    ["3.1", "5.2"],
        "nist_800_53_r5":  ["SC-7", "SC-28", "AC-4"],
        "pci_dss_v4":      ["3.2", "4.1", "10.2"],
        "iso_27001_2022":  ["A.8.12", "A.8.20", "A.5.14"],
    },
    "lateral_movement": {
        "cis_aws_v3":      ["5.1", "5.2", "5.3"],
        "cis_azure_v2":    ["6.1", "6.2"],
        "nist_800_53_r5":  ["SC-7", "AC-4", "SI-3"],
        "pci_dss_v4":      ["1.2", "1.3", "7.2"],
        "iso_27001_2022":  ["A.8.20", "A.8.22", "A.5.14"],
    },
    "identity_manipulation": {
        "cis_aws_v3":      ["1.1", "1.16", "1.22"],
        "cis_azure_v2":    ["1.1", "2.1"],
        "nist_800_53_r5":  ["AC-2", "AC-3", "IA-2"],
        "pci_dss_v4":      ["7.1", "8.2"],
        "iso_27001_2022":  ["A.5.18", "A.8.2"],
    },
    "reconnaissance": {
        "cis_aws_v3":      ["2.1", "3.1"],
        "cis_azure_v2":    ["5.1", "5.2"],
        "nist_800_53_r5":  ["AU-2", "AU-12", "SI-4"],
        "pci_dss_v4":      ["10.2", "11.5"],
        "iso_27001_2022":  ["A.8.16", "A.5.28"],
    },
    "initial_access": {
        "cis_aws_v3":      ["1.14", "2.1"],
        "cis_azure_v2":    ["1.2", "2.1"],
        "nist_800_53_r5":  ["AC-17", "IA-2", "SI-3"],
        "pci_dss_v4":      ["8.3", "11.5"],
        "iso_27001_2022":  ["A.8.5", "A.9.4"],
    },
    "execution": {
        "cis_aws_v3":      ["3.1", "5.1"],
        "cis_azure_v2":    ["5.1", "6.1"],
        "nist_800_53_r5":  ["CM-7", "SI-3", "AU-12"],
        "pci_dss_v4":      ["6.3", "10.2"],
        "iso_27001_2022":  ["A.8.19", "A.8.8"],
    },
    "collection": {
        "cis_aws_v3":      ["2.1", "2.7"],
        "cis_azure_v2":    ["3.1", "5.1"],
        "nist_800_53_r5":  ["AC-4", "AC-3", "AU-12"],
        "pci_dss_v4":      ["3.2", "7.1"],
        "iso_27001_2022":  ["A.8.12", "A.8.3"],
    },
    "supply_chain_compromise": {
        "cis_aws_v3":      ["5.3", "2.1"],
        "cis_azure_v2":    ["4.1", "5.1"],
        "nist_800_53_r5":  ["SA-12", "SA-15", "SI-7"],
        "pci_dss_v4":      ["6.3", "12.8"],
        "iso_27001_2022":  ["A.8.30", "A.5.19"],
    },
    "impact": {
        "cis_aws_v3":      ["2.6", "3.1"],
        "cis_azure_v2":    ["7.5", "5.1"],
        "nist_800_53_r5":  ["CP-9", "CP-10", "SI-12", "IR-4"],
        "pci_dss_v4":      ["12.3", "3.4"],
        "iso_27001_2022":  ["A.5.29", "A.8.13"],
    },
    "brute_force": {
        "cis_aws_v3":      ["1.14", "1.9"],
        "cis_azure_v2":    ["1.2", "2.3"],
        "nist_800_53_r5":  ["IA-5", "IA-7", "AC-7"],
        "pci_dss_v4":      ["8.3", "8.6"],
        "iso_27001_2022":  ["A.8.5", "A.9.4"],
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# Threat category fallback data (when technique lookup fails)
# ─────────────────────────────────────────────────────────────────────────────

CATEGORY_FALLBACK: dict[str, dict[str, Any]] = {
    "privilege_escalation": {
        "rationale": "Privilege escalation events indicate an actor gaining unauthorized elevated access, enabling broader lateral movement or administrative control.",
        "remediation": "1. Revoke unauthorized elevated permissions immediately.\n2. Review the actor's full activity history.\n3. Apply least-privilege RBAC and just-in-time access controls.\n4. Enable alerting for all privilege elevation events.",
        "refs": ["https://attack.mitre.org/tactics/TA0004/"],
    },
    "defense_evasion": {
        "rationale": "Defense evasion events indicate an actor disabling or circumventing security controls to avoid detection during subsequent attack stages.",
        "remediation": "1. Re-enable all disabled security controls immediately.\n2. Investigate follow-on actions by the actor.\n3. Apply SCPs / Azure Policy to prevent unauthorized security control modification.\n4. Configure independent alerting channels.",
        "refs": ["https://attack.mitre.org/tactics/TA0005/"],
    },
    "credential_access": {
        "rationale": "Credential access events indicate an actor attempting to harvest authentication material for persistent or elevated access.",
        "remediation": "1. Rotate potentially compromised credentials immediately.\n2. Enable MFA on all accounts.\n3. Audit access to credential stores.\n4. Use managed identities and secrets managers.",
        "refs": ["https://attack.mitre.org/tactics/TA0006/"],
    },
    "persistence": {
        "rationale": "Persistence events indicate an actor establishing mechanisms to maintain access that survives credential rotation or account remediation.",
        "remediation": "1. Remove the persistence mechanism immediately.\n2. Audit the actor's full scope of changes.\n3. Apply least-privilege controls on persistence-enabling operations.\n4. Enable alerts for all persistence-related events.",
        "refs": ["https://attack.mitre.org/tactics/TA0003/"],
    },
    "lateral_movement": {
        "rationale": "Lateral movement events indicate an actor pivoting between cloud resources, accounts, or regions to expand attack scope.",
        "remediation": "1. Restrict the actor's access immediately.\n2. Review network connectivity and access paths.\n3. Apply network segmentation controls.\n4. Enable flow log monitoring for cross-boundary traffic.",
        "refs": ["https://attack.mitre.org/tactics/TA0008/"],
    },
    "data_exfiltration": {
        "rationale": "Data exfiltration events indicate potential unauthorized transfer of sensitive data outside the organization's control.",
        "remediation": "1. Block the actor's access immediately.\n2. Identify data accessed and assess breach scope.\n3. Apply DLP policies to detect bulk data access.\n4. Enable storage access logging.",
        "refs": ["https://attack.mitre.org/tactics/TA0010/"],
    },
    "data_destruction": {
        "rationale": "Data destruction events indicate an actor performing irreversible deletion or encryption of organizational data.",
        "remediation": "1. Quarantine the actor's credentials immediately.\n2. Activate incident response and backup recovery procedures.\n3. Enable object versioning and soft-delete on all storage resources.\n4. Require MFA for destructive operations.",
        "refs": ["https://attack.mitre.org/tactics/TA0040/"],
    },
    "identity_manipulation": {
        "rationale": "Identity manipulation events indicate changes to user, group, or service principal attributes that may establish persistence or escalate privileges.",
        "remediation": "1. Revert unauthorized identity changes immediately.\n2. Audit the actor's full session activity.\n3. Enable alerts for all identity modification events.\n4. Apply change-control processes for privileged identity operations.",
        "refs": ["https://attack.mitre.org/tactics/TA0003/"],
    },
    "reconnaissance": {
        "rationale": "Reconnaissance events indicate an actor gathering information about the cloud environment to plan subsequent attack stages.",
        "remediation": "1. Investigate the source of reconnaissance activity.\n2. Restrict enumeration permissions to authorized roles.\n3. Enable activity monitoring for discovery API calls.\n4. Alert on bulk enumeration patterns.",
        "refs": ["https://attack.mitre.org/tactics/TA0043/"],
    },
    "impact": {
        "rationale": "Impact events indicate an actor causing disruption, destruction, or degradation of cloud resources and services.",
        "remediation": "1. Quarantine the actor immediately and halt ongoing destructive operations.\n2. Activate incident response procedures.\n3. Restore from clean backups.\n4. Apply resource locks on critical infrastructure.",
        "refs": ["https://attack.mitre.org/tactics/TA0040/"],
    },
    "collection": {
        "rationale": "Collection events indicate data is being gathered from cloud resources, often preceding exfiltration.",
        "remediation": "1. Restrict data access to least-privilege roles.\n2. Enable storage access logging.\n3. Alert on high-volume data access patterns.\n4. Apply DLP policies.",
        "refs": ["https://attack.mitre.org/tactics/TA0009/"],
    },
    "supply_chain_compromise": {
        "rationale": "Supply chain events indicate modifications to software, containers, or pipelines that may introduce malicious code affecting downstream consumers.",
        "remediation": "1. Revert unauthorized pipeline or registry changes.\n2. Enforce image signing and code review requirements.\n3. Enable audit logging for all CI/CD and registry operations.\n4. Scan all artifacts for malicious code before deployment.",
        "refs": ["https://attack.mitre.org/tactics/TA0001/"],
    },
    "brute_force": {
        "rationale": "Brute force events indicate automated password guessing or credential stuffing attacks against cloud accounts.",
        "remediation": "1. Enable account lockout after consecutive failures.\n2. Enforce MFA on all accounts.\n3. Apply Conditional Access risk-based policies.\n4. Block high-risk IP addresses.",
        "refs": ["https://attack.mitre.org/tactics/TA0006/"],
    },
    "execution": {
        "rationale": "Execution events indicate an actor running malicious code within the cloud environment, often indicating full compromise.",
        "remediation": "1. Terminate unauthorized compute resources.\n2. Revoke credentials used to launch the workloads.\n3. Apply workload protection policies.\n4. Enable behavioral monitoring.",
        "refs": ["https://attack.mitre.org/tactics/TA0002/"],
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# YAML writer — preserves field order and CIEM rule schema
# ─────────────────────────────────────────────────────────────────────────────

def _yaml_str(value: str) -> str:
    """Serialize a string value; use block literal for multi-line."""
    if "\n" in value:
        lines = value.rstrip("\n").split("\n")
        return "|\n" + "\n".join("  " + ln for ln in lines)
    # Quote if contains special YAML chars or starts with special chars
    if any(c in value for c in (':', '#', '[', ']', '{', '}', '&', '*', '!', '|', '>', '"', "'")):
        escaped = value.replace("'", "''")
        return f"'{escaped}'"
    return value


def _dump_rule(data: dict) -> str:
    """Serialize a CIEM rule dict into YAML preserving the expected field order."""
    lines = []

    SCALAR_FIELDS = [
        "rule_id", "service", "provider", "check_type", "severity",
        "title", "description",
    ]
    for field in SCALAR_FIELDS:
        if field in data:
            lines.append(f"{field}: {_yaml_str(str(data[field]))}")

    # rationale
    if "rationale" in data:
        lines.append(f"rationale: {_yaml_str(data['rationale'])}")

    # threat_category
    if "threat_category" in data:
        lines.append(f"threat_category: {data['threat_category']}")

    # mitre_tactics list
    if "mitre_tactics" in data:
        lines.append("mitre_tactics:")
        for t in data["mitre_tactics"]:
            lines.append(f"- {t}")

    # mitre_techniques list
    if "mitre_techniques" in data:
        lines.append("mitre_techniques:")
        for t in data["mitre_techniques"]:
            lines.append(f"- {t}")

    # risk_score
    if "risk_score" in data:
        lines.append(f"risk_score: {data['risk_score']}")

    # resource, source, is_active
    for field in ("resource", "source", "is_active"):
        if field in data:
            val = data[field]
            if isinstance(val, bool):
                lines.append(f"{field}: {'true' if val else 'false'}")
            else:
                lines.append(f"{field}: {_yaml_str(str(val))}")

    # compliance_frameworks
    if "compliance_frameworks" in data:
        lines.append("compliance_frameworks:")
        for fw, controls in data["compliance_frameworks"].items():
            lines.append(f"  {fw}:")
            for c in controls:
                lines.append(f"  - {c}")

    # remediation
    if "remediation" in data:
        lines.append(f"remediation: {_yaml_str(data['remediation'])}")

    # references
    if "references" in data:
        lines.append("references:")
        for ref in data["references"]:
            lines.append(f"- {ref}")

    # check_config (preserve raw YAML sub-block)
    if "check_config" in data:
        # Use PyYAML to serialize just the check_config sub-dict
        cc_yaml = yaml.dump(
            {"check_config": data["check_config"]},
            default_flow_style=False,
            allow_unicode=True,
        ).rstrip()
        lines.append(cc_yaml)

    # version
    if "version" in data:
        lines.append(f"version: '{data['version']}'")

    return "\n".join(lines) + "\n"


# ─────────────────────────────────────────────────────────────────────────────
# Enrichment lookup
# ─────────────────────────────────────────────────────────────────────────────

def _get_technique_meta(rule: dict) -> dict:
    """Return {rationale, remediation, refs} for the rule via technique or category."""
    techniques = rule.get("mitre_techniques") or []
    # Try exact technique, then parent, then fallback
    for tech in techniques:
        if tech in TECHNIQUE:
            return TECHNIQUE[tech]
    for tech in techniques:
        parent = tech.split(".")[0]
        if parent in TECHNIQUE:
            return TECHNIQUE[parent]
    # Category fallback
    cat = rule.get("threat_category", "")
    if cat in CATEGORY_FALLBACK:
        return CATEGORY_FALLBACK[cat]
    return {
        "rationale": f"Detected {rule.get('title', rule.get('rule_id', 'unknown'))} — review and investigate the actor's intent.",
        "remediation": "1. Investigate the triggering event.\n2. Revoke suspicious access.\n3. Review the actor's recent activity.",
        "refs": [],
    }


def _build_references(meta: dict, techniques: list[str]) -> list[str]:
    """Combine technique refs with MITRE ATT&CK URLs for any techniques not already covered."""
    refs = list(meta.get("refs", []))
    seen = set(refs)
    for tech in techniques:
        url = f"https://attack.mitre.org/techniques/{tech.replace('.', '/')}/"
        if url not in seen:
            refs.append(url)
            seen.add(url)
    return refs


def enrich_file(path: Path, dry_run: bool, force: bool) -> str:
    """Enrich a single CIEM rule YAML file. Returns status string."""
    raw = path.read_text(encoding="utf-8")
    rule = yaml.safe_load(raw)

    if not isinstance(rule, dict):
        return "SKIP (not a dict)"

    already_has = all(
        k in rule for k in ("rationale", "remediation", "references", "compliance_frameworks")
    )
    if already_has and not force:
        return "SKIP (already enriched)"

    meta = _get_technique_meta(rule)
    techniques = rule.get("mitre_techniques") or []
    cat = rule.get("threat_category", "")

    if "rationale" not in rule or force:
        rule["rationale"] = meta["rationale"]
    if "remediation" not in rule or force:
        rule["remediation"] = meta["remediation"]
    if "references" not in rule or force:
        rule["references"] = _build_references(meta, techniques)
    if "compliance_frameworks" not in rule or force:
        rule["compliance_frameworks"] = CATEGORY_COMPLIANCE.get(cat, {})

    if dry_run:
        return "DRY  (would write)"

    path.write_text(_dump_rule(rule), encoding="utf-8")
    return "OK"


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    p = argparse.ArgumentParser(description="Enrich CIEM rule YAMLs with remediation metadata")
    p.add_argument("--aws-only",   action="store_true")
    p.add_argument("--azure-only", action="store_true")
    p.add_argument("--dry-run",    action="store_true", help="Print what would change")
    p.add_argument("--force",      action="store_true", help="Overwrite existing fields")
    args = p.parse_args()

    dirs: list[Path] = []
    if not args.azure_only:
        dirs.append(AWS_CIEM_DIR)
    if not args.aws_only:
        dirs.append(AZURE_CIEM_DIR)

    total = ok = skip = err = 0
    for d in dirs:
        yamls = sorted(d.rglob("*.yaml"))
        print(f"\n── {d.name}  ({len(yamls)} files) ──────────────────────────")
        for path in yamls:
            total += 1
            try:
                status = enrich_file(path, dry_run=args.dry_run, force=args.force)
                if status.startswith("OK"):
                    ok += 1
                else:
                    skip += 1
                if args.dry_run:
                    print(f"  {status}  {path.name}")
            except Exception as exc:  # noqa: BLE001
                err += 1
                print(f"  ERROR  {path.name}: {exc}")

    print(f"\n── Summary ───────────────────────────────────────────")
    print(f"  Total   : {total}")
    print(f"  Enriched: {ok}")
    print(f"  Skipped : {skip}")
    print(f"  Errors  : {err}")
    if args.dry_run:
        print("  (dry-run — no files written)")


if __name__ == "__main__":
    main()
