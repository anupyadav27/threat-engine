#!/usr/bin/env python3
"""
Seed detection_guidance + remediation_guidance for mitre_technique_reference.

Populates AWS-specific CloudTrail events, GuardDuty types, CloudWatch patterns,
immediate/preventive/detective remediation actions, and severity_base.

Usage:
    THREAT_DB_HOST=... THREAT_DB_USER=... THREAT_DB_PASSWORD=... \
    python3 scripts/seed_mitre_guidance.py

    python3 scripts/seed_mitre_guidance.py --dry-run
"""

import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict

# ──────────────────────────────────────────────────────────────────────────────
# Detection & Remediation guidance per MITRE technique
#
# Structure:
#   detection_guidance: {
#     cloudtrail_events: [...],    -- CloudTrail API event names to monitor
#     guardduty_types: [...],      -- GuardDuty finding types
#     cloudwatch_patterns: [...],  -- CloudWatch Logs Insights patterns
#     data_sources: [...],         -- AWS data sources for detection
#   }
#   remediation_guidance: {
#     immediate: [...],    -- Immediate response actions
#     preventive: [...],   -- Preventive controls to implement
#     detective: [...],    -- Detective controls to enable
#     aws_services: [...], -- AWS services used for remediation
#   }
#   severity_base: str    -- Default severity (critical/high/medium/low)
# ──────────────────────────────────────────────────────────────────────────────

GUIDANCE: Dict[str, Dict[str, Any]] = {
    # ── Initial Access ────────────────────────────────────────────────────
    "T1190": {
        "severity_base": "critical",
        "detection_guidance": {
            "cloudtrail_events": ["UpdateFunctionCode", "CreateRestApi", "UpdateRestApi", "PutIntegration"],
            "guardduty_types": ["UnauthorizedAccess:EC2/MaliciousIPCaller", "Recon:EC2/PortProbeUnprotectedPort"],
            "cloudwatch_patterns": ["4xx/5xx spike on ALB", "Lambda invocation errors", "API Gateway unauthorized"],
            "data_sources": ["CloudTrail", "VPC Flow Logs", "ALB Access Logs", "WAF Logs"],
        },
        "remediation_guidance": {
            "immediate": ["Enable WAF with managed rule groups", "Block malicious IPs in security groups"],
            "preventive": ["Deploy WAF on all public endpoints", "Enable API Gateway request validation", "Use Lambda authorizers", "Keep runtime dependencies patched"],
            "detective": ["Enable GuardDuty", "Enable Inspector for vulnerability scanning", "Monitor ALB access logs for anomalies"],
            "aws_services": ["WAF", "Shield", "Inspector", "GuardDuty", "Security Hub"],
        },
    },
    "T1199": {
        "severity_base": "high",
        "detection_guidance": {
            "cloudtrail_events": ["AssumeRole", "CreateRole", "UpdateAssumeRolePolicy", "PutRolePolicy"],
            "guardduty_types": ["UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration"],
            "cloudwatch_patterns": ["AssumeRole from unusual account", "Cross-account role assumption spike"],
            "data_sources": ["CloudTrail", "IAM Access Analyzer"],
        },
        "remediation_guidance": {
            "immediate": ["Audit all cross-account trust policies", "Revoke suspicious role sessions"],
            "preventive": ["Use IAM Access Analyzer to detect external access", "Enforce SCP constraints on trust policies", "Require ExternalId for third-party roles"],
            "detective": ["Enable IAM Access Analyzer", "Alert on new cross-account role creation"],
            "aws_services": ["IAM Access Analyzer", "Organizations SCPs", "CloudTrail"],
        },
    },
    "T1078": {
        "severity_base": "high",
        "detection_guidance": {
            "cloudtrail_events": ["ConsoleLogin", "CreateAccessKey", "GetSessionToken", "AssumeRole", "AssumeRoleWithSAML"],
            "guardduty_types": ["UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B", "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom"],
            "cloudwatch_patterns": ["Console login from unusual IP/geo", "Multiple failed logins", "Access key usage from new IP"],
            "data_sources": ["CloudTrail", "GuardDuty", "IAM Credential Report"],
        },
        "remediation_guidance": {
            "immediate": ["Rotate all access keys for compromised user", "Revoke active sessions", "Enable MFA immediately"],
            "preventive": ["Enforce MFA for all IAM users", "Implement password policy (14+ chars)", "Use SSO instead of IAM users", "Rotate access keys every 90 days"],
            "detective": ["Enable GuardDuty", "Monitor ConsoleLogin events", "Alert on access key creation"],
            "aws_services": ["IAM", "IAM Identity Center (SSO)", "GuardDuty", "CloudTrail"],
        },
    },
    "T1078.004": {
        "severity_base": "high",
        "detection_guidance": {
            "cloudtrail_events": ["ConsoleLogin", "CreateAccessKey", "GetSessionToken", "AssumeRoleWithWebIdentity"],
            "guardduty_types": ["UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B"],
            "cloudwatch_patterns": ["Login from impossible travel locations", "API calls from tor exit nodes"],
            "data_sources": ["CloudTrail", "GuardDuty"],
        },
        "remediation_guidance": {
            "immediate": ["Disable compromised credentials", "Revoke temporary tokens via STS"],
            "preventive": ["Use IAM Identity Center", "Enforce MFA", "Use IP-based conditions in IAM policies"],
            "detective": ["GuardDuty credential exfiltration alerts", "CloudTrail anomaly detection"],
            "aws_services": ["IAM Identity Center", "GuardDuty", "STS"],
        },
    },
    # ── Execution ─────────────────────────────────────────────────────────
    "T1651": {
        "severity_base": "medium",
        "detection_guidance": {
            "cloudtrail_events": ["RunInstances", "InvokeFunction", "SendCommand", "StartSession"],
            "guardduty_types": ["UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"],
            "cloudwatch_patterns": ["Unusual API call volume", "CLI calls from new user-agent"],
            "data_sources": ["CloudTrail", "CloudTrail Insights"],
        },
        "remediation_guidance": {
            "immediate": ["Review recent API calls for the identity", "Revoke sessions if unauthorized"],
            "preventive": ["Implement least-privilege IAM policies", "Use Permission Boundaries", "Enforce SCP guardrails"],
            "detective": ["Enable CloudTrail Insights", "Monitor for unusual API patterns"],
            "aws_services": ["CloudTrail", "IAM", "Organizations SCPs"],
        },
    },
    "T1648": {
        "severity_base": "high",
        "detection_guidance": {
            "cloudtrail_events": ["CreateFunction", "UpdateFunctionCode", "InvokeFunction", "CreateStateMachine", "StartExecution"],
            "guardduty_types": [],
            "cloudwatch_patterns": ["Lambda function created in unusual region", "High invocation from unknown trigger"],
            "data_sources": ["CloudTrail", "Lambda CloudWatch Logs", "X-Ray traces"],
        },
        "remediation_guidance": {
            "immediate": ["Delete unauthorized Lambda functions", "Revoke execution role permissions"],
            "preventive": ["Use code signing for Lambda", "Restrict CreateFunction via SCP", "Enforce VPC-only Lambda"],
            "detective": ["Monitor Lambda creation events", "Alert on new functions in unused regions"],
            "aws_services": ["Lambda", "Step Functions", "CloudTrail", "Code Signing"],
        },
    },
    # ── Persistence ───────────────────────────────────────────────────────
    "T1098": {
        "severity_base": "high",
        "detection_guidance": {
            "cloudtrail_events": ["CreateAccessKey", "PutUserPolicy", "AttachUserPolicy", "AttachRolePolicy", "PutRolePolicy", "UpdateAssumeRolePolicy", "CreateLoginProfile", "UpdateLoginProfile"],
            "guardduty_types": ["Persistence:IAMUser/AnomalousBehavior"],
            "cloudwatch_patterns": ["New access key created", "Policy attached to user/role", "Trust policy modified"],
            "data_sources": ["CloudTrail", "IAM Access Analyzer", "Config Rules"],
        },
        "remediation_guidance": {
            "immediate": ["Delete unauthorized access keys", "Detach suspicious policies", "Revert trust policy changes"],
            "preventive": ["Use SCP to deny CreateAccessKey for root", "Enforce approval workflow for policy changes", "Tag-based access control"],
            "detective": ["AWS Config rule: iam-user-no-policies-check", "Alert on AttachPolicy events", "IAM Access Analyzer"],
            "aws_services": ["IAM", "Config", "IAM Access Analyzer", "Organizations SCPs"],
        },
    },
    "T1136.003": {
        "severity_base": "high",
        "detection_guidance": {
            "cloudtrail_events": ["CreateUser", "CreateRole", "CreateServiceLinkedRole"],
            "guardduty_types": ["Persistence:IAMUser/AnomalousBehavior"],
            "cloudwatch_patterns": ["New IAM user created", "New role created with admin policy"],
            "data_sources": ["CloudTrail", "Config"],
        },
        "remediation_guidance": {
            "immediate": ["Delete unauthorized IAM users/roles", "Audit all recently created identities"],
            "preventive": ["SCP deny CreateUser except from approved pipelines", "Enforce tagging on IAM resources"],
            "detective": ["Config rule: iam-user-unused-credentials-check", "Alert on CreateUser/CreateRole"],
            "aws_services": ["IAM", "Config", "Organizations SCPs"],
        },
    },
    "T1525": {
        "severity_base": "high",
        "detection_guidance": {
            "cloudtrail_events": ["RegisterImage", "CreateImage", "PutImage", "BatchCheckLayerAvailability"],
            "guardduty_types": [],
            "cloudwatch_patterns": ["AMI registered from unusual source", "ECR image push from unknown identity"],
            "data_sources": ["CloudTrail", "ECR image scanning", "Inspector"],
        },
        "remediation_guidance": {
            "immediate": ["Deregister suspicious AMIs", "Delete compromised ECR images", "Scan all images"],
            "preventive": ["Enable ECR image scanning on push", "Use only approved AMIs via SCP", "Lambda code signing"],
            "detective": ["Inspector ECR scanning", "Alert on RegisterImage events"],
            "aws_services": ["ECR", "Inspector", "Systems Manager", "Lambda Code Signing"],
        },
    },
    # ── Defense Evasion ───────────────────────────────────────────────────
    "T1562": {
        "severity_base": "critical",
        "detection_guidance": {
            "cloudtrail_events": ["StopLogging", "DeleteTrail", "DisableGuardDuty", "DeleteDetector", "DisableSecurityHub", "UpdateDetector"],
            "guardduty_types": ["Stealth:IAMUser/CloudTrailLoggingDisabled", "Stealth:IAMUser/PasswordPolicyChange"],
            "cloudwatch_patterns": ["CloudTrail stopped", "GuardDuty disabled", "Security Hub disabled"],
            "data_sources": ["CloudTrail", "Config", "GuardDuty"],
        },
        "remediation_guidance": {
            "immediate": ["Re-enable CloudTrail/GuardDuty/Security Hub immediately", "Investigate who disabled them"],
            "preventive": ["SCP deny StopLogging/DeleteTrail/DeleteDetector", "Enable CloudTrail organization trail"],
            "detective": ["Config rule: cloudtrail-enabled", "Config rule: guardduty-enabled-centralized", "Alert on any StopLogging event"],
            "aws_services": ["CloudTrail", "GuardDuty", "Security Hub", "Config", "Organizations SCPs"],
        },
    },
    "T1562.008": {
        "severity_base": "critical",
        "detection_guidance": {
            "cloudtrail_events": ["StopLogging", "DeleteTrail", "PutBucketLogging", "DeleteFlowLogs", "DeleteLogGroup"],
            "guardduty_types": ["Stealth:IAMUser/CloudTrailLoggingDisabled"],
            "cloudwatch_patterns": ["Trail stopped", "Log group deleted", "VPC Flow Logs deleted"],
            "data_sources": ["CloudTrail", "Config"],
        },
        "remediation_guidance": {
            "immediate": ["Re-enable logging immediately", "Check S3 bucket for log tampering"],
            "preventive": ["SCP deny StopLogging/DeleteTrail", "S3 Object Lock on log buckets", "Organization-level trail"],
            "detective": ["Config rule: cloudtrail-enabled", "Alert on DeleteLogGroup events"],
            "aws_services": ["CloudTrail", "S3 Object Lock", "Config", "Organizations"],
        },
    },
    "T1535": {
        "severity_base": "medium",
        "detection_guidance": {
            "cloudtrail_events": ["RunInstances", "CreateFunction", "CreateDBInstance"],
            "guardduty_types": ["CryptoCurrency:EC2/BitcoinTool.B"],
            "cloudwatch_patterns": ["API calls in opt-in regions", "Resources created in unusual regions"],
            "data_sources": ["CloudTrail", "Config (multi-region)"],
        },
        "remediation_guidance": {
            "immediate": ["Terminate resources in unauthorized regions", "Audit all opt-in region usage"],
            "preventive": ["SCP deny all actions in unapproved regions", "Use aws:RequestedRegion condition"],
            "detective": ["Config multi-region aggregator", "Alert on resources in non-standard regions"],
            "aws_services": ["Organizations SCPs", "Config", "GuardDuty"],
        },
    },
    "T1578": {
        "severity_base": "medium",
        "detection_guidance": {
            "cloudtrail_events": ["CreateSnapshot", "CopySnapshot", "ModifyInstanceAttribute", "RunInstances", "TerminateInstances"],
            "guardduty_types": ["UnauthorizedAccess:EC2/UnusualASNCaller"],
            "cloudwatch_patterns": ["Snapshot created and shared cross-account", "Instance launched from suspicious AMI"],
            "data_sources": ["CloudTrail", "Config", "EBS events"],
        },
        "remediation_guidance": {
            "immediate": ["Delete unauthorized snapshots", "Terminate suspicious instances"],
            "preventive": ["Encrypt all EBS volumes (default encryption)", "SCP restrict snapshot sharing", "Enforce launch template usage"],
            "detective": ["Config rule: encrypted-volumes", "Alert on ModifySnapshotAttribute (share events)"],
            "aws_services": ["EC2", "EBS", "KMS", "Config"],
        },
    },
    # ── Credential Access ─────────────────────────────────────────────────
    "T1552": {
        "severity_base": "high",
        "detection_guidance": {
            "cloudtrail_events": ["GetSecretValue", "GetParameter", "GetParametersByPath", "DescribeParameters"],
            "guardduty_types": ["CredentialAccess:IAMUser/AnomalousBehavior"],
            "cloudwatch_patterns": ["Unusual Secrets Manager access", "Parameter Store bulk read"],
            "data_sources": ["CloudTrail", "Secrets Manager audit logs"],
        },
        "remediation_guidance": {
            "immediate": ["Rotate all secrets accessed by compromised identity", "Revoke permissions"],
            "preventive": ["Use Secrets Manager with rotation", "Never store credentials in code/templates", "Enforce IMDSv2"],
            "detective": ["Alert on GetSecretValue from unusual identities", "Monitor Parameter Store access patterns"],
            "aws_services": ["Secrets Manager", "Systems Manager Parameter Store", "KMS"],
        },
    },
    "T1552.005": {
        "severity_base": "critical",
        "detection_guidance": {
            "cloudtrail_events": [],
            "guardduty_types": ["UnauthorizedAccess:EC2/MetadataDNSRebind", "UnauthorizedAccess:EC2/InstanceCredentialExfiltration"],
            "cloudwatch_patterns": ["IMDSv1 usage detected", "SSRF patterns in application logs"],
            "data_sources": ["VPC Flow Logs", "GuardDuty", "EC2 metadata metrics"],
        },
        "remediation_guidance": {
            "immediate": ["Switch to IMDSv2 (HttpTokens=required)", "Rotate instance profile credentials"],
            "preventive": ["Enforce IMDSv2 via launch template", "SCP deny IMDSv1", "Block metadata endpoint from containers"],
            "detective": ["Monitor IMDSv1 usage via CloudWatch metric", "GuardDuty SSRF findings"],
            "aws_services": ["EC2 (IMDSv2)", "GuardDuty", "Systems Manager"],
        },
    },
    "T1528": {
        "severity_base": "high",
        "detection_guidance": {
            "cloudtrail_events": ["GetSessionToken", "AssumeRole"],
            "guardduty_types": ["UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"],
            "cloudwatch_patterns": ["STS token used from external IP", "Lambda env vars accessed"],
            "data_sources": ["CloudTrail", "GuardDuty"],
        },
        "remediation_guidance": {
            "immediate": ["Revoke compromised STS sessions", "Rotate application credentials"],
            "preventive": ["Use short-lived STS tokens", "Enforce aws:SourceIp conditions", "Use VPC endpoints for STS"],
            "detective": ["GuardDuty credential exfiltration alerts", "Alert on STS use from external networks"],
            "aws_services": ["STS", "IAM", "GuardDuty", "VPC Endpoints"],
        },
    },
    # ── Discovery ─────────────────────────────────────────────────────────
    "T1580": {
        "severity_base": "low",
        "detection_guidance": {
            "cloudtrail_events": ["DescribeInstances", "ListBuckets", "DescribeDBInstances", "ListFunctions", "DescribeSecurityGroups"],
            "guardduty_types": ["Recon:IAMUser/ResourcePermissions"],
            "cloudwatch_patterns": ["High volume of Describe/List API calls", "Enumeration from new identity"],
            "data_sources": ["CloudTrail", "CloudTrail Insights"],
        },
        "remediation_guidance": {
            "immediate": ["Investigate the identity performing enumeration", "Check if credentials are compromised"],
            "preventive": ["Enforce least-privilege (no broad Describe access)", "Use Permission Boundaries"],
            "detective": ["Enable CloudTrail Insights for anomaly detection", "Alert on high-volume Describe calls"],
            "aws_services": ["CloudTrail Insights", "IAM", "GuardDuty"],
        },
    },
    # ── Collection ────────────────────────────────────────────────────────
    "T1530": {
        "severity_base": "high",
        "detection_guidance": {
            "cloudtrail_events": ["GetObject", "CopyObject", "GetBucketAcl", "GetBucketPolicy", "CopyDBSnapshot", "CreateDBSnapshot"],
            "guardduty_types": ["Exfiltration:S3/MaliciousIPCaller", "Exfiltration:S3/AnomalousBehavior"],
            "cloudwatch_patterns": ["Bulk S3 GetObject from unusual IP", "RDS snapshot shared cross-account"],
            "data_sources": ["S3 Access Logs", "CloudTrail data events", "GuardDuty S3 Protection"],
        },
        "remediation_guidance": {
            "immediate": ["Block public access on all S3 buckets", "Revoke snapshot sharing"],
            "preventive": ["Enable S3 Block Public Access (account-level)", "Encrypt all data at rest", "Use VPC endpoints for S3"],
            "detective": ["Enable S3 access logging", "GuardDuty S3 protection", "Macie for sensitive data"],
            "aws_services": ["S3", "Macie", "GuardDuty", "KMS"],
        },
    },
    # ── Exfiltration ──────────────────────────────────────────────────────
    "T1537": {
        "severity_base": "critical",
        "detection_guidance": {
            "cloudtrail_events": ["ModifySnapshotAttribute", "CopySnapshot", "PutBucketPolicy", "ModifyDBSnapshotAttribute"],
            "guardduty_types": ["Exfiltration:S3/AnomalousBehavior", "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration"],
            "cloudwatch_patterns": ["Snapshot shared with external account", "S3 bucket policy allows external access"],
            "data_sources": ["CloudTrail", "IAM Access Analyzer", "GuardDuty"],
        },
        "remediation_guidance": {
            "immediate": ["Unshare all externally-shared snapshots", "Remove external S3 bucket policies"],
            "preventive": ["SCP deny ModifySnapshotAttribute to external accounts", "S3 Block Public Access", "Deny cross-account sharing SCPs"],
            "detective": ["IAM Access Analyzer (external access)", "Alert on ModifySnapshotAttribute", "GuardDuty exfiltration findings"],
            "aws_services": ["IAM Access Analyzer", "Organizations SCPs", "GuardDuty"],
        },
    },
    # ── Impact ────────────────────────────────────────────────────────────
    "T1485": {
        "severity_base": "critical",
        "detection_guidance": {
            "cloudtrail_events": ["DeleteBucket", "DeleteObject", "DeleteDBInstance", "DeleteVolume", "DeleteSnapshot", "TerminateInstances"],
            "guardduty_types": ["Impact:S3/AnomalousBehavior.Delete"],
            "cloudwatch_patterns": ["Bulk delete operations", "DeleteBucket after removing versioning"],
            "data_sources": ["CloudTrail", "S3 access logs", "Config"],
        },
        "remediation_guidance": {
            "immediate": ["Enable S3 versioning + MFA Delete", "Restore from backups", "Check if point-in-time recovery exists"],
            "preventive": ["S3 Object Lock (WORM)", "RDS deletion protection", "DynamoDB point-in-time recovery", "AWS Backup with vault lock"],
            "detective": ["Alert on DeleteBucket/DeleteDBInstance", "Config rule: s3-bucket-versioning-enabled"],
            "aws_services": ["S3 Object Lock", "AWS Backup", "RDS", "DynamoDB PITR"],
        },
    },
    "T1486": {
        "severity_base": "critical",
        "detection_guidance": {
            "cloudtrail_events": ["CreateKey", "Encrypt", "DisableKey", "ScheduleKeyDeletion", "PutBucketEncryption"],
            "guardduty_types": ["Impact:EC2/WinRMBruteForce", "CryptoCurrency:EC2/BitcoinTool.B"],
            "cloudwatch_patterns": ["Unusual KMS key creation", "Bulk encryption operations", "Key scheduled for deletion"],
            "data_sources": ["CloudTrail", "KMS events", "GuardDuty"],
        },
        "remediation_guidance": {
            "immediate": ["Cancel KMS key deletion", "Restore from unencrypted backups", "Isolate affected instances"],
            "preventive": ["Use customer-managed KMS keys", "Enable S3 Object Lock", "AWS Backup with vault lock", "Immutable backups"],
            "detective": ["Alert on ScheduleKeyDeletion", "Monitor bulk Encrypt calls", "GuardDuty ransomware findings"],
            "aws_services": ["KMS", "AWS Backup Vault Lock", "S3 Object Lock"],
        },
    },
    "T1490": {
        "severity_base": "critical",
        "detection_guidance": {
            "cloudtrail_events": ["DeleteSnapshot", "DeregisterImage", "DeleteBackupVault", "DeleteRecoveryPoint", "DeleteDBSnapshot"],
            "guardduty_types": [],
            "cloudwatch_patterns": ["Backup deletion spike", "AMI deregistered", "Snapshot deleted after creation"],
            "data_sources": ["CloudTrail", "AWS Backup events"],
        },
        "remediation_guidance": {
            "immediate": ["Stop backup deletions", "Enable vault lock on remaining backups"],
            "preventive": ["AWS Backup Vault Lock (compliance mode)", "SCP deny DeleteSnapshot/DeleteRecoveryPoint", "MFA Delete on S3 versioning"],
            "detective": ["Alert on DeleteSnapshot/DeleteRecoveryPoint", "Monitor backup job status"],
            "aws_services": ["AWS Backup", "EBS", "RDS", "S3 MFA Delete"],
        },
    },
    "T1496": {
        "severity_base": "high",
        "detection_guidance": {
            "cloudtrail_events": ["RunInstances", "CreateFunction", "RunTask"],
            "guardduty_types": ["CryptoCurrency:EC2/BitcoinTool.B", "CryptoCurrency:EC2/BitcoinTool.B!DNS", "CryptoCurrency:Lambda/CryptoCurrency.B"],
            "cloudwatch_patterns": ["Sustained high CPU on EC2", "Lambda high invocation in unusual region", "Outbound traffic to mining pools"],
            "data_sources": ["GuardDuty", "CloudWatch Metrics", "VPC Flow Logs"],
        },
        "remediation_guidance": {
            "immediate": ["Terminate mining instances", "Delete unauthorized Lambda functions", "Block mining pool IPs"],
            "preventive": ["SCP restrict regions", "Instance type restrictions", "Budget alerts for unexpected spend"],
            "detective": ["GuardDuty crypto-mining detection", "Cost anomaly detection", "CloudWatch CPU alarms"],
            "aws_services": ["GuardDuty", "Cost Explorer", "Budgets", "EC2"],
        },
    },
    "T1531": {
        "severity_base": "critical",
        "detection_guidance": {
            "cloudtrail_events": ["DeleteUser", "DeleteAccessKey", "DeleteLoginProfile", "RemoveUserFromGroup", "DetachUserPolicy"],
            "guardduty_types": ["Persistence:IAMUser/AnomalousBehavior"],
            "cloudwatch_patterns": ["Bulk IAM user deletion", "Access keys deleted for multiple users"],
            "data_sources": ["CloudTrail", "Config"],
        },
        "remediation_guidance": {
            "immediate": ["Restore deleted users from backup/re-create", "Investigate attacker's identity"],
            "preventive": ["SCP deny DeleteUser except from admin role", "Break-glass procedures for account recovery"],
            "detective": ["Alert on DeleteUser/DeleteAccessKey events", "Config rule: iam-root-access-key-check"],
            "aws_services": ["IAM", "Organizations SCPs", "Config"],
        },
    },
    "T1489": {
        "severity_base": "high",
        "detection_guidance": {
            "cloudtrail_events": ["StopInstances", "TerminateInstances", "DeleteFunction", "StopDBInstance", "StopDBCluster"],
            "guardduty_types": [],
            "cloudwatch_patterns": ["Bulk StopInstances/TerminateInstances", "Production resources stopped"],
            "data_sources": ["CloudTrail", "EventBridge", "Config"],
        },
        "remediation_guidance": {
            "immediate": ["Restart stopped instances", "Restore terminated resources from snapshots"],
            "preventive": ["Enable EC2 termination protection", "RDS deletion protection", "Tag-based IAM conditions for production"],
            "detective": ["Alert on StopInstances/TerminateInstances in production", "EventBridge rules for state changes"],
            "aws_services": ["EC2", "RDS", "EventBridge", "Config"],
        },
    },
    # ── Lateral Movement ──────────────────────────────────────────────────
    "T1021": {
        "severity_base": "medium",
        "detection_guidance": {
            "cloudtrail_events": ["AssumeRole", "StartSession", "SendCommand"],
            "guardduty_types": ["UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration"],
            "cloudwatch_patterns": ["Session Manager sessions from unusual users", "Cross-account AssumeRole"],
            "data_sources": ["CloudTrail", "Session Manager logs", "VPC Flow Logs"],
        },
        "remediation_guidance": {
            "immediate": ["Revoke active SSM sessions", "Block suspicious AssumeRole"],
            "preventive": ["Use Session Manager instead of SSH/RDP", "Enforce MFA on role assumption", "Use VPC endpoints"],
            "detective": ["Log Session Manager sessions", "Alert on cross-account role assumptions"],
            "aws_services": ["Systems Manager", "IAM", "VPC Endpoints"],
        },
    },
    # ── Brute Force techniques ────────────────────────────────────────────
    "T1110": {
        "severity_base": "medium",
        "detection_guidance": {
            "cloudtrail_events": ["ConsoleLogin"],
            "guardduty_types": ["UnauthorizedAccess:IAMUser/ConsoleLogin", "Recon:IAMUser/MaliciousIPCaller"],
            "cloudwatch_patterns": ["Multiple failed ConsoleLogin events", "Rapid login attempts"],
            "data_sources": ["CloudTrail", "GuardDuty"],
        },
        "remediation_guidance": {
            "immediate": ["Lock affected accounts", "Enable MFA"],
            "preventive": ["Strong password policy", "MFA required", "Account lockout via Lambda custom solution"],
            "detective": ["GuardDuty brute-force detection", "CloudWatch alarm on failed logins"],
            "aws_services": ["IAM", "GuardDuty", "CloudWatch"],
        },
    },
    # ── Authentication manipulation ───────────────────────────────────────
    "T1556": {
        "severity_base": "high",
        "detection_guidance": {
            "cloudtrail_events": ["CreateSAMLProvider", "UpdateSAMLProvider", "DeactivateMFADevice", "DeleteVirtualMFADevice", "EnableMFADevice"],
            "guardduty_types": ["Persistence:IAMUser/AnomalousBehavior"],
            "cloudwatch_patterns": ["MFA device deactivated", "SAML provider modified", "Federation settings changed"],
            "data_sources": ["CloudTrail", "Config"],
        },
        "remediation_guidance": {
            "immediate": ["Re-enable MFA on affected users", "Revert SAML provider changes"],
            "preventive": ["SCP deny DeactivateMFADevice", "Audit SAML providers regularly", "Hardware MFA for root"],
            "detective": ["Alert on MFA deactivation events", "Config rule: mfa-enabled-for-iam-console-access"],
            "aws_services": ["IAM", "Config", "Organizations SCPs"],
        },
    },
    # ── Secrets from password stores ──────────────────────────────────────
    "T1555.006": {
        "severity_base": "high",
        "detection_guidance": {
            "cloudtrail_events": ["GetSecretValue", "GetParameter", "BatchGetSecretValue", "ListSecrets"],
            "guardduty_types": ["CredentialAccess:IAMUser/AnomalousBehavior"],
            "cloudwatch_patterns": ["Bulk GetSecretValue calls", "Secrets accessed from unusual identity"],
            "data_sources": ["CloudTrail", "Secrets Manager audit logs"],
        },
        "remediation_guidance": {
            "immediate": ["Rotate all accessed secrets", "Review who accessed which secrets"],
            "preventive": ["Least-privilege access to Secrets Manager", "Automatic secret rotation", "Resource-based policies on secrets"],
            "detective": ["Alert on GetSecretValue from unusual identities", "Monitor ListSecrets calls"],
            "aws_services": ["Secrets Manager", "KMS", "IAM"],
        },
    },
    # ── Event triggered execution ─────────────────────────────────────────
    "T1546": {
        "severity_base": "medium",
        "detection_guidance": {
            "cloudtrail_events": ["PutRule", "PutTargets", "CreateEventSourceMapping", "PutBucketNotificationConfiguration"],
            "guardduty_types": [],
            "cloudwatch_patterns": ["New EventBridge rule created", "S3 notification to unknown Lambda"],
            "data_sources": ["CloudTrail", "EventBridge"],
        },
        "remediation_guidance": {
            "immediate": ["Delete unauthorized event rules", "Remove suspicious Lambda triggers"],
            "preventive": ["SCP restrict EventBridge rule creation", "Review all event-driven triggers regularly"],
            "detective": ["Alert on PutRule/PutTargets events", "Audit Lambda triggers"],
            "aws_services": ["EventBridge", "Lambda", "CloudTrail"],
        },
    },
}


def _conn_str() -> str:
    host = os.getenv("THREAT_DB_HOST", "localhost")
    port = os.getenv("THREAT_DB_PORT", "5432")
    db = os.getenv("THREAT_DB_NAME", "threat_engine_threat")
    user = os.getenv("THREAT_DB_USER", "postgres")
    pwd = os.getenv("THREAT_DB_PASSWORD", "threat_password")
    return f"postgresql://{user}:{pwd}@{host}:{port}/{db}"


def seed_guidance(dry_run: bool = False):
    """Update mitre_technique_reference with detection + remediation guidance."""
    import psycopg2
    from psycopg2.extras import Json

    if dry_run:
        print(f"\n=== DRY RUN: {len(GUIDANCE)} techniques to update ===\n")
        for tid, g in sorted(GUIDANCE.items()):
            det = g.get("detection_guidance", {})
            rem = g.get("remediation_guidance", {})
            sev = g.get("severity_base", "?")
            ct_events = len(det.get("cloudtrail_events", []))
            gd_types = len(det.get("guardduty_types", []))
            imm_actions = len(rem.get("immediate", []))
            prev_actions = len(rem.get("preventive", []))
            print(f"  {tid:12s} | sev={sev:8s} | CT events={ct_events} | GD types={gd_types} | "
                  f"immediate={imm_actions} | preventive={prev_actions}")
        return

    conn = psycopg2.connect(_conn_str())
    try:
        with conn.cursor() as cur:
            updated = 0
            skipped = 0
            for technique_id, guidance in sorted(GUIDANCE.items()):
                cur.execute("""
                    UPDATE mitre_technique_reference
                    SET detection_guidance = %s,
                        remediation_guidance = %s,
                        severity_base = %s,
                        updated_at = %s
                    WHERE technique_id = %s
                """, (
                    Json(guidance.get("detection_guidance", {})),
                    Json(guidance.get("remediation_guidance", {})),
                    guidance.get("severity_base"),
                    datetime.now(timezone.utc),
                    technique_id,
                ))
                if cur.rowcount > 0:
                    updated += 1
                else:
                    skipped += 1
                    print(f"  WARNING: {technique_id} not found in mitre_technique_reference")

            conn.commit()
            print(f"\nUpdated {updated} techniques with detection + remediation guidance")
            if skipped:
                print(f"  Skipped {skipped} (not found in table)")

            # Stats
            cur.execute("""
                SELECT COUNT(*) as total,
                       COUNT(CASE WHEN detection_guidance != '{}' THEN 1 END) as with_detection,
                       COUNT(CASE WHEN remediation_guidance != '{}' THEN 1 END) as with_remediation,
                       COUNT(CASE WHEN severity_base IS NOT NULL THEN 1 END) as with_severity
                FROM mitre_technique_reference
            """)
            row = cur.fetchone()
            print(f"\n  Total techniques: {row[0]}")
            print(f"  With detection guidance:    {row[1]}/{row[0]}")
            print(f"  With remediation guidance:  {row[2]}/{row[0]}")
            print(f"  With severity_base:         {row[3]}/{row[0]}")
    finally:
        conn.close()


def main():
    dry_run = "--dry-run" in sys.argv
    seed_guidance(dry_run=dry_run)


if __name__ == "__main__":
    main()
