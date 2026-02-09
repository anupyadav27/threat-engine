#!/usr/bin/env python3
"""
Fill remaining MITRE guidance gaps for techniques referenced by rules.

18 techniques are referenced by rule_metadata but lack detection/remediation
guidance in mitre_technique_reference. This script adds AWS + Azure + GCP
guidance for all 18 to achieve 100% coverage.

Usage:
    python scripts/seed_mitre_gap_guidance.py --dry-run
    python scripts/seed_mitre_gap_guidance.py
"""

import argparse
import os
from typing import Any, Dict

import psycopg2
from psycopg2.extras import Json, RealDictCursor


def get_conn():
    return psycopg2.connect(
        host=os.getenv("THREAT_DB_HOST", "localhost"),
        port=int(os.getenv("THREAT_DB_PORT", "5432")),
        database=os.getenv("THREAT_DB_NAME", "threat_engine_threat"),
        user=os.getenv("THREAT_DB_USER", "postgres"),
        password=os.getenv("THREAT_DB_PASSWORD", ""),
    )


# ── Guidance data for the 18 gap techniques ─────────────────────────────────
# Each technique has: detection_guidance (aws + azure + gcp) and
#                     remediation_guidance (aws + azure + gcp)

GAP_GUIDANCE: Dict[str, Dict[str, Any]] = {

    # ── T1040: Network Sniffing ────────────────────────────────────────────
    "T1040": {
        "detection_guidance": {
            "cloudtrail_events": ["ec2:CreateTrafficMirrorSession", "ec2:CreateTrafficMirrorTarget"],
            "guardduty_types": ["UnauthorizedAccess:EC2/TorRelay"],
            "cloudwatch_patterns": ["VPC Traffic Mirroring session creation"],
            "data_sources": ["CloudTrail", "VPC Flow Logs", "Traffic Mirroring Logs"],
            "azure": {
                "activity_logs": ["Microsoft.Network/networkWatchers/packetCaptures/write"],
                "defender_alerts": ["Network packet capture detected"],
                "sentinel_rules": ["AzureActivity | where OperationName contains 'packetCaptures'"],
                "data_sources": ["Azure Activity Logs", "Network Watcher Logs"],
            },
            "gcp": {
                "audit_logs": ["compute.packetMirrorings.insert"],
                "scc_findings": [],
                "chronicle_rules": ["GCP Packet Mirroring session created"],
                "data_sources": ["Cloud Audit Logs", "VPC Flow Logs"],
            },
        },
        "remediation_guidance": {
            "immediate": ["Review VPC Traffic Mirroring sessions", "Audit packet capture configurations"],
            "preventive": ["Restrict Traffic Mirroring IAM permissions", "Use encrypted communication (TLS) for all services"],
            "aws_services": ["VPC Traffic Mirroring", "IAM", "VPC Flow Logs"],
            "azure": {
                "immediate": ["Review Network Watcher packet captures", "Audit NSG flow logs configuration"],
                "preventive": ["Restrict Network Watcher permissions", "Enforce encryption in transit"],
                "azure_services": ["Network Watcher", "NSG Flow Logs", "Azure Policy"],
            },
            "gcp": {
                "immediate": ["Review Packet Mirroring configurations", "Audit VPC flow logs"],
                "preventive": ["Restrict Packet Mirroring IAM permissions", "Use VPC Service Controls"],
                "gcp_services": ["Packet Mirroring", "VPC Flow Logs", "IAM"],
            },
        },
    },

    # ── T1046: Network Service Discovery ───────────────────────────────────
    "T1046": {
        "detection_guidance": {
            "cloudtrail_events": ["ec2:DescribeInstances", "ec2:DescribeSecurityGroups", "ec2:DescribeNetworkInterfaces"],
            "guardduty_types": ["Recon:EC2/PortProbeUnprotectedPort", "Recon:EC2/Portscan"],
            "cloudwatch_patterns": ["Unusual volume of Describe API calls from single principal"],
            "data_sources": ["CloudTrail", "GuardDuty", "VPC Flow Logs"],
            "azure": {
                "activity_logs": ["Microsoft.Network/networkInterfaces/read", "Microsoft.Network/networkSecurityGroups/read"],
                "defender_alerts": ["Port scanning detected", "Network enumeration activity"],
                "sentinel_rules": ["AzureNetworkAnalytics_CL | where FlowStatus_s == 'D' | summarize count() by SrcIP_s"],
                "data_sources": ["Azure Activity Logs", "NSG Flow Logs", "Azure Defender"],
            },
            "gcp": {
                "audit_logs": ["compute.instances.list", "compute.firewalls.list", "compute.networks.list"],
                "scc_findings": ["OPEN_FIREWALL"],
                "chronicle_rules": ["GCP excessive network enumeration API calls"],
                "data_sources": ["Cloud Audit Logs", "VPC Flow Logs"],
            },
        },
        "remediation_guidance": {
            "immediate": ["Review source of reconnaissance", "Block scanning IPs via security groups"],
            "preventive": ["Enable GuardDuty port scan detection", "Restrict network Describe permissions", "Use VPC endpoints to reduce exposure"],
            "aws_services": ["GuardDuty", "VPC Flow Logs", "Security Groups"],
            "azure": {
                "immediate": ["Review NSG flow logs for scanning patterns", "Block scanning IPs via NSG rules"],
                "preventive": ["Enable Azure Defender for network", "Restrict network read permissions"],
                "azure_services": ["Azure Defender", "NSG", "Network Watcher"],
            },
            "gcp": {
                "immediate": ["Review VPC flow logs for scanning patterns", "Update firewall rules to block scanners"],
                "preventive": ["Enable SCC Premium for network threat detection", "Use hierarchical firewall rules"],
                "gcp_services": ["SCC Premium", "VPC Firewall Rules", "Cloud Armor"],
            },
        },
    },

    # ── T1048: Exfiltration Over Alternative Protocol ──────────────────────
    "T1048": {
        "detection_guidance": {
            "cloudtrail_events": ["ec2:CreateVpcEndpoint", "s3:PutBucketPolicy"],
            "guardduty_types": ["Trojan:EC2/DNSDataExfiltration", "Exfiltration:S3/MaliciousIPCaller"],
            "cloudwatch_patterns": ["Unusual outbound traffic volume", "DNS query anomalies"],
            "data_sources": ["CloudTrail", "GuardDuty", "VPC Flow Logs", "Route 53 DNS Logs"],
            "azure": {
                "activity_logs": ["Microsoft.Network/dnsZones/write"],
                "defender_alerts": ["DNS tunneling detected", "Data exfiltration attempt"],
                "sentinel_rules": ["DnsEvents | where SubType == 'LookupQuery' | where Name contains_any (suspicious_domains)"],
                "data_sources": ["Azure DNS Logs", "Azure Firewall Logs", "Azure Defender"],
            },
            "gcp": {
                "audit_logs": ["dns.queries.report"],
                "scc_findings": ["DATA_EXFILTRATION"],
                "chronicle_rules": ["GCP DNS tunneling or unusual DNS query patterns"],
                "data_sources": ["Cloud DNS Logs", "VPC Flow Logs", "SCC Premium"],
            },
        },
        "remediation_guidance": {
            "immediate": ["Investigate anomalous DNS queries", "Block suspicious outbound connections"],
            "preventive": ["Enable GuardDuty DNS exfiltration detection", "Use VPC endpoints to restrict egress", "Enable Route 53 Resolver DNS Firewall"],
            "aws_services": ["GuardDuty", "Route 53 DNS Firewall", "VPC Flow Logs"],
            "azure": {
                "immediate": ["Review Azure Firewall logs for anomalous protocols", "Block suspicious DNS destinations"],
                "preventive": ["Enable Azure Firewall DNS proxy", "Use Private DNS Zones", "Deploy Azure Defender for DNS"],
                "azure_services": ["Azure Firewall", "Azure DNS", "Azure Defender"],
            },
            "gcp": {
                "immediate": ["Review Cloud DNS logs for tunneling patterns", "Block suspicious egress via firewall rules"],
                "preventive": ["Use Cloud DNS Response Policies", "Enable VPC Service Controls for data egress", "Deploy Cloud NAT with logging"],
                "gcp_services": ["Cloud DNS", "VPC Service Controls", "Cloud NAT"],
            },
        },
    },

    # ── T1049: System Network Connections Discovery ────────────────────────
    "T1049": {
        "detection_guidance": {
            "cloudtrail_events": ["ec2:DescribeNetworkInterfaces", "ec2:DescribeVpcPeeringConnections", "ec2:DescribeTransitGateways"],
            "guardduty_types": [],
            "cloudwatch_patterns": ["Burst of network topology Describe calls"],
            "data_sources": ["CloudTrail", "VPC Flow Logs"],
            "azure": {
                "activity_logs": ["Microsoft.Network/virtualNetworks/read", "Microsoft.Network/virtualNetworkPeerings/read"],
                "defender_alerts": [],
                "sentinel_rules": ["AzureActivity | where OperationName contains 'virtualNetwork' and OperationName endswith '/read'"],
                "data_sources": ["Azure Activity Logs"],
            },
            "gcp": {
                "audit_logs": ["compute.networks.list", "compute.subnetworks.list", "compute.interconnects.list"],
                "scc_findings": [],
                "chronicle_rules": ["GCP network topology enumeration"],
                "data_sources": ["Cloud Audit Logs"],
            },
        },
        "remediation_guidance": {
            "immediate": ["Review who is enumerating network topology", "Verify legitimate need for network read access"],
            "preventive": ["Restrict network Describe permissions to admin roles", "Use SCPs to limit network enumeration"],
            "aws_services": ["IAM", "CloudTrail", "Organizations SCPs"],
            "azure": {
                "immediate": ["Review principals with Network Reader role", "Audit recent network topology queries"],
                "preventive": ["Use custom RBAC roles without broad network read", "Enable activity log alerting for network enumeration"],
                "azure_services": ["Azure RBAC", "Azure Monitor Alerts"],
            },
            "gcp": {
                "immediate": ["Review principals with Compute Network Viewer", "Audit network API call patterns"],
                "preventive": ["Use IAM Recommender to reduce network permissions", "Custom roles without broad compute.networks.* access"],
                "gcp_services": ["IAM Recommender", "Custom Roles", "Organization Policies"],
            },
        },
    },

    # ── T1059: Command and Scripting Interpreter ───────────────────────────
    "T1059": {
        "detection_guidance": {
            "cloudtrail_events": ["ssm:SendCommand", "lambda:InvokeFunction", "ecs:ExecuteCommand"],
            "guardduty_types": ["Execution:Runtime/NewBinaryExecuted", "Execution:Runtime/SuspiciousCommand"],
            "cloudwatch_patterns": ["SSM RunCommand executions", "Lambda invocations from unusual sources"],
            "data_sources": ["CloudTrail", "GuardDuty Runtime Monitoring", "SSM Logs"],
            "azure": {
                "activity_logs": ["Microsoft.Compute/virtualMachines/runCommand/action", "Microsoft.Automation/automationAccounts/runbooks/draft/write"],
                "defender_alerts": ["Suspicious command execution", "Unusual script activity"],
                "sentinel_rules": ["AzureActivity | where OperationName contains 'runCommand'"],
                "data_sources": ["Azure Activity Logs", "Azure Defender", "Automation Logs"],
            },
            "gcp": {
                "audit_logs": ["compute.instances.setMetadata (startup-script)", "cloudfunctions.functions.call"],
                "scc_findings": ["EXECUTION_THREAT"],
                "chronicle_rules": ["GCP Run Command or startup script modification"],
                "data_sources": ["Cloud Audit Logs", "Cloud Functions Logs", "OS Login Logs"],
            },
        },
        "remediation_guidance": {
            "immediate": ["Review recent SSM RunCommand/Lambda invocations", "Check for unauthorized script execution"],
            "preventive": ["Restrict SSM SendCommand to specific instances", "Use Lambda function URLs with IAM auth", "Enable GuardDuty Runtime Monitoring"],
            "aws_services": ["SSM", "GuardDuty Runtime Monitoring", "Lambda"],
            "azure": {
                "immediate": ["Review Run Command history", "Audit Automation Account runbook executions"],
                "preventive": ["Restrict Run Command permissions", "Use Managed Identity for automation", "Enable Azure Defender for Servers"],
                "azure_services": ["Azure Automation", "Azure Defender", "Run Command"],
            },
            "gcp": {
                "immediate": ["Review startup script changes", "Audit Cloud Functions invocations"],
                "preventive": ["Restrict setMetadata permissions", "Use Cloud Functions with VPC connector", "Enable SCC Premium"],
                "gcp_services": ["Cloud Functions", "Compute Engine", "SCC Premium"],
            },
        },
    },

    # ── T1069: Permission Groups Discovery ─────────────────────────────────
    "T1069": {
        "detection_guidance": {
            "cloudtrail_events": ["iam:ListGroups", "iam:ListGroupsForUser", "iam:GetGroup", "iam:ListAttachedGroupPolicies"],
            "guardduty_types": ["Recon:IAMUser/UserPermissions"],
            "cloudwatch_patterns": ["Burst of IAM group enumeration calls"],
            "data_sources": ["CloudTrail", "GuardDuty"],
            "azure": {
                "activity_logs": ["Microsoft.Authorization/roleAssignments/read"],
                "defender_alerts": ["Azure AD enumeration detected"],
                "sentinel_rules": ["AuditLogs | where OperationName contains 'List groups' | summarize count() by InitiatedBy"],
                "data_sources": ["Azure AD Audit Logs", "Azure Activity Logs"],
            },
            "gcp": {
                "audit_logs": ["iam.roles.list", "cloudresourcemanager.projects.getIamPolicy"],
                "scc_findings": [],
                "chronicle_rules": ["GCP IAM role/group enumeration by single principal"],
                "data_sources": ["Cloud Audit Logs", "Workspace Admin Audit"],
            },
        },
        "remediation_guidance": {
            "immediate": ["Review principal performing group enumeration", "Check for compromised credentials"],
            "preventive": ["Restrict IAM List/Get permissions", "Use SCPs to limit IAM reconnaissance", "Enable GuardDuty IAM finding types"],
            "aws_services": ["GuardDuty", "IAM", "Organizations SCPs"],
            "azure": {
                "immediate": ["Review Azure AD audit logs for enumeration", "Verify enumeration is authorized"],
                "preventive": ["Restrict Azure AD directory read permissions", "Use Conditional Access to limit enumeration sources"],
                "azure_services": ["Azure AD", "Conditional Access", "Azure Monitor"],
            },
            "gcp": {
                "immediate": ["Review IAM API call patterns", "Verify enumeration is from authorized service"],
                "preventive": ["Use custom roles without broad IAM read", "Organization policies to restrict IAM queries"],
                "gcp_services": ["IAM", "Custom Roles", "Organization Policies"],
            },
        },
    },

    # ── T1087: Account Discovery ───────────────────────────────────────────
    "T1087": {
        "detection_guidance": {
            "cloudtrail_events": ["iam:ListUsers", "iam:ListRoles", "iam:ListServiceAccounts", "sts:GetCallerIdentity"],
            "guardduty_types": ["Recon:IAMUser/UserPermissions"],
            "cloudwatch_patterns": ["Excessive IAM user/role listing"],
            "data_sources": ["CloudTrail", "GuardDuty"],
            "azure": {
                "activity_logs": ["Microsoft.Authorization/roleDefinitions/read"],
                "defender_alerts": ["Account enumeration detected"],
                "sentinel_rules": ["AuditLogs | where OperationName == 'List users' | summarize count() by InitiatedBy"],
                "data_sources": ["Azure AD Audit Logs"],
            },
            "gcp": {
                "audit_logs": ["iam.serviceAccounts.list", "admin.googleapis.com/AdminService/listUsers"],
                "scc_findings": [],
                "chronicle_rules": ["GCP bulk account enumeration"],
                "data_sources": ["Cloud Audit Logs", "Workspace Admin Audit"],
            },
        },
        "remediation_guidance": {
            "immediate": ["Review source of account enumeration", "Verify credentials are not compromised"],
            "preventive": ["Restrict IAM ListUsers/ListRoles to admin roles", "Use SCPs to limit IAM reconnaissance"],
            "aws_services": ["IAM", "Organizations SCPs", "GuardDuty"],
            "azure": {
                "immediate": ["Review Azure AD audit logs for enumeration activity", "Check for compromised accounts"],
                "preventive": ["Restrict directory read access", "Enable Azure AD Identity Protection"],
                "azure_services": ["Azure AD", "Identity Protection", "Conditional Access"],
            },
            "gcp": {
                "immediate": ["Review IAM API call patterns for bulk listing", "Check for compromised service accounts"],
                "preventive": ["Use custom roles without broad IAM read", "Enable SCC for anomaly detection"],
                "gcp_services": ["IAM", "SCC", "Custom Roles"],
            },
        },
    },

    # ── T1119: Automated Collection ────────────────────────────────────────
    "T1119": {
        "detection_guidance": {
            "cloudtrail_events": ["s3:GetObject (bulk)", "s3:ListBucket", "rds:DownloadDBLogFilePortion"],
            "guardduty_types": ["Exfiltration:S3/AnomalousBehavior"],
            "cloudwatch_patterns": ["Unusual bulk S3 GetObject calls", "High-volume data access patterns"],
            "data_sources": ["CloudTrail Data Events", "S3 Access Logs", "GuardDuty S3 Protection"],
            "azure": {
                "activity_logs": ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read (bulk)"],
                "defender_alerts": ["Unusual data access pattern", "Bulk download from storage"],
                "sentinel_rules": ["StorageBlobLogs | summarize TotalBytes=sum(ResponseBodySize) by CallerIpAddress | where TotalBytes > threshold"],
                "data_sources": ["Storage Analytics Logs", "Azure Defender for Storage"],
            },
            "gcp": {
                "audit_logs": ["storage.objects.get (bulk)", "storage.objects.list"],
                "scc_findings": ["DATA_EXFILTRATION"],
                "chronicle_rules": ["GCP bulk data download from Cloud Storage"],
                "data_sources": ["Cloud Audit Logs (Data Access)", "Cloud Storage Logs"],
            },
        },
        "remediation_guidance": {
            "immediate": ["Investigate bulk data access patterns", "Review access credentials used"],
            "preventive": ["Enable S3 data event logging", "Use S3 Object Lock for sensitive data", "Implement VPC endpoints for S3 access"],
            "aws_services": ["S3 Access Logs", "GuardDuty S3 Protection", "Macie"],
            "azure": {
                "immediate": ["Review Storage Analytics logs for bulk access", "Investigate access patterns"],
                "preventive": ["Enable Azure Defender for Storage", "Use Private Endpoints for storage", "Implement Azure Information Protection"],
                "azure_services": ["Azure Defender for Storage", "Private Endpoints", "Azure Information Protection"],
            },
            "gcp": {
                "immediate": ["Review Cloud Storage access logs for bulk downloads", "Investigate source principals"],
                "preventive": ["Enable Data Access audit logging", "Use VPC Service Controls", "Implement DLP API scanning"],
                "gcp_services": ["Data Access Logs", "VPC Service Controls", "Cloud DLP"],
            },
        },
    },

    # ── T1136: Create Account ──────────────────────────────────────────────
    "T1136": {
        "detection_guidance": {
            "cloudtrail_events": ["iam:CreateUser", "iam:CreateRole", "iam:CreateLoginProfile"],
            "guardduty_types": ["Persistence:IAMUser/AnomalousBehavior"],
            "cloudwatch_patterns": ["New IAM user created outside of IaC pipeline"],
            "data_sources": ["CloudTrail", "GuardDuty", "AWS Config"],
            "azure": {
                "activity_logs": ["Microsoft.Authorization/roleAssignments/write"],
                "defender_alerts": ["New account created outside normal process"],
                "sentinel_rules": ["AuditLogs | where OperationName == 'Add user' and InitiatedBy !in (approved_services)"],
                "data_sources": ["Azure AD Audit Logs"],
            },
            "gcp": {
                "audit_logs": ["iam.serviceAccounts.create", "admin.googleapis.com/AdminService/createUser"],
                "scc_findings": ["ADMIN_SERVICE_ACCOUNT"],
                "chronicle_rules": ["GCP new service account or user created outside approved process"],
                "data_sources": ["Cloud Audit Logs", "Workspace Admin Audit"],
            },
        },
        "remediation_guidance": {
            "immediate": ["Review newly created accounts", "Verify account creation was authorized"],
            "preventive": ["Use IaC for all account creation", "SCPs to restrict CreateUser to specific roles", "Enable AWS Config rule for unauthorized users"],
            "aws_services": ["IAM", "Organizations SCPs", "AWS Config"],
            "azure": {
                "immediate": ["Review recently created Azure AD accounts", "Verify authorization"],
                "preventive": ["Use PIM for account creation", "Azure AD access reviews", "Conditional Access for new accounts"],
                "azure_services": ["Azure AD PIM", "Access Reviews", "Conditional Access"],
            },
            "gcp": {
                "immediate": ["Review recently created service accounts", "Audit new user accounts"],
                "preventive": ["Organization policies to restrict SA creation", "Use Terraform/IaC for all account provisioning"],
                "gcp_services": ["IAM", "Organization Policies", "Cloud Identity"],
            },
        },
    },

    # ── T1201: Password Policy Discovery ───────────────────────────────────
    "T1201": {
        "detection_guidance": {
            "cloudtrail_events": ["iam:GetAccountPasswordPolicy"],
            "guardduty_types": [],
            "cloudwatch_patterns": ["Password policy query from unusual source"],
            "data_sources": ["CloudTrail"],
            "azure": {
                "activity_logs": [],
                "defender_alerts": [],
                "sentinel_rules": ["AuditLogs | where OperationName contains 'password policy'"],
                "data_sources": ["Azure AD Audit Logs"],
            },
            "gcp": {
                "audit_logs": ["admin.googleapis.com/AdminService/getPasswordPolicy"],
                "scc_findings": [],
                "chronicle_rules": ["GCP password policy enumeration"],
                "data_sources": ["Workspace Admin Audit"],
            },
        },
        "remediation_guidance": {
            "immediate": ["Review who queried password policy", "Check for follow-up brute force attempts"],
            "preventive": ["Enforce strong password policies", "Enable MFA to reduce password dependency", "Monitor for password policy queries"],
            "aws_services": ["IAM Password Policy", "CloudWatch Alarms"],
            "azure": {
                "immediate": ["Review password policy query sources", "Monitor for brute force follow-up"],
                "preventive": ["Enforce strong password policies via Azure AD", "Enable Passwordless authentication"],
                "azure_services": ["Azure AD", "Password Protection", "Passwordless Auth"],
            },
            "gcp": {
                "immediate": ["Review password policy query sources", "Monitor for brute force follow-up"],
                "preventive": ["Enforce strong password policies in Cloud Identity", "Enable 2-Step Verification"],
                "gcp_services": ["Cloud Identity", "Security Key Enforcement"],
            },
        },
    },

    # ── T1204: User Execution ──────────────────────────────────────────────
    "T1204": {
        "detection_guidance": {
            "cloudtrail_events": ["lambda:InvokeFunction", "ec2:RunInstances (with user-data)"],
            "guardduty_types": ["Execution:Runtime/SuspiciousCommand"],
            "cloudwatch_patterns": ["Lambda invocation from untrusted source", "EC2 launch with suspicious user-data"],
            "data_sources": ["CloudTrail", "GuardDuty Runtime Monitoring"],
            "azure": {
                "activity_logs": ["Microsoft.Compute/virtualMachines/extensions/write"],
                "defender_alerts": ["Suspicious VM extension installed", "Malicious script execution"],
                "sentinel_rules": ["AzureActivity | where OperationName contains 'extensions/write'"],
                "data_sources": ["Azure Activity Logs", "Azure Defender for Servers"],
            },
            "gcp": {
                "audit_logs": ["compute.instances.setMetadata", "cloudfunctions.functions.create"],
                "scc_findings": [],
                "chronicle_rules": ["GCP suspicious startup script or function deployment"],
                "data_sources": ["Cloud Audit Logs", "Cloud Functions Logs"],
            },
        },
        "remediation_guidance": {
            "immediate": ["Review recently executed scripts/functions", "Check for malicious payloads"],
            "preventive": ["Restrict Lambda/EC2 launch permissions", "Use approved AMIs only", "Enable GuardDuty Runtime Monitoring"],
            "aws_services": ["GuardDuty", "Lambda", "EC2 AMI Management"],
            "azure": {
                "immediate": ["Review VM extension installations", "Check for malicious custom scripts"],
                "preventive": ["Restrict VM extension permissions", "Use Azure Policy to allow only approved extensions"],
                "azure_services": ["Azure Defender", "Azure Policy", "VM Extensions"],
            },
            "gcp": {
                "immediate": ["Review startup script modifications", "Audit Cloud Function deployments"],
                "preventive": ["Restrict setMetadata permissions", "Use Binary Authorization for containers"],
                "gcp_services": ["Binary Authorization", "Compute Engine", "Cloud Functions"],
            },
        },
    },

    # ── T1491: Defacement ──────────────────────────────────────────────────
    "T1491": {
        "detection_guidance": {
            "cloudtrail_events": ["s3:PutObject (on website bucket)", "cloudfront:UpdateDistribution"],
            "guardduty_types": [],
            "cloudwatch_patterns": ["Website bucket content modification", "CloudFront origin change"],
            "data_sources": ["CloudTrail", "S3 Access Logs", "CloudFront Logs"],
            "azure": {
                "activity_logs": ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write ($web container)"],
                "defender_alerts": ["Static website content modified"],
                "sentinel_rules": ["StorageBlobLogs | where ObjectKey contains '$web' and OperationName == 'PutBlob'"],
                "data_sources": ["Storage Analytics Logs", "Azure CDN Logs"],
            },
            "gcp": {
                "audit_logs": ["storage.objects.create (on website bucket)"],
                "scc_findings": [],
                "chronicle_rules": ["GCP static website bucket content modified"],
                "data_sources": ["Cloud Storage Logs", "Cloud CDN Logs"],
            },
        },
        "remediation_guidance": {
            "immediate": ["Restore website content from backup", "Restrict write access to website bucket"],
            "preventive": ["Enable S3 Object Versioning", "Use CloudFront with OAI", "MFA Delete on website buckets"],
            "aws_services": ["S3 Versioning", "CloudFront OAI", "MFA Delete"],
            "azure": {
                "immediate": ["Restore $web container from backup", "Review storage account access"],
                "preventive": ["Enable blob versioning", "Use Azure CDN with access restrictions", "Resource Lock on storage account"],
                "azure_services": ["Blob Versioning", "Azure CDN", "Resource Locks"],
            },
            "gcp": {
                "immediate": ["Restore website bucket from versioned backup", "Review bucket ACLs"],
                "preventive": ["Enable Object Versioning", "Use Cloud CDN with signed URLs", "Restrict bucket write access"],
                "gcp_services": ["Object Versioning", "Cloud CDN", "IAM"],
            },
        },
    },

    # ── T1498: Network Denial of Service ───────────────────────────────────
    "T1498": {
        "detection_guidance": {
            "cloudtrail_events": [],
            "guardduty_types": ["Backdoor:EC2/DenialOfService.Tcp", "Backdoor:EC2/DenialOfService.Udp"],
            "cloudwatch_patterns": ["Network traffic volume spike", "ALB/NLB connection count surge"],
            "data_sources": ["GuardDuty", "VPC Flow Logs", "AWS Shield Metrics", "CloudWatch Network Metrics"],
            "azure": {
                "activity_logs": [],
                "defender_alerts": ["DDoS attack detected"],
                "sentinel_rules": ["AzureDiagnostics | where Category == 'DDoSProtectionNotifications'"],
                "data_sources": ["Azure DDoS Protection Logs", "Azure Monitor Metrics"],
            },
            "gcp": {
                "audit_logs": [],
                "scc_findings": [],
                "chronicle_rules": ["GCP abnormal network traffic volume"],
                "data_sources": ["VPC Flow Logs", "Cloud Armor Logs", "Cloud Monitoring Metrics"],
            },
        },
        "remediation_guidance": {
            "immediate": ["Enable AWS Shield Advanced if not active", "Contact AWS DDoS Response Team"],
            "preventive": ["Deploy AWS Shield Advanced", "Use CloudFront for DDoS absorption", "Configure WAF rate-based rules"],
            "aws_services": ["AWS Shield", "CloudFront", "WAF", "Route 53"],
            "azure": {
                "immediate": ["Verify DDoS Protection Standard is active", "Review Azure Firewall rules"],
                "preventive": ["Enable DDoS Protection Standard on VNets", "Use Azure Front Door for absorption", "Configure WAF rate limiting"],
                "azure_services": ["DDoS Protection Standard", "Azure Front Door", "Azure WAF"],
            },
            "gcp": {
                "immediate": ["Enable Cloud Armor if not active", "Review current rate limiting rules"],
                "preventive": ["Deploy Cloud Armor with adaptive protection", "Use Cloud CDN for absorption", "Configure rate-based security policies"],
                "gcp_services": ["Cloud Armor", "Cloud CDN", "Cloud Load Balancing"],
            },
        },
    },

    # ── T1499: Endpoint Denial of Service ──────────────────────────────────
    "T1499": {
        "detection_guidance": {
            "cloudtrail_events": [],
            "guardduty_types": ["Backdoor:EC2/DenialOfService.Tcp"],
            "cloudwatch_patterns": ["Application-layer request spike", "5xx error rate increase"],
            "data_sources": ["GuardDuty", "ALB Access Logs", "CloudWatch Application Metrics"],
            "azure": {
                "activity_logs": [],
                "defender_alerts": ["Application DDoS attack"],
                "sentinel_rules": ["AzureDiagnostics | where httpStatusCode_d >= 500 | summarize count() by bin(TimeGenerated, 1m)"],
                "data_sources": ["Application Gateway Logs", "Azure Monitor Metrics"],
            },
            "gcp": {
                "audit_logs": [],
                "scc_findings": [],
                "chronicle_rules": ["GCP application-layer request volume anomaly"],
                "data_sources": ["Cloud Load Balancer Logs", "Cloud Monitoring"],
            },
        },
        "remediation_guidance": {
            "immediate": ["Enable WAF rate-based rules", "Scale out application tier"],
            "preventive": ["Deploy WAF with bot control", "Use Auto Scaling with aggressive policies", "Implement API throttling"],
            "aws_services": ["WAF Bot Control", "Auto Scaling", "CloudFront"],
            "azure": {
                "immediate": ["Enable Application Gateway WAF rules", "Scale out App Service/VMSS"],
                "preventive": ["Deploy Azure WAF with bot protection", "Use Application Gateway autoscaling", "Implement API Management rate limiting"],
                "azure_services": ["Azure WAF", "Application Gateway", "API Management"],
            },
            "gcp": {
                "immediate": ["Enable Cloud Armor rate limiting", "Scale out managed instance groups"],
                "preventive": ["Deploy Cloud Armor with adaptive protection", "Use Cloud CDN caching", "Implement API Gateway throttling"],
                "gcp_services": ["Cloud Armor", "Cloud CDN", "API Gateway", "Managed Instance Groups"],
            },
        },
    },

    # ── T1526: Cloud Service Discovery ─────────────────────────────────────
    "T1526": {
        "detection_guidance": {
            "cloudtrail_events": ["organizations:ListAccounts", "ec2:DescribeRegions", "s3:ListBuckets", "rds:DescribeDBInstances"],
            "guardduty_types": ["Discovery:S3/AnomalousBehavior"],
            "cloudwatch_patterns": ["Broad service enumeration across multiple AWS services"],
            "data_sources": ["CloudTrail", "GuardDuty"],
            "azure": {
                "activity_logs": ["Microsoft.Resources/subscriptions/resources/read"],
                "defender_alerts": ["Cloud resource enumeration"],
                "sentinel_rules": ["AzureActivity | where OperationName endswith '/read' | summarize dcount(OperationName) by Caller | where dcount_ > 20"],
                "data_sources": ["Azure Activity Logs"],
            },
            "gcp": {
                "audit_logs": ["cloudasset.assets.searchAllResources", "cloudresourcemanager.projects.list"],
                "scc_findings": [],
                "chronicle_rules": ["GCP broad resource enumeration across services"],
                "data_sources": ["Cloud Audit Logs", "Cloud Asset Inventory Logs"],
            },
        },
        "remediation_guidance": {
            "immediate": ["Review principal performing broad enumeration", "Check for credential compromise"],
            "preventive": ["Restrict broad Describe/List permissions", "Use SCPs to limit cross-service discovery", "Enable GuardDuty for anomaly detection"],
            "aws_services": ["GuardDuty", "Organizations SCPs", "IAM Access Analyzer"],
            "azure": {
                "immediate": ["Review principals with Reader role at subscription level", "Audit enumeration patterns"],
                "preventive": ["Use custom RBAC roles without broad read", "Enable Azure Defender for cloud"],
                "azure_services": ["Azure RBAC", "Azure Defender", "Azure Monitor"],
            },
            "gcp": {
                "immediate": ["Review principals with Viewer role at org/project level", "Audit Cloud Asset API usage"],
                "preventive": ["Use custom roles without broad resource read", "IAM Recommender to right-size"],
                "gcp_services": ["IAM Recommender", "Custom Roles", "Cloud Asset Inventory"],
            },
        },
    },

    # ── T1538: Cloud Service Dashboard ─────────────────────────────────────
    "T1538": {
        "detection_guidance": {
            "cloudtrail_events": ["signin:ConsoleLogin", "iam:GetAccountSummary"],
            "guardduty_types": ["UnauthorizedAccess:IAMUser/ConsoleLogin"],
            "cloudwatch_patterns": ["Console login from unusual location or IP"],
            "data_sources": ["CloudTrail", "GuardDuty"],
            "azure": {
                "activity_logs": [],
                "defender_alerts": ["Suspicious sign-in to Azure portal"],
                "sentinel_rules": ["SigninLogs | where AppDisplayName == 'Azure Portal' and RiskLevel != 'none'"],
                "data_sources": ["Azure AD Sign-in Logs"],
            },
            "gcp": {
                "audit_logs": ["console.cloud.google.com access"],
                "scc_findings": [],
                "chronicle_rules": ["GCP Console access from anomalous location"],
                "data_sources": ["Workspace Login Audit", "Cloud Identity Logs"],
            },
        },
        "remediation_guidance": {
            "immediate": ["Review console login events for unauthorized access", "Verify login location and IP"],
            "preventive": ["Enforce MFA for console access", "Use Conditional Access / Context-Aware Access", "Restrict console access to VPN IPs"],
            "aws_services": ["IAM MFA", "Organizations SCPs", "GuardDuty"],
            "azure": {
                "immediate": ["Review Azure portal sign-in logs", "Check for risky sign-ins"],
                "preventive": ["Conditional Access requiring compliant device", "Enable Azure AD Identity Protection", "Restrict portal access to trusted IPs"],
                "azure_services": ["Conditional Access", "Identity Protection", "Named Locations"],
            },
            "gcp": {
                "immediate": ["Review Cloud Console access logs", "Check for anomalous locations"],
                "preventive": ["Enable Context-Aware Access for Console", "Enforce 2SV for all users", "Use BeyondCorp for zero-trust access"],
                "gcp_services": ["BeyondCorp Enterprise", "Context-Aware Access", "Cloud Identity"],
            },
        },
    },

    # ── T1550: Use Alternate Authentication Material ───────────────────────
    "T1550": {
        "detection_guidance": {
            "cloudtrail_events": ["sts:AssumeRole", "sts:AssumeRoleWithSAML", "sts:AssumeRoleWithWebIdentity"],
            "guardduty_types": ["UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration"],
            "cloudwatch_patterns": ["STS AssumeRole from unusual source IP", "Session token used from different region"],
            "data_sources": ["CloudTrail", "GuardDuty"],
            "azure": {
                "activity_logs": ["Microsoft.Authorization/roleAssignments/write"],
                "defender_alerts": ["Token replay attack detected", "Suspicious token usage"],
                "sentinel_rules": ["AADServicePrincipalSignInLogs | where ResultType == 0 and IPAddress !in (known_ips)"],
                "data_sources": ["Azure AD Sign-in Logs", "Azure AD Audit Logs"],
            },
            "gcp": {
                "audit_logs": ["iam.serviceAccounts.generateAccessToken", "iam.serviceAccounts.signJwt"],
                "scc_findings": [],
                "chronicle_rules": ["GCP service account token generated from unusual source"],
                "data_sources": ["Cloud Audit Logs", "Service Account Activity Logs"],
            },
        },
        "remediation_guidance": {
            "immediate": ["Revoke compromised session tokens", "Rotate affected role credentials"],
            "preventive": ["Shorten STS session duration", "Use IP condition keys in role trust policies", "Enable GuardDuty credential exfiltration detection"],
            "aws_services": ["STS", "IAM Role Trust Policies", "GuardDuty"],
            "azure": {
                "immediate": ["Revoke refresh tokens", "Force re-authentication for affected users"],
                "preventive": ["Enable Continuous Access Evaluation", "Token lifetime policies", "Conditional Access for token binding"],
                "azure_services": ["CAE", "Token Lifetime Policies", "Conditional Access"],
            },
            "gcp": {
                "immediate": ["Revoke compromised service account tokens", "Rotate service account keys"],
                "preventive": ["Use short-lived credentials via Workload Identity", "Restrict generateAccessToken permission", "Enable IAM audit logging"],
                "gcp_services": ["Workload Identity", "IAM", "Cloud Audit Logs"],
            },
        },
    },

    # ── T1606: Forge Web Credentials ───────────────────────────────────────
    "T1606": {
        "detection_guidance": {
            "cloudtrail_events": ["sts:GetFederationToken", "iam:UpdateSAMLProvider"],
            "guardduty_types": ["UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS"],
            "cloudwatch_patterns": ["SAML provider configuration changes", "Federation token generation anomaly"],
            "data_sources": ["CloudTrail", "GuardDuty"],
            "azure": {
                "activity_logs": ["Microsoft.AADDomainServices/domainServices/write"],
                "defender_alerts": ["SAML token forgery detected", "Federation trust modification"],
                "sentinel_rules": ["AuditLogs | where OperationName contains 'Set federation' or OperationName contains 'Set domain authentication'"],
                "data_sources": ["Azure AD Audit Logs", "Azure AD Identity Protection"],
            },
            "gcp": {
                "audit_logs": ["iam.workloadIdentityPools.create", "iam.providers.create"],
                "scc_findings": [],
                "chronicle_rules": ["GCP Workload Identity Pool or OIDC provider created"],
                "data_sources": ["Cloud Audit Logs"],
            },
        },
        "remediation_guidance": {
            "immediate": ["Rotate SAML signing certificates", "Review federation trust configurations"],
            "preventive": ["Monitor SAML provider changes with CloudTrail alerts", "Restrict UpdateSAMLProvider permissions", "Use short-lived SAML assertions"],
            "aws_services": ["IAM SAML Providers", "CloudTrail Alerts", "AWS SSO"],
            "azure": {
                "immediate": ["Rotate token signing certificates", "Review all federation trusts"],
                "preventive": ["Monitor federation settings with Sentinel", "Use managed domains instead of federated", "Enable Azure AD Certificate-Based Auth"],
                "azure_services": ["Azure AD", "Sentinel", "Certificate-Based Auth"],
            },
            "gcp": {
                "immediate": ["Review Workload Identity Pool configurations", "Audit OIDC/SAML provider settings"],
                "preventive": ["Restrict Workload Identity Pool creation", "Monitor provider changes with audit logging"],
                "gcp_services": ["Workload Identity Federation", "Cloud Audit Logs", "Organization Policies"],
            },
        },
    },
}


def seed_guidance(conn, dry_run: bool = False):
    """Seed detection and remediation guidance for gap techniques."""
    updated = 0
    skipped = 0

    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        for tech_id, data in GAP_GUIDANCE.items():
            # Check if technique exists
            cur.execute("""
                SELECT technique_id, detection_guidance, remediation_guidance
                FROM mitre_technique_reference
                WHERE technique_id = %s
            """, (tech_id,))
            row = cur.fetchone()

            if not row:
                print(f"  SKIP (not in DB): {tech_id}")
                skipped += 1
                continue

            # Check if already has guidance
            existing_det = row["detection_guidance"]
            if existing_det and str(existing_det) not in ('{}', 'null', 'None'):
                print(f"  SKIP (already has guidance): {tech_id}")
                skipped += 1
                continue

            if dry_run:
                det_keys = list(data["detection_guidance"].keys())
                rem_keys = list(data["remediation_guidance"].keys())
                print(f"  WOULD UPDATE: {tech_id}")
                print(f"    detection keys: {det_keys}")
                print(f"    remediation keys: {rem_keys}")
            else:
                cur.execute("""
                    UPDATE mitre_technique_reference
                    SET detection_guidance = %s,
                        remediation_guidance = %s,
                        updated_at = NOW()
                    WHERE technique_id = %s
                """, (Json(data["detection_guidance"]), Json(data["remediation_guidance"]), tech_id))
                print(f"  UPDATED: {tech_id}")

            updated += 1

    if not dry_run:
        conn.commit()

    return updated, skipped


def verify_coverage(conn):
    """Verify all rule-referenced techniques now have guidance."""
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT
                COUNT(*) as total,
                COUNT(*) FILTER (
                    WHERE detection_guidance IS NOT NULL
                    AND detection_guidance::text != '{}'
                    AND detection_guidance::text != 'null'
                ) as has_guidance
            FROM mitre_technique_reference
        """)
        row = cur.fetchone()
        total = row["total"]
        has_guidance = row["has_guidance"]
        pct = round(has_guidance / total * 100, 1) if total > 0 else 0
        print(f"\n  Total techniques: {total}")
        print(f"  With guidance:    {has_guidance} ({pct}%)")
        print(f"  Without guidance: {total - has_guidance}")


def main():
    parser = argparse.ArgumentParser(description="Fill MITRE guidance gaps for rule-referenced techniques")
    parser.add_argument("--dry-run", action="store_true", help="Preview only, don't write to DB")
    args = parser.parse_args()

    conn = get_conn()

    print(f"\n{'='*70}")
    print(f"{'DRY RUN — ' if args.dry_run else ''}Filling MITRE Guidance Gaps")
    print(f"Techniques to seed: {len(GAP_GUIDANCE)}")
    print(f"{'='*70}\n")

    updated, skipped = seed_guidance(conn, args.dry_run)

    print(f"\n{'='*70}")
    action = "Would update" if args.dry_run else "Updated"
    print(f"{action}: {updated} techniques | Skipped: {skipped}")

    if not args.dry_run:
        print("\nVerifying coverage:")
        verify_coverage(conn)

    print(f"{'='*70}\n")

    conn.close()


if __name__ == "__main__":
    main()
