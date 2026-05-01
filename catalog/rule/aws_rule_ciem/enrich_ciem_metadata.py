#!/usr/bin/env python3
"""
Enrich all CIEM rule YAMLs with metadata:
  - severity, title, description, threat_category, risk_score
  - mitre_tactics, mitre_techniques, resource

Operates on catalog/rule/aws_rule_ciem/**/*.yaml (L1 + L2).
Writes metadata as top-level keys alongside rule_id, check_type, etc.
"""
from pathlib import Path
from typing import Dict, Optional, Tuple

import yaml

CATALOG_DIR = Path(__file__).parent

# ── 12 canonical threat categories ─────────────────────────────────────────
# operation keyword → (threat_category, [mitre_tactics], [mitre_techniques],
#                       severity, risk_score, short description)
_OP_MAP: Dict[str, Tuple] = {
    # ── Identity manipulation ─────────────────────────────────────────────
    "create_user":                 ("identity_manipulation", ["persistence", "initial_access"],    ["T1136.003", "T1078.004"], "high",     75, "New IAM user created — attacker may be establishing persistent access."),
    "create_login_profile":        ("identity_manipulation", ["persistence"],                       ["T1136.003"],             "high",     70, "Console login profile created for IAM user — enables console sign-in for previously API-only account."),
    "update_login_profile":        ("identity_manipulation", ["persistence", "credential_access"],  ["T1098.001"],             "high",     70, "IAM login profile updated — password reset or access modification detected."),
    "delete_user":                 ("identity_manipulation", ["defense_evasion"],                   ["T1531"],                 "high",     65, "IAM user deleted — may indicate account cleanup after attack or legitimate offboarding."),
    "create_virtual_mfa_device":   ("identity_manipulation", ["persistence"],                       ["T1136.003"],             "medium",   55, "Virtual MFA device created for IAM user."),
    "deactivate_mfa_device":       ("identity_manipulation", ["defense_evasion"],                   ["T1556.006"],             "high",     72, "MFA deactivated on IAM user — removes a key authentication control."),
    "delete_virtual_mfa_device":   ("identity_manipulation", ["defense_evasion"],                   ["T1556.006"],             "high",     72, "Virtual MFA device deleted — authentication control removed."),
    "enable_mfa_device":           ("identity_manipulation", ["persistence"],                       ["T1136.003"],             "low",      20, "MFA device enabled for IAM user."),
    "add_user_to_group":           ("identity_manipulation", ["privilege_escalation"],              ["T1098.001"],             "medium",   55, "User added to IAM group — group policy permissions applied to actor."),
    "remove_user_from_group":      ("identity_manipulation", ["defense_evasion"],                   ["T1531"],                 "medium",   45, "User removed from IAM group."),

    # ── Privilege escalation ──────────────────────────────────────────────
    "attach_user_policy":          ("privilege_escalation",  ["privilege_escalation"],              ["T1098.003"],             "high",     78, "Managed policy directly attached to IAM user — may grant over-privileged access."),
    "attach_role_policy":          ("privilege_escalation",  ["privilege_escalation"],              ["T1098.003"],             "high",     78, "Managed policy attached to IAM role — permissions scope expanded."),
    "attach_group_policy":         ("privilege_escalation",  ["privilege_escalation"],              ["T1098.003"],             "high",     78, "Managed policy attached to IAM group — all group members inherit new permissions."),
    "put_user_policy":             ("privilege_escalation",  ["privilege_escalation"],              ["T1098.003"],             "high",     78, "Inline policy added to IAM user — custom permissions applied directly."),
    "put_group_policy":            ("privilege_escalation",  ["privilege_escalation"],              ["T1098.003"],             "high",     78, "Inline policy added to IAM group — all members inherit new permissions."),
    "put_role_policy":             ("privilege_escalation",  ["privilege_escalation"],              ["T1098.003"],             "high",     78, "Inline policy added to IAM role."),
    "create_policy":               ("privilege_escalation",  ["privilege_escalation"],              ["T1098.003"],             "medium",   55, "New IAM policy created — precursor to privilege grant if attached."),
    "create_policy_version":       ("privilege_escalation",  ["privilege_escalation"],              ["T1098.003"],             "medium",   58, "New version of existing IAM policy created — may expand permissions."),
    "set_default_policy_version":  ("privilege_escalation",  ["privilege_escalation"],              ["T1098.003"],             "medium",   58, "Default IAM policy version changed — may activate previously inactive permissions."),
    "delete_policy":               ("privilege_escalation",  ["defense_evasion"],                   ["T1562.001"],             "medium",   50, "IAM policy deleted."),
    "create_role":                 ("privilege_escalation",  ["privilege_escalation", "persistence"],["T1098.003", "T1136.003"],"high",    72, "New IAM role created — may be used to assume elevated privileges."),
    "delete_role":                 ("privilege_escalation",  ["defense_evasion"],                   ["T1531"],                 "medium",   45, "IAM role deleted."),
    "attach_admin_policy":         ("privilege_escalation",  ["privilege_escalation"],              ["T1098.003"],             "critical", 95, "Admin-equivalent policy attached — full account control may have been granted."),
    "create_account_assignment":   ("privilege_escalation",  ["privilege_escalation"],              ["T1098.003"],             "high",     75, "SSO account assignment created — user granted access to AWS account via SSO."),
    "sso_create_account_assignment":("privilege_escalation", ["privilege_escalation"],              ["T1098.003"],             "high",     75, "SSO account assignment created via AWS SSO — account access granted."),
    "sso_create_permission_set":   ("privilege_escalation",  ["privilege_escalation"],              ["T1098.003"],             "medium",   60, "SSO permission set created — defines access scope for SSO assignments."),
    "sso_delete_account_assignment":("privilege_escalation", ["defense_evasion"],                   ["T1531"],                 "medium",   45, "SSO account assignment deleted."),
    "sso_delete_permission_set":   ("privilege_escalation",  ["defense_evasion"],                   ["T1531"],                 "low",      30, "SSO permission set deleted."),
    "sso_provision_permission_set":("privilege_escalation",  ["privilege_escalation"],              ["T1098.003"],             "medium",   55, "SSO permission set provisioned to accounts."),
    "org_attach_policy":           ("privilege_escalation",  ["privilege_escalation"],              ["T1098.003"],             "high",     80, "Policy attached at AWS Organizations level — affects all member accounts."),
    "org_create_policy":           ("privilege_escalation",  ["privilege_escalation"],              ["T1098.003"],             "high",     75, "Organizations policy created — scope covers all member accounts."),
    "org_update_policy":           ("privilege_escalation",  ["privilege_escalation"],              ["T1098.003"],             "high",     75, "Organizations policy updated — may expand permissions across all member accounts."),
    "org_detach_policy":           ("privilege_escalation",  ["defense_evasion"],                   ["T1562.001"],             "medium",   50, "Organizations policy detached."),
    "org_delete_policy":           ("privilege_escalation",  ["defense_evasion"],                   ["T1562.001"],             "medium",   45, "Organizations policy deleted."),
    "permission_boundary_removed": ("privilege_escalation",  ["privilege_escalation"],              ["T1548.005"],             "critical", 90, "IAM permission boundary removed — principal may now exceed original maximum permissions."),

    # ── Credential access ─────────────────────────────────────────────────
    "create_access_key":           ("credential_access",     ["credential_access", "persistence"],  ["T1098.001"],             "high",    75, "New IAM access key created — additional cloud credentials established for programmatic access."),
    "update_access_key_disable":   ("credential_access",     ["defense_evasion"],                   ["T1531"],                 "medium",   45, "IAM access key disabled."),
    "delete_access_key":           ("credential_access",     ["defense_evasion"],                   ["T1531"],                 "medium",   40, "IAM access key deleted."),
    "get_access_key_last_used":    ("credential_access",     ["discovery"],                         ["T1087.004"],             "low",      25, "IAM access key last-used information queried — reconnaissance of credential activity."),
    "ec2_get_password_data":       ("credential_access",     ["credential_access"],                 ["T1552.005"],             "high",     80, "Windows EC2 instance password retrieved — attacker obtained encrypted password data for decryption."),
    "ec2_get_console_screenshot":  ("credential_access",     ["credential_access", "discovery"],    ["T1552.005", "T1082"],    "high",     72, "EC2 console screenshot captured — may expose credentials or sensitive data displayed on screen."),
    "metadata_endpoint":           ("credential_access",     ["credential_access"],                 ["T1552.005"],             "high",     80, "EC2 instance metadata endpoint queried — SSRF or server-side access to credentials detected."),
    "sts_get_session_token":       ("credential_access",     ["credential_access"],                 ["T1528"],                 "medium",   55, "Temporary STS session token requested — may indicate credential harvesting."),
    "sts_get_federation_token":    ("credential_access",     ["credential_access", "lateral_movement"],["T1606.002", "T1550.001"],"high",   70, "Federated token obtained — enables acting as a federated user with scoped custom permissions."),
    "sts_decode_authorization_message":("credential_access", ["discovery"],                         ["T1087.004"],             "low",      25, "STS authorization message decoded — may expose internal policy details."),
    "root_access_key_used":        ("credential_access",     ["initial_access", "credential_access"],["T1552.005", "T1078.004"],"critical",95, "Root account access key used — highest-privilege credential exercised programmatically."),
    "root_console_login":          ("credential_access",     ["initial_access"],                    ["T1078.004"],             "critical", 95, "AWS root account console login detected — most privileged account used."),
    "root_access_key_created":     ("credential_access",     ["persistence", "credential_access"],  ["T1552.005"],             "critical", 95, "Root account access key created — highly dangerous, persistent programmatic access to root."),

    # ── Defense evasion ───────────────────────────────────────────────────
    "delete_cloudtrail":           ("defense_evasion",       ["defense_evasion"],                   ["T1562.008"],             "critical", 92, "CloudTrail trail deleted — audit logging disabled; attacker may be covering tracks."),
    "stop_logging":                ("defense_evasion",       ["defense_evasion"],                   ["T1562.008"],             "critical", 90, "CloudTrail logging stopped — audit log stream interrupted."),
    "update_trail":                ("defense_evasion",       ["defense_evasion"],                   ["T1562.008"],             "high",     75, "CloudTrail trail configuration modified — logging scope or destination changed."),
    "delete_trail":                ("defense_evasion",       ["defense_evasion"],                   ["T1562.008"],             "critical", 92, "CloudTrail trail deleted — audit logging capability destroyed."),
    "disable_security_hub":        ("defense_evasion",       ["defense_evasion"],                   ["T1562.001"],             "high",     80, "AWS Security Hub disabled — centralized security findings aggregation stopped."),
    "disable_macie":               ("defense_evasion",       ["defense_evasion"],                   ["T1562.001"],             "high",     75, "Amazon Macie disabled — sensitive data discovery and monitoring stopped."),
    "disable_guardduty":           ("defense_evasion",       ["defense_evasion"],                   ["T1562.001"],             "high",     80, "GuardDuty detector disabled — threat detection service deactivated."),
    "ec2_modify_instance_metadata_options":("defense_evasion",["defense_evasion"],                  ["T1562.001"],             "high",     70, "EC2 IMDS v1 enabled or hop limit increased — exposes instance metadata to SSRF attacks."),
    "ec2_modify_image_attribute":  ("defense_evasion",       ["defense_evasion"],                   ["T1578.004"],             "high",     72, "EC2 AMI attribute modified — launch permissions or description changed."),
    "delete_access_analyzer":      ("defense_evasion",       ["defense_evasion"],                   ["T1562.001"],             "high",     75, "IAM Access Analyzer deleted — external access detection capability removed."),
    "archive_access_analyzer_finding":("defense_evasion",    ["defense_evasion"],                   ["T1562.001"],             "medium",   45, "Access Analyzer finding archived — suppresses visibility into external access."),
    "modify_sg_rules":             ("defense_evasion",       ["defense_evasion"],                   ["T1562.007"],             "high",     72, "Security group rules modified — network access control changed."),
    "sg_all_ports_open":           ("defense_evasion",       ["defense_evasion", "initial_access"], ["T1562.007", "T1190"],    "critical", 88, "Security group opened to all ports — exposes all services to internet access."),
    "waf_rule_deleted":            ("defense_evasion",       ["defense_evasion"],                   ["T1562.007"],             "high",     78, "WAF rule deleted — web application protection weakened."),
    "waf_web_acl_deleted":         ("defense_evasion",       ["defense_evasion"],                   ["T1562.007"],             "critical", 88, "WAF Web ACL deleted — all WAF protections for associated resources removed."),

    # ── Lateral movement ──────────────────────────────────────────────────
    "sts_assume_role_with_saml":   ("lateral_movement",      ["lateral_movement", "initial_access"],["T1606.002", "T1078.004"],"high",    72, "Role assumed via SAML federation — forged or legitimate SAML token used to gain AWS access."),
    "sts_assume_role_with_web_identity":("lateral_movement", ["lateral_movement"],                  ["T1550.001"],             "high",     70, "Role assumed via web identity (OIDC) — application access token used to access AWS resources."),
    "cross_account_assume_role":   ("lateral_movement",      ["lateral_movement"],                  ["T1550.001"],             "high",     75, "Cross-account role assumption — application access token used for lateral movement between accounts."),
    "service_role_assumed":        ("lateral_movement",      ["lateral_movement"],                  ["T1550.001"],             "medium",   55, "AWS service role assumed — application access token reused for service-to-service movement."),
    "create_vpc_peering":          ("lateral_movement",      ["lateral_movement"],                  ["T1563.001"],             "high",     70, "VPC peering connection created — network path established between VPCs."),
    "igw_attached":                ("lateral_movement",      ["lateral_movement", "initial_access"],["T1563.001", "T1190"],    "high",     75, "Internet gateway attached to VPC — direct internet exposure added."),
    "transit_gateway_attached":    ("lateral_movement",      ["lateral_movement"],                  ["T1563.001"],             "medium",   58, "Transit gateway attachment created — route between networks established."),

    # ── Initial access ────────────────────────────────────────────────────
    "console_login":               ("initial_access",        ["initial_access"],                    ["T1078.004"],             "medium",   50, "AWS Management Console login recorded."),
    "console_login_no_mfa":        ("initial_access",        ["initial_access"],                    ["T1078.004"],             "high",     72, "Console login without MFA — account accessed without second factor."),
    "console_login_failure":       ("initial_access",        ["credential_access"],                 ["T1110.001"],             "medium",   55, "Console login failure — possible brute-force or credential stuffing attempt."),
    "switch_role_in_console":      ("initial_access",        ["initial_access", "privilege_escalation"],["T1078.004", "T1548.005"],"medium",50,"Role switch via console — user assumed different IAM role."),
    "org_create_account":          ("initial_access",        ["persistence"],                       ["T1136.003"],             "high",     70, "New AWS account created in organization — expands attack surface."),
    "org_remove_account":          ("initial_access",        ["defense_evasion"],                   ["T1531"],                 "medium",   50, "Account removed from AWS organization."),
    "org_leave_organization":      ("initial_access",        ["defense_evasion"],                   ["T1531"],                 "high",     70, "AWS account left organization — removes organizational controls and SCPs."),

    # ── Persistence ───────────────────────────────────────────────────────
    "create_oidc_provider":        ("persistence",           ["persistence"],                       ["T1556.007"],             "high",     75, "OIDC identity provider created — enables external identities to assume AWS roles via hybrid identity."),
    "update_oidc_provider_thumbprint":("persistence",        ["persistence"],                       ["T1556.007"],             "high",     72, "OIDC provider thumbprint updated — hybrid identity trust relationship modified for external IdP."),
    "delete_oidc_provider":        ("persistence",           ["defense_evasion"],                   ["T1531"],                 "medium",   45, "OIDC identity provider deleted."),
    "create_saml_provider":        ("persistence",           ["persistence"],                       ["T1556.007"],             "high",     75, "SAML identity provider created — hybrid identity federation to AWS enabled."),
    "delete_saml_provider":        ("persistence",           ["defense_evasion"],                   ["T1531"],                 "medium",   45, "SAML identity provider deleted."),
    "oidc_provider_created":       ("persistence",           ["persistence"],                       ["T1556.007"],             "high",     75, "OIDC identity provider created — external hybrid identity federation enabled."),
    "saml_provider_created":       ("persistence",           ["persistence"],                       ["T1556.007"],             "high",     75, "SAML identity provider created — hybrid identity federated access enabled."),
    "access_key_created":          ("persistence",           ["persistence", "credential_access"],  ["T1552.005"],             "high",     72, "IAM access key created — programmatic credential established."),
    "access_key_used_after_rotation_due":("persistence",     ["credential_access"],                 ["T1552.005"],             "high",     70, "Access key used after it was due for rotation — stale credential still active."),
    "backdoor_account":            ("persistence",           ["persistence"],                       ["T1136.003"],             "critical", 90, "Backdoor account creation pattern detected — attacker establishing hidden persistence."),
    "federation_abuse":            ("persistence",           ["persistence", "lateral_movement"],   ["T1556.007", "T1550.001"],"critical", 88, "Federation abuse pattern: identity provider created then used for role assumption."),
    "stale_credentials":           ("persistence",           ["credential_access"],                 ["T1552.005"],             "medium",   55, "Stale credentials pattern: access key in use significantly past rotation deadline."),
    "ec2_create_key_pair":         ("persistence",           ["persistence"],                       ["T1552.004"],             "high",     70, "EC2 key pair created — SSH credentials established for persistent instance access."),
    "ec2_import_key_pair":         ("persistence",           ["persistence"],                       ["T1552.004"],             "high",     72, "EC2 key pair imported — externally-controlled SSH credential added to account."),

    # ── Data exfiltration ─────────────────────────────────────────────────
    "get_object":                  ("data_exfiltration",     ["collection", "exfiltration"],        ["T1530"],                 "medium",   55, "S3 object downloaded — data accessed from object storage."),
    "delete_multiple_objects":     ("data_destruction",      ["impact"],                            ["T1485"],                 "high",     78, "Multiple S3 objects deleted in a single request — bulk data destruction."),
    "delete_object":               ("data_destruction",      ["impact"],                            ["T1485"],                 "medium",   60, "S3 object deleted."),
    "list_objects":                ("discovery",             ["discovery"],                         ["T1083"],                 "low",      25, "S3 bucket object listing performed — enumeration of stored data."),
    "get_acl":                     ("discovery",             ["discovery"],                         ["T1087.004"],             "low",      25, "S3 ACL retrieved — bucket or object access control list inspected."),
    "put_acl":                     ("data_exfiltration",     ["exfiltration"],                      ["T1537"],                 "high",     75, "S3 ACL modified — bucket or object permissions changed, potentially exposing data."),
    "put_object":                  ("data_exfiltration",     ["collection"],                        ["T1530"],                 "low",      30, "S3 object uploaded."),
    "no_such_key":                 ("discovery",             ["discovery"],                         ["T1083"],                 "low",      20, "S3 access failure (NoSuchKey) — may indicate object enumeration attempt."),
    "access_denied":               ("discovery",             ["discovery"],                         ["T1087.004"],             "low",      20, "Access denied on S3 operation — unauthorized access attempt or permission misconfiguration."),
    "get_policy":                  ("discovery",             ["discovery"],                         ["T1087.004"],             "low",      25, "S3 bucket policy retrieved — bucket policy inspected for potential vulnerabilities."),

    # ── Data destruction ──────────────────────────────────────────────────
    "delete_bucket":               ("data_destruction",      ["impact"],                            ["T1485"],                 "critical", 90, "S3 bucket deleted — all data and configuration permanently destroyed."),
    "terminate_instance":          ("data_destruction",      ["impact"],                            ["T1578.003"],             "high",     78, "EC2 instance terminated — compute resource permanently deleted."),
    "terminate_instances":         ("data_destruction",      ["impact"],                            ["T1578.003"],             "high",     78, "Multiple EC2 instances terminated — bulk compute destruction."),
    "delete_snapshot":             ("data_destruction",      ["impact"],                            ["T1485"],                 "high",     75, "EC2 snapshot deleted — backup data destroyed."),
    "delete_volume":               ("data_destruction",      ["impact"],                            ["T1485"],                 "high",     78, "EBS volume deleted — storage data destroyed."),
    "delete_db_instance":          ("data_destruction",      ["impact"],                            ["T1485"],                 "critical", 88, "RDS database instance deleted — may result in permanent data loss."),
    "delete_db_cluster":           ("data_destruction",      ["impact"],                            ["T1485"],                 "critical", 92, "RDS cluster deleted — entire database cluster destroyed."),

    # ── Execution ─────────────────────────────────────────────────────────
    "invoke_function":             ("execution",             ["execution"],                         ["T1651"],                 "medium",   55, "Lambda function invoked via cloud administration API — serverless code execution triggered."),
    "create_function":             ("execution",             ["execution", "persistence"],          ["T1651", "T1525"],        "high",     70, "Lambda function created — serverless executable deployed via cloud admin API."),
    "update_function_code":        ("execution",             ["execution"],                         ["T1651"],                 "high",     72, "Lambda function code updated via cloud admin API — existing function logic replaced."),
    "update_function_configuration":("execution",           ["execution", "defense_evasion"],      ["T1651", "T1562.001"],    "high",     68, "Lambda function configuration updated — execution environment modified via cloud admin API."),
    "add_permission":              ("execution",             ["privilege_escalation"],              ["T1651"],                 "medium",   60, "Lambda function permission added — resource-based policy granting invocation rights."),
    "pod_exec":                    ("execution",             ["execution"],                         ["T1059.013"],             "high",     80, "kubectl exec in pod detected — direct shell access via Kubernetes container CLI."),
    "exec":                        ("execution",             ["execution"],                         ["T1059.013"],             "high",     80, "Container exec command detected — interactive shell access via container CLI/API."),
    "batch_submit_job":            ("execution",             ["execution"],                         ["T1651"],                 "medium",   50, "AWS Batch job submitted — cloud-managed workload execution triggered."),
    "batch_create_compute_environment":("execution",         ["execution"],                         ["T1651"],                 "medium",   50, "Batch compute environment created — cloud execution infrastructure provisioned."),
    "batch_register_job_definition":("execution",            ["execution"],                         ["T1651"],                 "low",      30, "Batch job definition registered — cloud execution template created."),
    "run_task":                    ("execution",             ["execution"],                         ["T1610"],                 "medium",   55, "ECS task run — container workload deployed and executed."),
    "start_task":                  ("execution",             ["execution"],                         ["T1610"],                 "medium",   50, "ECS task started on specific container instance."),
    "register_task_definition":    ("execution",             ["execution", "persistence"],          ["T1610"],                 "medium",   55, "ECS task definition registered — container workload template created."),
    "update_service":              ("execution",             ["execution"],                         ["T1610"],                 "medium",   50, "ECS service updated — running container configuration changed."),

    # ── Discovery ─────────────────────────────────────────────────────────
    "enumerate_iam":               ("discovery",             ["discovery"],                         ["T1087.004"],             "medium",   50, "IAM resource enumeration detected — attacker mapping account permissions."),
    "enumerate_s3":                ("discovery",             ["discovery"],                         ["T1083"],                 "medium",   45, "S3 bucket enumeration detected — attacker listing accessible storage."),
    "admin_api_call":              ("discovery",             ["discovery"],                         ["T1087.004"],             "medium",   50, "Administrative API call made — management-plane action recorded."),
    "access_denied_spike":         ("discovery",             ["discovery"],                         ["T1087.004"],             "medium",   55, "Spike in access-denied errors — possible permission enumeration or unauthorized access attempt."),
    "brute_force":                 ("initial_access",        ["credential_access"],                 ["T1110.001"],             "high",     75, "Brute-force pattern detected against console login — repeated authentication failures."),
    "describe_security_groups":    ("discovery",             ["discovery"],                         ["T1580"],                 "low",      25, "Security group configuration queried — network controls enumerated."),
    "describe_instances":          ("discovery",             ["discovery"],                         ["T1580"],                 "low",      25, "EC2 instances listed — compute inventory enumerated."),
    "describe_vpcs":               ("discovery",             ["discovery"],                         ["T1580"],                 "low",      20, "VPC configuration described — network topology enumerated."),
    "list_trails":                 ("discovery",             ["discovery"],                         ["T1087.004"],             "low",      25, "CloudTrail trails listed — logging configuration enumerated."),
    "get_trail_status":            ("discovery",             ["discovery"],                         ["T1087.004"],             "low",      20, "CloudTrail trail status retrieved — logging activity checked."),
    "get_parameter":               ("discovery",             ["discovery", "credential_access"],    ["T1552.001"],             "medium",   55, "SSM Parameter Store value retrieved — may expose secrets or configuration."),
    "get_secret_value":            ("credential_access",     ["credential_access"],                 ["T1552.007"],             "high",     80, "Secrets Manager secret value retrieved — credential accessed via cloud secrets API."),
    "describe_clusters":           ("discovery",             ["discovery"],                         ["T1580"],                 "low",      25, "Kubernetes/ECS clusters described — container infrastructure enumerated."),
    "list_pods":                   ("discovery",             ["discovery"],                         ["T1613"],                 "low",      25, "Kubernetes pods listed — container workloads enumerated."),

    # ── Compute operations ────────────────────────────────────────────────
    "ec2_run_instances":           ("execution",             ["execution", "persistence"],          ["T1578.002"],             "high",     70, "EC2 instances launched — new compute resources provisioned."),
    "run_instances":               ("execution",             ["execution", "persistence"],          ["T1578.002"],             "high",     70, "EC2 instances launched — new compute resources provisioned."),
    "ec2_create_image":            ("persistence",           ["persistence"],                       ["T1578.001"],             "medium",   60, "EC2 AMI created from running instance — snapshot of instance state captured."),
    "ec2_modify_instance_attribute":("defense_evasion",      ["defense_evasion"],                   ["T1578.004"],             "medium",   55, "EC2 instance attribute modified — instance configuration changed."),
    "create_launch_template":      ("execution",             ["execution", "persistence"],          ["T1578.002"],             "medium",   55, "EC2 launch template created — reusable instance launch configuration established."),

    # ── Network operations ────────────────────────────────────────────────
    "global_accelerator_created":  ("lateral_movement",      ["lateral_movement"],                  ["T1090.003"],             "medium",   60, "Global Accelerator created — traffic routing through AWS edge network configured."),
    "create_vpc":                  ("lateral_movement",      ["lateral_movement"],                  ["T1563.001"],             "medium",   45, "VPC created — new isolated network environment provisioned."),
    "vpc_deleted":                 ("defense_evasion",       ["defense_evasion"],                   ["T1531"],                 "medium",   50, "VPC deleted — network environment removed."),
    "subnet_created":              ("lateral_movement",      ["lateral_movement"],                  ["T1563.001"],             "low",      25, "VPC subnet created."),
    "route_table_modified":        ("lateral_movement",      ["lateral_movement"],                  ["T1563.001"],             "medium",   50, "Route table modified — network routing changed."),
    "nacl_modified":               ("defense_evasion",       ["defense_evasion"],                   ["T1562.007"],             "medium",   55, "Network ACL modified — subnet-level access control changed."),
    "vpc_flow_logs_disabled":      ("defense_evasion",       ["defense_evasion"],                   ["T1562.008"],             "high",     78, "VPC flow logs disabled — network traffic logging stopped."),

    # ── WAF / ALB / Network security ─────────────────────────────────────
    "http_delete_method":          ("web_attack",            ["initial_access"],                    ["T1190"],                 "medium",   50, "HTTP DELETE method used via load balancer — destructive web request recorded."),
    "http_4xx":                    ("discovery",             ["discovery"],                         ["T1190"],                 "low",      20, "HTTP 4xx error detected — possible web enumeration or invalid request."),
    "http_5xx":                    ("discovery",             ["discovery"],                         ["T1190"],                 "low",      20, "HTTP 5xx server error detected — possible exploitation attempt causing server error."),
    "sql_injection":               ("web_attack",            ["initial_access"],                    ["T1190"],                 "critical", 90, "SQL injection pattern detected by WAF — web application attack attempt."),
    "xss_attempt":                 ("web_attack",            ["initial_access"],                    ["T1190"],                 "high",     78, "Cross-site scripting (XSS) pattern detected by WAF."),
    "path_traversal":              ("web_attack",            ["initial_access"],                    ["T1190"],                 "high",     78, "Path traversal attempt detected by WAF — directory traversal attack."),
    "waf_block":                   ("web_attack",            ["initial_access"],                    ["T1190"],                 "medium",   50, "WAF rule blocked a request — web attack attempt mitigated."),
    "waf_allow":                   ("discovery",             ["initial_access"],                    ["T1190"],                 "low",      25, "WAF allowed a request that matched a rule."),
    "rate_limit_exceeded":         ("web_attack",            ["initial_access"],                    ["T1498"],                 "medium",   55, "Rate limit exceeded — possible denial of service or aggressive scraping."),

    # ── Container / EKS ───────────────────────────────────────────────────
    "pod_privileged_container":    ("privilege_escalation",  ["privilege_escalation", "execution"], ["T1611", "T1059.013"],    "critical", 88, "Privileged container detected — container runs with host capabilities, enabling escape."),
    "pod_host_network":            ("lateral_movement",      ["lateral_movement"],                  ["T1610"],                 "high",     75, "Pod using host network namespace — container can access host network stack."),
    "pod_host_pid":                ("privilege_escalation",  ["privilege_escalation"],              ["T1611"],                 "high",     75, "Pod using host PID namespace — container can see and signal host processes."),
    "service_account_token_used":  ("credential_access",     ["credential_access"],                 ["T1528"],                 "medium",   55, "Kubernetes service account token used — workload credential access recorded."),
    "rbac_escalation":             ("privilege_escalation",  ["privilege_escalation"],              ["T1098.006"],             "high",     78, "Kubernetes RBAC privilege escalation — container cluster role binding expanded permissions."),
    "create_cluster":              ("execution",             ["execution", "persistence"],          ["T1610"],                 "medium",   55, "EKS/ECS cluster created — new container orchestration environment provisioned."),
    "delete_cluster":              ("data_destruction",      ["impact"],                            ["T1578.003"],             "high",     80, "Kubernetes cluster deleted — container orchestration environment destroyed."),
    "node_group_deleted":          ("data_destruction",      ["impact"],                            ["T1578.003"],             "medium",   60, "EKS node group deleted — compute capacity removed from cluster."),
    "update_cluster_config":       ("defense_evasion",       ["defense_evasion"],                   ["T1578.004"],             "medium",   55, "EKS cluster configuration updated — cluster settings changed."),
    "associate_encryption_config": ("defense_evasion",       ["defense_evasion"],                   ["T1578.004"],             "low",      30, "EKS encryption configuration changed."),

    # ── GuardDuty ─────────────────────────────────────────────────────────
    "critical_finding":            ("threat_detection",      ["collection"],                        ["T1595"],                 "critical", 90, "GuardDuty critical severity finding detected — high-confidence threat behavior identified."),
    "high_finding":                ("threat_detection",      ["collection"],                        ["T1595"],                 "high",     75, "GuardDuty high severity finding detected."),
    "medium_finding":              ("threat_detection",      ["collection"],                        ["T1595"],                 "medium",   50, "GuardDuty medium severity finding detected."),
    "low_finding":                 ("threat_detection",      ["collection"],                        ["T1595"],                 "low",      25, "GuardDuty low severity finding detected."),

    # ── Monitoring / CloudWatch ───────────────────────────────────────────
    "alarm_deleted":               ("defense_evasion",       ["defense_evasion"],                   ["T1562.001"],             "medium",   55, "CloudWatch alarm deleted — monitoring alert removed."),
    "log_group_deleted":           ("defense_evasion",       ["defense_evasion"],                   ["T1562.008"],             "high",     72, "CloudWatch log group deleted — log data and future logging capability destroyed."),
    "metric_filter_deleted":       ("defense_evasion",       ["defense_evasion"],                   ["T1562.008"],             "medium",   55, "CloudWatch metric filter deleted — automated alerting on log patterns removed."),
    "log_stream_deleted":          ("defense_evasion",       ["defense_evasion"],                   ["T1562.008"],             "medium",   55, "CloudWatch log stream deleted — log data destroyed."),
    "subscription_filter_deleted": ("defense_evasion",       ["defense_evasion"],                   ["T1562.008"],             "medium",   50, "CloudWatch subscription filter deleted — real-time log processing stopped."),

    # ── Storage ───────────────────────────────────────────────────────────
    "delete_file_system":          ("data_destruction",      ["impact"],                            ["T1485"],                 "critical", 90, "EFS file system deleted — shared file storage destroyed."),
    "share_snapshot":              ("data_exfiltration",     ["exfiltration"],                      ["T1537"],                 "high",     78, "RDS/EBS snapshot shared with external account — data accessible outside account."),
    "create_snapshot":             ("persistence",           ["collection"],                        ["T1530"],                 "low",      30, "Storage snapshot created."),
    "modify_snapshot_attribute":   ("data_exfiltration",     ["exfiltration"],                      ["T1537"],                 "high",     75, "Snapshot attribute modified — potentially shared with unauthorized accounts."),
    "copy_snapshot":               ("data_exfiltration",     ["exfiltration"],                      ["T1537"],                 "medium",   55, "Snapshot copied — data may be transferred to attacker-controlled account."),

    # ── CloudFront ────────────────────────────────────────────────────────
    "distribution_created":        ("execution",             ["initial_access"],                    ["T1583.003"],             "medium",   50, "CloudFront distribution created — content delivery endpoint established."),
    "distribution_deleted":        ("defense_evasion",       ["defense_evasion"],                   ["T1531"],                 "medium",   45, "CloudFront distribution deleted."),
    "update_distribution":         ("defense_evasion",       ["defense_evasion"],                   ["T1578.004"],             "medium",   50, "CloudFront distribution updated — CDN configuration changed."),
    "create_invalidation":         ("defense_evasion",       ["defense_evasion"],                   ["T1070"],                 "low",      25, "CloudFront cache invalidation created — cached content purged."),

    # ── DevOps ────────────────────────────────────────────────────────────
    "pipeline_deleted":            ("defense_evasion",       ["defense_evasion"],                   ["T1531"],                 "medium",   50, "CodePipeline deleted — CI/CD pipeline destroyed."),
    "pipeline_execution_started":  ("execution",             ["execution"],                         ["T1072"],                 "low",      25, "CodePipeline execution started — CI/CD pipeline triggered."),
    "start_pipeline_execution":    ("execution",             ["execution"],                         ["T1072"],                 "low",      25, "CodePipeline execution started."),
    "delete_pipeline":             ("defense_evasion",       ["defense_evasion"],                   ["T1531"],                 "medium",   50, "CodePipeline deleted."),
    "update_pipeline":             ("defense_evasion",       ["defense_evasion"],                   ["T1072"],                 "medium",   50, "CodePipeline updated — pipeline configuration changed."),
    "ecr_delete_repository":       ("data_destruction",      ["impact"],                            ["T1485"],                 "high",     75, "ECR container registry deleted — all images in repository destroyed."),
    "ecr_put_lifecycle_policy":    ("defense_evasion",       ["defense_evasion"],                   ["T1562.001"],             "medium",   50, "ECR lifecycle policy updated — image retention rules changed."),
    "ecr_batch_delete_image":      ("data_destruction",      ["impact"],                            ["T1485"],                 "high",     72, "ECR images bulk deleted — container images destroyed."),
    "codebuild_create_project":    ("execution",             ["execution"],                         ["T1072"],                 "low",      30, "CodeBuild project created — CI/CD build environment established."),
    "codebuild_delete_project":    ("defense_evasion",       ["defense_evasion"],                   ["T1531"],                 "low",      30, "CodeBuild project deleted."),
    "ecr_backdoor_image":          ("persistence",           ["persistence"],                       ["T1525"],                 "critical", 92, "Container image backdoor pattern detected — malicious image likely pushed to registry."),

    # ── RDS ───────────────────────────────────────────────────────────────
    "create_db_instance":          ("execution",             ["persistence"],                       ["T1578.002"],             "medium",   45, "RDS database instance created."),
    "rds_modify_db_instance":      ("defense_evasion",       ["defense_evasion"],                   ["T1578.004"],             "medium",   55, "RDS instance modified — database configuration changed."),
    "rds_create_db_snapshot":      ("collection",            ["collection"],                        ["T1530"],                 "medium",   50, "RDS database snapshot created — point-in-time copy of database made."),
    "rds_restore_db_instance":     ("data_exfiltration",     ["exfiltration"],                      ["T1537"],                 "high",     72, "RDS instance restored from snapshot — potentially used to access data from another account."),
    "rds_delete_db_instance":      ("data_destruction",      ["impact"],                            ["T1485"],                 "critical", 88, "RDS instance deleted — database service destroyed."),
    "rds_delete_db_cluster":       ("data_destruction",      ["impact"],                            ["T1485"],                 "critical", 92, "RDS cluster deleted — all databases in cluster destroyed."),

    # ── DNS / Route53 ─────────────────────────────────────────────────────
    "dns_change_resource_record":  ("lateral_movement",      ["lateral_movement", "defense_evasion"],["T1090.001", "T1584.002"],"high",  72, "Route53 DNS record changed — domain resolution modified."),
    "delete_hosted_zone":          ("data_destruction",      ["impact"],                            ["T1531"],                 "high",     78, "Route53 hosted zone deleted — all DNS records for domain destroyed."),
    "create_hosted_zone":          ("persistence",           ["persistence"],                       ["T1584.002"],             "medium",   45, "Route53 hosted zone created — DNS zone provisioned."),
    "change_resource_record_sets": ("lateral_movement",      ["lateral_movement"],                  ["T1584.002"],             "high",     72, "DNS records modified — domain routing changed."),

    # ── Correlation (L2) ─────────────────────────────────────────────────
    "privilege_escalation":        ("privilege_escalation",  ["privilege_escalation"],              ["T1548.005"],             "critical", 92, "Privilege escalation chain detected: permission boundary removed → policies attached → cross-account role assumed."),
    "lateral_movement":            ("lateral_movement",      ["lateral_movement", "discovery"],     ["T1548.005", "T1580"],    "critical", 92, "Lateral movement chain detected: enumeration → cross-account role assumption → network pivot."),
    "persistence":                 ("persistence",           ["persistence", "credential_access"],  ["T1136.003", "T1552.005"],"critical", 90, "Persistence chain detected: new user or identity provider created, followed by access key."),
    "account_takeover":            ("initial_access",        ["initial_access", "credential_access"],["T1078.004", "T1110"],   "critical", 95, "Account takeover pattern: login failures followed by successful login with suspicious activity."),
    "stale_credentials_pattern":   ("persistence",           ["credential_access"],                 ["T1552.005"],             "high",     75, "Stale credential usage pattern: access key active beyond rotation policy."),

    # ── IAM (remaining) ───────────────────────────────────────────────────
    "delete_account_password_policy":("defense_evasion",     ["defense_evasion"],                   ["T1562.001"],             "high",     72, "IAM account password policy deleted — authentication strength requirements removed."),
    "delete_login_profile":         ("identity_manipulation",["defense_evasion"],                   ["T1531"],                 "medium",   50, "IAM login profile deleted — console access removed from user."),
    "update_account_password_policy":("defense_evasion",     ["defense_evasion"],                   ["T1562.001"],             "medium",   55, "Account password policy updated — authentication requirements may have been weakened."),

    # ── ALB log operations ────────────────────────────────────────────────
    "admin_path_access":            ("web_attack",           ["discovery"],                         ["T1595.002"],             "medium",   55, "Request to admin path detected via load balancer — reconnaissance of admin interfaces."),
    "api_key_path_access":          ("web_attack",           ["credential_access"],                 ["T1552.001"],             "medium",   55, "Request targeting API key path — may indicate credential harvesting attempt."),
    "bad_gateway":                  ("discovery",            ["discovery"],                         ["T1595.002"],             "low",      20, "HTTP 502 Bad Gateway from ALB — upstream server unavailable or misconfigured."),
    "connection_timeout":           ("discovery",            ["discovery"],                         ["T1595.002"],             "low",      20, "Connection timeout at load balancer — service unavailability or DoS indicator."),
    "health_check_failure":         ("discovery",            ["discovery"],                         ["T1595.002"],             "low",      20, "ALB health check failure — backend target unhealthy or unreachable."),
    "http_401_unauthorized":        ("initial_access",       ["credential_access"],                 ["T1110.001"],             "medium",   45, "HTTP 401 Unauthorized — authentication required; possible credential enumeration."),
    "http_403_forbidden":           ("initial_access",       ["discovery"],                         ["T1595.002"],             "low",      25, "HTTP 403 Forbidden — authorization denied; possible path enumeration."),
    "http_404_not_found":           ("discovery",            ["discovery"],                         ["T1595.002"],             "low",      20, "HTTP 404 Not Found — resource not found; common during web enumeration."),
    "http_5xx_error":               ("discovery",            ["discovery"],                         ["T1595.002"],             "low",      20, "HTTP 5xx server error — backend failure; may indicate exploitation causing crashes."),
    "http_options_method":          ("discovery",            ["discovery"],                         ["T1595.002"],             "low",      20, "HTTP OPTIONS method detected — CORS preflight or server capability enumeration."),
    "http_patch_method":            ("web_attack",           ["initial_access"],                    ["T1190"],                 "low",      30, "HTTP PATCH method detected — partial resource modification request."),
    "repeated_server_errors":       ("discovery",            ["discovery"],                         ["T1595.002"],             "medium",   50, "Repeated server-side errors from same client — possible fuzzing or exploitation attempts."),
    "websocket_connection":         ("execution",            ["execution"],                         ["T1190"],                 "low",      25, "WebSocket connection initiated — persistent bidirectional channel established."),

    # ── CloudFront log operations ─────────────────────────────────────────
    "cache_miss":                   ("discovery",            ["discovery"],                         ["T1595.002"],             "low",      20, "CloudFront cache miss — request passed to origin; baseline traffic indicator."),
    "error_from_origin":            ("discovery",            ["discovery"],                         ["T1595.002"],             "low",      20, "CloudFront received error from origin — origin server issue detected."),
    "http_put_method":              ("web_attack",           ["initial_access"],                    ["T1190"],                 "low",      30, "HTTP PUT method via CloudFront — resource creation/replacement request."),
    "sensitive_path_access":        ("web_attack",           ["discovery"],                         ["T1595.002"],             "medium",   55, "Access to sensitive path via CloudFront — .env, config, or credential paths targeted."),

    # ── WAF log operations ─────────────────────────────────────────────────
    "allowed_request":              ("discovery",            ["initial_access"],                    ["T1190"],                 "low",      20, "WAF allowed a potentially matching request — verify rule configuration."),
    "anonymous_ip_block":           ("web_attack",           ["initial_access"],                    ["T1090"],                 "medium",   55, "WAF blocked request from anonymous IP (Tor/VPN/proxy) — potential attacker anonymization."),
    "aws_managed_rule_block":       ("web_attack",           ["initial_access"],                    ["T1190"],                 "medium",   55, "WAF AWS managed rule triggered and blocked request — known attack pattern detected."),
    "bot_control_block":            ("web_attack",           ["initial_access"],                    ["T1595.001"],             "medium",   50, "WAF bot control blocked automated request — bot or scraper activity detected."),
    "custom_rule_block":            ("web_attack",           ["initial_access"],                    ["T1190"],                 "medium",   55, "WAF custom rule blocked request — organization-defined security policy enforced."),
    "geo_restriction_block":        ("web_attack",           ["initial_access"],                    ["T1590"],                 "medium",   45, "WAF geo-restriction blocked request from prohibited country."),
    "ip_reputation_block":          ("web_attack",           ["initial_access"],                    ["T1090"],                 "high",     68, "WAF IP reputation list blocked request — known malicious IP detected."),
    "known_bad_input_block":        ("web_attack",           ["initial_access"],                    ["T1190"],                 "high",     72, "WAF known-bad-input rule blocked request — malformed or attack payload detected."),
    "log4j_exploit_block":          ("web_attack",           ["initial_access"],                    ["T1190"],                 "critical", 90, "WAF Log4Shell (Log4j) exploit attempt blocked — CVE-2021-44228 attack pattern detected."),
    "rate_limit_triggered":         ("web_attack",           ["initial_access"],                    ["T1498"],                 "medium",   55, "WAF rate-based rule triggered — excessive request volume from single source."),
    "request_blocked":              ("web_attack",           ["initial_access"],                    ["T1190"],                 "medium",   50, "WAF blocked an HTTP request — security rule matched."),
    "request_counted":              ("discovery",            ["discovery"],                         ["T1595.002"],             "low",      20, "WAF counted (but did not block) a matching request — monitoring threshold reached."),
    "size_constraint_block":        ("web_attack",           ["initial_access"],                    ["T1190"],                 "medium",   50, "WAF size constraint rule blocked oversized request — possible buffer overflow attempt."),
    "sqli_detected":                ("web_attack",           ["initial_access"],                    ["T1190"],                 "critical", 92, "WAF detected SQL injection pattern — database attack attempt blocked."),
    "xss_detected":                 ("web_attack",           ["initial_access"],                    ["T1190"],                 "high",     80, "WAF detected cross-site scripting (XSS) pattern — web attack blocked."),

    # ── VPC flow log operations ───────────────────────────────────────────
    "rdp_inbound":                  ("lateral_movement",     ["lateral_movement"],                  ["T1021.001"],             "high",     75, "Inbound RDP (port 3389) traffic detected — remote desktop access attempt."),
    "rejected_traffic":             ("discovery",            ["discovery"],                         ["T1046"],                 "low",      25, "VPC flow log rejected traffic — connection blocked by security group or NACL."),
    "ssh_inbound":                  ("lateral_movement",     ["lateral_movement"],                  ["T1021.004"],             "medium",   55, "Inbound SSH (port 22) traffic detected — remote shell access."),
    "dhcp_options_modified":        ("defense_evasion",      ["defense_evasion"],                   ["T1562.007"],             "medium",   55, "VPC DHCP options set modified — DNS or domain settings changed."),
    "flow_logs_deleted":            ("defense_evasion",      ["defense_evasion"],                   ["T1562.008"],             "high",     78, "VPC flow logs deleted — network traffic visibility eliminated."),
    "nat_gateway_created":          ("lateral_movement",     ["lateral_movement"],                  ["T1090.003"],             "medium",   50, "NAT gateway created — enables outbound internet access from private subnets."),
    "network_acl_permissive":       ("defense_evasion",      ["defense_evasion"],                   ["T1562.007"],             "high",     72, "Network ACL rule permits all traffic — subnet-level security control removed."),
    "transit_gateway_modified":     ("lateral_movement",     ["lateral_movement"],                  ["T1563.001"],             "medium",   55, "Transit gateway modified — inter-VPC routing changed."),
    "vpc_endpoint_created":         ("lateral_movement",     ["lateral_movement"],                  ["T1090.003"],             "medium",   50, "VPC endpoint created — private connectivity to AWS service established."),
    "database_port":                ("discovery",            ["discovery"],                         ["T1046"],                 "medium",   55, "Database port traffic in VPC flow logs — direct database connection attempt."),
    "dns_traffic":                  ("discovery",            ["discovery"],                         ["T1046"],                 "low",      20, "DNS traffic observed in VPC flow logs — baseline network activity."),
    "high_port_traffic":            ("discovery",            ["discovery"],                         ["T1046"],                 "low",      20, "High ephemeral port traffic in VPC flow logs — normal application traffic or port scan."),
    "icmp_flood":                   ("web_attack",           ["impact"],                            ["T1498"],                 "medium",   55, "ICMP flood detected in VPC flow logs — possible denial of service."),
    "vpc_deleted":                  ("data_destruction",     ["impact"],                            ["T1531"],                 "high",     75, "VPC deleted — all network infrastructure within VPC destroyed."),
    "subnet_created":               ("lateral_movement",     ["lateral_movement"],                  ["T1563.001"],             "low",      25, "VPC subnet created — new network segment provisioned."),
    "route_table_modified":         ("lateral_movement",     ["lateral_movement"],                  ["T1563.001"],             "medium",   50, "VPC route table modified — network routing changed."),
    "nacl_modified":                ("defense_evasion",      ["defense_evasion"],                   ["T1562.007"],             "medium",   55, "Network ACL modified — subnet access controls changed."),
    "vpc_flow_logs_disabled":       ("defense_evasion",      ["defense_evasion"],                   ["T1562.008"],             "high",     78, "VPC flow logs disabled — network traffic monitoring stopped."),

    # ── Network (netsec) operations ───────────────────────────────────────
    "cloudfront_create_distribution":("execution",          ["initial_access"],                    ["T1583.003"],             "medium",   50, "CloudFront distribution created — CDN endpoint provisioned."),
    "elb_create_load_balancer":     ("execution",           ["persistence"],                       ["T1583.003"],             "medium",   45, "Elastic Load Balancer created — traffic distribution endpoint provisioned."),
    "elb_modify_load_balancer_attributes":("defense_evasion",["defense_evasion"],                  ["T1578.004"],             "medium",   50, "ELB attributes modified — load balancer security or logging settings changed."),
    "elb_set_security_groups":      ("defense_evasion",     ["defense_evasion"],                   ["T1562.007"],             "medium",   55, "ELB security groups updated — load balancer network access controls changed."),
    "internet_gateway_attached":    ("lateral_movement",    ["lateral_movement", "initial_access"],["T1563.001", "T1190"],    "high",     78, "Internet gateway attached to VPC — direct internet exposure added."),
    "internet_gateway_created":     ("lateral_movement",    ["lateral_movement"],                  ["T1563.001"],             "medium",   55, "Internet gateway created — enables internet connectivity for VPC."),
    "network_firewall_deleted":     ("defense_evasion",     ["defense_evasion"],                   ["T1562.007"],             "critical", 88, "AWS Network Firewall deleted — network-level protection removed."),
    "network_firewall_policy_deleted":("defense_evasion",   ["defense_evasion"],                   ["T1562.007"],             "high",     78, "Network Firewall policy deleted — firewall rules removed."),
    "network_firewall_policy_updated":("defense_evasion",   ["defense_evasion"],                   ["T1562.007"],             "medium",   55, "Network Firewall policy updated — firewall rule set changed."),
    "cloudfront_geo_restriction_removed":("defense_evasion",["defense_evasion"],                   ["T1562.007"],             "medium",   50, "CloudFront geo-restriction removed — previously blocked regions can now access content."),
    "elb_access_log_disabled":      ("defense_evasion",     ["defense_evasion"],                   ["T1562.008"],             "high",     72, "ELB access logging disabled — load balancer traffic visibility removed."),
    "shield_protection_deleted":    ("defense_evasion",     ["defense_evasion"],                   ["T1562.001"],             "high",     78, "AWS Shield protection deleted — DDoS mitigation removed from resource."),
    "waf_acl_deleted":              ("defense_evasion",     ["defense_evasion"],                   ["T1562.007"],             "critical", 88, "WAF Web ACL deleted — all WAF rules protecting associated resources removed."),
    "c2_high_port":                 ("execution",           ["command_and_control"],               ["T1571"],                 "high",     78, "Traffic on non-standard high port — possible C2 communication channel."),
    "sg_open_to_world":             ("defense_evasion",     ["defense_evasion", "initial_access"], ["T1562.007", "T1190"],    "critical", 88, "Security group opened to entire internet — unrestricted inbound access detected."),
    "dns_exfil":                    ("data_exfiltration",   ["exfiltration", "command_and_control"],["T1048.003", "T1071.004"],"high",   80, "DNS-based data exfiltration pattern detected — data encoded in DNS queries tunneled out."),
    "high_bandwidth_egress":        ("data_exfiltration",   ["exfiltration"],                      ["T1048"],                 "high",     75, "Unusually high outbound bandwidth — bulk data transfer to external destination."),
    "high_port_scan":               ("discovery",           ["discovery"],                         ["T1046"],                 "medium",   55, "Port scan activity detected — systematic probing of network ports."),

    # ── DNS log operations ────────────────────────────────────────────────
    "crypto_mining_domain":         ("execution",           ["command_and_control"],               ["T1496"],                 "high",     80, "Known crypto-mining domain queried — cryptocurrency mining activity detected."),
    "crypto_mining_stratum":        ("execution",           ["command_and_control"],               ["T1496"],                 "high",     80, "Crypto mining stratum protocol traffic — mining pool communication detected."),
    "dynamic_dns_dynu":             ("execution",           ["command_and_control"],               ["T1568.001"],             "medium",   58, "Dynamic DNS provider (Dynu) queried — possible C2 fast-flux domain rotation."),
    "dynamic_dns_noip":             ("execution",           ["command_and_control"],               ["T1568.001"],             "medium",   58, "Dynamic DNS provider (No-IP) queried — possible C2 fast-flux domain rotation."),
    "dynamic_dns_provider":         ("execution",           ["command_and_control"],               ["T1568.001"],             "medium",   55, "Dynamic DNS provider queried — commonly abused for fast-flux C2 infrastructure."),
    "file_sharing_domain":          ("data_exfiltration",   ["exfiltration"],                      ["T1567"],                 "medium",   55, "File sharing domain queried — data may be exfiltrated via web service."),
    "mx_record_lookup":             ("discovery",           ["discovery"],                         ["T1590.002"],             "low",      25, "MX DNS record lookup — mail server discovery."),
    "ngrok_tunnel":                 ("execution",           ["command_and_control"],               ["T1572"],                 "high",     78, "Ngrok tunnel domain queried — protocol tunnel for C2 or data exfiltration via ngrok.io."),
    "pastebin_access":              ("data_exfiltration",   ["exfiltration"],                      ["T1567"],                 "medium",   55, "Pastebin.com DNS query — possible use for C2 instructions or data staging."),
    "reverse_lookup":               ("discovery",           ["discovery"],                         ["T1590"],                 "low",      25, "DNS reverse lookup (PTR record) — network reconnaissance activity."),
    "suspicious_subdomain":         ("execution",           ["command_and_control"],               ["T1568.002"],             "medium",   58, "Suspicious subdomain pattern in DNS query — possible domain generation algorithm (DGA) or C2 domain."),
    "txt_record_query":             ("discovery",           ["discovery"],                         ["T1590.002"],             "low",      25, "DNS TXT record query — may be used for SPF/DMARC recon or C2 beaconing."),

    # ── RDS database log operations ───────────────────────────────────────
    "admin_user_activity":          ("discovery",           ["discovery"],                         ["T1087"],                 "medium",   55, "RDS admin user activity detected — privileged database user action recorded."),
    "alter_table":                  ("defense_evasion",     ["defense_evasion"],                   ["T1485"],                 "medium",   55, "ALTER TABLE statement executed — database schema modified."),
    "connection_closed":            ("discovery",           ["discovery"],                         ["T1046"],                 "low",      20, "RDS database connection closed — routine session termination."),
    "create_table":                 ("execution",           ["execution"],                         ["T1059.007"],             "low",      25, "CREATE TABLE executed — new database table created."),
    "drop_table":                   ("data_destruction",    ["impact"],                            ["T1485"],                 "high",     78, "DROP TABLE executed — database table permanently deleted."),
    "drop_user":                    ("identity_manipulation",["defense_evasion"],                  ["T1531"],                 "medium",   50, "Database user dropped — database account deleted."),
    "failed_login":                 ("initial_access",      ["credential_access"],                 ["T1110.001"],             "medium",   50, "RDS login failure — authentication attempt failed."),
    "grant_privilege":              ("privilege_escalation",["privilege_escalation"],              ["T1098.001"],             "high",     72, "Database privilege granted to user — elevated permissions assigned."),
    "revoke_privilege":             ("privilege_escalation",["defense_evasion"],                   ["T1531"],                 "medium",   40, "Database privilege revoked."),
    "root_user_activity":           ("credential_access",   ["credential_access"],                 ["T1078.004"],             "high",     80, "RDS root/master user activity detected — highest-privilege database account used."),
    "select_sensitive":             ("data_exfiltration",   ["collection"],                        ["T1530"],                 "medium",   55, "SELECT query on sensitive database table — possible data reconnaissance or exfiltration."),

    # ── GuardDuty finding-based ops ───────────────────────────────────────
    "backdoor_activity":            ("execution",           ["command_and_control"],               ["T1587.001"],             "critical", 90, "GuardDuty detected backdoor activity — malware or implant communicating."),
    "credential_exfiltration":      ("credential_access",   ["credential_access", "exfiltration"], ["T1552.005", "T1041"],    "critical", 92, "GuardDuty detected credential exfiltration — credentials stolen and transmitted."),
    "crypto_mining":                ("execution",           ["impact"],                            ["T1496"],                 "high",     78, "GuardDuty detected cryptocurrency mining activity — compute resources abused."),
    "data_exfiltration":            ("data_exfiltration",   ["exfiltration"],                      ["T1537"],                 "critical", 92, "GuardDuty detected data exfiltration — sensitive data leaving account."),
    "policy_iam":                   ("privilege_escalation",["privilege_escalation"],              ["T1098.001"],             "high",     75, "GuardDuty IAM policy finding — anomalous or dangerous permission change."),
    "policy_s3_public":             ("data_exfiltration",   ["exfiltration"],                      ["T1530"],                 "high",     78, "GuardDuty: S3 bucket made public — data exposed to internet."),
    "recon_activity":               ("discovery",           ["discovery"],                         ["T1580"],                 "medium",   55, "GuardDuty detected reconnaissance activity — environment being probed."),
    "trojan_activity":              ("execution",           ["execution", "command_and_control"],  ["T1587.001", "T1573"],    "critical", 92, "GuardDuty detected trojan activity — malware executing in environment."),
    "unauthorized_access":          ("initial_access",      ["initial_access"],                    ["T1078.004"],             "high",     78, "GuardDuty detected unauthorized access — activity from unexpected source."),
    "unusual_api":                  ("discovery",           ["discovery"],                         ["T1087.004"],             "medium",   55, "GuardDuty detected unusual API activity — anomalous API call pattern."),

    # ── Lambda-specific operations ────────────────────────────────────────
    "concurrency_limit_removed":    ("defense_evasion",     ["defense_evasion"],                   ["T1562.001"],             "medium",   50, "Lambda concurrency limit removed — function can now scale without restriction."),
    "env_vars_updated":             ("defense_evasion",     ["defense_evasion"],                   ["T1562.001"],             "high",     70, "Lambda environment variables updated — function configuration changed; may expose secrets."),
    "execution_role_changed":       ("privilege_escalation",["privilege_escalation"],              ["T1098.001"],             "high",     75, "Lambda execution role changed — function permissions modified."),
    "function_code_updated":        ("execution",           ["execution"],                         ["T1651"],                 "high",     72, "Lambda function code updated via cloud admin API — existing function logic replaced."),
    "function_created":             ("execution",           ["execution", "persistence"],          ["T1651"],                 "high",     68, "Lambda function created — serverless compute workload deployed via cloud admin API."),
    "function_deleted":             ("defense_evasion",     ["defense_evasion"],                   ["T1531"],                 "medium",   45, "Lambda function deleted."),
    "function_url_public":          ("initial_access",      ["initial_access"],                    ["T1190"],                 "high",     78, "Lambda function URL configured for public access — serverless function exposed to internet."),
    "layer_permission_added":       ("persistence",         ["persistence"],                       ["T1648"],                 "medium",   55, "Lambda layer permission added — external account can use this layer."),
    "resource_policy_cross_account":("lateral_movement",    ["lateral_movement"],                  ["T1548.005"],             "high",     75, "Lambda resource policy grants cross-account invocation — external account can invoke function."),
    "connection_refused":           ("discovery",           ["discovery"],                         ["T1046"],                 "low",      20, "Lambda connection refused — function could not connect to external endpoint."),
    "lambda_add_layer_permission":  ("persistence",         ["persistence"],                       ["T1651"],                 "medium",   55, "Lambda layer permission added — sharing configuration changed via cloud admin API."),
    "lambda_create_event_source_mapping":("execution",      ["execution"],                         ["T1651"],                 "medium",   50, "Lambda event source mapping created — trigger configured for function."),
    "lambda_delete_function":       ("defense_evasion",     ["defense_evasion"],                   ["T1531"],                 "medium",   45, "Lambda function deleted."),
    "lambda_publish_layer_version": ("execution",           ["execution"],                         ["T1651"],                 "low",      30, "Lambda layer version published via cloud admin API."),

    # ── Container / ECS / EKS additional ops ─────────────────────────────
    "ecr_image_push":               ("persistence",         ["persistence"],                       ["T1525"],                 "medium",   55, "Container image pushed to ECR — new image version deployed to registry."),
    "ecr_image_scan_finding":       ("discovery",           ["discovery"],                         ["T1595"],                 "medium",   50, "ECR image scan finding — vulnerability detected in container image."),
    "ecr_repo_deleted":             ("data_destruction",    ["impact"],                            ["T1485"],                 "high",     75, "ECR container repository deleted — all images in repository destroyed."),
    "ecr_repo_policy_changed":      ("lateral_movement",    ["lateral_movement"],                  ["T1548.005"],             "medium",   58, "ECR repository policy changed — image access permissions modified."),
    "ecs_cluster_deleted":          ("data_destruction",    ["impact"],                            ["T1578.003"],             "high",     78, "ECS cluster deleted — all services and tasks terminated."),
    "ecs_exec_command":             ("execution",           ["execution"],                         ["T1059.013"],             "high",     80, "ECS Exec command executed — direct shell access via container CLI/API obtained."),
    "ecs_task_def_host_network":    ("lateral_movement",    ["lateral_movement"],                  ["T1610"],                 "high",     75, "ECS task definition uses host network — container has access to host network stack."),
    "ecs_task_privileged":          ("privilege_escalation",["privilege_escalation"],              ["T1611"],                 "critical", 88, "ECS task running in privileged mode — container has elevated host capabilities."),
    "eks_access_entry_created":     ("privilege_escalation",["privilege_escalation"],              ["T1098.001"],             "medium",   58, "EKS access entry created — IAM principal granted Kubernetes access."),
    "eks_cluster_public":           ("initial_access",      ["initial_access"],                    ["T1190"],                 "high",     75, "EKS cluster API server made publicly accessible — Kubernetes control plane exposed."),
    "clusterrole_create":           ("privilege_escalation",["privilege_escalation"],              ["T1098.006"],             "high",     75, "Kubernetes ClusterRole created — cluster-wide container cluster permissions defined."),
    "clusterrolebinding_create":    ("privilege_escalation",["privilege_escalation"],              ["T1098.006"],             "critical", 88, "Kubernetes ClusterRoleBinding created — cluster-wide container cluster role assigned to subject."),
    "configmap_modify":             ("defense_evasion",     ["defense_evasion"],                   ["T1562.001"],             "medium",   55, "Kubernetes ConfigMap modified — application configuration changed."),
    "crd_create":                   ("persistence",         ["persistence"],                       ["T1136"],                 "medium",   50, "Kubernetes CRD created — custom resource type added to cluster."),
    "daemonset_create":             ("persistence",         ["persistence", "execution"],          ["T1610"],                 "high",     72, "Kubernetes DaemonSet created — workload scheduled on every node."),
    "deployment_create":            ("execution",           ["execution"],                         ["T1610"],                 "medium",   50, "Kubernetes Deployment created — new workload deployed to cluster."),
    "ingress_modify":               ("defense_evasion",     ["defense_evasion"],                   ["T1562.007"],             "medium",   55, "Kubernetes Ingress modified — external traffic routing rules changed."),
    "namespace_create":             ("persistence",         ["persistence"],                       ["T1610"],                 "low",      25, "Kubernetes namespace created — new isolated environment provisioned."),
    "namespace_delete":             ("data_destruction",    ["impact"],                            ["T1578.003"],             "high",     75, "Kubernetes namespace deleted — all resources in namespace destroyed."),
    "networkpolicy_modify":         ("defense_evasion",     ["defense_evasion"],                   ["T1562.007"],             "medium",   55, "Kubernetes NetworkPolicy modified — pod-to-pod network access controls changed."),
    "pod_created":                  ("execution",           ["execution"],                         ["T1610"],                 "low",      25, "Kubernetes pod created — container workload started."),
    "pod_deleted":                  ("defense_evasion",     ["defense_evasion"],                   ["T1531"],                 "low",      25, "Kubernetes pod deleted."),
    "secret_accessed":              ("credential_access",   ["credential_access"],                 ["T1552.007"],             "high",     78, "Kubernetes Secret accessed via container API — sensitive credential data read from cluster."),
    "serviceaccount_create":        ("persistence",         ["persistence"],                       ["T1098.006"],             "medium",   55, "Kubernetes ServiceAccount created — container cluster workload identity provisioned."),

    # ── Storage operations ────────────────────────────────────────────────
    "dynamodb_create_global_table": ("execution",           ["persistence"],                       ["T1578.002"],             "low",      30, "DynamoDB global table created — replicated database provisioned."),
    "dynamodb_delete_backup":       ("data_destruction",    ["impact"],                            ["T1485"],                 "high",     75, "DynamoDB backup deleted — point-in-time recovery data destroyed."),
    "dynamodb_delete_table":        ("data_destruction",    ["impact"],                            ["T1485"],                 "critical", 88, "DynamoDB table deleted — all data and configuration permanently destroyed."),
    "dynamodb_export_table":        ("data_exfiltration",   ["collection", "exfiltration"],        ["T1530"],                 "high",     75, "DynamoDB table exported — full table data extracted to S3."),
    "dynamodb_update_table":        ("defense_evasion",     ["defense_evasion"],                   ["T1578.004"],             "medium",   45, "DynamoDB table updated — provisioning or encryption settings changed."),
    "ebs_create_snapshots_bulk":    ("data_exfiltration",   ["collection"],                        ["T1530"],                 "high",     72, "Multiple EBS snapshots created in bulk — possible data collection prior to exfiltration."),
    "ebs_modify_snapshot_attribute_public":("data_exfiltration",["exfiltration"],                  ["T1537"],                 "critical", 90, "EBS snapshot made public — volume data accessible to any AWS account."),
    "efs_create_file_system":       ("persistence",         ["persistence"],                       ["T1578.002"],             "low",      30, "EFS file system created — shared network storage provisioned."),
    "efs_put_file_system_policy":   ("data_exfiltration",   ["exfiltration"],                      ["T1537"],                 "high",     70, "EFS file system policy updated — may grant cross-account or public access."),
    "elasticache_create_replication_group":("persistence",  ["persistence"],                       ["T1578.002"],             "low",      30, "ElastiCache replication group created — in-memory cache cluster provisioned."),
    "elasticache_delete_replication_group":("data_destruction",["impact"],                         ["T1485"],                 "high",     75, "ElastiCache replication group deleted — cache cluster destroyed."),
    "fsx_create_file_system":       ("persistence",         ["persistence"],                       ["T1578.002"],             "low",      30, "FSx file system created — managed file storage provisioned."),
    "fsx_delete_file_system":       ("data_destruction",    ["impact"],                            ["T1485"],                 "critical", 88, "FSx file system deleted — managed file storage destroyed."),
    "glacier_delete_vault":         ("data_destruction",    ["impact"],                            ["T1485"],                 "high",     78, "Glacier vault deleted — long-term archive storage destroyed."),
    "s3_bucket_replication_enabled":("data_exfiltration",   ["exfiltration"],                      ["T1537"],                 "high",     72, "S3 bucket replication configured — objects will be automatically copied to destination bucket."),
    "s3_encryption_disabled":       ("defense_evasion",     ["defense_evasion"],                   ["T1562.001"],             "high",     72, "S3 bucket encryption disabled — data stored unencrypted."),
    "s3_public_access_block_removed":("data_exfiltration",  ["exfiltration"],                      ["T1530"],                 "critical", 90, "S3 public access block removed — bucket may become publicly accessible."),
    "encryption_disabled":          ("defense_evasion",     ["defense_evasion"],                   ["T1562.001"],             "high",     72, "Encryption disabled on storage resource — data stored unencrypted."),
    "bucket_policy_change":         ("data_exfiltration",   ["exfiltration"],                      ["T1537"],                 "high",     75, "S3 bucket policy changed — access permissions modified."),
    "public_access_block_removed":  ("data_exfiltration",   ["exfiltration"],                      ["T1530"],                 "critical", 90, "S3 public access block removed — bucket may be exposed to public internet."),
    "replication_enabled":          ("data_exfiltration",   ["exfiltration"],                      ["T1537"],                 "high",     72, "Storage replication enabled — data will be copied to replication destination."),
    "snapshot_shared":              ("data_exfiltration",   ["exfiltration"],                      ["T1537"],                 "critical", 88, "Storage snapshot shared with external account — backup data accessible outside account."),
    "data_exposure":                ("data_exfiltration",   ["exfiltration"],                      ["T1530"],                 "critical", 90, "Data exposure event detected — sensitive data may be publicly accessible."),
    "encryption_downgrade":         ("defense_evasion",     ["defense_evasion"],                   ["T1562.001"],             "high",     75, "Encryption downgrade detected — storage encryption standard weakened."),
    "glue_job_started":             ("execution",           ["execution"],                         ["T1059.007"],             "medium",   50, "AWS Glue ETL job started — data processing workload executed."),
    "kms_key_grant":                ("privilege_escalation",["privilege_escalation"],              ["T1098.001"],             "high",     72, "KMS key grant created — additional principal granted encryption/decryption permissions."),
    "rds_query_activity":           ("discovery",           ["collection"],                        ["T1530"],                 "medium",   55, "RDS query activity log event — database query recorded."),

    # ── Security services (secsvc) ────────────────────────────────────────
    "acm_delete_certificate":       ("defense_evasion",     ["defense_evasion"],                   ["T1562.001"],             "medium",   50, "ACM certificate deleted — TLS certificate removed."),
    "acm_export_certificate":       ("credential_access",   ["credential_access"],                 ["T1552.004"],             "high",     72, "ACM certificate exported — private key extracted from certificate manager."),
    "cloudtrail_put_event_selectors":("defense_evasion",    ["defense_evasion"],                   ["T1562.008"],             "high",     72, "CloudTrail event selectors modified — some API events may no longer be logged."),
    "config_delete_delivery_channel":("defense_evasion",    ["defense_evasion"],                   ["T1562.001"],             "high",     78, "AWS Config delivery channel deleted — configuration recording delivery stopped."),
    "config_delete_rule":           ("defense_evasion",     ["defense_evasion"],                   ["T1562.001"],             "medium",   58, "AWS Config rule deleted — compliance monitoring check removed."),
    "config_stop_recorder":         ("defense_evasion",     ["defense_evasion"],                   ["T1562.001"],             "critical", 88, "AWS Config recorder stopped — all configuration change tracking halted."),
    "guardduty_archive_findings":   ("defense_evasion",     ["defense_evasion"],                   ["T1562.001"],             "medium",   50, "GuardDuty findings archived — threat alerts suppressed from active view."),
    "guardduty_create_filter":      ("defense_evasion",     ["defense_evasion"],                   ["T1562.001"],             "medium",   55, "GuardDuty suppression filter created — specific finding types will be auto-suppressed."),
    "guardduty_delete_detector":    ("defense_evasion",     ["defense_evasion"],                   ["T1562.001"],             "critical", 92, "GuardDuty detector deleted — threat detection entirely disabled for region."),
    "guardduty_disable_org_admin":  ("defense_evasion",     ["defense_evasion"],                   ["T1562.001"],             "critical", 90, "GuardDuty org admin account disabled — organization-wide threat detection management removed."),
    "inspector_delete_assessment":  ("defense_evasion",     ["defense_evasion"],                   ["T1562.001"],             "medium",   55, "AWS Inspector assessment deleted — vulnerability scanning removed."),
    "macie_bucket_association":     ("discovery",           ["discovery"],                         ["T1087.004"],             "low",      25, "Macie S3 bucket association changed — data classification scope modified."),
    "securityhub_disable_control":  ("defense_evasion",     ["defense_evasion"],                   ["T1562.001"],             "high",     72, "Security Hub control disabled — security finding type suppressed."),
    "securityhub_disable_standards":("defense_evasion",     ["defense_evasion"],                   ["T1562.001"],             "high",     78, "Security Hub security standards disabled — compliance framework monitoring stopped."),
    "ssm_get_parameters":           ("credential_access",   ["credential_access"],                 ["T1552.001"],             "high",     72, "SSM Parameter Store GetParameters — bulk parameter/secret retrieval."),
    "waf_create_ip_set":            ("defense_evasion",     ["defense_evasion"],                   ["T1562.007"],             "medium",   45, "WAF IP set created — IP allowlist/blocklist modified."),
    "waf_create_rule":              ("defense_evasion",     ["defense_evasion"],                   ["T1562.007"],             "medium",   45, "WAF rule created — web traffic filtering rule added."),
    "waf_create_web_acl":           ("defense_evasion",     ["defense_evasion"],                   ["T1562.007"],             "medium",   45, "WAF Web ACL created — new web application firewall configuration provisioned."),
    "waf_delete_ip_set":            ("defense_evasion",     ["defense_evasion"],                   ["T1562.007"],             "medium",   55, "WAF IP set deleted — IP-based access control removed."),
    "waf_delete_rule":              ("defense_evasion",     ["defense_evasion"],                   ["T1562.007"],             "high",     68, "WAF rule deleted — web application protection rule removed."),
    "waf_delete_web_acl":           ("defense_evasion",     ["defense_evasion"],                   ["T1562.007"],             "critical", 88, "WAF Web ACL deleted — all WAF protections removed."),
    "waf_update_web_acl":           ("defense_evasion",     ["defense_evasion"],                   ["T1562.007"],             "medium",   55, "WAF Web ACL updated — firewall rule configuration changed."),
    "kms_delete_key":               ("data_destruction",    ["impact"],                            ["T1485"],                 "critical", 92, "KMS key scheduled for deletion — data encrypted with this key will become permanently inaccessible."),
    "kms_disable_key":              ("defense_evasion",     ["defense_evasion"],                   ["T1562.001"],             "high",     78, "KMS key disabled — encryption/decryption operations with this key will fail."),
    "kms_put_key_policy":           ("privilege_escalation",["privilege_escalation"],              ["T1098.001"],             "high",     72, "KMS key policy updated — encryption key access control modified."),

    # ── Compute additional ops ─────────────────────────────────────────────
    "ec2_stop_instances":           ("defense_evasion",     ["impact"],                            ["T1529"],                 "medium",   55, "EC2 instances stopped — compute resources taken offline."),
    "ecs_create_service":           ("execution",           ["execution", "persistence"],          ["T1610"],                 "medium",   50, "ECS service created — containerized workload deployed."),
    "ecs_delete_service":           ("data_destruction",    ["impact"],                            ["T1578.003"],             "medium",   50, "ECS service deleted — containerized workload stopped."),
    "ecs_execute_command":          ("execution",           ["execution"],                         ["T1059.013"],             "high",     80, "ECS Exec command — shell access via container CLI/API obtained."),
    "eks_associate_access_policy":  ("privilege_escalation",["privilege_escalation"],              ["T1098.001"],             "medium",   58, "EKS access policy associated — Kubernetes access permissions granted."),
    "eks_create_nodegroup":         ("execution",           ["execution"],                         ["T1610"],                 "medium",   45, "EKS node group created — new compute capacity added to cluster."),

    # ── DevOps operations ──────────────────────────────────────────────────
    "cfn_create_stack":             ("execution",           ["execution"],                         ["T1072"],                 "medium",   50, "CloudFormation stack created — infrastructure deployed via IaC template."),
    "cfn_delete_stack":             ("data_destruction",    ["impact"],                            ["T1578.003"],             "high",     72, "CloudFormation stack deleted — all resources in stack destroyed."),
    "cfn_execute_change_set":       ("execution",           ["execution"],                         ["T1072"],                 "medium",   50, "CloudFormation change set executed — infrastructure modified."),
    "cfn_update_stack":             ("defense_evasion",     ["execution"],                         ["T1072"],                 "medium",   55, "CloudFormation stack updated — infrastructure configuration changed."),
    "codebuild_start_build":        ("execution",           ["execution"],                         ["T1072"],                 "medium",   50, "CodeBuild build started — CI/CD build pipeline executed."),
    "codebuild_update_project":     ("defense_evasion",     ["execution"],                         ["T1072"],                 "medium",   50, "CodeBuild project updated — build configuration or environment changed."),
    "codedeploy_create_application":("execution",           ["persistence"],                       ["T1072"],                 "low",      30, "CodeDeploy application created — deployment target defined."),
    "codedeploy_create_deployment": ("execution",           ["execution"],                         ["T1072"],                 "medium",   50, "CodeDeploy deployment created — application version deployed to targets."),
    "codepipeline_create_pipeline": ("persistence",         ["persistence"],                       ["T1072"],                 "medium",   50, "CodePipeline created — CI/CD automation workflow established."),
    "codepipeline_put_action_revision":("execution",        ["execution"],                         ["T1072"],                 "low",      30, "CodePipeline action revision updated — pipeline artifact version changed."),
    "ecr_backdoor_image":           ("persistence",         ["persistence"],                       ["T1525"],                 "critical", 92, "Container image backdoor pattern: suspicious image push with known malicious indicators."),

    # ── Monitor / CloudWatch / Athena ─────────────────────────────────────
    "athena_create_named_query":    ("discovery",           ["discovery"],                         ["T1087.004"],             "low",      25, "Athena named query created — SQL query saved for data analysis."),
    "athena_start_query_execution": ("data_exfiltration",   ["collection"],                        ["T1530"],                 "medium",   55, "Athena query executed — S3 data queried via SQL; may indicate data reconnaissance."),
    "cloudwatch_delete_alarms":     ("defense_evasion",     ["defense_evasion"],                   ["T1562.001"],             "medium",   55, "CloudWatch alarms deleted — monitoring alerts removed."),
    "cloudwatch_disable_alarm_actions":("defense_evasion",  ["defense_evasion"],                   ["T1562.001"],             "medium",   55, "CloudWatch alarm actions disabled — automated responses to alarms stopped."),
    "cloudwatch_put_dashboard":     ("discovery",           ["discovery"],                         ["T1087.004"],             "low",      20, "CloudWatch dashboard created or updated."),
    "cloudwatch_put_metric_alarm":  ("persistence",         ["persistence"],                       ["T1087.004"],             "low",      20, "CloudWatch metric alarm created or updated."),
    "glue_create_crawler":          ("discovery",           ["collection"],                        ["T1530"],                 "low",      30, "Glue crawler created — data catalog discovery job configured."),
    "glue_create_job":              ("execution",           ["execution"],                         ["T1059.007"],             "low",      30, "Glue ETL job created — data transformation workload defined."),
    "glue_update_job":              ("execution",           ["execution"],                         ["T1059.007"],             "low",      30, "Glue ETL job updated — data transformation configuration changed."),
    "logs_delete_log_group":        ("defense_evasion",     ["defense_evasion"],                   ["T1562.008"],             "high",     75, "CloudWatch log group deleted — log data and future logging capability destroyed."),
    "logs_filter_deleted":          ("defense_evasion",     ["defense_evasion"],                   ["T1562.008"],             "medium",   55, "CloudWatch log metric filter deleted — automated alerting on log events removed."),
    "eventbridge_rule_deleted":     ("defense_evasion",     ["defense_evasion"],                   ["T1562.001"],             "medium",   55, "EventBridge rule deleted — automated event response removed."),
    "eventbridge_disable_rule":     ("defense_evasion",     ["defense_evasion"],                   ["T1562.001"],             "medium",   55, "EventBridge rule disabled — event-driven automation stopped."),

    # ── PaaS operations (API Gateway, Cognito, etc.) ─────────────────────
    "apigateway_create_api_key":    ("credential_access",   ["persistence"],                       ["T1552.001"],             "medium",   55, "API Gateway API key created — programmatic access credential established."),
    "apigateway_create_rest_api":   ("execution",           ["persistence"],                       ["T1190"],                 "medium",   50, "API Gateway REST API created — new API endpoint provisioned."),
    "apigateway_create_stage":      ("execution",           ["execution"],                         ["T1190"],                 "low",      30, "API Gateway stage created — API deployment environment configured."),
    "apigateway_delete_rest_api":   ("data_destruction",    ["impact"],                            ["T1531"],                 "medium",   50, "API Gateway REST API deleted — API endpoint destroyed."),
    "apigateway_update_stage":      ("defense_evasion",     ["defense_evasion"],                   ["T1578.004"],             "medium",   50, "API Gateway stage updated — API configuration changed."),
    "cognito_admin_set_user_password":("identity_manipulation",["credential_access"],              ["T1098.001"],             "high",     70, "Cognito admin set user password — account credentials reset by admin."),
    "cognito_create_identity_pool": ("persistence",         ["persistence"],                       ["T1098.005"],             "medium",   55, "Cognito identity pool created — federated identity access to AWS resources configured."),
    "cognito_create_user_pool":     ("persistence",         ["persistence"],                       ["T1136.003"],             "medium",   50, "Cognito user pool created — managed user directory provisioned."),
    "cognito_update_identity_pool": ("persistence",         ["persistence"],                       ["T1098.005"],             "medium",   55, "Cognito identity pool updated — federated identity configuration changed."),
    "cognito_update_user_pool":     ("defense_evasion",     ["defense_evasion"],                   ["T1562.001"],             "medium",   50, "Cognito user pool updated — authentication configuration changed."),
    "elasticbeanstalk_create_environment":("execution",     ["execution"],                         ["T1578.002"],             "medium",   45, "Elastic Beanstalk environment created — application stack provisioned."),
    "elasticbeanstalk_terminate_environment":("data_destruction",["impact"],                       ["T1578.003"],             "medium",   55, "Elastic Beanstalk environment terminated — application stack destroyed."),
    "sagemaker_create_notebook":    ("execution",           ["execution"],                         ["T1059.007"],             "medium",   50, "SageMaker notebook instance created — ML development environment provisioned."),
    "sagemaker_delete_notebook":    ("data_destruction",    ["impact"],                            ["T1578.003"],             "medium",   45, "SageMaker notebook instance deleted."),
    "sns_create_topic":             ("persistence",         ["persistence"],                       ["T1583.003"],             "low",      25, "SNS topic created — messaging endpoint provisioned."),
    "sns_delete_topic":             ("data_destruction",    ["impact"],                            ["T1531"],                 "low",      25, "SNS topic deleted."),
    "sqs_create_queue":             ("persistence",         ["persistence"],                       ["T1583.003"],             "low",      25, "SQS queue created — message queue provisioned."),
    "sqs_delete_queue":             ("data_destruction",    ["impact"],                            ["T1531"],                 "low",      30, "SQS queue deleted — message queue destroyed."),
    "step_function_deleted":        ("data_destruction",    ["impact"],                            ["T1531"],                 "medium",   45, "Step Functions state machine deleted."),
    "appsync_create_api":           ("execution",           ["initial_access"],                    ["T1190"],                 "medium",   45, "AppSync GraphQL API created."),
    "appsync_update_api":           ("defense_evasion",     ["defense_evasion"],                   ["T1578.004"],             "medium",   45, "AppSync GraphQL API updated."),

    # ── Threat correlation (existing L1s) ─────────────────────────────────
    "delete_db":                    ("data_destruction",    ["impact"],                            ["T1485"],                 "critical", 90, "Database deletion detected — all data permanently destroyed."),
    "delete_flow_logs":             ("defense_evasion",     ["defense_evasion"],                   ["T1562.008"],             "high",     78, "VPC flow logs deleted — network traffic visibility eliminated."),
    "delete_kms_key":               ("data_destruction",    ["impact"],                            ["T1485"],                 "critical", 92, "KMS key deleted — data encrypted with this key permanently inaccessible."),
    "disable_s3_logging":           ("defense_evasion",     ["defense_evasion"],                   ["T1562.008"],             "high",     72, "S3 server access logging disabled — bucket access tracking stopped."),
    "ec2_snapshot_shared":          ("data_exfiltration",   ["exfiltration"],                      ["T1537"],                 "critical", 88, "EC2 snapshot shared with external account — disk data accessible outside account."),
    "modify_security_group":        ("defense_evasion",     ["defense_evasion"],                   ["T1562.007"],             "high",     72, "Security group modified — network access control rules changed."),
    "pass_role":                    ("privilege_escalation",["privilege_escalation"],              ["T1548.005"],             "high",     80, "IAM role passed to service — service inherits role permissions; possible privilege escalation."),
    "rds_snapshot_public":          ("data_exfiltration",   ["exfiltration"],                      ["T1537"],                 "critical", 90, "RDS snapshot made public — database backup accessible to all AWS accounts."),
    "root_account_usage":           ("initial_access",      ["initial_access", "credential_access"],["T1078.004"],            "critical", 95, "Root account usage detected — highest-privilege account activity recorded."),
    "s3_make_public":               ("data_exfiltration",   ["exfiltration"],                      ["T1530"],                 "critical", 92, "S3 bucket or object made public — data exposed to internet."),
    "s3_public_policy":             ("data_exfiltration",   ["exfiltration"],                      ["T1530"],                 "critical", 90, "S3 bucket policy grants public access — data accessible without authentication."),
    "steal_access_key":             ("credential_access",   ["credential_access"],                 ["T1552.005"],             "critical", 92, "Access key theft pattern detected — credential exfiltration activity identified."),
    "unauthorized_api_call":        ("discovery",           ["discovery"],                         ["T1087.004"],             "medium",   55, "Unauthorized API call — operation denied due to insufficient permissions."),
    "sensitive_data_access":        ("data_exfiltration",   ["collection"],                        ["T1530"],                 "high",     75, "Access to sensitive data resource detected."),

    # ── CIEM correlation rule L1s ─────────────────────────────────────────
    "policy_attached":              ("privilege_escalation",["privilege_escalation"],              ["T1098.003"],             "high",     78, "IAM policy attached — permissions granted to principal."),
    "policy_created":               ("privilege_escalation",["privilege_escalation"],              ["T1098.003"],             "medium",   55, "IAM policy created — new permission set defined."),

    # ── DataSec / Datasec ──────────────────────────────────────────────────
    "glue_job_start":               ("execution",           ["execution"],                         ["T1059.007"],             "medium",   50, "Glue ETL job started — data processing pipeline executed."),
    "datasec_data_exposure":        ("data_exfiltration",   ["exfiltration"],                      ["T1530"],                 "critical", 90, "Data exposure detected — sensitive data publicly accessible."),
    "mass_download":                ("data_exfiltration",   ["collection", "exfiltration"],        ["T1530"],                 "high",     78, "Mass download of data detected — large-scale bulk data access in progress."),
    "residency_violation":          ("data_exfiltration",   ["exfiltration"],                      ["T1537"],                 "high",     72, "Data residency violation — data transferred to non-compliant region or account."),

    # ── Storage (S3/RDS/Redshift/ElastiCache) ─────────────────────────────
    "elasticache_modify_replication_group":("defense_evasion",["defense_evasion"],                ["T1578.004"],             "medium",   50, "ElastiCache replication group modified — cache cluster configuration changed."),
    "rds_modify_cluster_snapshot_attribute":("data_exfiltration",["exfiltration"],                ["T1537"],                 "critical", 88, "RDS cluster snapshot attribute modified — snapshot may be shared with external accounts."),
    "rds_modify_db_instance_public":("initial_access",      ["initial_access"],                   ["T1190"],                 "critical", 88, "RDS instance modified to be publicly accessible — database exposed to internet."),
    "rds_restore_from_snapshot":    ("data_exfiltration",   ["exfiltration"],                      ["T1537"],                 "high",     72, "RDS instance restored from snapshot — may be used to access data in another account."),
    "rds_share_db_snapshot":        ("data_exfiltration",   ["exfiltration"],                      ["T1537"],                 "critical", 90, "RDS snapshot shared with external account — database backup accessible outside account."),
    "redshift_authorize_snapshot_access":("data_exfiltration",["exfiltration"],                   ["T1537"],                 "critical", 88, "Redshift snapshot access authorized to external account — data warehouse backup exposed."),
    "redshift_create_cluster_snapshot":("collection",       ["collection"],                        ["T1530"],                 "medium",   50, "Redshift cluster snapshot created — full data warehouse backup taken."),
    "redshift_modify_cluster_public":("initial_access",     ["initial_access"],                   ["T1190"],                 "critical", 88, "Redshift cluster modified to be publicly accessible — data warehouse exposed to internet."),
    "s3_delete_bucket_encryption":  ("defense_evasion",     ["defense_evasion"],                   ["T1562.001"],             "high",     75, "S3 bucket encryption deleted — objects will be stored unencrypted."),
    "s3_delete_bucket_policy":      ("data_exfiltration",   ["exfiltration"],                      ["T1537"],                 "high",     70, "S3 bucket policy deleted — access restrictions may have been removed."),
    "s3_put_bucket_acl":            ("data_exfiltration",   ["exfiltration"],                      ["T1530"],                 "high",     78, "S3 bucket ACL updated — bucket permissions changed, check for public access grants."),
    "s3_put_bucket_cors":           ("defense_evasion",     ["defense_evasion"],                   ["T1562.001"],             "medium",   55, "S3 bucket CORS policy updated — cross-origin access rules modified."),
    "s3_put_bucket_policy":         ("data_exfiltration",   ["exfiltration"],                      ["T1537"],                 "high",     75, "S3 bucket policy updated — check for public or cross-account access grants."),
    "s3_put_bucket_public_access_block_disable":("data_exfiltration",["exfiltration"],            ["T1530"],                 "critical", 92, "S3 public access block disabled — bucket no longer protected from public exposure."),
    "s3_put_bucket_replication":    ("data_exfiltration",   ["exfiltration"],                      ["T1537"],                 "high",     75, "S3 bucket replication configured — objects automatically copied to destination."),
    "s3_put_bucket_versioning_suspend":("data_destruction", ["impact"],                            ["T1485"],                 "high",     72, "S3 bucket versioning suspended — ability to recover deleted or overwritten objects removed."),
    "s3_put_bucket_website":        ("execution",           ["initial_access"],                    ["T1190"],                 "medium",   55, "S3 bucket configured as static website — public HTTP endpoint added to bucket."),
    "s3_put_object_lock_configuration":("defense_evasion",  ["defense_evasion"],                   ["T1562.001"],             "medium",   50, "S3 object lock configuration changed — object immutability settings modified."),

    # ── PaaS (EventBridge, SES, Step Functions, SNS, SQS) ─────────────────
    "eventbridge_create_event_bus": ("persistence",         ["persistence"],                       ["T1546"],                 "medium",   50, "EventBridge event bus created — new event routing endpoint established."),
    "eventbridge_delete_rule":      ("defense_evasion",     ["defense_evasion"],                   ["T1562.001"],             "medium",   55, "EventBridge rule deleted — automated event response removed."),
    "eventbridge_put_permission":   ("privilege_escalation",["privilege_escalation"],              ["T1098.003"],             "high",     72, "EventBridge cross-account permission added — external account can put events to bus."),
    "eventbridge_put_rule":         ("persistence",         ["persistence"],                       ["T1546"],                 "medium",   55, "EventBridge rule created or updated — automated event trigger configured."),
    "eventbridge_put_targets":      ("persistence",         ["persistence"],                       ["T1546"],                 "medium",   55, "EventBridge rule targets updated — event response actions modified."),
    "ses_create_email_identity":    ("persistence",         ["persistence"],                       ["T1585.002"],             "medium",   55, "SES email identity created — email sending capability provisioned; potential phishing base."),
    "ses_send_email":               ("initial_access",      ["initial_access"],                    ["T1566.001"],             "medium",   55, "Email sent via SES — may indicate phishing campaign or data exfiltration via email."),
    "sfn_create_state_machine":     ("execution",           ["execution"],                         ["T1651"],                 "medium",   45, "Step Functions state machine created — automated workflow orchestration provisioned."),
    "sfn_start_execution":          ("execution",           ["execution"],                         ["T1651"],                 "medium",   45, "Step Functions execution started — automated workflow triggered."),
    "sfn_update_state_machine":     ("defense_evasion",     ["defense_evasion"],                   ["T1651"],                 "medium",   50, "Step Functions state machine updated — workflow logic or IAM role changed."),
    "sns_set_topic_attributes":     ("defense_evasion",     ["defense_evasion"],                   ["T1562.001"],             "medium",   50, "SNS topic attributes updated — messaging endpoint configuration changed."),
    "sns_subscribe":                ("persistence",         ["persistence"],                       ["T1546"],                 "medium",   50, "SNS subscription created — endpoint will receive all topic notifications."),
    "sqs_purge_queue":              ("data_destruction",    ["impact"],                            ["T1485"],                 "high",     75, "SQS queue purged — all queued messages permanently deleted."),
    "sqs_set_queue_attributes":     ("defense_evasion",     ["defense_evasion"],                   ["T1562.001"],             "medium",   45, "SQS queue attributes updated — message queue configuration changed."),

    # ── Security services (remaining) ─────────────────────────────────────
    "guardduty_update_detector_disable":("defense_evasion", ["defense_evasion"],                   ["T1562.001"],             "critical", 90, "GuardDuty detector updated to disable — threat detection service being deactivated."),
    "inspector_delete_filter":      ("defense_evasion",     ["defense_evasion"],                   ["T1562.001"],             "medium",   50, "AWS Inspector suppression filter deleted."),
    "inspector_disabled":           ("defense_evasion",     ["defense_evasion"],                   ["T1562.001"],             "high",     78, "AWS Inspector disabled — vulnerability and exposure findings stopped."),
    "kms_create_grant":             ("privilege_escalation",["privilege_escalation"],              ["T1098.001"],             "high",     72, "KMS key grant created — additional principal granted cryptographic operations."),
    "kms_disable_key_rotation":     ("defense_evasion",     ["defense_evasion"],                   ["T1562.001"],             "medium",   58, "KMS key rotation disabled — encryption key will not be automatically rotated."),
    "kms_schedule_key_deletion":    ("data_destruction",    ["impact"],                            ["T1485"],                 "critical", 92, "KMS key scheduled for deletion — data encrypted with this key will become permanently inaccessible."),
    "macie_delete_custom_data_identifier":("defense_evasion",["defense_evasion"],                  ["T1562.001"],             "medium",   50, "Macie custom data identifier deleted — sensitive data pattern detection removed."),
    "macie_disabled":               ("defense_evasion",     ["defense_evasion"],                   ["T1562.001"],             "high",     78, "Amazon Macie disabled — sensitive data discovery and classification monitoring stopped."),
    "secretsmanager_delete_secret": ("data_destruction",    ["impact"],                            ["T1485"],                 "high",     75, "Secrets Manager secret deleted — stored credential permanently removed."),
    "secretsmanager_put_resource_policy":("data_exfiltration",["exfiltration"],                   ["T1537"],                 "high",     75, "Secrets Manager resource policy updated — may grant cross-account access to secrets."),
    "secretsmanager_put_secret_value":("credential_access", ["credential_access"],                 ["T1552.007"],             "high",     72, "Secrets Manager secret value updated — credential value modified via cloud secrets API."),
    "securityhub_disabled":         ("defense_evasion",     ["defense_evasion"],                   ["T1562.001"],             "high",     80, "AWS Security Hub disabled — centralized security finding aggregation stopped."),
    "securityhub_update_findings":  ("defense_evasion",     ["defense_evasion"],                   ["T1562.001"],             "medium",   50, "Security Hub findings suppressed or status changed."),

    # ── Network security (remaining) ──────────────────────────────────────
    "route53_associate_vpc":        ("lateral_movement",    ["lateral_movement"],                  ["T1584.002"],             "medium",   50, "Route53 hosted zone associated with VPC — private DNS resolution scope extended."),
    "route53_change_record_sets":   ("lateral_movement",    ["lateral_movement"],                  ["T1584.002"],             "high",     72, "Route53 DNS records changed — domain resolution modified."),
    "security_group_created":       ("defense_evasion",     ["defense_evasion"],                   ["T1562.007"],             "low",      25, "EC2 security group created — new network access control provisioned."),
    "security_group_deleted":       ("defense_evasion",     ["defense_evasion"],                   ["T1562.007"],             "medium",   50, "EC2 security group deleted — network access control removed."),
    "security_group_egress_modified":("defense_evasion",    ["defense_evasion"],                   ["T1562.007"],             "medium",   55, "Security group egress rules modified — outbound traffic controls changed."),
    "subnet_auto_assign_public_ip": ("initial_access",      ["initial_access"],                    ["T1190"],                 "high",     70, "Subnet configured to auto-assign public IPs — all launched instances will be internet-facing."),
    "transit_gateway_created":      ("lateral_movement",    ["lateral_movement"],                  ["T1563.001"],             "medium",   50, "Transit gateway created — centralized routing hub for multiple VPCs provisioned."),
    "transit_gateway_peering_accepted":("lateral_movement", ["lateral_movement"],                  ["T1563.001"],             "medium",   55, "Transit gateway peering accepted — cross-account network path established."),
    "transit_gateway_peering_created":("lateral_movement",  ["lateral_movement"],                  ["T1563.001"],             "medium",   55, "Transit gateway peering created — cross-account network routing initiated."),
    "vpc_created":                  ("lateral_movement",    ["lateral_movement"],                  ["T1563.001"],             "low",      25, "VPC created — new isolated network environment provisioned."),
    "waf_delete_rule_group":        ("defense_evasion",     ["defense_evasion"],                   ["T1562.007"],             "high",     75, "WAF rule group deleted — set of web application protection rules removed."),
    "waf_disassociate_web_acl":     ("defense_evasion",     ["defense_evasion"],                   ["T1562.007"],             "high",     78, "WAF Web ACL disassociated from resource — web application firewall protection removed."),

    # ── Kubernetes / EKS audit (remaining) ────────────────────────────────
    "pod_attach":                   ("execution",           ["execution"],                         ["T1059.013"],             "high",     78, "kubectl attach to pod — interactive session attached to running container process."),
    "pod_delete":                   ("defense_evasion",     ["defense_evasion"],                   ["T1531"],                 "medium",   45, "Kubernetes pod deleted — container workload terminated."),
    "pod_portforward":              ("lateral_movement",    ["lateral_movement"],                  ["T1563.001"],             "high",     75, "kubectl port-forward — local port tunneled to pod; lateral access established."),
    "privileged_pod":               ("privilege_escalation",["privilege_escalation"],              ["T1611"],                 "critical", 88, "Privileged Kubernetes pod detected — container running with full host capabilities."),
    "role_binding_modify":          ("privilege_escalation",["privilege_escalation"],              ["T1098.006"],             "high",     78, "Kubernetes RoleBinding modified — container cluster permissions changed."),
    "secret_access":                ("credential_access",   ["credential_access"],                 ["T1552.007"],             "high",     78, "Kubernetes Secret accessed via container API — credential data read from cluster."),
    "secret_create":                ("persistence",         ["persistence"],                       ["T1552.007"],             "medium",   55, "Kubernetes Secret created — credential data stored in cluster."),
    "secret_delete":                ("defense_evasion",     ["defense_evasion"],                   ["T1531"],                 "medium",   50, "Kubernetes Secret deleted — credential data removed from cluster."),
    "secret_list":                  ("credential_access",   ["discovery"],                         ["T1552.007"],             "medium",   55, "Kubernetes Secrets listed via container API — credential enumeration in cluster."),
    "token_request":                ("credential_access",   ["credential_access"],                 ["T1528"],                 "medium",   58, "Kubernetes service account token requested — workload credential issued."),
    "webhook_modify":               ("defense_evasion",     ["defense_evasion", "persistence"],    ["T1562.001", "T1546"],    "high",     75, "Kubernetes admission webhook modified — API request interception changed; may bypass security controls."),

    # ── Threat correlation L1 (remaining) ─────────────────────────────────
    "s3_share_cross_account":       ("data_exfiltration",   ["exfiltration"],                      ["T1537"],                 "critical", 90, "S3 bucket shared cross-account — data accessible from external AWS account."),
    "sts_assume_role_from_external":("lateral_movement",    ["lateral_movement"],                  ["T1550.001"],             "high",     75, "Role assumed by external/unexpected principal — cross-account access token used."),
    "update_assume_role_policy":    ("privilege_escalation",["privilege_escalation"],              ["T1098.003"],             "high",     78, "IAM role trust policy updated — who can assume this role has changed."),
    "cover_tracks":                 ("defense_evasion",     ["defense_evasion"],                   ["T1562.008"],             "critical", 90, "Evidence deletion pattern — logs, trails, or monitoring disabled in sequence."),
    "credential_compromise":        ("credential_access",   ["credential_access"],                 ["T1552.005"],             "critical", 92, "Credential compromise pattern detected — credentials accessed or exfiltrated."),
    "data_exfil":                   ("data_exfiltration",   ["exfiltration"],                      ["T1537"],                 "critical", 90, "Data exfiltration pattern — large volume of data leaving account."),
    "privilege_escalation_chain":   ("privilege_escalation",["privilege_escalation"],              ["T1098.003"],             "critical", 95, "Privilege escalation chain — sequence of permission-expanding operations detected."),
    "ransomware":                   ("data_destruction",    ["impact"],                            ["T1486"],                 "critical", 98, "Ransomware-like pattern — mass data encryption or deletion in progress."),
    "recon_then_exploit":           ("discovery",           ["discovery", "initial_access"],       ["T1580", "T1190"],        "critical", 90, "Recon-then-exploit pattern — enumeration immediately followed by exploitation."),

    # ── Container (remaining) ─────────────────────────────────────────────
    "eks_cluster_public_endpoint":  ("initial_access",      ["initial_access"],                    ["T1190"],                 "high",     78, "EKS cluster API server made publicly accessible — Kubernetes control plane exposed to internet."),
    "eks_nodegroup_created":        ("execution",           ["execution", "persistence"],          ["T1610"],                 "medium",   45, "EKS node group created — new compute capacity added to cluster."),
    "eks_rbac_binding_created":     ("privilege_escalation",["privilege_escalation"],              ["T1098.006"],             "high",     78, "EKS RBAC binding created — container cluster role assigned to subject."),
    "anonymous_access":             ("initial_access",      ["initial_access"],                    ["T1078.004"],             "critical", 88, "Anonymous access to Kubernetes API — unauthenticated request reached cluster API server."),
    "hostpath_mount":               ("privilege_escalation",["privilege_escalation"],              ["T1611"],                 "high",     80, "Pod mounting host filesystem path — container can read/write host directories."),
    "secrets_accessed":             ("credential_access",   ["credential_access"],                 ["T1552.007"],             "high",     78, "Multiple Kubernetes Secrets accessed — bulk credential retrieval from cluster."),

    # ── Lambda log operations (remaining) ─────────────────────────────────
    "credential_error":             ("credential_access",   ["credential_access"],                 ["T1552.005"],             "medium",   55, "Lambda credential error — function unable to authenticate; possible misconfiguration or stolen role."),
    "env_var_access":               ("credential_access",   ["credential_access"],                 ["T1552.001"],             "high",     72, "Lambda environment variable accessed — function environment inspected; may contain secrets."),
    "function_error":               ("discovery",           ["discovery"],                         ["T1651"],                 "low",      20, "Lambda function execution error — runtime error recorded."),
    "import_error":                 ("discovery",           ["discovery"],                         ["T1651"],                 "low",      20, "Lambda import error — dependency missing."),
    "invocation_report":            ("discovery",           ["execution"],                         ["T1651"],                 "low",      20, "Lambda invocation report — function execution statistics recorded."),
    "structured_event":             ("discovery",           ["execution"],                         ["T1651"],                 "low",      20, "Lambda structured log event — custom application data recorded from function."),
    "unauthorized_error":           ("initial_access",      ["credential_access"],                 ["T1110.001"],             "medium",   55, "Lambda unauthorized error — function invocation denied; possible credential misuse."),

    # ── DevOps (remaining) ─────────────────────────────────────────────────
    "ecr_put_image":                ("persistence",         ["persistence"],                       ["T1525"],                 "medium",   55, "Container image pushed to ECR — new image uploaded; verify for malicious content."),
    "ecr_set_repository_policy":    ("lateral_movement",    ["lateral_movement"],                  ["T1537"],                 "high",     72, "ECR repository policy updated — check for cross-account access grants."),
    "ssm_delete_parameter":         ("data_destruction",    ["impact"],                            ["T1485"],                 "medium",   55, "SSM Parameter Store parameter deleted — stored configuration or secret removed."),
    "ssm_put_parameter":            ("persistence",         ["persistence"],                       ["T1552.001"],             "high",     70, "SSM Parameter Store parameter created or updated — may store credentials or malicious config."),
    "ssm_send_command":             ("execution",           ["execution"],                         ["T1651"],                 "high",     80, "SSM Run Command executed on EC2 instance — remote command execution via cloud admin API."),
    "ssm_start_session":            ("execution",           ["execution"],                         ["T1021.007"],             "high",     80, "SSM Session Manager session started — interactive shell to EC2 instance via cloud service."),

    # ── Network flow (remaining) ───────────────────────────────────────────
    "lateral_movement_internal":    ("lateral_movement",    ["lateral_movement"],                  ["T1021.007"],             "high",     72, "Internal lateral movement pattern detected — traffic between private subnets to new targets."),
    "port_scan_detected":           ("discovery",           ["discovery"],                         ["T1046"],                 "medium",   55, "Port scan detected in network traffic — systematic probing of multiple ports or hosts."),
    "rdp_from_internet":            ("initial_access",      ["initial_access"],                    ["T1021.001"],             "critical", 88, "RDP access from internet to EC2 instance — remote desktop exposed to public internet."),
    "ssh_from_internet":            ("initial_access",      ["initial_access"],                    ["T1021.004"],             "high",     75, "SSH access from internet to EC2 instance — remote shell exposed to public internet."),
    "tunnel_port":                  ("execution",           ["command_and_control"],               ["T1572"],                 "high",     75, "Traffic on tunnel protocol port — possible C2 via protocol tunneling."),

    # ── Compute (remaining) ────────────────────────────────────────────────
    "lambda_put_function_concurrency":("execution",         ["execution"],                         ["T1651"],                 "medium",   45, "Lambda function concurrency limit updated — execution scaling changed."),
    "lightsail_create_instance":    ("execution",           ["execution", "persistence"],          ["T1578.002"],             "medium",   55, "Lightsail instance created — VPS provisioned; possible rogue compute for C2."),
    "lightsail_create_key_pair":    ("persistence",         ["persistence"],                       ["T1552.004"],             "high",     70, "Lightsail key pair created — SSH credential established for persistent VPS access."),
    "lightsail_open_instance_public_ports":("initial_access",["initial_access"],                  ["T1190"],                 "high",     75, "Lightsail instance ports opened to public internet — services externally exposed."),

    # ── CloudWatch / monitoring (remaining) ───────────────────────────────
    "logs_delete_retention_policy": ("defense_evasion",     ["defense_evasion"],                   ["T1562.008"],             "medium",   55, "CloudWatch log group retention policy deleted — log lifetime no longer enforced."),
    "logs_put_resource_policy":     ("privilege_escalation",["privilege_escalation"],              ["T1098.003"],             "medium",   55, "CloudWatch Logs resource policy updated — cross-account or cross-service access configured."),
    "logs_put_retention_policy":    ("defense_evasion",     ["defense_evasion"],                   ["T1562.008"],             "medium",   50, "CloudWatch log group retention policy updated — log retention duration changed."),
    "logs_put_subscription_filter": ("persistence",         ["persistence", "collection"],         ["T1546"],                 "medium",   55, "CloudWatch log subscription filter added — log events forwarded to external destination."),

    # ── DNS (remaining) ───────────────────────────────────────────────────
    "tor_exit_node":                ("initial_access",      ["initial_access"],                    ["T1090.003"],             "high",     78, "Tor exit node DNS query — connection via anonymizing network detected."),
    "tunneling_long_subdomain":     ("data_exfiltration",   ["exfiltration", "command_and_control"],["T1048.003", "T1071.004"],"high",   78, "Long subdomain in DNS query — DNS tunneling pattern detected."),

    # ── VPC flow (remaining) ──────────────────────────────────────────────
    "internal_portscan":            ("discovery",           ["discovery"],                         ["T1046"],                 "medium",   58, "Internal port scan in VPC flow logs — east-west lateral reconnaissance."),
    "large_data_transfer":          ("data_exfiltration",   ["exfiltration"],                      ["T1048"],                 "high",     78, "Large data transfer in VPC flow logs — bulk movement to external destination."),

    # ── CloudFront (remaining) ─────────────────────────────────────────────
    "http_4xx_error":               ("discovery",           ["discovery"],                         ["T1595.002"],             "low",      20, "HTTP 4xx error from CloudFront — client-side error; may indicate web enumeration."),

    # ── RDS (remaining) ────────────────────────────────────────────────────
    "truncate_table":               ("data_destruction",    ["impact"],                            ["T1485"],                 "critical", 88, "TRUNCATE TABLE executed — all rows instantly deleted from database table."),
}

# ── Resource type mapping from rule_id pattern ──────────────────────────────
_SERVICE_RESOURCE_MAP = {
    "iam":         "iam_principal",
    "s3":          "s3_bucket",
    "ec2":         "ec2_instance",
    "compute":     "ec2_instance",
    "lambda":      "lambda_function",
    "rds":         "rds_instance",
    "eks":         "eks_cluster",
    "container":   "eks_cluster",
    "vpc":         "vpc",
    "network":     "vpc",
    "netsec":      "security_group",
    "alb":         "elb_load_balancer",
    "cloudfront":  "cloudfront_distribution",
    "secsvc":      "security_service",
    "guardduty":   "guardduty_finding",
    "monitor":     "cloudwatch_alarm",
    "devops":      "codepipeline",
    "datasec":     "s3_bucket",
    "dns":         "route53_zone",
    "waf":         "waf_webacl",
    "paas":        "aws_service",
    "storage":     "storage_resource",
    "threat":      "multi_resource",
    "ciem":        "multi_resource",
}

# Human-readable title prefix by service
_SERVICE_TITLE_PREFIX = {
    "iam":       "IAM",
    "s3":        "S3",
    "ec2":       "EC2",
    "compute":   "Compute",
    "lambda":    "Lambda",
    "rds":       "RDS",
    "eks":       "EKS",
    "container": "Container",
    "vpc":       "VPC",
    "network":   "Network",
    "netsec":    "Network Security",
    "alb":       "ALB",
    "cloudfront":"CloudFront",
    "secsvc":    "Security Services",
    "guardduty": "GuardDuty",
    "monitor":   "CloudWatch",
    "devops":    "DevOps",
    "datasec":   "Data Security",
    "dns":       "Route53",
    "waf":       "WAF",
    "paas":      "PaaS",
    "storage":   "Storage",
    "threat":    "Threat",
    "ciem":      "CIEM",
}


def _normalize_op(op: str) -> str:
    """Normalize operation string for lookup."""
    return op.lower().replace(" ", "_").replace("-", "_")


def _lookup_op(op: str) -> Optional[Tuple]:
    """Look up operation metadata — exact match then suffix match."""
    norm = _normalize_op(op)
    if norm in _OP_MAP:
        return _OP_MAP[norm]
    # Try removing common prefixes
    for prefix in ("ec2_", "rds_", "eks_", "ecs_", "alb_", "waf_", "dns_",
                   "s3_", "iam_", "batch_", "codebuild_", "ecr_", "sso_",
                   "sts_", "org_"):
        if norm.startswith(prefix):
            stripped = norm[len(prefix):]
            if stripped in _OP_MAP:
                return _OP_MAP[stripped]
    # Partial suffix match
    for key, val in _OP_MAP.items():
        if norm.endswith(key) or key.endswith(norm):
            return val
    return None


_UPPER_WORDS = {"ec2", "iam", "s3", "rds", "eks", "ecs", "vpc", "alb", "nlb",
                "mfa", "sts", "sso", "oidc", "saml", "ami", "api", "acl",
                "acm", "kms", "sns", "sqs", "ebs", "efs", "waf", "cdn",
                "dns", "ip", "url", "ssm", "id", "http", "https", "sql"}


def _pretty_op(op: str) -> str:
    """Convert snake_case operation to human title, preserving abbreviations."""
    words = op.split("_")
    out = []
    for w in words:
        if w.lower() in _UPPER_WORDS:
            out.append(w.upper())
        else:
            out.append(w.capitalize())
    return " ".join(out)


def _title_from_rule_id(rule_id: str, service: str) -> str:
    """Generate human-readable title from rule_id."""
    parts = rule_id.split(".")
    op = _pretty_op(parts[-1])
    log_type = parts[-2] if len(parts) > 2 else ""
    svc_label = _SERVICE_TITLE_PREFIX.get(service, service.upper())
    if log_type == "correlation":
        return f"Correlation: {op}"
    return f"{svc_label}: {op}"


def _infer_metadata(rule_id: str, service: str, check_type: str, check_config: dict) -> dict:
    """Infer all metadata fields for a rule."""
    parts = rule_id.split(".")
    op = parts[-1]

    # For L2 correlation — use middle segment
    if check_type == "log_correlation":
        # Might be aws.ciem.correlation.privilege_escalation → op=privilege_escalation
        # or aws.threat.correlation.lateral_movement → op=lateral_movement
        pass

    meta = _lookup_op(op)
    if meta is None:
        # Fallback: generic by service
        threat_category = "discovery"
        mitre_tactics = ["discovery"]
        mitre_techniques = ["T1087.004"]
        severity = "low"
        risk_score = 25
        description = f"Detected {op.replace('_', ' ')} operation in AWS {service.upper()} logs."
    else:
        threat_category, mitre_tactics, mitre_techniques, severity, risk_score, description = meta

    # Severity override for L2 (correlations are always at least high)
    if check_type == "log_correlation" and severity not in ("critical",):
        severity = "high"
        risk_score = max(risk_score, 75)

    resource = _SERVICE_RESOURCE_MAP.get(service, "aws_resource")
    title = _title_from_rule_id(rule_id, service)

    return {
        "severity":        severity,
        "title":           title,
        "description":     description,
        "threat_category": threat_category,
        "mitre_tactics":   mitre_tactics,
        "mitre_techniques": mitre_techniques,
        "risk_score":      risk_score,
        "resource":        resource,
    }


def enrich_file(yaml_path: Path, dry_run: bool = False) -> bool:
    """Enrich a single CIEM rule YAML with metadata. Returns True if modified."""
    with open(yaml_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not data or not isinstance(data, dict):
        return False

    rule_id = data.get("rule_id", "")
    if not rule_id.startswith("aws."):
        return False

    service = data.get("service", "")
    check_type = data.get("check_type", "log")
    check_config = data.get("check_config", {}) or {}

    # Always re-enrich (overwrite) — idempotent, ensures consistent metadata

    inferred = _infer_metadata(rule_id, service, check_type, check_config)

    # Overwrite all metadata fields from inference
    changed = False
    for key, val in inferred.items():
        if data.get(key) != val:
            data[key] = val
            changed = True

    if not changed:
        return False

    if not dry_run:
        # Write back preserving comments is hard — use yaml.dump
        # Order: rule_id, service, provider, check_type, severity, title, description,
        #        threat_category, mitre_tactics, mitre_techniques, risk_score, resource,
        #        source, is_active, check_config, version
        ordered = {}
        for k in ("rule_id", "service", "provider", "check_type",
                  "severity", "title", "description",
                  "threat_category", "mitre_tactics", "mitre_techniques",
                  "risk_score", "resource",
                  "source", "is_active", "check_config", "version"):
            if k in data:
                ordered[k] = data[k]
        # Any remaining keys
        for k, v in data.items():
            if k not in ordered:
                ordered[k] = v

        with open(yaml_path, "w", encoding="utf-8") as f:
            yaml.dump(ordered, f, default_flow_style=False, allow_unicode=True,
                      sort_keys=False)

    return True


def main():
    import argparse
    p = argparse.ArgumentParser(description="Enrich CIEM rule YAMLs with metadata")
    p.add_argument("--dry-run", action="store_true", help="Show what would change, don't write")
    p.add_argument("--dir", default=str(CATALOG_DIR), help="CIEM catalog directory")
    args = p.parse_args()

    catalog = Path(args.dir)
    all_yamls = list(catalog.rglob("*.yaml"))
    all_yamls = [y for y in all_yamls if y.name != Path(__file__).name]

    enriched = 0
    skipped = 0
    for yaml_path in sorted(all_yamls):
        # Skip the script itself
        if yaml_path.suffix != ".yaml":
            continue
        try:
            modified = enrich_file(yaml_path, dry_run=args.dry_run)
            if modified:
                enriched += 1
                if args.dry_run:
                    print(f"  WOULD enrich: {yaml_path.name}")
            else:
                skipped += 1
        except Exception as e:
            print(f"  ERROR {yaml_path.name}: {e}")

    print(f"\nDone. {'Would enrich' if args.dry_run else 'Enriched'}: {enriched}, "
          f"Already complete / skipped: {skipped}")


if __name__ == "__main__":
    main()
