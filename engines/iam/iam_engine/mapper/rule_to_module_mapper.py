"""
Map threat findings to IAM security modules using rule_id patterns.

IAM-relevant findings are identified by:
  1. rule_id containing '.iam.' (e.g. aws.iam.role.*, aws.iam.policy.*)
  2. resource_type == 'iam'
  3. Specific IAM-related keywords in rule_id

Modules are derived from the rule_id pattern (e.g. 'role', 'policy', 'password', 'mfa').
"""

from typing import Dict, List, Optional
import logging
import re

logger = logging.getLogger(__name__)

# IAM-relevant rule_id patterns
IAM_RULE_PATTERNS = [
    re.compile(r'\.iam\.'),              # aws.iam.role.*, aws.iam.policy.*
    re.compile(r'\.iam_'),               # e.g. aws.service.iam_fine_grained
    re.compile(r'\.mfa[._]'),            # MFA rules
    re.compile(r'\.password[._]'),       # Password rules
    re.compile(r'\.root[._]'),           # Root account rules
    re.compile(r'\.sso[._]'),            # SSO rules
    # Azure IAM/identity patterns
    re.compile(r'\.entraid\.'),          # azure.entraid.*
    re.compile(r'\.aad\.'),              # azure.aad.*
    re.compile(r'\.managedidentity\.'),  # azure.managedidentity.*
    re.compile(r'\.serviceprincipal\.'), # azure.serviceprincipal.*
    re.compile(r'\.rbac\.'),             # azure.rbac.*
    re.compile(r'\.pim\.'),              # azure.pim.*
    # GCP IAM/identity patterns
    re.compile(r'\.serviceaccount\.'),   # gcp.serviceaccount.*
    re.compile(r'\.workloadidentity\.'), # gcp.workloadidentity.*
    re.compile(r'\.orgpolicy\.'),        # gcp.orgpolicy.*
]

# Module derivation from rule_id keywords
MODULE_KEYWORDS = {
    'least_privilege': ['least_privilege', 'rbac', 'privilege_escalation', 'overly_permissive',
                        'wildcard_admin', 'full_admin', 'no_policies_without_constraints',
                        'resource_constraints', 'fine_grained_access', 'scopes_or_s_least',
                        'serviceaccount'],
    'policy_analysis': ['policy', 'managed_policy', 'managedpolicy', 'inline_policies',
                        'attached_only_to', 'versioning_and_change', 'conditions_used'],
    'mfa': ['mfa', 'multi_factor', 'hardware_mfa'],
    'role_management': ['role', 'trust_principals', 'trust_external_id', 'session_duration',
                        'max_session_duration', 'workload_identity', 'instanceprofile',
                        'samlprovider', 'oidcprovider',
                        'managedidentity', 'serviceprincipal', 'workloadidentity'],
    'password_policy': ['password', 'reuse_24', 'expires_passwords', 'minimum_length',
                        'lowercase', 'uppercase', 'number', 'symbol'],
    'access_control': ['access', 'root_usage', 'avoid_root', 'inactive_90',
                       'console_access', 'console_password', 'guest_accounts',
                       'centralization', 'key_rotation', 'support_role',
                       'group_has_users',
                       'entraid', 'aad', 'pim', 'orgpolicy'],
}


def _is_iam_relevant(rule_id: str, resource_type: str = '') -> bool:
    """Check if a finding is IAM-relevant based on rule_id or resource_type."""
    if not rule_id:
        return False
    rule_lower = rule_id.lower()
    # Direct pattern match
    for pattern in IAM_RULE_PATTERNS:
        if pattern.search(rule_lower):
            return True
    # Resource type check
    if resource_type and resource_type.lower() == 'iam':
        return True
    return False


def _derive_modules(rule_id: str) -> List[str]:
    """Derive IAM security modules from rule_id patterns."""
    if not rule_id:
        return ['access_control']
    rule_lower = rule_id.lower()
    modules = []
    for module, keywords in MODULE_KEYWORDS.items():
        for kw in keywords:
            if kw in rule_lower:
                modules.append(module)
                break
    if not modules:
        modules.append('access_control')
    return list(dict.fromkeys(modules))  # deduplicate preserving order


class RuleToModuleMapper:
    """Maps findings to IAM security modules (least_privilege, mfa, policy_analysis, etc.)."""

    def __init__(self, rule_db_path: Optional[str] = None):
        # rule_db_path no longer needed — IAM relevance is determined from rule_id patterns
        pass

    def get_modules_for_finding(self, finding: Dict) -> List[str]:
        rule_id = finding.get("rule_id", "")
        resource_type = finding.get("resource_type", "")
        if not _is_iam_relevant(rule_id, resource_type):
            return []
        return _derive_modules(rule_id)

    def map_finding_to_modules(self, finding: Dict) -> Dict:
        modules = self.get_modules_for_finding(finding)
        out = finding.copy()
        out["iam_security_modules"] = modules
        out["is_iam_relevant"] = len(modules) > 0
        return out

    def map_findings_to_modules(self, findings: List[Dict]) -> List[Dict]:
        return [self.map_finding_to_modules(f) for f in findings]

    def get_module_statistics(self, findings: List[Dict]) -> Dict[str, int]:
        stats = {}
        for f in findings:
            for m in f.get("iam_security_modules", []):
                stats[m] = stats.get(m, 0) + 1
        return stats
