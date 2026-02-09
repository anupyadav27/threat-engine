"""
Map threat findings to data security modules using rule_id and resource_type patterns.

Data-security-relevant findings are identified by:
  1. resource_type being a data store (s3, rds, dynamodb, redshift, glacier, etc.)
  2. rule_id containing data-security keywords (encryption, backup, logging, etc.)

Modules are derived from rule_id patterns.
"""

from typing import Dict, List, Optional, Set
import logging
import re

logger = logging.getLogger(__name__)

# Data-security relevant resource types
DATA_SECURITY_RESOURCE_TYPES = {
    's3', 'rds', 'dynamodb', 'redshift', 'glacier', 'documentdb',
    'neptune', 'glue', 'lakeformation', 'macie', 'ecr', 'kms',
    'elasticache', 'dax', 'efs', 'fsx',
}

# Data-security relevant rule_id patterns
DATA_SECURITY_RULE_PATTERNS = [
    re.compile(r'\.s3\.'),
    re.compile(r'\.rds\.'),
    re.compile(r'\.dynamodb\.'),
    re.compile(r'\.redshift\.'),
    re.compile(r'\.glacier\.'),
    re.compile(r'\.documentdb\.'),
    re.compile(r'\.neptune\.'),
    re.compile(r'\.glue\.'),
    re.compile(r'\.lakeformation\.'),
    re.compile(r'\.macie\.'),
    re.compile(r'\.ecr\.'),
    re.compile(r'\.kms\.'),
    re.compile(r'\.elasticache\.'),
    re.compile(r'\.efs\.'),
    re.compile(r'\.fsx\.'),
    re.compile(r'encryption'),
    re.compile(r'backup'),
    re.compile(r'data_protection'),
]

# Module derivation from rule_id keywords
DATA_SECURITY_MODULE_KEYWORDS = {
    'data_protection_encryption': ['encryption', 'encrypt', 'kms', 'sse', 'tls', 'ssl',
                                    'at_rest', 'in_transit', 'cmk', 'key_rotation'],
    'data_classification': ['classification', 'sensitive', 'macie', 'pii', 'phi',
                           'tagging', 'labeling'],
    'data_access_control': ['access', 'policy', 'acl', 'bucket_policy', 'public',
                           'block_public', 'restrict', 'permission', 'iam'],
    'data_backup_recovery': ['backup', 'snapshot', 'replication', 'recovery',
                            'retention', 'versioning', 'lifecycle', 'pitr'],
    'data_logging_monitoring': ['logging', 'monitoring', 'audit', 'trail',
                                'cloudtrail', 'access_logging', 'event'],
    'data_residency': ['residency', 'region', 'cross_region', 'geo',
                       'location', 'sovereignty'],
    'data_lifecycle': ['lifecycle', 'retention', 'expiration', 'deletion',
                       'archival', 'transition'],
}


def _is_data_security_relevant(rule_id: str, resource_type: str = '') -> bool:
    """Check if a finding is data-security-relevant."""
    if not rule_id and not resource_type:
        return False
    # Resource type check
    if resource_type and resource_type.lower() in DATA_SECURITY_RESOURCE_TYPES:
        return True
    # Rule pattern check
    rule_lower = (rule_id or '').lower()
    for pattern in DATA_SECURITY_RULE_PATTERNS:
        if pattern.search(rule_lower):
            return True
    return False


def _derive_modules(rule_id: str, resource_type: str = '') -> List[str]:
    """Derive data security modules from rule_id patterns."""
    if not rule_id:
        return ['data_access_control']
    rule_lower = rule_id.lower()
    modules = []
    for module, keywords in DATA_SECURITY_MODULE_KEYWORDS.items():
        for kw in keywords:
            if kw in rule_lower:
                modules.append(module)
                break
    if not modules:
        # Default module based on resource type
        if resource_type and resource_type.lower() in DATA_SECURITY_RESOURCE_TYPES:
            modules.append('data_access_control')
    return list(dict.fromkeys(modules))  # deduplicate preserving order


class RuleToModuleMapper:
    """Maps findings to data security modules."""

    def __init__(self, rule_db_path: Optional[str] = None):
        # rule_db_path no longer needed — relevance determined by patterns
        pass

    def get_modules_for_finding(self, finding: Dict) -> List[str]:
        rule_id = finding.get("rule_id", "")
        resource_type = finding.get("resource_type", "") or finding.get("service", "")
        if not _is_data_security_relevant(rule_id, resource_type):
            return []
        return _derive_modules(rule_id, resource_type)

    def map_finding_to_modules(self, finding: Dict) -> Dict:
        modules = self.get_modules_for_finding(finding)
        enriched = finding.copy()
        enriched["data_security_modules"] = modules
        enriched["is_data_security_relevant"] = len(modules) > 0
        return enriched

    def map_findings_to_modules(self, findings: List[Dict]) -> List[Dict]:
        return [self.map_finding_to_modules(f) for f in findings]

    def group_findings_by_module(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        grouped = {}
        for f in findings:
            for module in f.get("data_security_modules", []):
                grouped.setdefault(module, []).append(f)
        return grouped

    def get_module_statistics(self, findings: List[Dict]) -> Dict[str, int]:
        stats = {}
        for f in findings:
            for module in f.get("data_security_modules", []):
                stats[module] = stats.get(module, 0) + 1
        return stats

    def filter_by_module(self, findings: List[Dict], module: str) -> List[Dict]:
        return [f for f in findings if module in f.get("data_security_modules", [])]
