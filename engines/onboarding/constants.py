"""
Onboarding engine constants — account_type/tenant_type validation.
"""
from typing import Dict, FrozenSet

# Maps tenant_type → the set of account_type values that are allowed for that tenant.
# A 'cloud' tenant can hold any account type.
# A 'security' tenant (future) might restrict to secops/vulnerability only.
VALID_ACCOUNT_TYPES: Dict[str, FrozenSet[str]] = {
    "cloud":     frozenset({"cloud_csp", "vulnerability", "secops", "code_security",
                            "database", "middleware"}),
    "security":  frozenset({"vulnerability", "secops", "code_security"}),
    "database":  frozenset({"database"}),
    "agent":     frozenset({"cloud_csp"}),
}

# Fallback set used when tenant_type is unknown / not set.
DEFAULT_VALID_ACCOUNT_TYPES: FrozenSet[str] = frozenset(
    {"cloud_csp", "vulnerability", "secops", "code_security", "database", "middleware"}
)

# Maps cloud/db provider string → default account_type when the caller omits account_type.
PROVIDER_TO_ACCOUNT_TYPE: Dict[str, str] = {
    "aws":       "cloud_csp",
    "azure":     "cloud_csp",
    "gcp":       "cloud_csp",
    "oci":       "cloud_csp",
    "alicloud":  "cloud_csp",
    "ibm":       "cloud_csp",
    "k8s":       "cloud_csp",
    "agent":     "cloud_csp",
    "postgres":  "database",
    "mysql":     "database",
    "mssql":     "database",
    "mongodb":   "database",
    "oracle":    "database",
    # VCS / code-repository providers → code_security account type
    "github":    "code_security",
    "gitlab":    "code_security",
    "bitbucket": "code_security",
}
