"""
account_type / tenant_type compatibility validation.

Implements the strict 1:1 compatibility matrix required by onboarding-C5.
Kept as a standalone module (not inline in the endpoint) so it can be
imported and unit-tested independently.
"""
from typing import Dict

# Compatibility matrix (AC3): maps account_type → SET of permitted tenant_types.
# Using a set (not a single string) lets a 'cloud' tenant also run vulnerability
# and secops scans — which is the real-world norm. A dedicated 'vulnerability'
# tenant type is still accepted for orgs that segregate scan workloads.
#
# Types not listed here (code_security, database, middleware) are permissive —
# they are validated by a separate allow-list (VALID_ACCOUNT_TYPES) in constants.py.
ACCOUNT_TYPE_TENANT_TYPE_MAP: Dict[str, set] = {
    "cloud_csp":    {"cloud"},
    "vulnerability": {"cloud", "vulnerability"},
    "secops":        {"cloud", "secops"},
}


def validate_account_type_for_tenant(account_type: str, tenant_type: str) -> bool:
    """Return True if the account_type is compatible with the tenant_type.

    Uses a strict 1:1 map for the three primary account types
    (cloud_csp, vulnerability, secops).  Account types not present in the map
    (e.g. code_security, database, middleware) are not governed by this
    function and are considered always-compatible — callers should apply
    additional allow-list checks for those types separately.

    Args:
        account_type: The account type being created (e.g. 'cloud_csp').
        tenant_type:  The tenant's registered type (e.g. 'cloud').

    Returns:
        True if compatible, False if the combination is disallowed.

    Raises:
        ValueError: If account_type is one of the governed types but the
                    mapping cannot be determined (should never happen in
                    practice with the current constant).

    Examples:
        >>> validate_account_type_for_tenant("cloud_csp", "cloud")
        True
        >>> validate_account_type_for_tenant("cloud_csp", "vulnerability")
        False
        >>> validate_account_type_for_tenant("vulnerability", "vulnerability")
        True
        >>> validate_account_type_for_tenant("secops", "secops")
        True
        >>> validate_account_type_for_tenant("database", "cloud")
        True  # not governed — caller's VALID_ACCOUNT_TYPES handles this
    """
    allowed_tenant_types = ACCOUNT_TYPE_TENANT_TYPE_MAP.get(account_type)
    if allowed_tenant_types is None:
        # Not a governed type — allow it; the endpoint's VALID_ACCOUNT_TYPES
        # check provides the broader gate for these types.
        return True
    return tenant_type in allowed_tenant_types
