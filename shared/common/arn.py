"""
ARN Normalizer — Canonical Resource Identifier
================================================
Converts resource UIDs to the CSP-native canonical format.

For AWS: ARN — ``arn:{partition}:{service}:{region}:{account}:{resource-type}/{resource-id}``
For Azure: ARM Resource ID — ``/subscriptions/{subId}/resourceGroups/...``
For GCP: selfLink — ``projects/{project}/zones/{zone}/instances/{name}``
For OCI: OCID — ``ocid1.{type}.oc1.{realm}.{id}``
For IBM: CRN — ``crn:v1:bluemix:public:{service}:{region}:...``
For AliCloud: ACS ARN — ``acs:{service}:{region}:{account}:{type}/{id}``

``resource_uid`` is the single column name across all engines — but the
VALUE is always the CSP-native canonical identifier.

The ``resource_inventory_identifier`` table (inventory DB) holds
identifier_pattern templates for 6,500+ resources across all CSPs.
The ``canonical_type`` column maps to the resource_type names used by
discovery/inventory engines, enabling pattern lookup.

Usage::

    from shared.common.arn import normalize_resource_uid, parse_arn

    uid = normalize_resource_uid(
        resource_uid="ec2:ap-south-1:588989875114:sg-008801ad727d19fb4",
        resource_type="ec2.security-group",
        provider="aws",
        region="ap-south-1",
        account_id="588989875114",
    )
    # => "arn:aws:ec2:ap-south-1:588989875114:security-group/sg-008801ad727d19fb4"

=== DATABASE & TABLE MAP ===
Tables READ (optional):  resource_inventory_identifier (via get_identifier_pattern)
Tables WRITTEN: None
===
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


# ── ARN prefix-to-resource-type mapping ──────────────────────────────────────
# Maps resource-id prefix (e.g. "sg-") to the ARN resource-type segment
# and the AWS service if different from the discovery service.

_EC2_PREFIX_MAP = {
    "sg-":      "security-group",
    "subnet-":  "subnet",
    "igw-":     "internet-gateway",
    "vpc-":     "vpc",
    "vol-":     "volume",
    "snap-":    "snapshot",
    "lt-":      "launch-template",
    "eni-":     "network-interface",
    "acl-":     "network-acl",
    "rtb-":     "route-table",
    "nat-":     "natgateway",
    "eipalloc-":"elastic-ip",
    "pcx-":     "vpc-peering-connection",
    "vpce-":    "vpc-endpoint",
    "i-":       "instance",
    "ami-":     "image",
    "tgw-rtb-": "transit-gateway-route-table",
    "tgw-attach-": "transit-gateway-attachment",
    "tgw-":     "transit-gateway",
    "r-":       "vpc-block-public-access-exclusion",
    "cgw-":     "customer-gateway",
    "vgw-":     "vpn-gateway",
    "dopt-":    "dhcp-options",
    "fl-":      "flow-log",
    "eigw-":    "egress-only-internet-gateway",
    "pl-":      "prefix-list",
    "asg-":     "auto-scaling-group",
}

# IAM resources have no region and a different ARN structure
_IAM_RESOURCE_TYPES = {
    "user", "role", "policy", "group", "instance-profile",
    "saml-provider", "oidc-provider", "server-certificate",
}

# S3 buckets have no region and no account in their ARN
_S3_ARN = True

# Services where region is empty in the ARN
_GLOBAL_SERVICES = {"iam", "s3", "sts", "organizations", "cloudfront", "route53", "waf"}


@dataclass(frozen=True)
class ParsedARN:
    """Parsed components of an ARN."""
    partition: str   # aws, aws-cn, aws-us-gov
    service: str     # ec2, iam, s3, ...
    region: str      # ap-south-1, us-east-1, "" for global
    account_id: str  # 12-digit account ID, "" for s3
    resource: str    # resource-type/resource-id or just resource-id


def parse_arn(arn: str) -> Optional[ParsedARN]:
    """Parse an ARN string into components. Returns None if not a valid ARN."""
    if not arn or not arn.startswith("arn:"):
        return None
    parts = arn.split(":", 5)
    if len(parts) < 6:
        return None
    return ParsedARN(
        partition=parts[1],
        service=parts[2],
        region=parts[3],
        account_id=parts[4],
        resource=parts[5],
    )


def is_arn(uid: str) -> bool:
    """Check if a string is already in ARN format."""
    return uid.startswith("arn:") and uid.count(":") >= 5


def _detect_ec2_resource_type(resource_id: str) -> Optional[str]:
    """Detect EC2 resource type from the resource-id prefix."""
    # Check longer prefixes first (tgw-rtb- before tgw-)
    for prefix in sorted(_EC2_PREFIX_MAP, key=len, reverse=True):
        if resource_id.startswith(prefix):
            return _EC2_PREFIX_MAP[prefix]
    return None


def _build_arn(
    service: str,
    region: str,
    account_id: str,
    resource_type: str,
    resource_id: str,
    partition: str = "aws",
) -> str:
    """Build a properly formatted ARN."""
    if service in _GLOBAL_SERVICES:
        region = ""
    if service == "s3":
        # S3 bucket ARN: arn:aws:s3:::bucket-name
        return f"arn:{partition}:s3:::{resource_id}"
    if service == "iam":
        # IAM ARN: arn:aws:iam::account:resource-type/resource-id
        return f"arn:{partition}:iam::{account_id}:{resource_type}/{resource_id}"
    # Standard: arn:aws:service:region:account:resource-type/resource-id
    return f"arn:{partition}:{service}:{region}:{account_id}:{resource_type}/{resource_id}"


def _parse_short_uid(uid: str) -> Optional[dict]:
    """
    Parse a short-form UID like ``ec2:ap-south-1:588989875114:sg-xxx``.

    Returns dict with keys: service, region, account_id, resource_id
    or None if the UID doesn't match the expected pattern.
    """
    parts = uid.split(":")
    if len(parts) < 3:
        return None
    # Must NOT start with arn:
    if parts[0] == "arn":
        return None

    service = parts[0]
    if len(parts) == 4:
        return {
            "service": service,
            "region": parts[1],
            "account_id": parts[2],
            "resource_id": parts[3],
        }
    elif len(parts) == 3:
        return {
            "service": service,
            "region": parts[1],
            "account_id": "",
            "resource_id": parts[2],
        }
    return None


def _infer_arn_resource_type(
    service: str,
    resource_id: str,
    resource_type_hint: str = "",
) -> Optional[str]:
    """
    Infer the ARN resource-type segment from available information.

    Uses: prefix-based detection (sg- → security-group),
          resource_type hint (ec2.security-group → security-group),
          and known IAM resource types.
    """
    # 1. EC2 prefix-based detection (most reliable)
    if service == "ec2":
        detected = _detect_ec2_resource_type(resource_id)
        if detected:
            return detected

    # 2. resource_type hint: "ec2.security-group" → "security-group"
    if resource_type_hint and "." in resource_type_hint:
        suffix = resource_type_hint.split(".", 1)[1]
        # Normalize underscores to hyphens
        normalized = suffix.replace("_", "-")
        if normalized:
            return normalized

    # 3. IAM resources
    if service == "iam":
        # resource_id for IAM is usually the name (no prefix)
        # Use the resource_type_hint to determine
        if resource_type_hint:
            for iam_type in _IAM_RESOURCE_TYPES:
                if iam_type in resource_type_hint.lower():
                    return iam_type
        # Default IAM resource type based on common patterns
        return "resource"

    return None


def normalize_resource_uid(
    resource_uid: str,
    resource_type: str = "",
    provider: str = "aws",
    region: str = "",
    account_id: str = "",
    resource_arn: str = "",
    partition: str = "aws",
) -> str:
    """
    Normalize a resource UID to canonical ARN format.

    If the UID is already an ARN, returns it unchanged.
    If a ``resource_arn`` is provided, returns that.
    Otherwise, attempts to construct the ARN from available metadata.

    Args:
        resource_uid: The current resource UID (may be short-form or ARN).
        resource_type: Discovery resource type (e.g. "ec2.security-group").
        provider: Cloud provider ("aws", "azure", "gcp").
        region: AWS region.
        account_id: AWS account ID.
        resource_arn: Explicit ARN if available.
        partition: AWS partition (default "aws").

    Returns:
        Full ARN string, or original UID if normalization fails.
    """
    # Already have an explicit ARN — use it
    if resource_arn and is_arn(resource_arn):
        return resource_arn

    # Already in ARN format — no change needed
    if is_arn(resource_uid):
        return resource_uid

    # Only normalize AWS resources for now
    if provider.lower() != "aws":
        return resource_uid

    # Parse short-form UID
    parsed = _parse_short_uid(resource_uid)
    if not parsed:
        return resource_uid

    svc = parsed["service"]
    res_region = parsed["region"] or region
    res_account = parsed["account_id"] or account_id
    res_id = parsed["resource_id"]

    if not res_account:
        return resource_uid  # Can't build ARN without account

    # Detect the ARN resource-type segment
    arn_resource_type = _infer_arn_resource_type(svc, res_id, resource_type)
    if not arn_resource_type:
        return resource_uid  # Can't determine resource type

    return _build_arn(
        service=svc,
        region=res_region,
        account_id=res_account,
        resource_type=arn_resource_type,
        resource_id=res_id,
        partition=partition,
    )


# ── DB-backed pattern lookup ────────────────────────────────────────────────
# Optional: use resource_inventory_identifier table as the single source of truth
# for identifier patterns.  Engines can call get_identifier_pattern() once at startup
# and cache the result for the scan's lifetime.

_pattern_cache: dict = {}


def get_identifier_pattern(
    csp: str,
    service: str,
    canonical_type: str,
    db_connection=None,
) -> Optional[str]:
    """
    Look up the identifier_pattern from resource_inventory_identifier.

    Uses the ``canonical_type`` column which maps to the resource_type names
    that discovery/inventory engines actually produce (e.g. 'security-group',
    'instance', 'bucket').

    Args:
        csp: Cloud provider ('aws', 'azure', 'gcp', 'oci', 'ibm', 'alicloud')
        service: AWS service name ('ec2', 'iam', 's3', ...)
        canonical_type: Normalized resource type ('security-group', 'instance', ...)
        db_connection: psycopg2 connection to the inventory database.
                       If None, returns from in-memory cache only.

    Returns:
        Identifier pattern string (e.g. "arn:${Partition}:ec2:...") or None.
    """
    cache_key = (csp, service, canonical_type)
    if cache_key in _pattern_cache:
        return _pattern_cache[cache_key]

    if db_connection is None:
        return None

    try:
        with db_connection.cursor() as cur:
            cur.execute(
                """SELECT identifier_pattern
                   FROM resource_inventory_identifier
                   WHERE csp = %s AND service = %s AND canonical_type = %s
                   LIMIT 1""",
                (csp, service, canonical_type),
            )
            row = cur.fetchone()
            pattern = row[0] if row else None
            _pattern_cache[cache_key] = pattern
            return pattern
    except Exception:
        return None


def preload_identifier_patterns(db_connection, csp: str = "aws") -> int:
    """
    Bulk-load all identifier patterns for a CSP into the in-memory cache.

    Call once at engine startup. Returns the number of patterns loaded.

    Args:
        db_connection: psycopg2 connection to the inventory database.
        csp: Cloud provider to load patterns for.

    Returns:
        Number of patterns loaded.
    """
    try:
        with db_connection.cursor() as cur:
            cur.execute(
                """SELECT service, canonical_type, identifier_pattern
                   FROM resource_inventory_identifier
                   WHERE csp = %s AND canonical_type IS NOT NULL
                     AND identifier_pattern IS NOT NULL
                     AND identifier_pattern != ''""",
                (csp,),
            )
            count = 0
            for service, canonical_type, pattern in cur.fetchall():
                _pattern_cache[(csp, service, canonical_type)] = pattern
                count += 1
            return count
    except Exception:
        return 0
