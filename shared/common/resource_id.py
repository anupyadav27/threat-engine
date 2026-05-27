"""
Resource ID — Canonical Resource Identifier
============================================
Single module for generating and parsing canonical resource IDs across all CSPs.

Every cloud resource has ONE identifier — stored in ``resource_uid`` across all
engine tables. The value is the CSP-native canonical identifier:

    AWS      → ARN:  arn:aws:ec2:us-east-1:123456789012:instance/i-0abc1234
    Azure    → ARM:  azure/sub-abc/eastus/compute/virtualmachine/my-vm
    GCP      → RID:  gcp/my-project/us-central1/compute/instance/my-instance
    OCI      → OCID: ocid1.instance.oc1.ap-mumbai-1.abcxyz
    AliCloud → ACS:  acs:ecs:cn-hangzhou:123456:instance/i-xxx
    IBM      → CRN:  crn:v1:bluemix:public:is:us-south:account::instance:xxx
    K8s      → Path: k8s/cluster-id/default/secret/db-credentials

Usage::

    from engine_common.resource_id import make_resource_id, parse_resource_id

    uid = make_resource_id(
        csp="aws", service="ec2", resource_type="instance",
        region="us-east-1", account="123456789012", name="i-0abc1234",
    )
    # => "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc1234"

    uid = make_resource_id(
        csp="k8s", service="core", resource_type="secret",
        region="", account="my-cluster", name="db-creds", namespace="default",
    )
    # => "k8s/my-cluster/default/secret/db-creds"

=== DATABASE & TABLE MAP ===
Tables READ (optional):  di_resource_catalog (via get_identifier_pattern)
Tables WRITTEN: None
===
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Optional

# ── RDS hostname → resource_uid ───────────────────────────────────────────────
_RDS_HOST_RE = re.compile(
    r"^([^.]+)\.[^.]+\.([a-z][a-z0-9-]+)\.rds\.amazonaws\.com$",
    re.IGNORECASE,
)

# ── EC2 resource-id prefix → ARN resource-type segment ───────────────────────
_EC2_PREFIX_MAP = {
    "sg-":          "security-group",
    "subnet-":      "subnet",
    "igw-":         "internet-gateway",
    "vpc-":         "vpc",
    "vol-":         "volume",
    "snap-":        "snapshot",
    "lt-":          "launch-template",
    "eni-":         "network-interface",
    "acl-":         "network-acl",
    "rtb-":         "route-table",
    "nat-":         "natgateway",
    "eipalloc-":    "elastic-ip",
    "pcx-":         "vpc-peering-connection",
    "vpce-":        "vpc-endpoint",
    "i-":           "instance",
    "ami-":         "image",
    "tgw-rtb-":     "transit-gateway-route-table",
    "tgw-attach-":  "transit-gateway-attachment",
    "tgw-":         "transit-gateway",
    "r-":           "vpc-block-public-access-exclusion",
    "cgw-":         "customer-gateway",
    "vgw-":         "vpn-gateway",
    "dopt-":        "dhcp-options",
    "fl-":          "flow-log",
    "eigw-":        "egress-only-internet-gateway",
    "pl-":          "prefix-list",
    "asg-":         "auto-scaling-group",
}

_IAM_RESOURCE_TYPES = {
    "user", "role", "policy", "group", "instance-profile",
    "saml-provider", "oidc-provider", "server-certificate",
}

_GLOBAL_SERVICES = {"iam", "s3", "sts", "organizations", "cloudfront", "route53", "waf"}

# ── In-memory pattern cache (populated by preload_identifier_patterns) ────────
_pattern_cache: Dict[Any, Any] = {}


# =============================================================================
# Parsed ARN dataclass (AWS)
# =============================================================================

@dataclass(frozen=True)
class ParsedARN:
    """Parsed components of an AWS ARN."""
    partition: str
    service: str
    region: str
    account_id: str
    resource: str


# =============================================================================
# CSP Builder classes
# =============================================================================

class _AWSBuilder:
    """Builds AWS ARNs from resource metadata."""

    def build(
        self,
        service: str,
        resource_type: str,
        region: str,
        account: str,
        name: str,
        partition: str = "aws",
        **_kw: Any,
    ) -> str:
        if service in _GLOBAL_SERVICES:
            region = ""
        if service == "s3":
            return f"arn:{partition}:s3:::{name}"
        if service == "iam":
            rt = resource_type.replace(".", "-") if resource_type else "resource"
            return f"arn:{partition}:iam::{account}:{rt}/{name}"
        rt = resource_type.replace(".", "-") if resource_type else name
        return f"arn:{partition}:{service}:{region}:{account}:{rt}/{name}"

    def normalize(
        self,
        resource_uid: str,
        resource_type: str = "",
        region: str = "",
        account_id: str = "",
        resource_arn: str = "",
        partition: str = "aws",
    ) -> str:
        """Normalize a short-form AWS UID to full ARN. Returns uid unchanged on failure."""
        if resource_arn and resource_arn.startswith("arn:"):
            return resource_arn
        if resource_uid.startswith("arn:"):
            return resource_uid

        parts = resource_uid.split(":")
        if len(parts) < 3 or parts[0] == "arn":
            return resource_uid

        svc = parts[0]
        res_region = parts[1] if len(parts) >= 4 else region
        res_account = parts[2] if len(parts) >= 4 else account_id
        res_id = parts[3] if len(parts) >= 4 else (parts[2] if len(parts) == 3 else "")

        if not res_account:
            return resource_uid

        arn_rt = self._infer_resource_type(svc, res_id, resource_type)
        if not arn_rt:
            return resource_uid

        return self.build(
            service=svc,
            resource_type=arn_rt,
            region=res_region,
            account=res_account,
            name=res_id,
            partition=partition,
        )

    def _infer_resource_type(self, service: str, resource_id: str, hint: str) -> Optional[str]:
        if service == "ec2":
            for prefix in sorted(_EC2_PREFIX_MAP, key=len, reverse=True):
                if resource_id.startswith(prefix):
                    return _EC2_PREFIX_MAP[prefix]
            return None  # unknown EC2 resource — skip rather than guess
        if hint and "." in hint:
            return hint.split(".", 1)[1].replace("_", "-")
        if service == "iam":
            if hint:
                for t in _IAM_RESOURCE_TYPES:
                    if t in hint.lower():
                        return t
            return "resource"
        # For all other services (s3, route53, wafv2, cloudfront, etc.):
        # use hint directly — build() has service-specific ARN logic.
        if hint:
            return hint.replace("_", "-")
        return None


class _AzureBuilder:
    """Builds Azure ARM resource IDs."""

    def build(
        self,
        service: str,
        resource_type: str,
        region: str,
        account: str,
        name: str,
        resource_group: str = "",
        **_kw: Any,
    ) -> str:
        # account = subscription ID
        if resource_group:
            return (
                f"/subscriptions/{account}/resourceGroups/{resource_group}"
                f"/providers/Microsoft.{service.capitalize()}/{resource_type}/{name}"
            )
        return f"azure/{account}/{region}/{service}/{resource_type}/{name}"


class _GCPBuilder:
    """Builds GCP resource names."""

    def build(
        self,
        service: str,
        resource_type: str,
        region: str,
        account: str,
        name: str,
        **_kw: Any,
    ) -> str:
        # account = project ID
        if region:
            return f"//{ service }.googleapis.com/projects/{account}/locations/{region}/{resource_type}s/{name}"
        return f"//{service}.googleapis.com/projects/{account}/{resource_type}s/{name}"


class _OCIBuilder:
    """Builds OCI resource identifiers."""

    def build(
        self,
        service: str,
        resource_type: str,
        region: str,
        account: str,
        name: str,
        **_kw: Any,
    ) -> str:
        # If name is already an OCID, return as-is
        if name.startswith("ocid1."):
            return name
        return f"oci/{account}/{region}/{service}/{resource_type}/{name}"


class _AliCloudBuilder:
    """Builds AliCloud ACS ARNs."""

    def build(
        self,
        service: str,
        resource_type: str,
        region: str,
        account: str,
        name: str,
        **_kw: Any,
    ) -> str:
        return f"acs:{service}:{region}:{account}:{resource_type}/{name}"


class _IBMBuilder:
    """Builds IBM Cloud CRNs."""

    def build(
        self,
        service: str,
        resource_type: str,
        region: str,
        account: str,
        name: str,
        **_kw: Any,
    ) -> str:
        # If name is already a CRN, return as-is
        if name.startswith("crn:"):
            return name
        return f"crn:v1:bluemix:public:{service}:{region}:{account}::{resource_type}:{name}"


class _K8sBuilder:
    """Builds Kubernetes canonical resource IDs.

    Format: k8s/{cluster_id}/{namespace}/{kind}/{name}

    cluster_id = the EKS/GKE/AKS cluster name or UID (account param).
    namespace  = K8s namespace (default: 'cluster' for non-namespaced resources).
    kind       = resource_type (secret, configmap, pod, deployment, etc.)
    name       = metadata.name
    """

    def build(
        self,
        service: str,
        resource_type: str,
        region: str,
        account: str,
        name: str,
        namespace: str = "cluster",
        **_kw: Any,
    ) -> str:
        kind = resource_type.lower().replace(".", "-")
        ns = namespace or "cluster"
        return f"k8s/{account}/{ns}/{kind}/{name}"


# ── Builder registry ──────────────────────────────────────────────────────────
_BUILDERS: Dict[str, Any] = {
    "aws":       _AWSBuilder(),
    "azure":     _AzureBuilder(),
    "gcp":       _GCPBuilder(),
    "oci":       _OCIBuilder(),
    "alicloud":  _AliCloudBuilder(),
    "ibm":       _IBMBuilder(),
    "k8s":       _K8sBuilder(),
}

_aws_builder = _BUILDERS["aws"]


# =============================================================================
# Public API
# =============================================================================

def make_resource_id(
    csp: str,
    service: str,
    resource_type: str,
    region: str,
    account: str,
    name: str,
    **kwargs: Any,
) -> str:
    """Generate a canonical resource ID for any CSP resource.

    This is the single entry point all engines use when writing resource_uid.
    Discovery engine calls this before writing to discovery_findings; all other
    engines just read the value — they never generate it.

    Args:
        csp:           Cloud provider: aws | azure | gcp | oci | alicloud | ibm | k8s
        service:       Service name (ec2, s3, compute, core, ...)
        resource_type: Resource type within the service (instance, bucket, secret, ...)
        region:        Region/location/zone. Empty string for global resources (IAM, S3).
        account:       Account/subscription/project/cluster identifier.
        name:          Resource name or native ID (instance ID, resource name, etc.)
        **kwargs:      CSP-specific extras:
                         K8s:   namespace (str, default "cluster")
                         Azure: resource_group (str)
                         AWS:   partition (str, default "aws")

    Returns:
        Canonical resource_uid string.

    Raises:
        ValueError: If csp is not a recognised provider.
    """
    builder = _BUILDERS.get(csp.lower())
    if not builder:
        raise ValueError(
            f"Unknown CSP '{csp}'. Supported: {sorted(_BUILDERS)}"
        )
    return builder.build(
        service=service,
        resource_type=resource_type,
        region=region,
        account=account,
        name=name,
        **kwargs,
    )


def parse_resource_id(uid: str) -> Dict[str, str]:
    """Parse a canonical resource_uid back into components.

    Returns a dict with keys: csp, service, resource_type, region, account, name.
    For unrecognised formats, returns {'csp': 'unknown', 'raw': uid}.
    """
    if uid.startswith("arn:"):
        parsed = parse_arn(uid)
        if parsed:
            parts = parsed.resource.split("/", 1)
            return {
                "csp":           "aws",
                "service":       parsed.service,
                "resource_type": parts[0],
                "region":        parsed.region,
                "account":       parsed.account_id,
                "name":          parts[1] if len(parts) > 1 else parsed.resource,
            }
    if uid.startswith("k8s/"):
        parts = uid.split("/")
        return {
            "csp":           "k8s",
            "service":       "core",
            "resource_type": parts[3] if len(parts) > 3 else "",
            "region":        "",
            "account":       parts[1] if len(parts) > 1 else "",
            "name":          parts[4] if len(parts) > 4 else "",
            "namespace":     parts[2] if len(parts) > 2 else "cluster",
        }
    if uid.startswith("azure/") or uid.startswith("/subscriptions/"):
        return {"csp": "azure", "raw": uid}
    if uid.startswith("//") and ".googleapis.com/" in uid:
        return {"csp": "gcp", "raw": uid}
    if uid.startswith("ocid1."):
        return {"csp": "oci", "raw": uid}
    if uid.startswith("acs:"):
        return {"csp": "alicloud", "raw": uid}
    if uid.startswith("crn:"):
        return {"csp": "ibm", "raw": uid}
    return {"csp": "unknown", "raw": uid}


# =============================================================================
# AWS-specific helpers (kept for backward compatibility)
# =============================================================================

def parse_arn(arn: str) -> Optional[ParsedARN]:
    """Parse an AWS ARN string into components. Returns None if not a valid ARN."""
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
    """Return True if the string is an AWS ARN."""
    return uid.startswith("arn:") and uid.count(":") >= 5


def normalize_resource_uid(
    resource_uid: str,
    resource_type: str = "",
    provider: str = "aws",
    region: str = "",
    account_id: str = "",
    resource_arn: str = "",
    partition: str = "aws",
) -> str:
    """Normalize a short-form AWS UID to a full ARN.

    If the UID is already an ARN or a non-AWS provider, returns it unchanged.
    This is kept for backward compatibility — new code should use make_resource_id().
    """
    if provider.lower() != "aws":
        return resource_uid
    return _aws_builder.normalize(
        resource_uid=resource_uid,
        resource_type=resource_type,
        region=region,
        account_id=account_id,
        resource_arn=resource_arn,
        partition=partition,
    )


def host_to_resource_uid(
    host: str,
    provider: str = "",
    account_id: str = "",
) -> str:
    """Convert a database hostname to canonical resource_uid.

    For AWS RDS endpoints, constructs the RDS ARN from the hostname.
    All other hosts are returned unchanged.
    """
    if not host:
        return host
    m = _RDS_HOST_RE.match(host)
    if m:
        db_identifier = m.group(1)
        region = m.group(2)
        return f"arn:aws:rds:{region}:{account_id}:db:{db_identifier}"
    return host


# =============================================================================
# DB-backed pattern lookup (di_resource_catalog table)
# =============================================================================

def get_identifier_pattern(
    csp: str,
    service: str,
    canonical_type: str,
    db_connection: Any = None,
) -> Optional[str]:
    """Look up the identifier_pattern from di_resource_catalog.

    Args:
        csp:            Cloud provider (aws, azure, gcp, oci, ibm, alicloud)
        service:        Service name (ec2, iam, s3, ...)
        canonical_type: Normalised resource type (security-group, instance, ...)
        db_connection:  psycopg2 connection to inventory DB. If None, cache only.

    Returns:
        Identifier pattern string or None.
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
                   FROM di_resource_catalog
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


def preload_identifier_patterns(db_connection: Any, csp: str = "aws") -> int:
    """Bulk-load all identifier patterns for a CSP into the in-memory cache.

    Call once at engine startup. Returns the number of patterns loaded.
    """
    try:
        with db_connection.cursor() as cur:
            cur.execute(
                """SELECT service, canonical_type, identifier_pattern
                   FROM di_resource_catalog
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
