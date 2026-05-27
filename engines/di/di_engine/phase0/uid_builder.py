"""
Phase 0 — UID Builder

Template syntax:
  {item.FieldName}      — field from the emitted item dict
  {context.region}      — scan context value (region, account_id, partition, csp)
  {context.account_id}  — cloud account/subscription/project ID
  {context.partition}   — 'aws' | 'aws-cn' | 'aws-us-gov' | csp name
  {parent.FieldName}    — field from the parent resource (chained ops)

uid_source values:
  'template'  — resolve uid_template string with placeholder substitution
  'field'     — scan well-known CSP identifier fields (ARN, OCID, ARM, CRN)
  'heuristic' — try field scan, then K8s uid/name assembly
"""
from __future__ import annotations

import re
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger("di.phase0.uid_builder")

_TEMPLATE_RE = re.compile(r"\{(\w+)\.([^}]+)\}")

CANONICAL_PREFIXES = {
    "aws": ("arn:",),
    "azure": ("/subscriptions/",),
    # GCP: JSON API uses googleapis.com; Storage JSON API uses storage.googleapis.com
    "gcp": ("projects/", "https://www.googleapis.com/", "https://storage.googleapis.com/"),
    "oci": ("ocid1.",),
    "ibm": ("crn:",),
    "alicloud": ("acs:", "alicloud:"),
    "k8s": ("k8s://",),
}

_ARN_CANDIDATES = (
    # First priority: use the pre-built canonical UID set by the service_scanner.
    # This covers services like S3 where list_buckets returns no ARN field but
    # resource_id.py's _AWSBuilder.build() constructs the correct ARN.
    "resource_uid",
    "Arn", "ARN", "ResourceArn", "GraphqlApiArn",
    # Mapping-level ARNs ranked before source/target ARNs so the mapping
    # itself is the canonical UID (not the SQS/Kinesis/DynamoDB source).
    "EventSourceMappingArn",
    "resource_arn",
    "FunctionArn", "RoleArn", "PolicyArn", "TopicArn", "QueueArn",
    "StreamArn", "ClusterArn", "BucketArn", "CertificateArn",
    "DomainArn", "LayerArn", "TableArn", "NamespaceArn",
    "RepositoryArn", "SecretARN", "SnapshotArn", "VolumeArn",
    "AlarmArn", "AssociationArn", "PipelineArn", "StateMachineArn",
    "WorkspaceArn", "ResolverArn", "AccessPointArn", "FileSystemArn",
)

_CSP_FIELD_CANDIDATES: Dict[str, tuple] = {
    "aws": _ARN_CANDIDATES,
    "oci": ("id", "identifier", "ocid"),
    "azure": ("id", "resourceId"),
    "ibm": ("crn", "id", "resourceId"),
    "gcp": ("selfLink", "name", "id"),
    # AliCloud: Arn field contains canonical acs: URI for IAM/RAM resources
    "alicloud": ("Arn", "id", "ResourceId", "InstanceId", "BucketName"),
    "k8s": ("uid", "name"),
}


class ResourceIdMissingError(ValueError):
    """Raised when no canonical UID can be derived for a resource.

    Not a fatal scan error — the row is skipped and logged to di_scan_errors.
    """

    def __init__(
        self,
        csp: str,
        service: str,
        resource_type: str,
        reason: str,
        item_keys: Optional[str] = None,
    ) -> None:
        self.csp = csp
        self.service = service
        self.resource_type = resource_type
        self.reason = reason
        self.item_keys = item_keys
        super().__init__(
            f"ResourceIdMissingError csp={csp} service={service} "
            f"resource_type={resource_type}: {reason}"
        )


def build_uid(
    uid_template: Optional[str],
    uid_source: str,
    item: Any,
    context: Dict[str, Any],
    parent: Optional[Dict[str, Any]] = None,
    identifier: Optional[Dict[str, Any]] = None,
) -> str:
    """Build a canonical resource_uid.

    Args:
        uid_template: Template string with {item.*}/{context.*}/{parent.*} placeholders.
        uid_source: 'template' | 'field' | 'heuristic'
        item: Raw emitted item from the scanner (dict or string for list-of-names ops).
        context: Scan context — must contain 'csp', 'region', 'account_id', 'partition'.
        parent: Parent resource item for chained/nested resources.
        identifier: Full identifier row dict (for error messages).

    Returns:
        Canonical resource UID string.

    Raises:
        ResourceIdMissingError: When no canonical UID can be derived.
    """
    csp = context.get("csp", "aws")
    svc = (identifier or {}).get("service", "")
    rtype = (identifier or {}).get("resource_type", "")

    # String items: ops like EKS list_clusters return bare cluster name strings
    if isinstance(item, str):
        region = context.get("region", "")
        account_id = context.get("account_id", "")
        return f"{csp}:{svc}:{region}:{account_id}:{item}"

    if not isinstance(item, dict):
        raise ResourceIdMissingError(
            csp=csp, service=svc, resource_type=rtype,
            reason=f"item is type {type(item).__name__}, expected dict or str",
        )

    item_keys = ",".join(list(item.keys())[:20])

    # Strategy 1: template resolution
    if uid_template and uid_source == "template":
        try:
            val = _resolve_template(uid_template, item, context, parent)
            if val and _is_canonical(val, csp):
                return val
        except KeyError:
            # Template placeholder missing from this item (e.g. row-level uid_template
            # applies to all root ops for a service but only fits one of them).
            # Fall through to Strategy 2 (field scan) instead of failing immediately.
            pass

    # Strategy 2: scan well-known CSP identifier fields
    candidates = _CSP_FIELD_CANDIDATES.get(csp, _ARN_CANDIDATES)
    for key in candidates:
        val = item.get(key)
        if val and isinstance(val, str) and _is_canonical(val, csp):
            return val

    # Strategy 3: AWS heuristic ARN construction for resources without ARN fields
    # Covers ENIs, IGWs, NACLs, EBS volumes, EC2 instances, DynamoDB tables, etc.
    if csp == "aws":
        region = context.get("region", "")
        account_id = context.get("account_id", "")
        partition = context.get("partition", "aws")
        _aws_arn_map = [
            ("NetworkInterfaceId", "ec2", "network-interface"),
            ("InternetGatewayId", "ec2", "internet-gateway"),
            ("NetworkAclId", "ec2", "network-acl"),
            ("VolumeId", "ec2", "volume"),
            ("InstanceId", "ec2", "instance"),
            ("VpcEndpointId", "ec2", "vpc-endpoint"),
            ("TransitGatewayRouteTableId", "ec2", "transit-gateway-route-table"),
            ("SubnetId", "ec2", "subnet"),
            ("VpcId", "ec2", "vpc"),
            # SSM
            ("AssociationId", "ssm", "association"),
            # VPC flow logs
            ("FlowLogId", "ec2", "vpc-flow-log"),
            # ELB classic (v1): has LoadBalancerName but no ARN field
            ("LoadBalancerName", "elasticloadbalancing", "loadbalancer"),
        ]
        for field, svc_name, resource_prefix in _aws_arn_map:
            val = item.get(field)
            if val and isinstance(val, str):
                return f"arn:{partition}:{svc_name}:{region}:{account_id}:{resource_prefix}/{val}"
        # DynamoDB: TableName → arn:aws:dynamodb:region:account:table/name
        table_name = item.get("TableName")
        if table_name:
            return f"arn:{partition}:dynamodb:{region}:{account_id}:table/{table_name}"
        # EKS cluster by name
        cluster_name = item.get("name") or item.get("ClusterName")
        if cluster_name and rtype and "eks" in rtype.lower():
            return f"arn:{partition}:eks:{region}:{account_id}:cluster/{cluster_name}"

    # Strategy 4: K8s uid/name assembly
    # K8s YAML emits flat keys "metadata.uid"/"metadata.name" (not nested dicts)
    if csp == "k8s":
        uid_val = (item.get("metadata.uid") or item.get("uid")
                   or item.get("metadata.name") or item.get("name"))
        ns = item.get("metadata.namespace") or item.get("namespace", "default")
        kind = item.get("kind", rtype)
        account_id = context.get("account_id", "")
        if uid_val:
            return f"k8s://{account_id}/{kind}/{ns}/{uid_val}"

    raise ResourceIdMissingError(
        csp=csp,
        service=svc,
        resource_type=rtype,
        reason=(
            f"No canonical UID found. uid_source={uid_source!r} "
            f"uid_template={uid_template!r}"
        ),
        item_keys=item_keys,
    )


def _resolve_template(
    template: str,
    item: Dict[str, Any],
    context: Dict[str, Any],
    parent: Optional[Dict[str, Any]],
) -> str:
    """Substitute {source.dotpath} placeholders in template string."""
    sources: Dict[str, Any] = {
        "item": item,
        "context": context,
        "parent": parent or {},
    }

    def replace_match(m: re.Match) -> str:
        source_name = m.group(1)
        dotpath = m.group(2)
        source = sources.get(source_name)
        if source is None:
            raise KeyError(f"{source_name}.{dotpath}")
        val = _extract(source, dotpath)
        if val is None:
            raise KeyError(f"{source_name}.{dotpath}")
        return str(val)

    return _TEMPLATE_RE.sub(replace_match, template)


def _extract(obj: Any, dotpath: str) -> Optional[Any]:
    """Extract a value from a nested dict using dot-separated path."""
    node: Any = obj
    for part in dotpath.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
        if node is None:
            return None
    return node


def _is_canonical(val: str, csp: str) -> bool:
    """Return True if val starts with the canonical prefix for this CSP."""
    prefixes = CANONICAL_PREFIXES.get(csp, ("arn:",))
    return any(val.startswith(p) for p in prefixes)


def build_canonical_uid(
    item: Dict[str, Any],
    identifier: Dict[str, Any],
    provider: str,
    region: str,
    account_id: str,
) -> str:
    """Backward-compatible wrapper around build_uid for old callers."""
    context = {
        "csp": provider,
        "region": region,
        "account_id": account_id,
        "partition": "aws" if provider == "aws" else provider,
    }
    return build_uid(
        uid_template=identifier.get("uid_template"),
        uid_source=identifier.get("uid_source", "heuristic"),
        item=item,
        context=context,
        identifier=identifier,
    )
