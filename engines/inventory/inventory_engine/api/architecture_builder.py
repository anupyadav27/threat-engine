"""
Architecture Hierarchy Builder (v2)

Transforms flat inventory assets + taxonomy classifications + relationships
into a nested architecture hierarchy suitable for rendering cloud topology
diagrams in the frontend.

The output is CSP-agnostic: AWS VPC = Azure VNet = GCP VPC = OCI VCN =
AliCloud VSwitch.  Resources are split into PRIMARY (rendered as chips
inside regions/VPCs/subnets) and SUPPORTING (collected into a reference
table with short IDs like SG-1, IAM-R2).

Usage::

    from architecture_builder import build_architecture_hierarchy

    result = build_architecture_hierarchy(assets, taxonomy, relationships)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# CSP-agnostic VNet / Subnet resource_type sets
VNET_TYPES: Set[str] = {
    "ec2.vpc", "vpc.vpc", "network.virtual-network", "vnet.vnet",
    "vcn.vcn", "core.vcn", "vpc.network", "is.vpc",
}
SUBNET_TYPES: Set[str] = {
    "ec2.subnet", "vpc.subnet", "network.subnet", "core.subnet",
    "vpc.subnetwork", "is.subnet",
}

# Subcategory → short prefix for supporting-resource reference IDs
SUBCAT_PREFIXES: Dict[str, str] = {
    "role": "IAM-R", "user": "IAM-U", "policy": "IAM-P", "group": "IAM-G",
    "instance_profile": "IAM-IP", "service_account": "SA",
    "firewall": "SG", "firewall_rule": "SGR", "nsg": "NSG",
    "security_list": "SL", "waf": "WAF",
    "key": "KMS-K", "secret": "SEC", "certificate": "CERT",
    "vpc": "VPC", "vcn": "VCN", "subnet": "SUB", "gateway": "GW", "igw": "IGW",
    "nat_gateway": "NAT", "route_table": "RT", "nacl": "NACL", "acl": "NACL",
    "nic": "ENI", "eip": "EIP", "endpoint": "VPCe", "transit_gateway": "TGW",
    "dns": "DNS", "metrics": "CW", "alarm": "CW-A", "log_group": "CW-L",
    "audit": "CT", "config_rule": "CFG", "block": "EBS", "snapshot": "SNAP",
}

# Fallback prefixes by category (used when subcategory has no mapping)
CAT_PREFIXES: Dict[str, str] = {
    "identity": "IAM", "security": "SEC", "encryption": "ENC",
    "monitoring": "MON", "logging": "LOG", "management": "MGT",
    "network": "NET", "compute": "CMP", "storage": "STR",
}

# Supporting-service group metadata (label + icon for the UI)
SUPPORTING_GROUPS: Dict[str, Dict[str, str]] = {
    "identity":   {"label": "Identity & Access",       "icon": "KeyRound"},
    "security":   {"label": "Firewall & Security",     "icon": "Shield"},
    "encryption": {"label": "Encryption & Secrets",    "icon": "Lock"},
    "network":    {"label": "Network",                 "icon": "Network"},
    "compute":    {"label": "Compute",                 "icon": "Server"},
    "monitoring": {"label": "Monitoring",              "icon": "Activity"},
    "logging":    {"label": "Logging & Audit",         "icon": "FileText"},
    "storage":    {"label": "Storage",                 "icon": "HardDrive"},
    "management": {"label": "Management",              "icon": "Settings"},
}

# Remap certain taxonomy categories / subcategories into a more logical
# supporting-service group.  The key is ``(category, subcategory)`` and the
# value is the target group key in SUPPORTING_GROUPS.  Subcategory ``"*"``
# means "any subcategory within this category".
_SUPPORTING_GROUP_OVERRIDES: Dict[tuple, str] = {
    # ENI / EIP are networking infra but conceptually "compute-attached"
    ("network", "nic"):             "compute",
    ("network", "eip"):             "compute",
    # EBS volumes / snapshots → compute (attached to EC2)
    ("storage", "block"):           "compute",
    ("storage", "snapshot"):        "compute",
    # CloudTrail, audit, log groups, logs → logging
    ("monitoring", "audit"):        "logging",
    ("monitoring", "log_group"):    "logging",
    ("monitoring", "logs"):         "logging",
    ("monitoring", "logging"):      "logging",
    ("monitoring", "generic"):      "logging",   # cloudtrail.resource
    # Config, compliance → management
    ("monitoring", "configuration"): "management",
    ("monitoring", "compliance"):    "management",
    # DNS (Route 53) stays in network
    # CloudWatch metrics / alarms stay in monitoring (no override needed)
    # SSM, Config → management (default fallback already handles this)
}

# Subnet type → sort order (public first, storage last)
SUBNET_TYPE_ORDER: Dict[str, int] = {
    "public": 0, "private": 1, "database": 2, "analytics": 3, "storage": 4,
}

# Category display order inside a subnet's resources_by_category
SUBNET_CATEGORY_ORDER: List[str] = [
    "edge", "compute", "container", "database", "analytics",
    "ai_ml", "storage", "messaging", "iot", "other",
]

# Subcategories that belong in the VPC-infrastructure bar
VPC_INFRA_SUBCATEGORIES: Set[str] = {
    "igw", "gateway", "nat_gateway", "route_table", "nacl", "acl",
    "vpc_endpoint", "endpoint", "transit_gateway", "vpn", "peering",
}


# ---------------------------------------------------------------------------
# VNet / Subnet detection helpers
# ---------------------------------------------------------------------------

def _is_vnet(resource_type: str) -> bool:
    """Return True if *resource_type* represents a VPC/VNet/VCN container."""
    rt_lower = resource_type.lower()
    if resource_type in VNET_TYPES:
        return True
    return (
        "vpc" in rt_lower
        and "subnet" not in rt_lower
        and "endpoint" not in rt_lower
    )


def _is_subnet(resource_type: str) -> bool:
    """Return True if *resource_type* represents a subnet / vswitch."""
    if resource_type in SUBNET_TYPES:
        return True
    rt_lower = resource_type.lower()
    return "subnet" in rt_lower or "vswitch" in rt_lower


# ---------------------------------------------------------------------------
# Subnet type inference
# ---------------------------------------------------------------------------

_PUBLIC_KEYWORDS = ("public", "dmz", "bastion", "external")
_DATABASE_KEYWORDS = ("database", "rds")
_ANALYTICS_KEYWORDS = ("analytics", "sagemaker", "emr")
_STORAGE_KEYWORDS = ("storage", "efs", "fsx", "backup")

# Compiled regex for word-boundary keyword matching (avoids false
# positives like "c2db02" matching "db").
import re as _re

_KW_PATTERNS = {
    "public":    _re.compile(r"(?:^|[\s_\-/])(?:" + "|".join(_PUBLIC_KEYWORDS) + r")(?:[\s_\-/]|$)", _re.I),
    "database":  _re.compile(r"(?:^|[\s_\-/])(?:" + "|".join(_DATABASE_KEYWORDS) + r")(?:[\s_\-/]|$)", _re.I),
    "analytics": _re.compile(r"(?:^|[\s_\-/])(?:" + "|".join(_ANALYTICS_KEYWORDS) + r")(?:[\s_\-/]|$)", _re.I),
    "storage":   _re.compile(r"(?:^|[\s_\-/])(?:" + "|".join(_STORAGE_KEYWORDS) + r")(?:[\s_\-/]|$)", _re.I),
}


def _infer_subnet_type(
    subnet_name: Optional[str],
    subnet_uid: Optional[str],
    resources: List[Dict[str, Any]],
) -> str:
    """Infer a subnet's functional type from its name and contained resources.

    Args:
        subnet_name: Human-readable name of the subnet.
        subnet_uid: Unique identifier of the subnet resource.
        resources: List of enriched resource dicts placed in this subnet.

    Returns:
        One of ``"public"``, ``"private"``, ``"database"``, ``"analytics"``,
        or ``"storage"``.
    """
    # Synthetic default subnets always get "private"
    if subnet_uid and "::default-subnet" in subnet_uid:
        return "private"

    name_lower = (subnet_name or "").lower()
    # Only match keywords in the NAME, not in hex UIDs
    for stype in ("public", "database", "analytics", "storage"):
        if _KW_PATTERNS[stype].search(name_lower):
            return stype

    # Heuristic: edge resources (IGW, LB) imply public; DB resources imply database
    has_edge = any(r.get("category") == "edge" for r in resources)
    if has_edge:
        return "public"
    has_db = any(r.get("category") == "database" for r in resources)
    if has_db:
        return "database"

    return "private"


# ---------------------------------------------------------------------------
# Taxonomy lookup
# ---------------------------------------------------------------------------

def _classify(
    asset: Dict[str, Any],
    taxonomy: Dict[str, Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """Look up the taxonomy entry for *asset*.

    Args:
        asset: A single inventory asset dict (must have ``resource_type``
            and optionally ``provider``).
        taxonomy: Map of ``"{provider}.{resource_type}"`` to classification
            dict (category, subcategory, scope, resource_role, etc.).

    Returns:
        The taxonomy dict or ``None`` if no match.
    """
    rt = asset.get("resource_type", "")
    provider = (asset.get("provider") or "aws").lower()
    key = f"{provider}.{rt}"
    return taxonomy.get(key)


# ---------------------------------------------------------------------------
# Reference-ID generator
# ---------------------------------------------------------------------------

class _RefIdGenerator:
    """Generates short, stable reference IDs for supporting resources.

    Each supporting resource gets an ID like ``SG-1``, ``IAM-R2``, etc.
    The prefix is chosen from the subcategory first, falling back to the
    category prefix, then a generic ``"REF"`` prefix.
    """

    def __init__(self) -> None:
        self._counters: Dict[str, int] = {}
        self._uid_to_ref: Dict[str, str] = {}

    def get(self, asset_entry: Dict[str, Any]) -> str:
        """Return (or create) the reference ID for *asset_entry*.

        Args:
            asset_entry: Enriched asset dict (must have ``resource_uid``,
                and optionally ``subcategory`` / ``category``).

        Returns:
            A short reference string such as ``"SG-1"`` or ``"IAM-R3"``.
        """
        uid = asset_entry["resource_uid"]
        if uid in self._uid_to_ref:
            return self._uid_to_ref[uid]

        subcat = asset_entry.get("subcategory", "")
        cat = asset_entry.get("category", "other")
        prefix = SUBCAT_PREFIXES.get(subcat, CAT_PREFIXES.get(cat, "REF"))

        self._counters[prefix] = self._counters.get(prefix, 0) + 1
        ref_id = f"{prefix}-{self._counters[prefix]}"
        self._uid_to_ref[uid] = ref_id
        return ref_id

    @property
    def uid_to_ref(self) -> Dict[str, str]:
        """Read-only view of uid → ref_id mappings built so far."""
        return self._uid_to_ref


# ---------------------------------------------------------------------------
# Asset enrichment
# ---------------------------------------------------------------------------

def _enrich_asset(
    asset: Dict[str, Any],
    tax: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Build a front-end-friendly resource entry from raw asset + taxonomy.

    Args:
        asset: Raw inventory asset row.
        tax: Matching taxonomy classification (may be ``None``).

    Returns:
        Enriched dict ready for inclusion in the hierarchy.
    """
    cat = tax.get("category", "other") if tax else "other"
    subcat = tax.get("subcategory", "other") if tax else "other"
    resource_role = tax.get("resource_role", "primary") if tax else "primary"

    return {
        "resource_uid": asset["resource_uid"],
        "resource_type": asset.get("resource_type", ""),
        "resource_id": asset.get("resource_id"),
        "name": (
            asset.get("display_name")
            or asset.get("name")
            or asset.get("resource_id")
        ),
        "display_name": tax.get("display_name") if tax else None,
        "risk_score": asset.get("risk_score"),
        "criticality": asset.get("criticality"),
        "compliance_status": asset.get("compliance_status"),
        "tags": asset.get("tags"),
        "category": cat,
        "subcategory": subcat,
        "service_model": tax.get("service_model") if tax else None,
        "managed_by": tax.get("managed_by") if tax else None,
        "access_pattern": tax.get("access_pattern") if tax else None,
        "is_container": tax.get("is_container", False) if tax else False,
        "diagram_priority": tax.get("diagram_priority", 5) if tax else 5,
        "resource_role": resource_role,
        "classified": tax is not None,
    }


# ---------------------------------------------------------------------------
# Relationship index builders
# ---------------------------------------------------------------------------

def _build_relationship_indexes(
    relationships: List[Dict[str, Any]],
) -> Tuple[Dict[str, str], Dict[str, List[str]], Dict[str, List[str]]]:
    """Index relationships by type for fast lookups.

    Args:
        relationships: List of relationship dicts, each having
            ``from_uid``, ``to_uid``, and ``relation_type``.

    Returns:
        A 3-tuple of:
        - ``contained_by``: child_uid -> parent_uid
        - ``attached_to``: child_uid -> [parent_uids]
        - ``uses_map``: child_uid -> [target_uids]
    """
    contained_by: Dict[str, str] = {}
    attached_to: Dict[str, List[str]] = {}
    uses_map: Dict[str, List[str]] = {}

    # Two passes: first collect all contained_by edges, then pick the most
    # specific parent (subnet > vpc) for each child.
    containment_edges: Dict[str, List[Tuple[str, str]]] = {}

    for rel in relationships:
        rt = rel["relation_type"]
        from_uid = rel["from_uid"]
        to_uid = rel["to_uid"]
        to_rt = rel.get("to_resource_type", "")

        if rt == "contained_by":
            containment_edges.setdefault(from_uid, []).append((to_uid, to_rt))
        elif rt in ("attached_to", "associated_with"):
            attached_to.setdefault(from_uid, []).append(to_uid)
        elif rt in ("uses", "encrypted_by", "assumes"):
            uses_map.setdefault(from_uid, []).append(to_uid)

    # For each child, prefer the most specific container:
    # subnet > vpc > anything else
    for child_uid, parents in containment_edges.items():
        best_uid = parents[0][0]
        best_specificity = 0
        for p_uid, p_rt in parents:
            if _is_subnet(p_rt):
                if best_specificity < 2:
                    best_uid, best_specificity = p_uid, 2
            elif _is_vnet(p_rt):
                if best_specificity < 1:
                    best_uid, best_specificity = p_uid, 1
        contained_by[child_uid] = best_uid

        # Also store the vpc link for subnets (subnet → vpc)
        if best_specificity == 2:
            for p_uid, p_rt in parents:
                if _is_vnet(p_rt):
                    contained_by[best_uid] = p_uid
                    break

    return contained_by, attached_to, uses_map


# ---------------------------------------------------------------------------
# Reference-map builder (primary ↔ supporting cross-references)
# ---------------------------------------------------------------------------

def _build_reference_map(
    relationships: List[Dict[str, Any]],
    attached_to: Dict[str, List[str]],
    uses_map: Dict[str, List[str]],
    uid_to_ref: Dict[str, str],
) -> Dict[str, List[str]]:
    """Build a map of primary resource_uid -> [supporting ref_ids].

    Scans attached_to, uses_map, and raw relationships (both directions)
    to find every supporting resource referenced by (or referencing) a
    primary resource.

    Args:
        relationships: Raw relationship list.
        attached_to: Indexed attached_to / associated_with edges.
        uses_map: Indexed uses / encrypted_by / assumes edges.
        uid_to_ref: Map of supporting resource uid -> ref_id.

    Returns:
        Dict mapping primary resource uid to sorted, deduplicated list of
        supporting ref_ids (e.g. ``["IAM-R1", "SG-2"]``).
    """
    ref_map: Dict[str, List[str]] = {}

    # Forward direction: primary → supporting
    for uid, targets in attached_to.items():
        for target_uid in targets:
            if target_uid in uid_to_ref:
                ref_map.setdefault(uid, []).append(uid_to_ref[target_uid])

    for uid, targets in uses_map.items():
        for target_uid in targets:
            if target_uid in uid_to_ref:
                ref_map.setdefault(uid, []).append(uid_to_ref[target_uid])

    # Both directions from raw relationships
    _LINK_TYPES = ("attached_to", "associated_with", "uses", "encrypted_by")
    for rel in relationships:
        if rel["relation_type"] not in _LINK_TYPES:
            continue
        from_uid, to_uid = rel["from_uid"], rel["to_uid"]

        # supporting → primary: annotate the primary
        if from_uid in uid_to_ref and to_uid not in uid_to_ref:
            ref_map.setdefault(to_uid, []).append(uid_to_ref[from_uid])
        # primary → supporting: annotate the primary
        if to_uid in uid_to_ref and from_uid not in uid_to_ref:
            ref_map.setdefault(from_uid, []).append(uid_to_ref[to_uid])

    # Deduplicate and sort
    for uid in ref_map:
        ref_map[uid] = sorted(set(ref_map[uid]))

    return ref_map


# ---------------------------------------------------------------------------
# Supporting cross-references (supporting ↔ supporting)
# ---------------------------------------------------------------------------

def _build_supporting_cross_refs(
    relationships: List[Dict[str, Any]],
    uid_to_ref: Dict[str, str],
) -> List[Dict[str, str]]:
    """Find relationships where both endpoints are supporting resources.

    Args:
        relationships: Raw relationship list.
        uid_to_ref: Map of supporting resource uid -> ref_id.

    Returns:
        List of ``{"from_ref", "to_ref", "relation"}`` dicts.
    """
    cross_refs: List[Dict[str, str]] = []
    for rel in relationships:
        from_uid, to_uid = rel["from_uid"], rel["to_uid"]
        if from_uid in uid_to_ref and to_uid in uid_to_ref:
            cross_refs.append({
                "from_ref": uid_to_ref[from_uid],
                "to_ref": uid_to_ref[to_uid],
                "relation": rel["relation_type"],
            })
    return cross_refs


# ---------------------------------------------------------------------------
# VPC infrastructure extraction
# ---------------------------------------------------------------------------

def _populate_vpc_infrastructure(
    accounts_map: Dict[str, Dict[str, Any]],
    contained_by: Dict[str, str],
) -> None:
    """Move supporting network resources into their parent VPC's infra bar.

    Mutates ``vpc["vpc_infrastructure"]`` in-place for each VPC found in
    *accounts_map*.

    Args:
        accounts_map: The mutable accounts dict (account_id -> account).
        contained_by: child_uid -> parent_uid containment index.
    """
    for acct in accounts_map.values():
        for reg in acct["regions"].values():
            for vpc in reg["vpcs"].values():
                vpc_uid = vpc["vpc_uid"]
                infra_items: List[Dict[str, Any]] = []

                for group_key in ("network", "security"):
                    grp = acct["supporting_services"].get(group_key, {})
                    for _region_key, rlist in grp.get("regional", {}).items():
                        for res in rlist:
                            res_uid = res["resource_uid"]
                            if contained_by.get(res_uid) != vpc_uid:
                                continue
                            subcat = res.get("subcategory", "")
                            if subcat in VPC_INFRA_SUBCATEGORIES or res.get("category") == "network":
                                infra_items.append({
                                    "ref_id": res.get("ref_id", ""),
                                    "resource_type": res["resource_type"],
                                    "display_name": res.get("display_name") or res.get("name"),
                                    "subcategory": subcat,
                                    "resource_uid": res_uid,
                                })

                vpc["vpc_infrastructure"] = infra_items


# ---------------------------------------------------------------------------
# Subnet finalization (type inference + AZ extraction)
# ---------------------------------------------------------------------------

def _finalize_subnets(
    accounts_map: Dict[str, Dict[str, Any]],
    uid_to_asset: Dict[str, Dict[str, Any]],
) -> None:
    """Infer subnet types and extract AZ badges.  Mutates in-place.

    Args:
        accounts_map: The mutable accounts dict.
        uid_to_asset: Resource uid -> raw asset dict for AZ lookup.
    """
    for acct in accounts_map.values():
        for reg in acct["regions"].values():
            for vpc in reg["vpcs"].values():
                for sn in vpc["subnets"].values():
                    all_res = sn.pop("_all_resources", [])
                    sn["subnet_type"] = _infer_subnet_type(
                        sn["name"], sn["subnet_uid"], all_res,
                    )

                    # Extract AZ from the subnet asset's properties /
                    # emitted_fields (most reliable), then fallback to
                    # top-level fields, then to the parent region.
                    subnet_asset = uid_to_asset.get(sn["subnet_uid"])
                    az = None
                    if subnet_asset:
                        props = subnet_asset.get("properties") or {}
                        ef = props.get("emitted_fields") or {}
                        config = subnet_asset.get("configuration") or {}
                        az = (
                            ef.get("AvailabilityZone")
                            or ef.get("availability_zone")
                            or config.get("AvailabilityZone")
                            or subnet_asset.get("availability_zone")
                            or subnet_asset.get("az")
                        )
                    sn["az"] = az or reg.get("region")

                    # Fix subnet display name — use subnet ID from UID
                    # when name is a placeholder like "ip-name".
                    if sn.get("name") in (None, "", "ip-name"):
                        uid_parts = sn["subnet_uid"].rsplit("/", 1)
                        sn["name"] = uid_parts[-1] if len(uid_parts) > 1 else sn["subnet_uid"]


# ---------------------------------------------------------------------------
# Interface connection tracking (cross-subnet flows)
# ---------------------------------------------------------------------------

def _detect_interface_connections(
    accounts_map: Dict[str, Dict[str, Any]],
    relationships: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Detect cross-subnet relationships where subnet types differ.

    For example, a load balancer in a public subnet talking to an EC2
    instance in a private subnet produces an interface connection.

    Args:
        accounts_map: Finalized accounts dict (subnets still as dicts).
        relationships: Raw relationship list.

    Returns:
        List of interface connection dicts.
    """
    connections: List[Dict[str, Any]] = []

    for acct in accounts_map.values():
        for reg in acct["regions"].values():
            for vpc in reg["vpcs"].values():
                # Build quick lookup: resource_uid -> subnet_uid and
                # subnet_uid -> subnet_type
                subnet_type_map: Dict[str, str] = {}
                resource_to_subnet: Dict[str, str] = {}

                for sn in vpc["subnets"].values():
                    subnet_type_map[sn["subnet_uid"]] = sn["subnet_type"]
                    for cat_resources in sn["resources_by_category"].values():
                        for r in cat_resources:
                            resource_to_subnet[r["resource_uid"]] = sn["subnet_uid"]

                for rel in relationships:
                    if rel["relation_type"] in ("contained_by", "contains"):
                        continue
                    from_sub = resource_to_subnet.get(rel["from_uid"])
                    to_sub = resource_to_subnet.get(rel["to_uid"])
                    if from_sub and to_sub and from_sub != to_sub:
                        from_type = subnet_type_map.get(from_sub, "private")
                        to_type = subnet_type_map.get(to_sub, "private")
                        if from_type != to_type:
                            connections.append({
                                "from_subnet": from_sub,
                                "to_subnet": to_sub,
                                "from_type": from_type,
                                "to_type": to_type,
                                "from_resource": rel["from_uid"],
                                "to_resource": rel["to_uid"],
                                "relation": rel["relation_type"],
                            })

    return connections


# ---------------------------------------------------------------------------
# Dict-to-list serialization (final output shaping)
# ---------------------------------------------------------------------------

def _serialize_accounts(
    accounts_map: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Convert the nested dict-of-dicts into JSON-friendly lists.

    Subnets are sorted by ``SUBNET_TYPE_ORDER`` (public first).

    Args:
        accounts_map: The mutable accounts dict.

    Returns:
        List of account dicts with regions/vpcs/subnets as lists.
    """
    accounts: List[Dict[str, Any]] = []

    for acct in accounts_map.values():
        regions: List[Dict[str, Any]] = []
        for reg in acct["regions"].values():
            vpcs: List[Dict[str, Any]] = []
            for vpc in reg["vpcs"].values():
                raw_subnets = list(vpc["subnets"].values())
                # Hide the synthetic "VPC Resources" default subnet when
                # the VPC already has real subnets with resources.  The
                # default subnet only exists as a catch-all for instances
                # that lack containment edges; showing it alongside real
                # subnets creates confusing duplicates.
                real_subnets = [
                    s for s in raw_subnets
                    if "::default-subnet" not in s.get("subnet_uid", "")
                ]
                real_have_resources = any(
                    s.get("resources_by_category")
                    for s in real_subnets
                )
                if real_have_resources:
                    filtered_subnets = real_subnets
                else:
                    filtered_subnets = raw_subnets
                subnets = sorted(
                    filtered_subnets,
                    key=lambda s: SUBNET_TYPE_ORDER.get(
                        s.get("subnet_type", "private"), 1,
                    ),
                )
                vpcs.append({
                    "vpc_uid": vpc["vpc_uid"],
                    "name": vpc["name"],
                    "subnets": subnets,
                    "vpc_infrastructure": vpc.get("vpc_infrastructure", []),
                    "edge_services": vpc.get("edge_services", []),
                })
            regions.append({
                "region": reg["region"],
                "regional_primary": reg.get("regional_primary", {}),
                "vpcs": vpcs,
            })

        accounts.append({
            "account_id": acct["account_id"],
            "provider": acct["provider"],
            "global_primary": acct.get("global_primary", {}),
            "public_services": acct.get("public_services", {}),
            "regions": regions,
            "supporting_services": acct.get("supporting_services", {}),
        })

    return accounts


# ---------------------------------------------------------------------------
# Helpers for the main loop
# ---------------------------------------------------------------------------

def _ensure_account(
    accounts_map: Dict[str, Dict[str, Any]],
    account_id: str,
    provider: str,
) -> Dict[str, Any]:
    """Return (or create) the account entry in *accounts_map*."""
    if account_id not in accounts_map:
        accounts_map[account_id] = {
            "account_id": account_id,
            "provider": provider,
            "global_primary": {},
            "regions": {},
            "supporting_services": {},
        }
    return accounts_map[account_id]


def _ensure_region(
    acct: Dict[str, Any],
    region: str,
) -> Dict[str, Any]:
    """Return (or create) a region dict inside *acct*."""
    if region not in acct["regions"]:
        acct["regions"][region] = {
            "region": region,
            "regional_primary": {},
            "vpcs": {},
        }
    return acct["regions"][region]


def _resolve_display_name(asset: Optional[Dict[str, Any]], fallback: str) -> str:
    """Pick the best human-readable name from an asset dict."""
    if not asset:
        return fallback
    return (
        asset.get("display_name")
        or asset.get("name")
        or asset.get("resource_id")
        or fallback
    )


# ---------------------------------------------------------------------------
# Primary resource placement
# ---------------------------------------------------------------------------

def _infer_vpc_from_peers(
    uid: str,
    attached_to: Dict[str, List[str]],
    uses_map: Dict[str, List[str]],
    contained_by: Dict[str, str],
    uid_to_asset: Dict[str, Dict[str, Any]],
) -> Tuple[Optional[str], Optional[str]]:
    """Infer VPC/subnet by following peer relationships transitively.

    If a resource has no direct ``contained_by`` edge to a VPC or subnet,
    check its ``attached_to`` and ``uses`` targets.  If any peer (e.g. a
    security group) is itself ``contained_by`` a VPC, infer the VPC.

    Returns:
        ``(vpc_uid, subnet_uid)`` — either or both may be ``None``.
    """
    peers: List[str] = []
    peers.extend(attached_to.get(uid, []))
    peers.extend(uses_map.get(uid, []))

    for peer_uid in peers:
        vpc_uid, subnet_uid = _walk_containment(
            peer_uid, uid_to_asset, contained_by,
        )
        if vpc_uid:
            return vpc_uid, subnet_uid
    return None, None


def _place_primary_resource(
    asset_entry: Dict[str, Any],
    asset: Dict[str, Any],
    scope: str,
    cat: str,
    region: str,
    acct: Dict[str, Any],
    uid_to_asset: Dict[str, Dict[str, Any]],
    contained_by: Dict[str, str],
    attached_to: Dict[str, List[str]],
    uses_map: Dict[str, List[str]],
) -> None:
    """Route a primary resource to the correct position in the hierarchy.

    Depending on *scope*, the resource is placed into:
    - ``global_primary`` (scope == "global")
    - a VPC subnet (scope in "vpc", "subnet", "az")
    - ``regional_primary`` (scope == "regional" or fallback)

    Args:
        asset_entry: Enriched resource dict.
        asset: Raw inventory asset.
        scope: Taxonomy scope (global / regional / vpc / subnet / az).
        cat: Taxonomy category.
        region: Cloud region string.
        acct: The mutable account dict.
        uid_to_asset: uid -> raw asset lookup.
        contained_by: Containment index (child -> parent).
        attached_to: Indexed attached_to / associated_with edges.
        uses_map: Indexed uses / encrypted_by / assumes edges.
    """
    if scope == "global":
        acct["global_primary"].setdefault(cat, []).append(asset_entry)
        return

    # Only resources whose taxonomy scope indicates VPC-level placement
    # (vpc, subnet, az) should be placed inside VPC containers.
    # Resources with scope=regional (e.g. Lambda, S3) stay in regional_primary
    # even if they have a VPC interface — the interface is the VPC resource,
    # not the service itself.
    if scope in ("vpc", "subnet", "az"):
        reg = _ensure_region(acct, region)
        uid = asset["resource_uid"]

        vpc_uid, subnet_uid = _walk_containment(uid, uid_to_asset, contained_by)

        # Fallback: infer VPC from peer relationships (e.g. attached SG)
        if not vpc_uid:
            vpc_uid, subnet_uid = _infer_vpc_from_peers(
                uid, attached_to, uses_map, contained_by, uid_to_asset,
            )

        if vpc_uid:
            _place_in_vpc(
                reg, vpc_uid, subnet_uid, asset_entry, cat,
                uid_to_asset, contained_by,
            )
        else:
            reg["regional_primary"].setdefault(cat, []).append(asset_entry)
        return

    # Default: regional scope → regional_primary
    reg = _ensure_region(acct, region)
    reg["regional_primary"].setdefault(cat, []).append(asset_entry)


def _walk_containment(
    uid: str,
    uid_to_asset: Dict[str, Dict[str, Any]],
    contained_by: Dict[str, str],
) -> Tuple[Optional[str], Optional[str]]:
    """Walk the containment chain to find the parent VPC and subnet.

    Args:
        uid: The resource's uid.
        uid_to_asset: uid -> raw asset.
        contained_by: child -> parent containment index.

    Returns:
        ``(vpc_uid, subnet_uid)`` — either or both may be ``None``.
    """
    vpc_uid: Optional[str] = None
    subnet_uid: Optional[str] = None

    parent = contained_by.get(uid)
    if not parent:
        return vpc_uid, subnet_uid

    parent_asset = uid_to_asset.get(parent)
    if not parent_asset:
        return vpc_uid, subnet_uid

    parent_rt = parent_asset.get("resource_type", "")

    if _is_subnet(parent_rt):
        subnet_uid = parent
        vpc_parent = contained_by.get(subnet_uid)
        if vpc_parent:
            vpc_uid = vpc_parent
    elif _is_vnet(parent_rt):
        vpc_uid = parent

    return vpc_uid, subnet_uid


def _place_in_vpc(
    reg: Dict[str, Any],
    vpc_uid: str,
    subnet_uid: Optional[str],
    asset_entry: Dict[str, Any],
    cat: str,
    uid_to_asset: Dict[str, Dict[str, Any]],
    contained_by: Dict[str, str],
) -> None:
    """Place a resource into a VPC (and optionally a subnet).

    Creates the VPC / subnet containers on first encounter.

    Args:
        reg: The mutable region dict.
        vpc_uid: VPC resource uid.
        subnet_uid: Subnet resource uid (may be ``None``).
        asset_entry: Enriched resource dict.
        cat: Taxonomy category.
        uid_to_asset: uid -> raw asset.
        contained_by: Containment index.
    """
    if vpc_uid not in reg["vpcs"]:
        vpc_name = _resolve_display_name(uid_to_asset.get(vpc_uid), vpc_uid)
        reg["vpcs"][vpc_uid] = {
            "vpc_uid": vpc_uid,
            "name": vpc_name,
            "subnets": {},
            "vpc_infrastructure": [],
        }

    vpc = reg["vpcs"][vpc_uid]

    if subnet_uid:
        if subnet_uid not in vpc["subnets"]:
            subnet_name = _resolve_display_name(
                uid_to_asset.get(subnet_uid), subnet_uid,
            )
            vpc["subnets"][subnet_uid] = {
                "subnet_uid": subnet_uid,
                "name": subnet_name,
                "subnet_type": "private",  # overwritten during finalization
                "resources_by_category": {},
                "_all_resources": [],
            }

        sn = vpc["subnets"][subnet_uid]
        sn["resources_by_category"].setdefault(cat, []).append(asset_entry)
        sn["_all_resources"].append(asset_entry)
    else:
        # VPC-scoped but no subnet — place in a "default" subnet within the VPC
        default_sn_uid = f"{vpc_uid}::default-subnet"
        if default_sn_uid not in vpc["subnets"]:
            vpc["subnets"][default_sn_uid] = {
                "subnet_uid": default_sn_uid,
                "name": "VPC Resources",
                "subnet_type": "private",
                "resources_by_category": {},
                "_all_resources": [],
            }
        sn = vpc["subnets"][default_sn_uid]
        sn["resources_by_category"].setdefault(cat, []).append(asset_entry)
        sn["_all_resources"].append(asset_entry)


# ---------------------------------------------------------------------------
# Supporting resource placement
# ---------------------------------------------------------------------------

def _place_supporting_resource(
    asset_entry: Dict[str, Any],
    scope: str,
    cat: str,
    region: str,
    acct: Dict[str, Any],
    ref_gen: _RefIdGenerator,
) -> None:
    """Route a supporting resource into the correct reference group.

    Args:
        asset_entry: Enriched resource dict.
        scope: Taxonomy scope.
        cat: Taxonomy category.
        region: Cloud region string.
        acct: The mutable account dict.
        ref_gen: Reference-ID generator instance.
    """
    ref_id = ref_gen.get(asset_entry)
    asset_entry["ref_id"] = ref_id

    subcat = asset_entry.get("subcategory", "")
    # Check override map first (specific subcategory, then wildcard)
    group_key = _SUPPORTING_GROUP_OVERRIDES.get(
        (cat, subcat),
        _SUPPORTING_GROUP_OVERRIDES.get((cat, "*"), None),
    )
    if group_key is None:
        group_key = cat if cat in SUPPORTING_GROUPS else "management"
    if group_key not in acct["supporting_services"]:
        acct["supporting_services"][group_key] = {"global": [], "regional": {}}

    grp = acct["supporting_services"][group_key]
    if scope == "global":
        grp["global"].append(asset_entry)
    else:
        grp["regional"].setdefault(region, []).append(asset_entry)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def _infer_containment_from_properties(
    assets: List[Dict[str, Any]],
    relationships: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Infer contained_by relationships from VpcId/SubnetId in asset properties.

    When the relationship pipeline doesn't produce containment edges (e.g.
    because emitted_fields got overwritten), fall back to reading VpcId and
    SubnetId directly from the asset's properties or emitted_fields.

    This creates:
    - instance → subnet (contained_by) when SubnetId is present
    - instance → vpc (contained_by) when only VpcId is present
    - subnet → vpc (contained_by) when subnet has VpcId

    Returns the extended relationships list.
    """
    existing_edges = {
        (r["from_uid"], r["to_uid"])
        for r in relationships
        if r.get("relation_type") == "contained_by"
    }

    new_rels: List[Dict[str, Any]] = []
    for asset in assets:
        uid = asset.get("resource_uid", "")
        rt = asset.get("resource_type", "")
        region = asset.get("region", "")
        account_id = asset.get("account_id", "")
        provider = (asset.get("provider") or "aws").lower()

        # Look for VpcId / SubnetId in properties, emitted_fields, or config.
        # Inventory stores emitted_fields nested under properties:
        #   properties.emitted_fields.VpcId (most common path)
        #   properties.VpcId (if flattened)
        #   configuration.VpcId (if promoted to config)
        props = asset.get("properties") or {}
        ef = props.get("emitted_fields") or {}
        config = asset.get("configuration") or {}

        vpc_id = (
            ef.get("VpcId") or props.get("VpcId")
            or config.get("VpcId")
        )
        subnet_id = (
            ef.get("SubnetId") or props.get("SubnetId")
            or config.get("SubnetId")
        )

        if not vpc_id and not subnet_id:
            continue

        # Skip if this asset IS a vpc or subnet
        if _is_vnet(rt) or _is_subnet(rt):
            # But handle subnet → vpc containment
            if _is_subnet(rt) and vpc_id:
                vpc_arn = f"arn:aws:ec2:{region}:{account_id}:vpc/{vpc_id}"
                if (uid, vpc_arn) not in existing_edges:
                    new_rels.append({
                        "from_uid": uid,
                        "to_uid": vpc_arn,
                        "relation_type": "contained_by",
                        "to_resource_type": "ec2.vpc",
                    })
                    existing_edges.add((uid, vpc_arn))
            continue

        # For non-container resources: prefer subnet, fall back to vpc
        if subnet_id:
            subnet_arn = f"arn:aws:ec2:{region}:{account_id}:subnet/{subnet_id}"
            if (uid, subnet_arn) not in existing_edges:
                new_rels.append({
                    "from_uid": uid,
                    "to_uid": subnet_arn,
                    "relation_type": "contained_by",
                    "to_resource_type": "ec2.subnet",
                })
                existing_edges.add((uid, subnet_arn))

            # Also link subnet → vpc if we know both
            if vpc_id:
                vpc_arn = f"arn:aws:ec2:{region}:{account_id}:vpc/{vpc_id}"
                if (subnet_arn, vpc_arn) not in existing_edges:
                    new_rels.append({
                        "from_uid": subnet_arn,
                        "to_uid": vpc_arn,
                        "relation_type": "contained_by",
                        "to_resource_type": "ec2.vpc",
                    })
                    existing_edges.add((subnet_arn, vpc_arn))
        elif vpc_id:
            vpc_arn = f"arn:aws:ec2:{region}:{account_id}:vpc/{vpc_id}"
            if (uid, vpc_arn) not in existing_edges:
                new_rels.append({
                    "from_uid": uid,
                    "to_uid": vpc_arn,
                    "relation_type": "contained_by",
                    "to_resource_type": "ec2.vpc",
                })
                existing_edges.add((uid, vpc_arn))

    if new_rels:
        logger.info(
            "Inferred %d containment relationships from asset properties "
            "(VpcId/SubnetId)",
            len(new_rels),
        )
    return relationships + new_rels


def _synthesize_containers(
    assets: List[Dict[str, Any]],
    relationships: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Create synthetic VPC/subnet assets from relationship targets.

    Discovery scanners often don't enumerate VPC and subnet resources as
    standalone inventory_findings entries.  However, ``contained_by``
    relationships reference them as ``to_uid`` targets.  This function
    detects those missing containers and injects lightweight synthetic
    assets so that ``_walk_containment`` can resolve the hierarchy.

    Args:
        assets: Existing inventory asset list.
        relationships: Relationship dicts with ``from_uid``, ``to_uid``,
            ``relation_type``, ``to_resource_type``.

    Returns:
        Extended asset list (original + synthetic entries).
    """
    existing_uids = {a["resource_uid"] for a in assets}

    # Collect missing container targets from contained_by relationships
    missing: Dict[str, Dict[str, Any]] = {}
    for rel in relationships:
        if rel.get("relation_type") != "contained_by":
            continue
        to_uid = rel.get("to_uid", "")
        to_rt = rel.get("to_resource_type", "")
        if not to_uid or to_uid in existing_uids or to_uid in missing:
            continue
        if not (_is_vnet(to_rt) or _is_subnet(to_rt)):
            continue

        # Infer account/region from a child that references this container
        from_uid = rel.get("from_uid", "")
        child = next((a for a in assets if a["resource_uid"] == from_uid), None)

        # Extract a short resource_id from the UID (last segment after / or :)
        short_id = to_uid.rsplit("/", 1)[-1] if "/" in to_uid else to_uid.rsplit(":", 1)[-1]

        missing[to_uid] = {
            "resource_uid": to_uid,
            "resource_type": to_rt,
            "resource_id": short_id,
            "name": short_id,
            "display_name": short_id,
            "provider": child.get("provider", "aws") if child else "aws",
            "account_id": child.get("account_id", "unknown") if child else "unknown",
            "region": child.get("region", "unknown") if child else "unknown",
            "tags": None,
            "risk_score": None,
            "criticality": None,
            "compliance_status": None,
            "is_synthetic": True,
        }

    if missing:
        logger.info(
            "Synthesized %d container assets (VPCs/subnets) from relationships",
            len(missing),
        )
    return assets + list(missing.values())


# ---------------------------------------------------------------------------
# Post-processing: relocate resources into VPC containers
# ---------------------------------------------------------------------------

# Categories that should always go inside VPCs, not in regional_primary
_VPC_BOUND_CATEGORIES = {"compute", "database", "edge", "container"}

# Resource types that MUST stay in regional_primary (never relocate into VPC)
_REGIONAL_ONLY_TYPES = {"lambda.function"}

# EFS types — relocated into VPC subnets as "file_storage"
_EFS_TYPES = {"efs.file-system", "efs.filesystem", "elasticfilesystem.file-system"}

# S3 types — extracted from regional_primary into VPC storage column
_S3_TYPES = {"s3.bucket", "s3.general-purpose-bucket", "s3.directory-bucket"}


def _relocate_edge_into_vpc(
    accounts_map: Dict[str, Dict[str, Any]],
    contained_by: Dict[str, str],
    uid_to_asset: Dict[str, Dict[str, Any]],
) -> None:
    """Move edge resources (IGW, NAT, etc.) from regional_primary into VPC.

    Edge services are attached to VPCs.  If a VPC exists in the region,
    place edge resources inside a dedicated ``edge`` section on the VPC
    dict (rendered above subnets in the frontend).  Mutates in-place.
    """
    for acct in accounts_map.values():
        for reg in acct["regions"].values():
            edge_items = reg.get("regional_primary", {}).pop("edge", [])
            if not edge_items:
                continue

            # Find the first VPC in this region (or create one)
            vpcs = reg.get("vpcs", {})
            if not vpcs:
                # No VPC in this region; put edge items back
                reg.setdefault("regional_primary", {})["edge"] = edge_items
                continue

            # Place edge items into VPC
            first_vpc_key = next(iter(vpcs))
            vpc = vpcs[first_vpc_key]
            vpc.setdefault("edge_services", []).extend(edge_items)


def _relocate_regional_into_vpc(
    accounts_map: Dict[str, Dict[str, Any]],
    uid_to_asset: Dict[str, Dict[str, Any]],
) -> None:
    """Move compute/database/container resources from regional_primary into VPC.

    Resources with scope=az that ended up in regional_primary (because
    they lack containment relationships) should still be shown inside the
    VPC — in a special 'VPC Resources' default subnet, grouped by AZ.

    **Exclusions:**
    - Lambda functions stay in regional_primary (re-categorised as "lambda")
    - EFS file systems are placed as "file_storage" inside VPC subnets

    Mutates in-place.
    """
    for acct in accounts_map.values():
        for reg in acct["regions"].values():
            vpcs = reg.get("vpcs", {})
            if not vpcs:
                continue

            first_vpc_key = next(iter(vpcs))
            vpc = vpcs[first_vpc_key]

            moved_any = False
            for cat in list(_VPC_BOUND_CATEGORIES - {"edge"}):
                items = reg.get("regional_primary", {}).pop(cat, [])
                if not items:
                    continue

                # Separate Lambda items — they stay in regional_primary
                lambda_items: List[Dict[str, Any]] = []
                vpc_items: List[Dict[str, Any]] = []
                for item in items:
                    if item.get("resource_type") in _REGIONAL_ONLY_TYPES:
                        lambda_items.append(item)
                    else:
                        vpc_items.append(item)

                # Put Lambda back into regional_primary under its own category
                if lambda_items:
                    rp = reg.setdefault("regional_primary", {})
                    rp.setdefault("lambda", []).extend(lambda_items)

                if not vpc_items:
                    continue

                # Place into a "VPC Resources" default subnet
                default_sn_uid = f"{first_vpc_key}::default-subnet"
                if default_sn_uid not in vpc["subnets"]:
                    vpc["subnets"][default_sn_uid] = {
                        "subnet_uid": default_sn_uid,
                        "name": "VPC Resources",
                        "subnet_type": "private",
                        "resources_by_category": {},
                        "_all_resources": [],
                    }
                sn = vpc["subnets"][default_sn_uid]
                sn["resources_by_category"].setdefault(cat, []).extend(vpc_items)
                sn["_all_resources"].extend(vpc_items)
                moved_any = True

            # Also relocate EFS from regional storage into VPC as file_storage
            storage_items = reg.get("regional_primary", {}).get("storage", [])
            if storage_items:
                efs_items: List[Dict[str, Any]] = []
                remaining_storage: List[Dict[str, Any]] = []
                for item in storage_items:
                    if item.get("resource_type") in _EFS_TYPES:
                        efs_items.append(item)
                    else:
                        remaining_storage.append(item)

                if efs_items:
                    if remaining_storage:
                        reg["regional_primary"]["storage"] = remaining_storage
                    else:
                        reg.get("regional_primary", {}).pop("storage", None)

                    default_sn_uid = f"{first_vpc_key}::default-subnet"
                    if default_sn_uid not in vpc["subnets"]:
                        vpc["subnets"][default_sn_uid] = {
                            "subnet_uid": default_sn_uid,
                            "name": "VPC Resources",
                            "subnet_type": "private",
                            "resources_by_category": {},
                            "_all_resources": [],
                        }
                    sn = vpc["subnets"][default_sn_uid]
                    sn["resources_by_category"].setdefault(
                        "file_storage", [],
                    ).extend(efs_items)
                    sn["_all_resources"].extend(efs_items)
                    moved_any = True

            if moved_any:
                logger.info(
                    "Relocated regional compute/db/container resources into VPC %s",
                    first_vpc_key,
                )


def _extract_public_services(
    accounts_map: Dict[str, Dict[str, Any]],
) -> None:
    """Extract AWS public services into account-level public_services.

    AWS "public" services (S3, DynamoDB, SQS, SNS, CloudFront, Route53,
    Bedrock, etc.) are NOT VPC-bound and NOT truly regional in the
    networking sense.  This function pulls matching resource types out of
    ``regional_primary`` across all regions and collects them into
    ``acct["public_services"]`` — a dict keyed by category, each holding
    a list of resource entries tagged with their source region.

    Lambda stays in ``regional_primary`` (displayed inside the region box
    as "Compute · Lambda").

    The "Public Services" panel is rendered at account level, as a
    vertical column parallel to the regions column.

    Mutates in-place.
    """
    # Resource types considered "public" (not VPC-bound, not regional-compute)
    _PUBLIC_TYPES: Set[str] = {
        # Storage
        "s3.bucket", "s3.general-purpose-bucket", "s3.directory-bucket",
        # NoSQL / Database public
        "dynamodb.table", "dynamodb.global-table",
        # Messaging
        "sqs.queue", "sns.topic", "sns.subscription",
        "eventbridge.event-bus", "events.rule",
        # CDN / Edge
        "cloudfront.distribution", "cloudfront.function",
        # DNS
        "route53.hosted-zone", "route53.health-check",
        # AI / ML (public endpoints)
        "bedrock.model", "bedrock.custom-model",
        "sagemaker.endpoint", "sagemaker.notebook-instance",
        # Analytics (serverless / public)
        "athena.workgroup", "glue.database", "glue.crawler",
        "kinesis.stream", "firehose.delivery-stream",
        # App integration
        "stepfunctions.state-machine", "states.state-machine",
        "appsync.graphql-api",
        # Secrets / Config (public service plane)
        "secretsmanager.secret", "ssm.parameter",
    }

    # Also match any resource whose category is in this set AND is not
    # Lambda (already filtered out)
    _PUBLIC_CATEGORIES: Set[str] = {"storage", "messaging", "analytics",
                                     "ai_ml", "edge"}

    for acct in accounts_map.values():
        ps: Dict[str, List[Dict[str, Any]]] = {}

        for reg in acct.get("regions", {}).values():
            rp = reg.get("regional_primary", {})
            region_name = reg.get("region", "")

            for cat in list(rp.keys()):
                # Lambda stays in regional_primary
                if cat == "lambda":
                    continue

                items = rp.get(cat, [])
                public_items: List[Dict[str, Any]] = []
                keep_items: List[Dict[str, Any]] = []
                keep_lambda: List[Dict[str, Any]] = []

                for item in items:
                    rt = item.get("resource_type", "")
                    if rt in _PUBLIC_TYPES or cat in _PUBLIC_CATEGORIES:
                        item["region"] = region_name
                        public_items.append(item)
                    elif rt in _REGIONAL_ONLY_TYPES:
                        # Re-categorize Lambda as "lambda" regardless of
                        # original category (may still be "compute" in regions
                        # that have no VPC for _relocate_regional_into_vpc)
                        keep_lambda.append(item)
                    else:
                        keep_items.append(item)

                if public_items:
                    ps.setdefault(cat, []).extend(public_items)

                # Re-categorize Lambda into its own "lambda" key
                if keep_lambda:
                    rp.setdefault("lambda", []).extend(keep_lambda)

                if keep_items:
                    rp[cat] = keep_items
                else:
                    rp.pop(cat, None)

        if ps:
            acct["public_services"] = ps


def _infer_paas_from_tags(
    tags: Any,
) -> Optional[str]:
    """Infer PaaS association from EC2 instance tags.

    AWS managed services tag their EC2 instances with well-known keys:

    - EKS: ``eks:cluster-name``, ``aws:eks:cluster-name``,
      ``kubernetes.io/cluster/*``
    - RDS: ``aws:rds:cluster-id``
    - ECS: ``aws:ecs:*``, ``ecs:cluster``
    - SageMaker: ``aws:sagemaker:*``, ``sagemaker:*``
    - EMR: ``aws:elasticmapreduce:*``, ``aws:emr:*``
    - Redshift: ``aws:redshift:*``
    - ElastiCache: ``aws:elasticache:*``
    - OpenSearch: ``aws:opensearch:*``

    Args:
        tags: Tag dict (may be ``None``, ``dict``, or JSON string).

    Returns:
        A PaaS label like ``"eks"``, ``"rds"``, etc., or ``None``.
    """
    if not tags:
        return None
    if isinstance(tags, str):
        try:
            import json
            tags = json.loads(tags)
        except (ValueError, TypeError):
            return None
    if not isinstance(tags, dict):
        return None

    tag_keys_lower = [k.lower() for k in tags.keys()]

    # Tag-key patterns → PaaS label (checked in priority order)
    _TAG_PATTERNS: List[Tuple[str, List[str]]] = [
        ("eks", ["eks:cluster-name", "aws:eks:cluster-name",
                 "kubernetes.io/cluster/", "k8s.io/cluster-autoscaler/"]),
        ("ecs", ["aws:ecs:", "ecs:cluster"]),
        ("rds", ["aws:rds:", "rds:"]),
        ("sagemaker", ["aws:sagemaker:", "sagemaker:"]),
        ("emr", ["aws:elasticmapreduce:", "aws:emr:"]),
        ("redshift", ["aws:redshift:", "redshift:"]),
        ("elasticache", ["aws:elasticache:", "elasticache:"]),
        ("opensearch", ["aws:opensearch:", "aws:es:", "opensearch:"]),
    ]

    for label, prefixes in _TAG_PATTERNS:
        for tag_key in tag_keys_lower:
            for prefix in prefixes:
                if tag_key.startswith(prefix) or tag_key == prefix:
                    return label
    return None


def _group_compute_by_association(
    accounts_map: Dict[str, Dict[str, Any]],
    relationships: List[Dict[str, Any]],
    uid_to_asset: Dict[str, Dict[str, Any]],
) -> None:
    """Split compute resources into sub-groups by associated PaaS service.

    Uses two strategies (in order of priority):

    1. **Relationship edges**: EC2 instances linked to EKS/RDS/ECS etc.
       via ``runs_on``, ``attached_to``, ``managed_by`` relationships.
    2. **Tag-based inference**: AWS managed services tag their EC2 nodes
       with well-known keys (``eks:cluster-name``, ``aws:ecs:*``, etc.).
       This is the primary mechanism since most discovery scans capture
       tags but may not build explicit relationship edges.

    Mutates subnet ``resources_by_category`` dicts in-place, adding new
    keys like ``compute_eks``, ``compute_rds`` and removing those items
    from the original ``compute`` list.
    """
    # Build reverse index: instance_uid → set of associated service types
    # We check both directions of relationships
    _SERVICE_PATTERNS = {
        "eks":        {"eks.", "kubernetes.", "k8s."},
        "rds":        {"rds."},
        "redshift":   {"redshift."},
        "sagemaker":  {"sagemaker."},
        "emr":        {"emr.", "elasticmapreduce."},
        "ecs":        {"ecs."},
        "lambda":     {"lambda."},
        "elasticache": {"elasticache."},
        "opensearch": {"opensearch.", "es."},
    }
    _COMPUTE_TYPES = {"ec2.instance"}

    # Index: compute_uid → service_label
    compute_assoc: Dict[str, str] = {}

    # ── Strategy 1: Relationship edges ──
    for rel in relationships:
        rt = rel.get("relation_type", "")
        if rt not in ("runs_on", "attached_to", "associated_with", "uses",
                       "contained_by", "managed_by"):
            continue
        from_uid, to_uid = rel["from_uid"], rel["to_uid"]
        from_rt = rel.get("from_resource_type", "")
        to_rt = rel.get("to_resource_type", "")

        # Case 1: compute → service (compute uses/attached_to service)
        if from_rt in _COMPUTE_TYPES:
            for label, prefixes in _SERVICE_PATTERNS.items():
                if any(to_rt.startswith(p) for p in prefixes):
                    compute_assoc[from_uid] = label
                    break

        # Case 2: service → compute (e.g. EKS cluster runs_on EC2)
        if to_rt in _COMPUTE_TYPES:
            for label, prefixes in _SERVICE_PATTERNS.items():
                if any(from_rt.startswith(p) for p in prefixes):
                    compute_assoc[to_uid] = label
                    break

    rel_count = len(compute_assoc)

    # ── Strategy 2: Tag-based inference (fallback for un-linked instances) ──
    for uid, asset in uid_to_asset.items():
        if uid in compute_assoc:
            continue  # already resolved via relationships
        rt = asset.get("resource_type", "")
        if rt not in _COMPUTE_TYPES:
            continue
        tags = asset.get("tags")
        label = _infer_paas_from_tags(tags)
        if label:
            compute_assoc[uid] = label

    tag_count = len(compute_assoc) - rel_count

    if not compute_assoc:
        logger.info("Compute association grouping: no PaaS associations found")
        return

    logger.info(
        "Compute association grouping: %d instances linked to services "
        "(%d via relationships, %d via tags) → %s",
        len(compute_assoc), rel_count, tag_count,
        ", ".join(f"{v}: {sum(1 for x in compute_assoc.values() if x == v)}"
                  for v in sorted(set(compute_assoc.values()))),
    )

    # Walk subnets and split compute into sub-groups
    for acct in accounts_map.values():
        for reg in acct.get("regions", {}).values():
            for vpc in reg.get("vpcs", {}).values():
                for sn in vpc.get("subnets", {}).values():
                    cats = sn.get("resources_by_category", {})
                    compute = cats.get("compute")
                    if not compute:
                        continue

                    plain: List[Dict[str, Any]] = []
                    groups: Dict[str, List[Dict[str, Any]]] = {}
                    for item in compute:
                        uid = item.get("resource_uid", "")
                        label = compute_assoc.get(uid)
                        if label:
                            key = f"compute_{label}"
                            groups.setdefault(key, []).append(item)
                        else:
                            plain.append(item)

                    if groups:
                        if plain:
                            cats["compute"] = plain
                        else:
                            del cats["compute"]
                        for key, items in groups.items():
                            cats[key] = items


def _embed_ref_ids(
    accounts_map: Dict[str, Dict[str, Any]],
    reference_map: Dict[str, List[str]],
) -> None:
    """Stamp ``ref_ids`` onto each primary resource entry in the hierarchy.

    Walks accounts → regions → vpcs → subnets → resources and also
    regional_primary / global_primary.  Mutates in-place.
    """
    def _stamp_list(items: List[Dict[str, Any]]) -> None:
        for item in items:
            uid = item.get("resource_uid")
            if uid and uid in reference_map:
                item["ref_ids"] = reference_map[uid]

    def _stamp_dict(d: Dict[str, List[Dict[str, Any]]]) -> None:
        for items in d.values():
            _stamp_list(items)

    for acct in accounts_map.values():
        _stamp_dict(acct.get("global_primary", {}))
        _stamp_dict(acct.get("public_services", {}))
        for reg in acct["regions"].values():
            _stamp_dict(reg.get("regional_primary", {}))
            for vpc in reg.get("vpcs", {}).values():
                _stamp_list(vpc.get("edge_services", []))
                for sn in vpc.get("subnets", {}).values():
                    _stamp_dict(sn.get("resources_by_category", {}))


def build_architecture_hierarchy(
    assets: List[Dict[str, Any]],
    taxonomy: Dict[str, Dict[str, Any]],
    relationships: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Build a nested architecture hierarchy (v2) from flat data.

    Transforms a flat list of inventory assets, a taxonomy classification
    map, and a list of inter-resource relationships into a nested JSON
    structure suitable for rendering cloud architecture diagrams.

    Args:
        assets: List of inventory asset dicts.  Each must have at least
            ``resource_uid`` and ``resource_type``.
        taxonomy: Classification map keyed by ``"{provider}.{resource_type}"``
            with values containing ``category``, ``subcategory``, ``scope``,
            ``resource_role``, etc.
        relationships: List of relationship dicts with ``from_uid``,
            ``to_uid``, and ``relation_type``.

    Returns:
        A dict with top-level keys:

        - ``accounts`` — nested account/region/vpc/subnet hierarchy
        - ``relationships`` — pass-through of the input relationships
        - ``reference_map`` — primary uid -> [supporting ref_ids]
        - ``supporting_cross_refs`` — supporting-to-supporting links
        - ``interface_connections`` — cross-subnet-type flows
        - ``supporting_groups_meta`` — UI metadata for supporting groups
    """
    # -- Synthesize missing VPC/subnet containers from relationships ---------
    assets = _synthesize_containers(assets, relationships)

    # -- Infer containment from asset properties (VpcId/SubnetId) -----------
    relationships = _infer_containment_from_properties(assets, relationships)
    assets = _synthesize_containers(assets, relationships)

    # -- Build indexes -------------------------------------------------------
    uid_to_asset = {a["resource_uid"]: a for a in assets}
    contained_by, attached_to, uses_map = _build_relationship_indexes(relationships)
    ref_gen = _RefIdGenerator()

    # -- Main classification loop --------------------------------------------
    accounts_map: Dict[str, Dict[str, Any]] = {}
    for asset in assets:
        rt = asset.get("resource_type", "")

        # VPC / Subnet containers are structural — skip as resource chips
        if _is_vnet(rt) or _is_subnet(rt):
            continue

        tax = _classify(asset, taxonomy)

        scope = tax.get("scope", "regional") if tax else "regional"
        cat = tax.get("category", "other") if tax else "other"
        resource_role = tax.get("resource_role", "primary") if tax else "primary"
        region = asset.get("region", "global")
        account_id = asset.get("account_id", "unknown")
        provider = (asset.get("provider") or "aws").lower()

        acct = _ensure_account(accounts_map, account_id, provider)
        asset_entry = _enrich_asset(asset, tax)

        if resource_role == "supporting":
            _place_supporting_resource(
                asset_entry, scope, cat, region, acct, ref_gen,
            )
        else:
            _place_primary_resource(
                asset_entry, asset, scope, cat, region,
                acct, uid_to_asset, contained_by,
                attached_to, uses_map,
            )

    # -- Post-processing -----------------------------------------------------
    uid_to_ref = ref_gen.uid_to_ref

    # VPC infrastructure bar
    _populate_vpc_infrastructure(accounts_map, contained_by)

    # Move edge resources from regional_primary into VPC
    _relocate_edge_into_vpc(accounts_map, contained_by, uid_to_asset)

    # Move remaining regional compute/database into VPC (default subnet)
    _relocate_regional_into_vpc(accounts_map, uid_to_asset)

    # Extract public services (S3, DynamoDB, etc.) into account-level panel
    _extract_public_services(accounts_map)

    # Subnet type inference + AZ badges
    _finalize_subnets(accounts_map, uid_to_asset)

    # Cross-references
    reference_map = _build_reference_map(
        relationships, attached_to, uses_map, uid_to_ref,
    )
    supporting_cross_refs = _build_supporting_cross_refs(
        relationships, uid_to_ref,
    )

    # Compute association grouping (Compute, Compute-EKS, Compute-RDS, etc.)
    _group_compute_by_association(accounts_map, relationships, uid_to_asset)

    # Embed ref_ids (supporting service references) on each primary resource
    _embed_ref_ids(accounts_map, reference_map)

    # Interface connections (must run before serialization since subnets
    # are still dicts keyed by uid at this point)
    interface_connections = _detect_interface_connections(
        accounts_map, relationships,
    )

    # -- Serialize to JSON-friendly lists ------------------------------------
    accounts = _serialize_accounts(accounts_map)

    return {
        "accounts": accounts,
        "relationships": relationships,
        "reference_map": reference_map,
        "supporting_cross_refs": supporting_cross_refs,
        "interface_connections": interface_connections,
        "supporting_groups_meta": SUPPORTING_GROUPS,
    }
