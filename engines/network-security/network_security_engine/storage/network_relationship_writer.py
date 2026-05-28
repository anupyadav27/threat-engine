"""
Network relationship writer — derives topology edges from NetworkTopology and writes
them to asset_relationships in the DI DB.

This extends the per-engine pattern:
  findings   → threat_engine_network (own DB)
  posture    → threat_engine_di.resource_security_posture
  relationships → threat_engine_di.asset_relationships  ← this module

Edges written per provider run:
  subnet      → GOVERNED_BY       → nacl
  subnet      → ROUTES_VIA        → route_table
  route_table → ROUTES_VIA        → igw / nat_gateway / tgw  (by route target type)
  vpc         → PEERED_WITH        → peer_vpc  (same-account)
  vpc         → PEERED_WITH_EXTERNAL → peer_vpc  (cross-account, lateral_movement)
  vpc         → CONNECTED_VIA     → tgw
  vpc         → HAS_ENDPOINT      → vpce
  vpce        → ROUTES_TO         → aws-service:s3/dynamodb  (Gateway type only)
  resource    → PROTECTED_BY      → sg  (enriched with effective_exposure in metadata)
  resource    → INTERNET_ACCESSIBLE → pseudo:internet:global  (ExposureLevel.INTERNET only)

UID format for AWS:
  VPC:          arn:aws:ec2:{region}:{acct_id}:vpc/{vpc_id}
  Subnet:       arn:aws:ec2:{region}:{acct_id}:subnet/{subnet_id}
  NACL:         arn:aws:ec2:{region}:{acct_id}:network-acl/{nacl_id}
  RouteTable:   arn:aws:ec2:{region}:{acct_id}:route-table/{rtb_id}
  IGW:          arn:aws:ec2:{region}:{acct_id}:internet-gateway/{igw_id}
  NAT:          arn:aws:ec2:{region}:{acct_id}:natgateway/{nat_id}
  TGW:          arn:aws:ec2:{region}:{acct_id}:transit-gateway/{tgw_id}
  VPCe:         arn:aws:ec2:{region}:{acct_id}:vpc-endpoint/{vpce_id}
  SG:           arn:aws:ec2:{region}:{acct_id}:security-group/{sg_id}
  Internet:     pseudo:internet:global  (virtual node — no real ARN)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from engine_common.db_connections import get_di_conn
from engine_common.relationship_writer import upsert_asset_relationships

logger = logging.getLogger(__name__)

_INTERNET_UID = "pseudo:internet:global"
_INTERNET_TYPE = "internet"

# AWS Gateway-type VPCe services that have direct routing entries
_GATEWAY_VPCE_SERVICES = frozenset({"s3", "dynamodb"})


def write_network_relationships(
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
    topology: Any,               # NetworkTopology
    sg_attachments: Optional[Dict[str, List[Dict]]] = None,
) -> int:
    """Derive topology edges from NetworkTopology and upsert to asset_relationships.

    Non-fatal — any exception is caught and logged so a relationship write failure
    never aborts the main scan pipeline.

    Returns:
        Number of edges written (0 on error).
    """
    try:
        edges = _derive_edges(topology, account_id, sg_attachments or {})
        if not edges:
            logger.info(
                "Network relationship writer: no edges for scan %s (topology empty?)", scan_run_id
            )
            return 0

        conn = get_di_conn()
        try:
            written = upsert_asset_relationships(
                conn, edges,
                scan_run_id=scan_run_id,
                tenant_id=tenant_id,
                account_id=account_id,
                provider=provider,
            )
            logger.info(
                "Network relationship writer: wrote %d edges for scan %s", written, scan_run_id
            )
            return written
        finally:
            conn.close()

    except Exception as exc:
        logger.warning(
            "Network relationship writer failed (non-fatal): %s", exc, exc_info=True
        )
        return 0


def _derive_edges(
    topology: Any,
    account_id: str,
    sg_attachments: Dict[str, List[Dict]],
) -> List[Dict[str, Any]]:
    """Walk the NetworkTopology and produce all relationship edge dicts."""
    edges: List[Dict[str, Any]] = []

    for vpc_id, vpc in topology.vpcs.items():
        region = vpc.region or "unknown"
        acct = vpc.account_id or account_id

        vpc_uid = _vpc_arn(region, acct, vpc_id)

        # ── Subnet → GOVERNED_BY → NACL ──────────────────────────────────
        for subnet_id, subnet in vpc.subnets.items():
            subnet_uid = _subnet_arn(region, acct, subnet_id)

            if subnet.nacl_id:
                nacl_uid = _nacl_arn(region, acct, subnet.nacl_id)
                edges.append({
                    "source_uid": subnet_uid,
                    "source_type": "subnet",
                    "target_uid": nacl_uid,
                    "target_type": "network_acl",
                    "relation_type": "GOVERNED_BY",
                    "relation_metadata": {
                        "nacl_id": subnet.nacl_id,
                        "is_public": subnet.is_public,
                    },
                })

            # ── Subnet → ROUTES_VIA → RouteTable ─────────────────────────
            if subnet.route_table_id:
                rtb_uid = _rtb_arn(region, acct, subnet.route_table_id)
                edges.append({
                    "source_uid": subnet_uid,
                    "source_type": "subnet",
                    "target_uid": rtb_uid,
                    "target_type": "route_table",
                    "relation_type": "ROUTES_VIA",
                    "relation_metadata": {
                        "route_table_id": subnet.route_table_id,
                        "is_public": subnet.is_public,
                    },
                })

        # ── RouteTable → ROUTES_VIA → IGW / NAT / TGW ────────────────────
        for rtb_id, rtb in vpc.route_tables.items():
            rtb_uid = _rtb_arn(region, acct, rtb_id)
            for route in rtb.routes:
                target_uid, target_type = _resolve_route_target(route, region, acct)
                if target_uid is None:
                    continue
                edges.append({
                    "source_uid": rtb_uid,
                    "source_type": "route_table",
                    "target_uid": target_uid,
                    "target_type": target_type,
                    "relation_type": "ROUTES_VIA",
                    "relation_metadata": {
                        "destination_cidr": route.destination_cidr,
                        "target_type": route.target_type,
                        "target_id": route.target_id,
                        "state": getattr(route, "state", None),
                    },
                })

        # ── VPC → PEERED_WITH / PEERED_WITH_EXTERNAL → peer VPC ──────────
        for pcx in vpc.peering_connections:
            peer_vpc_id = pcx.get("peer_vpc_id")
            if not peer_vpc_id:
                continue
            peer_account = pcx.get("peer_account") or acct
            peer_region = pcx.get("peer_region") or region

            cross_account = peer_account != acct
            relation_type = "PEERED_WITH_EXTERNAL" if cross_account else "PEERED_WITH"

            peer_vpc_uid = _vpc_arn(peer_region, peer_account, peer_vpc_id)
            edges.append({
                "source_uid": vpc_uid,
                "source_type": "vpc",
                "target_uid": peer_vpc_uid,
                "target_type": "vpc",
                "relation_type": relation_type,
                "relation_metadata": {
                    "pcx_id": pcx.get("pcx_id"),
                    "peer_account": peer_account,
                    "peer_region": peer_region,
                    "attack_path_category": "lateral_movement" if cross_account else "network_path",
                },
            })

        # ── VPC → CONNECTED_VIA → TGW ─────────────────────────────────────
        for attachment in vpc.tgw_attachments:
            tgw_id = attachment.get("tgw_id") or attachment.get("transit_gateway_id")
            if not tgw_id:
                continue
            tgw_uid = _tgw_arn(region, acct, tgw_id)
            edges.append({
                "source_uid": vpc_uid,
                "source_type": "vpc",
                "target_uid": tgw_uid,
                "target_type": "transit_gateway",
                "relation_type": "CONNECTED_VIA",
                "relation_metadata": {
                    "attachment_id": attachment.get("attachment_id"),
                    "tgw_id": tgw_id,
                    "state": attachment.get("state"),
                },
            })

        # ── VPC → HAS_ENDPOINT → VPCe; VPCe → ROUTES_TO → aws-service ───
        for vpce in vpc.vpc_endpoints:
            vpce_id = vpce.get("vpce_id") or vpce.get("id")
            if not vpce_id:
                continue
            vpce_uid = _vpce_arn(region, acct, vpce_id)
            service_name = vpce.get("service_name") or ""
            vpce_type = (vpce.get("type") or vpce.get("vpce_type") or "").lower()

            edges.append({
                "source_uid": vpc_uid,
                "source_type": "vpc",
                "target_uid": vpce_uid,
                "target_type": "vpc_endpoint",
                "relation_type": "HAS_ENDPOINT",
                "relation_metadata": {
                    "vpce_id": vpce_id,
                    "service_name": service_name,
                    "vpce_type": vpce_type,
                    "state": vpce.get("state"),
                },
            })

            # Gateway-type endpoints (S3, DynamoDB) create a routing edge
            if vpce_type == "gateway":
                svc_short = _vpce_service_short(service_name)
                if svc_short in _GATEWAY_VPCE_SERVICES:
                    svc_uid = f"aws-service:{region}:{svc_short}"
                    edges.append({
                        "source_uid": vpce_uid,
                        "source_type": "vpc_endpoint",
                        "target_uid": svc_uid,
                        "target_type": "aws_service",
                        "relation_type": "ROUTES_TO",
                        "relation_metadata": {
                            "service": svc_short,
                            "vpce_id": vpce_id,
                        },
                    })

        # ── SG → PROTECTED_BY / INTERNET_ACCESSIBLE ───────────────────────
        # We write edges per SG, not per attached resource (avoids fan-out explosion).
        # The attack-path engine joins via sg_attachments.
        edges.extend(
            _derive_sg_edges(vpc, region, acct, sg_attachments)
        )

    return edges


def _derive_sg_edges(
    vpc: Any,
    region: str,
    acct: str,
    sg_attachments: Dict[str, List[Dict]],
) -> List[Dict[str, Any]]:
    """Derive PROTECTED_BY and INTERNET_ACCESSIBLE edges from the SG analysis."""
    from network_security_engine.analyzers.security_group_analyzer import compute_effective_exposure
    from network_security_engine.models import ExposureLevel

    edges: List[Dict[str, Any]] = []

    for sg_id, sg in vpc.security_groups.items():
        sg_uid = sg.resource_uid or _sg_arn(region, acct, sg_id)
        effective = compute_effective_exposure(sg, vpc, None)  # topology not needed for basic check

        # Enrich attachment data
        attached = sg_attachments.get(sg_uid) or sg_attachments.get(sg_id) or []
        open_ports = _get_open_ports(sg)

        for resource in attached:
            resource_uid = resource.get("resource_uid") or resource.get("uid")
            if not resource_uid:
                continue
            resource_type = resource.get("resource_type") or resource.get("type") or "resource"

            edges.append({
                "source_uid": resource_uid,
                "source_type": resource_type,
                "target_uid": sg_uid,
                "target_type": "security_group",
                "relation_type": "PROTECTED_BY",
                "relation_metadata": {
                    "sg_id": sg_id,
                    "sg_name": sg.sg_name,
                    "effective_exposure": effective.value,
                    "open_ports": open_ports[:20],
                    "inbound_open_to_world": sg.inbound_open_to_world,
                },
            })

            if effective == ExposureLevel.INTERNET:
                edges.append({
                    "source_uid": resource_uid,
                    "source_type": resource_type,
                    "target_uid": _INTERNET_UID,
                    "target_type": _INTERNET_TYPE,
                    "relation_type": "INTERNET_ACCESSIBLE",
                    "relation_metadata": {
                        "via_sg": sg_id,
                        "open_ports": open_ports[:20],
                        "attack_path_category": "internet_facing",
                    },
                })

    return edges


def _get_open_ports(sg: Any) -> List[int]:
    ports: List[int] = []
    for rule in sg.inbound_rules:
        if not rule.is_open_to_world:
            continue
        if rule.port_from == -1:
            return [-1]  # all ports
        for p in range(rule.port_from, min(rule.port_to + 1, rule.port_from + 11)):
            ports.append(p)
    return sorted(set(ports))


def _resolve_route_target(route: Any, region: str, acct: str):
    """Map a RouteEntry to (target_uid, target_type) — returns (None, None) to skip."""
    ttype = (route.target_type or "").lower()
    tid = route.target_id or ""
    if not tid:
        return None, None

    if ttype == "igw":
        return f"arn:aws:ec2:{region}:{acct}:internet-gateway/{tid}", "internet_gateway"
    if ttype == "nat":
        return f"arn:aws:ec2:{region}:{acct}:natgateway/{tid}", "nat_gateway"
    if ttype in ("tgw", "transit-gateway"):
        return _tgw_arn(region, acct, tid), "transit_gateway"
    if ttype in ("pcx", "vpc-peering-connection"):
        return f"arn:aws:ec2:{region}:{acct}:vpc-peering-connection/{tid}", "vpc_peering_connection"
    if ttype in ("vpce", "vpc-endpoint"):
        return _vpce_arn(region, acct, tid), "vpc_endpoint"
    return None, None


# ── ARN helpers ──────────────────────────────────────────────────────────────

def _vpc_arn(region: str, acct: str, vpc_id: str) -> str:
    return f"arn:aws:ec2:{region}:{acct}:vpc/{vpc_id}"

def _subnet_arn(region: str, acct: str, subnet_id: str) -> str:
    return f"arn:aws:ec2:{region}:{acct}:subnet/{subnet_id}"

def _nacl_arn(region: str, acct: str, nacl_id: str) -> str:
    return f"arn:aws:ec2:{region}:{acct}:network-acl/{nacl_id}"

def _rtb_arn(region: str, acct: str, rtb_id: str) -> str:
    return f"arn:aws:ec2:{region}:{acct}:route-table/{rtb_id}"

def _sg_arn(region: str, acct: str, sg_id: str) -> str:
    return f"arn:aws:ec2:{region}:{acct}:security-group/{sg_id}"

def _tgw_arn(region: str, acct: str, tgw_id: str) -> str:
    return f"arn:aws:ec2:{region}:{acct}:transit-gateway/{tgw_id}"

def _vpce_arn(region: str, acct: str, vpce_id: str) -> str:
    return f"arn:aws:ec2:{region}:{acct}:vpc-endpoint/{vpce_id}"

def _vpce_service_short(service_name: str) -> str:
    """Extract short service name from VPCe endpoint service name.

    e.g. 'com.amazonaws.us-east-1.s3' → 's3'
    """
    parts = service_name.rsplit(".", 1)
    return parts[-1].lower() if parts else service_name.lower()
