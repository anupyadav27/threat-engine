"""
Network Security — Discovery DB Reader

Loads raw network resource data from the discoveries database.
Services: ec2 (VPC, SG, NACL, routes, IGW, NAT, ENI), elbv2, elb,
          wafv2, cloudfront, route53, networkfirewall, directconnect.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)

# Discovery IDs → network resource grouping
NETWORK_DISCOVERY_MAP = {
    # Core VPC/EC2 network
    "vpcs":                  "aws.ec2.describe_vpcs",
    "subnets":               "aws.ec2.describe_subnets",
    "security_groups":       "aws.ec2.describe_security_groups",
    "sg_rules":              "aws.ec2.describe_security_group_rules",
    "nacls":                 "aws.ec2.describe_network_acls",
    "route_tables":          "aws.ec2.describe_route_tables",
    "igws":                  "aws.ec2.describe_internet_gateways",
    "nat_gateways":          "aws.ec2.describe_nat_gateways",
    "vpc_endpoints":         "aws.ec2.describe_vpc_endpoints",
    "peering":               "aws.ec2.describe_vpc_peering_connections",
    "tgws":                  "aws.ec2.describe_transit_gateways",
    "tgw_attachments":       "aws.ec2.describe_transit_gateway_attachments",
    "tgw_route_tables":      "aws.ec2.describe_transit_gateway_route_tables",
    "tgw_vpc_attachments":   "aws.ec2.describe_transit_gateway_vpc_attachments",
    "eips":                  "aws.ec2.describe_addresses",
    "enis":                  "aws.ec2.describe_network_interfaces",
    "flow_logs":             "aws.ec2.describe_flow_logs",
    "egress_igws":           "aws.ec2.describe_egress_only_internet_gateways",

    # Load Balancers
    "elbv2_lbs":             "aws.elbv2.describe_load_balancers",
    "elbv2_listeners":       "aws.elbv2.describe_listeners",
    "elbv2_target_groups":   "aws.elbv2.describe_target_groups",
    "elbv2_rules":           "aws.elbv2.describe_rules",
    "elbv2_ssl_policies":    "aws.elbv2.describe_ssl_policies",
    "elbv2_lb_attrs":        "aws.elbv2.describe_load_balancer_attributes",
    "elbv2_listener_certs":  "aws.elbv2.describe_listener_certificates",
    "elbv2_target_health":   "aws.elbv2.describe_target_health",
    "elb_lbs":               "aws.elb.describe_load_balancers",
    "elb_attrs":             "aws.elb.describe_load_balancer_attributes",

    # WAF
    "wafv2_web_acls":        "aws.wafv2.list_web_ac_ls",
    "wafv2_web_acl_detail":  "aws.wafv2.get_web_acl",
    "wafv2_ip_sets":         "aws.wafv2.list_ip_sets",
    "wafv2_rule_groups":     "aws.wafv2.list_rule_groups",
    "wafv2_resources":       "aws.wafv2.list_resources_for_web_acl",
    "wafv2_logging":         "aws.wafv2.list_logging_configurations",
    "wafv2_managed_rules":   "aws.wafv2.list_available_managed_rule_groups",

    # Network Firewall
    "nfw_firewalls":         "aws.networkfirewall.list_firewalls",
    "nfw_detail":            "aws.networkfirewall.describe_firewall",
    "nfw_policy":            "aws.networkfirewall.describe_firewall_policy",
    "nfw_rule_groups":       "aws.networkfirewall.list_rule_groups",
    "nfw_logging":           "aws.networkfirewall.describe_logging_configuration",
}


def _get_discoveries_conn():
    """Return a fresh psycopg2 connection to the discoveries DB."""
    return psycopg2.connect(
        host=os.getenv("DISCOVERIES_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("DISCOVERIES_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("DISCOVERIES_DB_NAME", "threat_engine_discoveries"),
        user=os.getenv("DISCOVERIES_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("DISCOVERIES_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
        connect_timeout=10,
    )


class NetworkDiscoveryReader:
    """Read network resources from the discoveries database."""

    def load_all_network_resources(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: Optional[str] = None,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Load all network-relevant discovery data for a scan.

        Returns:
            Dict keyed by logical name (vpcs, subnets, security_groups, ...)
            with lists of discovery rows.
        """
        result: Dict[str, List[Dict]] = {}

        discovery_ids = list(NETWORK_DISCOVERY_MAP.values())

        conn = _get_discoveries_conn()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                query = """
                    SELECT discovery_id, resource_uid, resource_id, region,
                           service, raw_response, emitted_fields, config_hash
                    FROM discovery_findings
                    WHERE scan_run_id = %s
                      AND tenant_id = %s
                      AND discovery_id = ANY(%s)
                """
                params = [scan_run_id, tenant_id, discovery_ids]

                if account_id:
                    query += " AND account_id = %s"
                    params.append(account_id)

                cur.execute(query, params)
                rows = cur.fetchall()
        finally:
            conn.close()

        # Group by logical name
        disc_id_to_name = {v: k for k, v in NETWORK_DISCOVERY_MAP.items()}
        for row in rows:
            disc_id = row["discovery_id"]
            logical_name = disc_id_to_name.get(disc_id, disc_id)
            result.setdefault(logical_name, []).append(dict(row))

        logger.info(
            "Loaded %d network resources across %d categories for scan %s",
            sum(len(v) for v in result.values()),
            len(result),
            scan_run_id,
        )
        return result

    def load_by_discovery_id(
        self,
        scan_run_id: str,
        tenant_id: str,
        discovery_id: str,
        account_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Load resources for a single discovery_id."""
        conn = _get_discoveries_conn()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                query = """
                    SELECT resource_uid, resource_id, region, service,
                           raw_response, emitted_fields, config_hash
                    FROM discovery_findings
                    WHERE scan_run_id = %s
                      AND tenant_id = %s
                      AND discovery_id = %s
                """
                params = [scan_run_id, tenant_id, discovery_id]
                if account_id:
                    query += " AND account_id = %s"
                    params.append(account_id)

                cur.execute(query, params)
                return [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()

    def get_resource_counts(
        self,
        scan_run_id: str,
        tenant_id: str,
    ) -> Dict[str, int]:
        """Get counts of each network resource type for reporting."""
        conn = _get_discoveries_conn()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                discovery_ids = list(NETWORK_DISCOVERY_MAP.values())
                cur.execute("""
                    SELECT discovery_id, COUNT(*) as cnt
                    FROM discovery_findings
                    WHERE scan_run_id = %s
                      AND tenant_id = %s
                      AND discovery_id = ANY(%s)
                    GROUP BY discovery_id
                """, [scan_run_id, tenant_id, discovery_ids])

                disc_id_to_name = {v: k for k, v in NETWORK_DISCOVERY_MAP.items()}
                return {
                    disc_id_to_name.get(r["discovery_id"], r["discovery_id"]): r["cnt"]
                    for r in cur.fetchall()
                }
        finally:
            conn.close()
