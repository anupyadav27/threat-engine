"""Seed structural container types into resource_inventory_identifier.

Revision:  0005_inventory_structural_rii
Previous:  0004_inventory_rls
Engine:    inventory
Database:  threat_engine_inventory

Description:
    VPCs, subnets, and key network gateway types are discovered by the discovery
    engine (describe_vpcs, describe_subnets, etc.) and stored in inventory_findings,
    but they are NOT present in the step5 catalog JSON files because they are
    structural containers rather than independently-inventoried PaaS resources.

    This means:
      1. resource_inventory_identifier has no row for ec2.vpc / ec2.subnet
      2. architecture_resource_placement (seeded from RII) also lacks them
      3. The architecture builder SQL INNER JOINs ARP → VPCs/subnets are excluded
         from the assets list → architecture page shows 0 VPCs

    Fix: insert minimal RII rows for these structural types with:
      - should_inventory = true  (include in all engine queries)
      - show_in_architecture = true
      - is_container = true      (VPC and subnet are hierarchy containers)
      - diagram_priority = 1     (highest priority — always shown)

    These rows are protected from catalog-loader overwrites because they use
    ON CONFLICT (csp, service, resource_type) DO NOTHING, so a re-run of the
    catalog loader (which uses ON CONFLICT DO UPDATE) will only update existing
    rows and won't delete these seeded rows.

    After running this migration, re-run create_architecture_tables.py seed_placement
    to propagate the new RII rows into architecture_resource_placement.

    Idempotent: uses INSERT … ON CONFLICT DO NOTHING.
"""
from __future__ import annotations
from alembic import op
import sqlalchemy as sa

revision = "0005_inventory_structural_rii"
down_revision = "0004_inventory_rls"
branch_labels = None
depends_on = None


# ── Structural types to seed ──────────────────────────────────────────────────
# (csp, service, canonical_type, classification, scope, category, subcategory,
#  is_container, container_parent, diagram_priority, show_in_architecture)
_STRUCTURAL_TYPES = [
    # VPC — regional container
    ("aws", "ec2", "vpc",
     "PRIMARY_RESOURCE", "regional", "network", "vpc",
     True,  "region",      1, True),
    # Subnet — AZ-scoped container inside VPC
    ("aws", "ec2", "subnet",
     "PRIMARY_RESOURCE", "az",       "network", "subnet",
     True,  "ec2.vpc",     1, True),
    # Internet Gateway — attached to VPC
    ("aws", "ec2", "internet-gateway",
     "PRIMARY_RESOURCE", "vpc",      "network", "igw",
     False, "ec2.vpc",     2, True),
    # NAT Gateway — inside a subnet
    ("aws", "ec2", "nat-gateway",
     "PRIMARY_RESOURCE", "subnet",   "network", "natgw",
     False, "ec2.subnet",  2, True),
    # Transit Gateway — regional, connects VPCs/accounts
    ("aws", "ec2", "transit-gateway",
     "PRIMARY_RESOURCE", "regional", "network", "tgw",
     False, "region",      2, True),
    # VPN Gateway — attached to VPC
    ("aws", "ec2", "vpn-gateway",
     "PRIMARY_RESOURCE", "vpc",      "network", "vpn",
     False, "ec2.vpc",     3, True),
    # VPC Peering Connection
    ("aws", "ec2", "vpc-peering-connection",
     "PRIMARY_RESOURCE", "vpc",      "network", "peer",
     False, "ec2.vpc",     3, True),
    # Security Group — scoped to VPC, shown as supporting
    ("aws", "ec2", "security-group",
     "PRIMARY_RESOURCE", "vpc",      "security", "sg",
     False, "ec2.vpc",     2, True),
    # Route Table — supporting
    ("aws", "ec2", "route-table",
     "SUB_RESOURCE",     "subnet",   "network", "rt",
     False, "ec2.subnet",  4, False),
    # Network ACL — supporting
    ("aws", "ec2", "network-acl",
     "PRIMARY_RESOURCE", "vpc",      "security", "nacl",
     False, "ec2.vpc",     3, True),
    # VPC Endpoint — edge service
    ("aws", "ec2", "vpc-endpoint",
     "PRIMARY_RESOURCE", "vpc",      "network", "vpce",
     False, "ec2.vpc",     3, True),
    # Elastic IP
    ("aws", "ec2", "address",
     "PRIMARY_RESOURCE", "regional", "network", "eip",
     False, "region",      4, True),
    # Network Interface — sub-resource, not shown in arch by default
    ("aws", "ec2", "network-interface",
     "SUB_RESOURCE",     "subnet",   "network", "eni",
     False, "ec2.subnet",  5, False),
]


def upgrade() -> None:
    conn = op.get_bind()
    for row in _STRUCTURAL_TYPES:
        (csp, service, canonical_type, classification, scope, category,
         subcategory, is_container, container_parent, diagram_priority,
         show_in_architecture) = row

        conn.execute(sa.text("""
            INSERT INTO resource_inventory_identifier
                (csp, service, resource_type, canonical_type,
                 classification, scope, category, subcategory,
                 is_container, container_parent, diagram_priority,
                 should_inventory, show_in_inventory, show_in_architecture,
                 has_arn, identifier_type,
                 root_ops, enrich_ops)
            VALUES
                (:csp, :service, :canonical_type, :canonical_type,
                 :classification, :scope, :category, :subcategory,
                 :is_container, :container_parent, :diagram_priority,
                 true, true, :show_in_architecture,
                 true, 'arn',
                 '[]'::jsonb, '[]'::jsonb)
            ON CONFLICT (csp, service, resource_type) DO NOTHING
        """), {
            "csp": csp,
            "service": service,
            "canonical_type": canonical_type,
            "classification": classification,
            "scope": scope,
            "category": category,
            "subcategory": subcategory,
            "is_container": is_container,
            "container_parent": container_parent,
            "diagram_priority": diagram_priority,
            "show_in_architecture": show_in_architecture,
        })


def downgrade() -> None:
    conn = op.get_bind()
    for row in _STRUCTURAL_TYPES:
        _, service, canonical_type = row[0], row[1], row[2]
        conn.execute(sa.text("""
            DELETE FROM resource_inventory_identifier
            WHERE csp = 'aws' AND service = :service AND resource_type = :canonical_type
        """), {"service": service, "canonical_type": canonical_type})
