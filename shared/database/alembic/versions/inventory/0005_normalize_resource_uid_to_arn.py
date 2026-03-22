"""Normalize resource_uid to canonical ARN format.

Revision ID: 0005_normalize_uid_arn
Revises: 0004_inventory_rls

Converts short-form resource UIDs (e.g. ec2:ap-south-1:588989875114:sg-xxx)
to canonical ARN format (arn:aws:ec2:ap-south-1:588989875114:security-group/sg-xxx)
in inventory_findings.resource_uid, inventory_relationships.from_uid/to_uid,
inventory_asset_history.resource_uid, and inventory_drift.resource_uid.

Also deduplicates inventory_findings rows where both ARN and short-form exist
for the same resource (keeps the ARN version).
"""
from alembic import op
from sqlalchemy import text

revision = "0005_normalize_uid_arn"
down_revision = "0004_inventory_rls"
branch_labels = None
depends_on = None

# EC2 resource-id prefix → ARN resource-type mapping
# Ordered: longer prefixes first so tgw-rtb- matches before tgw-
_EC2_PREFIX_MAP = [
    ("tgw-rtb-", "transit-gateway-route-table"),
    ("tgw-attach-", "transit-gateway-attachment"),
    ("eipalloc-", "elastic-ip"),
    ("eigw-", "egress-only-internet-gateway"),
    ("dopt-", "dhcp-options"),
    ("snap-", "snapshot"),
    ("subnet-", "subnet"),
    ("vpce-", "vpc-endpoint"),
    ("sg-", "security-group"),
    ("igw-", "internet-gateway"),
    ("vpc-", "vpc"),
    ("vol-", "volume"),
    ("lt-", "launch-template"),
    ("eni-", "network-interface"),
    ("acl-", "network-acl"),
    ("rtb-", "route-table"),
    ("nat-", "natgateway"),
    ("pcx-", "vpc-peering-connection"),
    ("i-", "instance"),
    ("ami-", "image"),
    ("tgw-", "transit-gateway"),
    ("r-", "vpc-block-public-access-exclusion"),
    ("cgw-", "customer-gateway"),
    ("vgw-", "vpn-gateway"),
    ("fl-", "flow-log"),
    ("pl-", "prefix-list"),
    ("asg-", "auto-scaling-group"),
]


def _build_ec2_cases(col: str = "resource_uid") -> str:
    """Build SQL CASE WHEN clauses for EC2 prefix → ARN conversion."""
    cases = []
    for prefix, arn_type in _EC2_PREFIX_MAP:
        # Escape hyphens for PostgreSQL regex
        escaped = prefix.replace("-", "\\-")
        cases.append(
            f"WHEN {col} ~ '^ec2:[^:]+:[^:]+:{escaped}' THEN "
            f"'arn:aws:ec2:' || split_part({col}, ':', 2) || ':' || "
            f"split_part({col}, ':', 3) || ':{arn_type}/' || "
            f"split_part({col}, ':', 4)"
        )
    return "\n            ".join(cases)


def upgrade():
    conn = op.get_bind()

    # ── Step 1: EC2 resources in inventory_findings ───────────────────────
    cases = _build_ec2_cases()
    conn.execute(text(f"""
        UPDATE inventory_findings
        SET resource_uid = CASE
            {cases}
            ELSE resource_uid
        END
        WHERE resource_uid !~ '^arn:'
          AND resource_uid ~ '^ec2:[^:]+:[^:]+:.+'
    """))

    # ── Step 2: IAM resources (need resource_type to pick sub-type) ──────
    iam_map = {
        "iam.user": "user", "iam.role": "role", "iam.group": "group",
        "iam.policy": "policy", "iam.instance-profile": "instance-profile",
        "iam.instance_profile": "instance-profile",
        "iam.saml-provider": "saml-provider", "iam.oidc-provider": "oidc-provider",
        "iam.server-certificate": "server-certificate",
    }
    for res_type, arn_type in iam_map.items():
        conn.execute(text(
            "UPDATE inventory_findings "
            "SET resource_uid = 'arn:aws:iam::' || split_part(resource_uid, ':', 3) || "
            f"':{arn_type}/' || split_part(resource_uid, ':', 4) "
            "WHERE resource_uid !~ '^arn:' "
            "  AND resource_uid ~ '^iam:[^:]+:[^:]+:.+' "
            f"  AND resource_type = '{res_type}'"
        ))

    # ── Step 3: S3 resources ─────────────────────────────────────────────
    conn.execute(text("""
        UPDATE inventory_findings
        SET resource_uid = 'arn:aws:s3:::' || split_part(resource_uid, ':', 4)
        WHERE resource_uid !~ '^arn:'
          AND resource_uid ~ '^s3:[^:]+:[^:]+:.+'
    """))

    # ── Step 4: Generic fallback using resource_type hint ────────────────
    # e.g. resource_type='ec2.group' → 'group', resource_type='lambda.function' → 'function'
    conn.execute(text("""
        UPDATE inventory_findings
        SET resource_uid = 'arn:aws:' ||
            split_part(resource_uid, ':', 1) || ':' ||
            split_part(resource_uid, ':', 2) || ':' ||
            split_part(resource_uid, ':', 3) || ':' ||
            REPLACE(
                SUBSTRING(resource_type FROM POSITION('.' IN resource_type) + 1),
                '_', '-'
            ) || '/' ||
            split_part(resource_uid, ':', 4)
        WHERE resource_uid !~ '^arn:'
          AND resource_uid ~ '^[a-z0-9]+:[^:]+:[^:]+:.+'
          AND resource_type LIKE '%.%'
    """))

    # ── Step 5: Deduplicate (keep latest updated_at) ─────────────────────
    conn.execute(text("""
        DELETE FROM inventory_findings a
        USING inventory_findings b
        WHERE a.resource_uid = b.resource_uid
          AND a.tenant_id = b.tenant_id
          AND a.asset_id != b.asset_id
          AND a.updated_at < b.updated_at
    """))

    # ── Step 6: Normalize inventory_relationships ────────────────────────
    for col in ("from_uid", "to_uid"):
        cases = _build_ec2_cases(col)
        conn.execute(text(f"""
            UPDATE inventory_relationships
            SET {col} = CASE
                {cases}
                ELSE {col}
            END
            WHERE {col} !~ '^arn:'
              AND {col} ~ '^[a-z0-9]+:[^:]+:[^:]+:.+'
        """))

    # ── Step 7: Normalize history and drift tables ───────────────────────
    for tbl in ("inventory_asset_history", "inventory_drift"):
        cases = _build_ec2_cases()
        try:
            conn.execute(text(f"""
                UPDATE {tbl}
                SET resource_uid = CASE
                    {cases}
                    ELSE resource_uid
                END
                WHERE resource_uid !~ '^arn:'
                  AND resource_uid ~ '^[a-z0-9]+:[^:]+:[^:]+:.+'
            """))
        except Exception:
            pass  # Table may not exist yet


def downgrade():
    # One-way migration — can't distinguish original format.
    pass
