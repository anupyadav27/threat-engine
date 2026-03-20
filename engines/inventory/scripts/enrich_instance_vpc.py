#!/usr/bin/env python3
"""
Enrich EC2 Instance VPC/Subnet Data
=====================================
Backfills VpcId and SubnetId into inventory_findings for EC2 instances
that were discovered via describe_instance_status (which lacks networking info).

This script:
1. Reads EC2 instances from inventory_findings that lack VpcId
2. Calls AWS DescribeInstances to get VpcId/SubnetId per instance
3. Updates the properties JSONB column with the networking fields
4. After running, execute apply_relationship_rules.py to create containment edges

Usage:
    export INVENTORY_DB_URL="postgresql://user:pass@host:5432/threat_engine_inventory"
    python enrich_instance_vpc.py --tenant-id <tid> [--region ap-south-1] [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional

import boto3
import psycopg2
import psycopg2.extras

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger(__name__)


def _connect(dsn: Optional[str] = None):
    dsn = dsn or os.getenv("INVENTORY_DB_URL")
    if not dsn:
        sys.exit("Set INVENTORY_DB_URL or pass --dsn")
    return psycopg2.connect(dsn)


def _get_instances_missing_vpc(
    conn, tenant_id: str, region: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Find EC2 instances in inventory_findings that lack VpcId in emitted_fields."""
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        region_filter = ""
        params = [tenant_id]
        if region:
            region_filter = "AND region = %s"
            params.append(region)

        cur.execute(f"""
            SELECT resource_uid, resource_id, region, account_id,
                   properties
            FROM inventory_findings
            WHERE tenant_id = %s
              AND resource_type = 'ec2.instance'
              AND provider = 'aws'
              {region_filter}
              AND (
                  properties->'emitted_fields'->>'VpcId' IS NULL
                  OR properties->'emitted_fields'->>'VpcId' = ''
              )
            ORDER BY region, resource_uid
        """, params)
        return [dict(r) for r in cur.fetchall()]


def _fetch_vpc_data_from_aws(
    instances: List[Dict[str, Any]],
) -> Dict[str, Dict[str, str]]:
    """Call AWS DescribeInstances to get VpcId/SubnetId for each instance.

    Returns:
        Dict mapping instance_id -> {VpcId, SubnetId, ...}
    """
    # Group by region
    by_region: Dict[str, List[str]] = {}
    uid_to_instance_id: Dict[str, str] = {}

    for inst in instances:
        region = inst["region"]
        # Extract real instance ID from emitted_fields or resource_id
        props = inst.get("properties") or {}
        if isinstance(props, str):
            props = json.loads(props)
        ef = props.get("emitted_fields") or {}
        instance_id = ef.get("InstanceId") or inst["resource_id"]

        # Skip non-instance-id values (e.g., AvailabilityZoneIds like aps1-az1)
        if not instance_id.startswith("i-"):
            log.warning("Skipping non-instance resource_id: %s (uid=%s)",
                        instance_id, inst["resource_uid"])
            continue

        by_region.setdefault(region, []).append(instance_id)
        uid_to_instance_id[inst["resource_uid"]] = instance_id

    result: Dict[str, Dict[str, str]] = {}

    for region, instance_ids in by_region.items():
        log.info("Fetching %d instances from %s", len(instance_ids), region)
        ec2 = boto3.client("ec2", region_name=region)

        # Batch in groups of 100 (AWS limit is 1000)
        for i in range(0, len(instance_ids), 100):
            batch = instance_ids[i:i + 100]
            try:
                resp = ec2.describe_instances(InstanceIds=batch)
                for reservation in resp.get("Reservations", []):
                    for inst in reservation.get("Instances", []):
                        iid = inst["InstanceId"]
                        result[iid] = {
                            "VpcId": inst.get("VpcId"),
                            "SubnetId": inst.get("SubnetId"),
                            "PrivateIpAddress": inst.get("PrivateIpAddress"),
                            "PublicIpAddress": inst.get("PublicIpAddress"),
                            "InstanceType": inst.get("InstanceType"),
                            "SecurityGroups": inst.get("SecurityGroups"),
                            "Placement": inst.get("Placement"),
                            "IamInstanceProfile": inst.get("IamInstanceProfile"),
                            "ImageId": inst.get("ImageId"),
                            "Architecture": inst.get("Architecture"),
                            "Tags": inst.get("Tags"),
                        }
            except Exception as e:
                log.error("Failed to describe instances in %s: %s", region, e)

    return result


def _update_inventory_findings(
    conn,
    tenant_id: str,
    instances: List[Dict[str, Any]],
    vpc_data: Dict[str, Dict[str, str]],
    dry_run: bool = False,
) -> int:
    """Update properties.emitted_fields with VpcId/SubnetId for each instance."""
    updated = 0

    with conn.cursor() as cur:
        for inst in instances:
            props = inst.get("properties") or {}
            if isinstance(props, str):
                props = json.loads(props)
            ef = props.get("emitted_fields") or {}
            instance_id = ef.get("InstanceId") or inst["resource_id"]

            if instance_id not in vpc_data:
                continue

            aws_data = vpc_data[instance_id]
            vpc_id = aws_data.get("VpcId")
            subnet_id = aws_data.get("SubnetId")

            if not vpc_id:
                continue

            # Merge AWS networking data into emitted_fields
            ef.update(aws_data)
            props["emitted_fields"] = ef

            if dry_run:
                log.info("[DRY RUN] Would update %s: VpcId=%s SubnetId=%s",
                         inst["resource_uid"][:60], vpc_id, subnet_id)
            else:
                cur.execute("""
                    UPDATE inventory_findings
                    SET properties = %s
                    WHERE resource_uid = %s AND tenant_id = %s
                """, (json.dumps(props), inst["resource_uid"], tenant_id))

            updated += 1

    if not dry_run:
        conn.commit()

    return updated


def main():
    parser = argparse.ArgumentParser(description="Enrich EC2 instances with VPC/Subnet data")
    parser.add_argument("--tenant-id", required=True, help="Tenant ID")
    parser.add_argument("--region", help="Filter to specific AWS region")
    parser.add_argument("--dsn", help="Database connection string")
    parser.add_argument("--dry-run", action="store_true", help="Show changes without applying")
    args = parser.parse_args()

    conn = _connect(args.dsn)

    # Step 1: Find instances missing VpcId
    instances = _get_instances_missing_vpc(conn, args.tenant_id, args.region)
    log.info("Found %d instances missing VpcId", len(instances))

    if not instances:
        log.info("Nothing to do.")
        return

    # Step 2: Fetch VPC data from AWS
    vpc_data = _fetch_vpc_data_from_aws(instances)
    log.info("Got VPC data for %d instances from AWS", len(vpc_data))

    # Step 3: Update inventory_findings
    updated = _update_inventory_findings(
        conn, args.tenant_id, instances, vpc_data, args.dry_run
    )

    log.info(
        "%s %d instances with VPC/Subnet data",
        "Would update" if args.dry_run else "Updated",
        updated,
    )

    conn.close()

    if not args.dry_run and updated > 0:
        log.info(
            "Next step: run apply_relationship_rules.py to create containment edges:\n"
            "  python apply_relationship_rules.py --account <account_id> --provider aws"
        )


if __name__ == "__main__":
    main()
