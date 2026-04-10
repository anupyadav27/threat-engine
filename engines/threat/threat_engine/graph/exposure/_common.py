"""
CSP-agnostic internet exposure detection.

Uses data already loaded into the Neo4j graph:
  - Check findings with rule_id patterns known to indicate public exposure
  - Resource configuration JSON fields for public IPs / public endpoints
  - Storage bucket public-access findings

Works for ALL cloud providers (AWS, Azure, GCP, OCI, AliCloud, IBM).
These sections run first so every CSP gets baseline coverage even if no
CSP-specific discovery data is available.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Set

logger = logging.getLogger(__name__)

# rule_id substrings that universally signal internet exposure across all CSPs
_EXPOSURE_RULE_PATTERNS = [
    "exposed_to_internet",       # AWS SG port_*_exposed_to_internet
    "public_access",             # S3 / Azure Storage public access
    "publicly_accessible",       # RDS / Redshift publicly accessible
    "public_ip",                 # EC2 / GCE public IP assigned
    "unrestricted",              # unrestricted inbound/outbound
    "open_to_world",             # generic "open to world" pattern
    "0_0_0_0",                   # literal 0.0.0.0 in rule ID
    "internet_facing",           # ELB scheme=internet-facing
    "ingress_from_all",          # NSG / VPC FW inbound from all
    "restrict_public_access",    # bucket restrict-public-access check
    "public_access_restricted",  # API GW / App Service check
    "function_url",              # Lambda function URL enabled
    "scheme_internet",           # ALB/NLB internet-facing scheme
    "allow_all",                 # Azure / GCP "allow all" firewall rule
    "external_access",           # GCP / OCI external access enabled
    "public_endpoint",           # AKS / GKE / Azure SQL public endpoint
]


def _merge_exposes(session: Any, uids: list, reason: str) -> int:
    """Batch-create Internet -[:EXPOSES]-> Resource edges. Returns edge count."""
    count = 0
    for i in range(0, len(uids), 200):
        chunk = uids[i:i + 200]
        r = session.run("""
            UNWIND $uids AS uid
            MATCH (i:Internet {uid: 'INTERNET'})
            MATCH (r:Resource {uid: uid})
            MERGE (i)-[e:EXPOSES]->(r)
            SET e.reason = $reason
            RETURN COUNT(e) AS c
        """, uids=chunk, reason=reason)
        rec = r.single()
        count += rec["c"] if rec else 0
    return count


def detect(
    session: Any,
    tenant_id: str,
    pg_conn_fn: Callable,
    exposed_uids: Set[str],
) -> int:
    """CSP-agnostic exposure detection. Returns count of new EXPOSES edges."""
    count = 0

    # ── 1. Check findings with internet-exposure rule_id patterns ─────────────
    # The check engine evaluated rules like SG open ports, public access, public IP.
    # These finding nodes are already in the graph via HAS_FINDING edges.
    try:
        where_clauses = " OR ".join(
            f"f.rule_id CONTAINS '{p}'" for p in _EXPOSURE_RULE_PATTERNS
        )
        result = session.run(f"""
            MATCH (r:Resource {{tenant_id: $tid}})-[:HAS_FINDING]->(f:Finding)
            WHERE {where_clauses}
            RETURN DISTINCT r.uid AS uid, r.resource_type AS rtype,
                   collect(DISTINCT f.rule_id)[0..3] AS sample_rules
        """, tid=tenant_id)

        new_uids = []
        for record in result:
            uid = record["uid"]
            if uid and uid not in exposed_uids:
                exposed_uids.add(uid)
                new_uids.append(uid)
                session.run("""
                    MATCH (i:Internet {uid: 'INTERNET'})
                    MATCH (r:Resource {uid: $uid})
                    MERGE (i)-[e:EXPOSES]->(r)
                    SET e.reason = 'check_finding_exposure',
                        e.resource_type = $rtype
                """, uid=uid, rtype=record["rtype"] or "")
        count += len(new_uids)
        logger.debug(f"common: check_findings patterns matched {len(new_uids)} resources")
    except Exception as exc:
        logger.warning(f"common: check_findings exposure detection failed: {exc}")

    # ── 2. Public storage via findings (S3, Azure Blob, GCS, OCI Object Storage) ─
    try:
        result = session.run("""
            MATCH (r:Resource {tenant_id: $tid})-[:HAS_FINDING]->(f:Finding)
            WHERE (f.rule_id CONTAINS 'public' OR f.rule_id CONTAINS 'anonymous'
                   OR (f.title IS NOT NULL AND toLower(f.title) CONTAINS 'public'))
              AND (r.resource_type CONTAINS 's3'
                   OR r.resource_type CONTAINS 'storage'
                   OR r.resource_type CONTAINS 'bucket'
                   OR r.resource_type CONTAINS 'blob'
                   OR r.resource_type CONTAINS 'object_storage')
            RETURN DISTINCT r.uid AS uid
        """, tid=tenant_id)
        new_uids = [rec["uid"] for rec in result
                    if rec.get("uid") and rec["uid"] not in exposed_uids]
        for uid in new_uids:
            exposed_uids.add(uid)
        count += _merge_exposes(session, new_uids, "public_storage_finding")
    except Exception as exc:
        logger.warning(f"common: public storage exposure detection failed: {exc}")

    # ── 3. Public IP / public endpoint in resource configuration JSON ──────────
    # Covers resources where the inventory engine stored raw configuration
    # and the IP/endpoint field is non-null. Works for any CSP that stores
    # configuration JSON in the Resource node.
    try:
        result = session.run("""
            MATCH (r:Resource {tenant_id: $tid})
            WHERE r.configuration IS NOT NULL
              AND (
                r.configuration CONTAINS '"PublicIpAddress"'
                OR r.configuration CONTAINS '"public_ip"'
                OR r.configuration CONTAINS '"natIP"'
                OR r.configuration CONTAINS '"primaryPublicIPAddress"'
                OR r.configuration CONTAINS '"publicIpAddress"'
                OR r.configuration CONTAINS '"PubliclyAccessible": true'
                OR r.configuration CONTAINS '"PublicNetworkAccess": "Enabled"'
                OR r.configuration CONTAINS '"public_endpoint": true'
                OR r.configuration CONTAINS '"enabledForExternalUsers": true'
              )
              AND NOT (
                r.configuration CONTAINS '"PublicIpAddress": null'
                OR r.configuration CONTAINS '"PublicIpAddress": ""'
                OR r.configuration CONTAINS '"PublicIpAddress":"None"'
              )
            RETURN DISTINCT r.uid AS uid
        """, tid=tenant_id)
        new_uids = [rec["uid"] for rec in result
                    if rec.get("uid") and rec["uid"] not in exposed_uids]
        for uid in new_uids:
            exposed_uids.add(uid)
        count += _merge_exposes(session, new_uids, "public_ip_from_config")
        logger.debug(f"common: config JSON matched {len(new_uids)} resources")
    except Exception as exc:
        logger.warning(f"common: config-based exposure detection failed: {exc}")

    return count
