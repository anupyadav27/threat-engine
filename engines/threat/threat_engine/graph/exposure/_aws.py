"""
AWS-specific internet exposure detection.

Queries the `discovery_findings` PostgreSQL table for authoritative AWS-specific
exposure signals that the check engine may not fully cover (because check rules
fire on SG-rule ARNs rather than instance ARNs).

Services covered:
  EC2 instances with PublicIpAddress
  Security-Group-based traversal → compute behind exposed SGs
  API Gateway (REST + HTTP) — always public by default
  Lambda functions — trigger-accessible
  ELBv2 internet-facing load balancers
  RDS / Aurora with PubliclyAccessible = true
  OpenSearch / Elasticsearch without VPC config
  Redshift clusters with PubliclyAccessible = true
  EKS clusters with EndpointPublicAccess = true
  Cognito identity pools with unauthenticated access
  CloudFront distributions — always internet-facing
"""

from __future__ import annotations

import logging
from typing import Any, Callable, List, Set

from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)


def _merge_exposes(session: Any, uids: List[str], reason: str) -> int:
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


def _disc_conn(pg_conn_fn: Callable):
    """Open a connection to the discoveries DB."""
    return pg_conn_fn("threat_engine_discoveries")


def detect(
    session: Any,
    tenant_id: str,
    pg_conn_fn: Callable,
    exposed_uids: Set[str],
) -> int:
    """AWS-specific exposure detection. Returns count of new EXPOSES edges."""
    count = 0
    count += _ec2_public_ip(session, pg_conn_fn, exposed_uids)
    count += _sg_based_traversal(session, tenant_id, exposed_uids)
    count += _api_gateway(session, tenant_id, exposed_uids)
    count += _lambda_functions(session, tenant_id, exposed_uids)
    count += _elbv2_internet_facing(session, pg_conn_fn, exposed_uids)
    count += _rds_public(session, pg_conn_fn, exposed_uids)
    count += _opensearch_public(session, pg_conn_fn, exposed_uids)
    count += _redshift_public(session, pg_conn_fn, exposed_uids)
    count += _eks_public_api(session, pg_conn_fn, tenant_id, exposed_uids)
    count += _cognito_unauthenticated(session, tenant_id, exposed_uids)
    count += _cloudfront(session, tenant_id, exposed_uids)
    return count


# ── EC2: public IP from discovery_findings ────────────────────────────────────
# The check engine fires "exposed_to_internet" on security-group-rule ARNs,
# not instance ARNs. Pull PublicIpAddress directly from discovery.
def _ec2_public_ip(
    session: Any,
    pg_conn_fn: Callable,
    exposed_uids: Set[str],
) -> int:
    try:
        conn = _disc_conn(pg_conn_fn)
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT DISTINCT
                        emitted_fields->>'InstanceId' AS instance_id,
                        account_id, region
                    FROM discovery_findings
                    WHERE discovery_id = 'aws.ec2.describe_instances'
                      AND emitted_fields->>'PublicIpAddress' IS NOT NULL
                      AND emitted_fields->>'PublicIpAddress' NOT IN ('', 'None', 'null')
                """)
                rows = cur.fetchall()
        finally:
            conn.close()

        new_uids = []
        for row in rows:
            iid = row.get("instance_id")
            if not iid:
                continue
            uid = f"arn:aws:ec2:{row['region']}:{row['account_id']}:instance/{iid}"
            if uid not in exposed_uids:
                exposed_uids.add(uid)
                new_uids.append(uid)

        n = _merge_exposes(session, new_uids, "ec2_public_ip_from_discovery")
        if new_uids:
            logger.info(f"aws: EC2 public-IP: {len(new_uids)} instances → {n} edges")
        return n
    except Exception as exc:
        logger.warning(f"aws: EC2 public-IP detection failed: {exc}")
        return 0


# ── SG-based traversal: compute behind exposed security groups ────────────────
def _sg_based_traversal(
    session: Any,
    tenant_id: str,
    exposed_uids: Set[str],
) -> int:
    try:
        # Step 1: SG-rule ARNs with check findings indicating 0.0.0.0/0 exposure
        result = session.run("""
            MATCH (r:Resource {tenant_id: $tid})-[:HAS_FINDING]->(f:Finding)
            WHERE r.resource_type = 'ec2.security-group-rule'
              AND (f.rule_id CONTAINS 'exposed_to_internet'
                OR f.rule_id CONTAINS 'unrestricted'
                OR f.rule_id CONTAINS '0_0_0_0')
            RETURN DISTINCT r.uid AS sg_rule_uid
        """, tid=tenant_id)
        sg_rule_uids = [rec["sg_rule_uid"] for rec in result if rec.get("sg_rule_uid")]
        if not sg_rule_uids:
            return 0

        # Step 2: Parent SG nodes that CONTAIN these rules
        result2 = session.run("""
            MATCH (sg:Resource)-[:CONTAINS]->(rule:Resource)
            WHERE rule.uid IN $sg_rule_uids
              AND sg.resource_type = 'ec2.security-group'
            RETURN DISTINCT sg.uid AS sg_uid
        """, sg_rule_uids=sg_rule_uids[:500])
        sg_uids = [rec["sg_uid"] for rec in result2 if rec.get("sg_uid")]
        if not sg_uids:
            return 0

        # Step 3: Compute resources PROTECTED_BY these SGs
        result3 = session.run("""
            MATCH (compute:Resource)-[:PROTECTED_BY]->(sg:Resource)
            WHERE sg.uid IN $sg_uids
              AND compute.tenant_id = $tid
              AND NOT compute.resource_type IN [
                'ec2.security-group', 'ec2.security-group-rule',
                'ec2.network-acl', 'ec2.subnet'
              ]
            RETURN DISTINCT compute.uid AS uid
        """, sg_uids=sg_uids[:500], tid=tenant_id)

        new_uids = []
        for rec in result3:
            uid = rec.get("uid")
            if uid and uid not in exposed_uids:
                exposed_uids.add(uid)
                new_uids.append(uid)

        n = _merge_exposes(session, new_uids, "sg_rule_open_to_internet")
        if new_uids:
            logger.info(f"aws: SG-based traversal: {len(new_uids)} compute resources → {n} edges")
        return n
    except Exception as exc:
        logger.warning(f"aws: SG-based traversal failed: {exc}")
        return 0


# ── API Gateway: REST and HTTP APIs are internet-accessible by default ─────────
def _api_gateway(
    session: Any,
    tenant_id: str,
    exposed_uids: Set[str],
) -> int:
    try:
        result = session.run("""
            MATCH (r:Resource {tenant_id: $tid})
            WHERE r.resource_type IN [
                'apigateway.item_rest_api', 'apigateway.resource',
                'apigatewayv2.api', 'apigatewayv2.item_api'
            ]
            RETURN r.uid AS uid, r.region AS region, r.account_id AS account_id
        """, tid=tenant_id)

        new_uids = []
        for rec in result:
            uid = rec.get("uid")
            if uid and uid not in exposed_uids:
                exposed_uids.add(uid)
                new_uids.append(uid)

        n = _merge_exposes(session, new_uids, "api_gateway_public")

        # API GW → Lambda INVOKES edges (path continues into Lambda)
        session.run("""
            MATCH (apigw:Resource {tenant_id: $tid})
            WHERE apigw.resource_type IN [
                'apigateway.item_rest_api', 'apigatewayv2.api'
            ]
            MATCH (fn:LambdaFunction {tenant_id: $tid,
                                      account_id: apigw.account_id,
                                      region: apigw.region})
            MERGE (apigw)-[e:INVOKES]->(fn)
            SET e.attack_path_category = 'lateral_movement'
        """, tid=tenant_id)

        if new_uids:
            logger.info(f"aws: API Gateway: {len(new_uids)} APIs → {n} edges")
        return n
    except Exception as exc:
        logger.warning(f"aws: API Gateway exposure failed: {exc}")
        return 0


# ── Lambda: all functions are potentially trigger-accessible ──────────────────
def _lambda_functions(
    session: Any,
    tenant_id: str,
    exposed_uids: Set[str],
) -> int:
    try:
        result = session.run("""
            MATCH (r:LambdaFunction {tenant_id: $tid})
            WHERE NOT EXISTS { MATCH (:Internet)-[:EXPOSES]->(r) }
            RETURN r.uid AS uid
        """, tid=tenant_id)
        new_uids = [rec["uid"] for rec in result
                    if rec.get("uid") and rec["uid"] not in exposed_uids]
        for uid in new_uids:
            exposed_uids.add(uid)

        n = _merge_exposes(session, new_uids, "lambda_trigger_accessible")
        if new_uids:
            logger.info(f"aws: Lambda: {len(new_uids)} functions → {n} edges")
        return n
    except Exception as exc:
        logger.warning(f"aws: Lambda exposure failed: {exc}")
        return 0


# ── ELBv2: internet-facing load balancers from discovery ─────────────────────
def _elbv2_internet_facing(
    session: Any,
    pg_conn_fn: Callable,
    exposed_uids: Set[str],
) -> int:
    try:
        conn = _disc_conn(pg_conn_fn)
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT DISTINCT
                        emitted_fields->>'LoadBalancerArn' AS lb_arn
                    FROM discovery_findings
                    WHERE discovery_id = 'aws.elbv2.describe_load_balancers'
                      AND emitted_fields->>'Scheme' = 'internet-facing'
                      AND emitted_fields->>'LoadBalancerArn' IS NOT NULL
                """)
                rows = cur.fetchall()
        finally:
            conn.close()

        new_uids = [row["lb_arn"] for row in rows
                    if row.get("lb_arn") and row["lb_arn"] not in exposed_uids]
        for uid in new_uids:
            exposed_uids.add(uid)

        n = _merge_exposes(session, new_uids, "elb_internet_facing")
        if new_uids:
            logger.info(f"aws: ELBv2: {len(new_uids)} LBs → {n} edges")
        return n
    except Exception as exc:
        logger.warning(f"aws: ELBv2 exposure failed: {exc}")
        return 0


# ── RDS: PubliclyAccessible = true ───────────────────────────────────────────
def _rds_public(
    session: Any,
    pg_conn_fn: Callable,
    exposed_uids: Set[str],
) -> int:
    try:
        conn = _disc_conn(pg_conn_fn)
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT DISTINCT
                        COALESCE(
                            emitted_fields->>'DBInstanceArn',
                            emitted_fields->>'DBClusterArn'
                        ) AS arn
                    FROM discovery_findings
                    WHERE discovery_id IN (
                        'aws.rds.describe_db_instances',
                        'aws.rds.describe_db_clusters'
                    )
                      AND lower(emitted_fields->>'PubliclyAccessible') = 'true'
                      AND COALESCE(
                          emitted_fields->>'DBInstanceArn',
                          emitted_fields->>'DBClusterArn'
                      ) IS NOT NULL
                """)
                rows = cur.fetchall()
        finally:
            conn.close()

        new_uids = [row["arn"] for row in rows
                    if row.get("arn") and row["arn"] not in exposed_uids]
        for uid in new_uids:
            exposed_uids.add(uid)

        n = _merge_exposes(session, new_uids, "rds_publicly_accessible")
        if new_uids:
            logger.info(f"aws: RDS public: {len(new_uids)} instances/clusters → {n} edges")
        return n
    except Exception as exc:
        logger.warning(f"aws: RDS public exposure failed: {exc}")
        return 0


# ── OpenSearch / Elasticsearch: no VPC config = public ───────────────────────
def _opensearch_public(
    session: Any,
    pg_conn_fn: Callable,
    exposed_uids: Set[str],
) -> int:
    try:
        conn = _disc_conn(pg_conn_fn)
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT DISTINCT
                        COALESCE(
                            emitted_fields->>'DomainArn',
                            emitted_fields->>'ARN'
                        ) AS arn
                    FROM discovery_findings
                    WHERE discovery_id IN (
                        'aws.opensearch.describe_domains',
                        'aws.elasticsearch.describe_domains',
                        'aws.es.describe_elasticsearch_domains'
                    )
                      AND (
                        emitted_fields->'VPCOptions' IS NULL
                        OR emitted_fields->>'VPCOptions' IN ('null', '{}', '')
                        OR emitted_fields->'AccessPolicies' IS NULL
                        OR emitted_fields->>'AccessPolicies' = ''
                      )
                      AND COALESCE(
                          emitted_fields->>'DomainArn',
                          emitted_fields->>'ARN'
                      ) IS NOT NULL
                """)
                rows = cur.fetchall()
        finally:
            conn.close()

        new_uids = [row["arn"] for row in rows
                    if row.get("arn") and row["arn"] not in exposed_uids]
        for uid in new_uids:
            exposed_uids.add(uid)

        n = _merge_exposes(session, new_uids, "opensearch_public_endpoint")
        if new_uids:
            logger.info(f"aws: OpenSearch public: {len(new_uids)} domains → {n} edges")
        return n
    except Exception as exc:
        logger.warning(f"aws: OpenSearch public exposure failed: {exc}")
        return 0


# ── Redshift: PubliclyAccessible = true ──────────────────────────────────────
def _redshift_public(
    session: Any,
    pg_conn_fn: Callable,
    exposed_uids: Set[str],
) -> int:
    try:
        conn = _disc_conn(pg_conn_fn)
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT DISTINCT
                        emitted_fields->>'ClusterNamespaceArn' AS arn
                    FROM discovery_findings
                    WHERE discovery_id = 'aws.redshift.describe_clusters'
                      AND lower(emitted_fields->>'PubliclyAccessible') = 'true'
                      AND emitted_fields->>'ClusterNamespaceArn' IS NOT NULL
                """)
                rows = cur.fetchall()
        finally:
            conn.close()

        new_uids = [row["arn"] for row in rows
                    if row.get("arn") and row["arn"] not in exposed_uids]
        for uid in new_uids:
            exposed_uids.add(uid)

        n = _merge_exposes(session, new_uids, "redshift_publicly_accessible")
        if new_uids:
            logger.info(f"aws: Redshift public: {len(new_uids)} clusters → {n} edges")
        return n
    except Exception as exc:
        logger.warning(f"aws: Redshift public exposure failed: {exc}")
        return 0


# ── EKS: EndpointPublicAccess = true ─────────────────────────────────────────
def _eks_public_api(
    session: Any,
    pg_conn_fn: Callable,
    tenant_id: str,
    exposed_uids: Set[str],
) -> int:
    try:
        conn = _disc_conn(pg_conn_fn)
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT DISTINCT
                        emitted_fields->>'ClusterArn' AS arn
                    FROM discovery_findings
                    WHERE discovery_id = 'aws.eks.describe_clusters'
                      AND lower(
                        emitted_fields->'ResourcesVpcConfig'->>'EndpointPublicAccess'
                      ) = 'true'
                      AND emitted_fields->>'ClusterArn' IS NOT NULL
                """)
                rows = cur.fetchall()
        finally:
            conn.close()

        new_uids = [row["arn"] for row in rows
                    if row.get("arn") and row["arn"] not in exposed_uids]
        for uid in new_uids:
            exposed_uids.add(uid)

        n = _merge_exposes(session, new_uids, "eks_public_api_endpoint")

        # EKS → K8s ServiceAccount: privilege escalation into cluster
        try:
            session.run("""
                MATCH (eks:EKSCluster {tenant_id: $tid})
                MATCH (sa:K8sServiceAccount {tenant_id: $tid, account_id: eks.account_id})
                MERGE (eks)-[e:CONTAINS]->(sa)
                SET e.attack_path_category = 'privilege_escalation',
                    e.reason = 'eks_pod_service_account'
            """, tid=tenant_id)
        except Exception:
            pass

        if new_uids:
            logger.info(f"aws: EKS public API: {len(new_uids)} clusters → {n} edges")
        return n
    except Exception as exc:
        logger.warning(f"aws: EKS public API exposure failed: {exc}")
        return 0


# ── Cognito: identity pools with unauthenticated access (T1621) ──────────────
def _cognito_unauthenticated(
    session: Any,
    tenant_id: str,
    exposed_uids: Set[str],
) -> int:
    try:
        result = session.run("""
            MATCH (r:Resource {tenant_id: $tid})-[:HAS_FINDING]->(f:Finding)
            WHERE r.resource_type IN ['cognito.identity-pool', 'cognito.resource']
              AND (f.rule_id CONTAINS 'unauthenticated'
                OR f.rule_id CONTAINS 'allow_unauthenticated'
                OR f.rule_id CONTAINS 'unauth_role')
            RETURN DISTINCT r.uid AS uid
        """, tid=tenant_id)
        new_uids = [rec["uid"] for rec in result
                    if rec.get("uid") and rec["uid"] not in exposed_uids]
        for uid in new_uids:
            exposed_uids.add(uid)

        n = _merge_exposes(session, new_uids, "cognito_unauthenticated_access")
        if new_uids:
            logger.info(f"aws: Cognito unauthenticated: {len(new_uids)} pools → {n} edges")
        return n
    except Exception as exc:
        logger.warning(f"aws: Cognito exposure failed: {exc}")
        return 0


# ── CloudFront: always internet-facing ────────────────────────────────────────
def _cloudfront(
    session: Any,
    tenant_id: str,
    exposed_uids: Set[str],
) -> int:
    try:
        result = session.run("""
            MATCH (r:CloudFrontDistribution {tenant_id: $tid})
            WHERE NOT EXISTS { MATCH (:Internet)-[:EXPOSES]->(r) }
            RETURN r.uid AS uid
        """, tid=tenant_id)
        new_uids = [rec["uid"] for rec in result
                    if rec.get("uid") and rec["uid"] not in exposed_uids]
        for uid in new_uids:
            exposed_uids.add(uid)

        n = _merge_exposes(session, new_uids, "cloudfront_internet_facing")
        if new_uids:
            logger.info(f"aws: CloudFront: {len(new_uids)} distributions → {n} edges")
        return n
    except Exception as exc:
        logger.warning(f"aws: CloudFront exposure failed: {exc}")
        return 0
