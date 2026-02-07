"""
Security Graph Builder — Populates Neo4j from PostgreSQL inventory + threat data.

Creates a Wiz-style security graph with:
  - Resource nodes  (S3Bucket, IAMRole, IAMPolicy, SecurityGroup, Lambda, etc.)
  - Threat nodes    (ThreatDetection overlaid on resources)
  - Finding nodes   (MisconfigFinding per rule violation)
  - Relationship edges (REFERENCES, RELATES_TO, HAS_THREAT, HAS_FINDING, etc.)
  - Virtual nodes   (Internet, Account, Region) for reachability analysis

Node labels map AWS resource types → graph-friendly labels:
  s3.resource       → S3Bucket
  iam.role          → IAMRole
  iam.policy        → IAMPolicy
  ec2.security-group → SecurityGroup
  lambda.resource   → LambdaFunction
  vpc.subnet        → Subnet
  iam.user          → IAMUser
  iam.group         → IAMGroup
  iam.instance-profile → InstanceProfile
"""

from __future__ import annotations

import logging
import os
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ── Resource type → Neo4j label mapping ──────────────────────────────────────
RESOURCE_TYPE_LABELS: Dict[str, str] = {
    "s3.resource": "S3Bucket",
    "s3": "S3Bucket",
    "iam.role": "IAMRole",
    "iam.policy": "IAMPolicy",
    "iam.user": "IAMUser",
    "iam.group": "IAMGroup",
    "iam.instance-profile": "InstanceProfile",
    "ec2.security-group": "SecurityGroup",
    "ec2.iam-instance-profile-association": "InstanceProfileAssociation",
    "lambda.resource": "LambdaFunction",
    "vpc.subnet": "Subnet",
}


def _neo4j_label(resource_type: str) -> str:
    """Map resource type to Neo4j node label."""
    return RESOURCE_TYPE_LABELS.get(resource_type, "CloudResource")


def _safe_props(d: Dict[str, Any], max_depth: int = 1) -> Dict[str, Any]:
    """Flatten a dict for Neo4j properties (Neo4j doesn't support nested maps)."""
    flat: Dict[str, Any] = {}
    for k, v in d.items():
        if v is None:
            continue
        if isinstance(v, (str, int, float, bool)):
            flat[k] = v
        elif isinstance(v, (list, tuple)):
            # Convert list to string if contains non-primitives
            if v and isinstance(v[0], dict):
                flat[k] = json.dumps(v)
            else:
                flat[k] = [str(x) for x in v]
        elif isinstance(v, dict) and max_depth > 0:
            for k2, v2 in v.items():
                if isinstance(v2, (str, int, float, bool)):
                    flat[f"{k}_{k2}"] = v2
        elif isinstance(v, datetime):
            flat[k] = v.isoformat()
        else:
            flat[k] = str(v)[:500]
    return flat


class SecurityGraphBuilder:
    """
    Builds and maintains the security graph in Neo4j.

    Usage:
        builder = SecurityGraphBuilder()
        stats = builder.build_graph(tenant_id="588989875114")
        print(stats)  # {"nodes_created": 350, "relationships_created": 850, ...}
    """

    def __init__(
        self,
        neo4j_uri: Optional[str] = None,
        neo4j_user: Optional[str] = None,
        neo4j_password: Optional[str] = None,
    ):
        self._uri = neo4j_uri or os.getenv("NEO4J_URI", "neo4j+s://17ec5cbb.databases.neo4j.io")
        self._user = neo4j_user or os.getenv("NEO4J_USER", "neo4j")
        self._password = neo4j_password or os.getenv("NEO4J_PASSWORD", "")
        self._driver = None

    def _get_driver(self):
        if self._driver is None:
            from neo4j import GraphDatabase
            self._driver = GraphDatabase.driver(
                self._uri, auth=(self._user, self._password)
            )
        return self._driver

    def close(self):
        if self._driver:
            self._driver.close()
            self._driver = None

    # ── PostgreSQL data loaders ──────────────────────────────────────────

    def _pg_conn(self, db_name: str):
        import psycopg2
        host = os.getenv("THREAT_DB_HOST", "localhost")
        port = os.getenv("THREAT_DB_PORT", "5432")
        user = os.getenv("THREAT_DB_USER", "postgres")
        pwd = os.getenv("THREAT_DB_PASSWORD", "")
        return psycopg2.connect(
            f"postgresql://{user}:{pwd}@{host}:{port}/{db_name}"
        )

    def _load_inventory_findings(self, tenant_id: str) -> List[Dict[str, Any]]:
        from psycopg2.extras import RealDictCursor
        conn = self._pg_conn("threat_engine_inventory")
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Match by tenant_id OR account_id (inventory may use different tenant naming)
                cur.execute("""
                    SELECT asset_id, resource_uid, provider, account_id, region,
                           resource_type, resource_id, name, properties,
                           configuration, compliance_status, risk_score,
                           criticality, tags, labels
                    FROM inventory_findings
                    WHERE tenant_id = %s OR account_id = %s
                """, (tenant_id, tenant_id))
                return [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()

    def _load_inventory_relationships(self, tenant_id: str) -> List[Dict[str, Any]]:
        from psycopg2.extras import RealDictCursor
        conn = self._pg_conn("threat_engine_inventory")
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT from_uid, to_uid, relation_type,
                           source_resource_uid, target_resource_uid,
                           relationship_type, relationship_strength,
                           bidirectional, properties
                    FROM inventory_relationships
                    WHERE tenant_id = %s OR account_id = %s
                """, (tenant_id, tenant_id))
                return [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()

    def _load_threat_detections(self, tenant_id: str) -> List[Dict[str, Any]]:
        from psycopg2.extras import RealDictCursor
        conn = self._pg_conn("threat_engine_threat")
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT detection_id, scan_id, detection_type,
                           rule_id, rule_name, resource_arn, resource_id,
                           resource_type, account_id, region, provider,
                           severity, confidence, status, threat_category,
                           mitre_tactics, mitre_techniques
                    FROM threat_detections
                    WHERE tenant_id = %s
                """, (tenant_id,))
                return [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()

    def _load_check_findings(self, tenant_id: str) -> List[Dict[str, Any]]:
        from psycopg2.extras import RealDictCursor
        conn = self._pg_conn("threat_engine_check")
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT cf.id AS finding_id, cf.check_scan_id, cf.rule_id,
                           cf.resource_uid, cf.resource_type,
                           cf.status,
                           rm.severity, rm.title, rm.service, rm.domain,
                           rm.mitre_techniques, rm.mitre_tactics
                    FROM check_findings cf
                    LEFT JOIN rule_metadata rm ON cf.rule_id = rm.rule_id
                    WHERE cf.tenant_id = %s AND cf.status = 'FAIL'
                    LIMIT 5000
                """, (tenant_id,))
                return [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()

    def _load_threat_analyses(self, tenant_id: str) -> List[Dict[str, Any]]:
        from psycopg2.extras import RealDictCursor
        conn = self._pg_conn("threat_engine_threat")
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT a.analysis_id, a.detection_id, a.risk_score,
                           a.verdict, a.analysis_results, a.recommendations,
                           a.attack_chain
                    FROM threat_analysis a
                    WHERE a.tenant_id = %s
                """, (tenant_id,))
                return [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()

    # ── Neo4j graph writers ──────────────────────────────────────────────

    def _clear_graph(self, tenant_id: str):
        """Remove all nodes/rels for this tenant."""
        driver = self._get_driver()
        with driver.session() as session:
            session.run(
                "MATCH (n {tenant_id: $tid}) DETACH DELETE n",
                tid=tenant_id,
            )
            logger.info(f"Cleared existing graph for tenant {tenant_id}")

    def _create_constraints(self):
        """Create uniqueness constraints and indexes."""
        driver = self._get_driver()
        constraints = [
            "CREATE CONSTRAINT IF NOT EXISTS FOR (r:Resource) REQUIRE r.uid IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (t:ThreatDetection) REQUIRE t.detection_id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (f:Finding) REQUIRE f.finding_id IS UNIQUE",
            "CREATE INDEX IF NOT EXISTS FOR (r:Resource) ON (r.tenant_id)",
            "CREATE INDEX IF NOT EXISTS FOR (r:Resource) ON (r.account_id)",
            "CREATE INDEX IF NOT EXISTS FOR (r:Resource) ON (r.resource_type)",
            "CREATE INDEX IF NOT EXISTS FOR (t:ThreatDetection) ON (t.severity)",
            "CREATE INDEX IF NOT EXISTS FOR (t:ThreatDetection) ON (t.resource_arn)",
        ]
        with driver.session() as session:
            for c in constraints:
                try:
                    session.run(c)
                except Exception as e:
                    logger.debug(f"Constraint/index note: {e}")

    def _create_resource_nodes(
        self, session, findings: List[Dict[str, Any]], tenant_id: str
    ) -> int:
        """Create Resource nodes from inventory_findings."""
        count = 0
        # Batch in groups of 100
        batch_size = 100
        for i in range(0, len(findings), batch_size):
            batch = findings[i:i + batch_size]
            params = []
            for f in batch:
                label = _neo4j_label(f.get("resource_type", ""))
                props = {
                    "uid": f["resource_uid"],
                    "asset_id": str(f["asset_id"]),
                    "tenant_id": tenant_id,
                    "provider": f.get("provider", "aws"),
                    "account_id": f.get("account_id", ""),
                    "region": f.get("region", ""),
                    "resource_type": f.get("resource_type", ""),
                    "resource_id": f.get("resource_id", ""),
                    "name": f.get("name", ""),
                    "compliance_status": f.get("compliance_status", ""),
                    "risk_score": f.get("risk_score", 0),
                    "criticality": f.get("criticality", ""),
                    "label": label,
                }
                params.append(props)

            session.run("""
                UNWIND $batch AS p
                MERGE (r:Resource {uid: p.uid})
                SET r += p,
                    r:Resource
            """, batch=params)

            # Also add specific labels
            for f in batch:
                label = _neo4j_label(f.get("resource_type", ""))
                if label != "CloudResource":
                    try:
                        session.run(
                            f"MATCH (r:Resource {{uid: $uid}}) SET r:`{label}`",
                            uid=f["resource_uid"],
                        )
                    except Exception:
                        pass

            count += len(batch)

        return count

    def _create_virtual_nodes(self, session, tenant_id: str, accounts: Set[str], regions: Set[str]) -> int:
        """Create Internet, Account, and Region virtual nodes."""
        count = 0

        # Internet node
        session.run("""
            MERGE (i:Internet:VirtualNode {uid: 'INTERNET'})
            SET i.name = 'Internet', i.tenant_id = $tid, i.risk_score = 100
        """, tid=tenant_id)
        count += 1

        # Account nodes
        for acct in accounts:
            session.run("""
                MERGE (a:Account:VirtualNode {uid: $uid})
                SET a.name = $name, a.tenant_id = $tid, a.account_id = $acct
            """, uid=f"account:{acct}", name=f"AWS Account {acct}", tid=tenant_id, acct=acct)
            count += 1

        # Region nodes
        for region in regions:
            session.run("""
                MERGE (rg:Region:VirtualNode {uid: $uid})
                SET rg.name = $name, rg.tenant_id = $tid, rg.region = $region
            """, uid=f"region:{region}", name=region, tid=tenant_id, region=region)
            count += 1

        return count

    def _create_resource_relationships(
        self, session, relationships: List[Dict[str, Any]]
    ) -> int:
        """Create edges between resource nodes from inventory_relationships."""
        count = 0
        batch_size = 200

        for i in range(0, len(relationships), batch_size):
            batch = relationships[i:i + batch_size]
            params = []
            for rel in batch:
                src = rel.get("source_resource_uid") or rel.get("from_uid") or ""
                dst = rel.get("target_resource_uid") or rel.get("to_uid") or ""
                rel_type = (rel.get("relationship_type") or rel.get("relation_type") or "RELATED").upper().replace(" ", "_")

                if not src or not dst or src == dst:
                    continue

                params.append({
                    "src": src,
                    "dst": dst,
                    "rel_type": rel_type,
                    "strength": rel.get("relationship_strength", "strong"),
                    "bidirectional": rel.get("bidirectional", False),
                })

            if not params:
                continue

            # Create REFERENCES relationships
            refs = [p for p in params if p["rel_type"] == "REFERENCES"]
            if refs:
                session.run("""
                    UNWIND $batch AS p
                    MATCH (a:Resource {uid: p.src})
                    MATCH (b:Resource {uid: p.dst})
                    MERGE (a)-[r:REFERENCES]->(b)
                    SET r.strength = p.strength
                """, batch=refs)
                count += len(refs)

            # Create RELATED relationships
            related = [p for p in params if p["rel_type"] == "RELATED"]
            if related:
                session.run("""
                    UNWIND $batch AS p
                    MATCH (a:Resource {uid: p.src})
                    MATCH (b:Resource {uid: p.dst})
                    MERGE (a)-[r:RELATES_TO]->(b)
                    SET r.strength = p.strength
                """, batch=related)
                count += len(related)

            # Any other types
            other = [p for p in params if p["rel_type"] not in ("REFERENCES", "RELATED")]
            for p in other:
                try:
                    session.run(f"""
                        MATCH (a:Resource {{uid: $src}})
                        MATCH (b:Resource {{uid: $dst}})
                        MERGE (a)-[r:`{p['rel_type']}`]->(b)
                        SET r.strength = $strength
                    """, src=p["src"], dst=p["dst"], strength=p["strength"])
                    count += 1
                except Exception:
                    pass

            # Bidirectional edges
            bidir = [p for p in params if p.get("bidirectional")]
            for p in bidir:
                try:
                    session.run("""
                        MATCH (a:Resource {uid: $dst})
                        MATCH (b:Resource {uid: $src})
                        MERGE (a)-[r:RELATES_TO]->(b)
                        SET r.strength = $strength
                    """, src=p["src"], dst=p["dst"], strength=p["strength"])
                    count += 1
                except Exception:
                    pass

        return count

    def _create_hierarchy_edges(self, session, findings: List[Dict[str, Any]]) -> int:
        """Connect resources to Account and Region virtual nodes."""
        count = 0
        for f in findings:
            uid = f["resource_uid"]
            acct = f.get("account_id")
            region = f.get("region")

            if acct:
                session.run("""
                    MATCH (r:Resource {uid: $uid})
                    MATCH (a:Account {uid: $acct_uid})
                    MERGE (a)-[:CONTAINS]->(r)
                """, uid=uid, acct_uid=f"account:{acct}")
                count += 1

            if region:
                session.run("""
                    MATCH (r:Resource {uid: $uid})
                    MATCH (rg:Region {uid: $region_uid})
                    MERGE (rg)-[:HOSTS]->(r)
                """, uid=uid, region_uid=f"region:{region}")
                count += 1

        return count

    def _create_threat_nodes(
        self, session, detections: List[Dict[str, Any]], tenant_id: str
    ) -> int:
        """Create ThreatDetection nodes and link to Resource nodes."""
        count = 0
        for det in detections:
            det_id = str(det["detection_id"])
            resource_arn = det.get("resource_arn", "")
            mitre_techniques = det.get("mitre_techniques") or []
            mitre_tactics = det.get("mitre_tactics") or []

            props = {
                "detection_id": det_id,
                "tenant_id": tenant_id,
                "scan_id": det.get("scan_id", ""),
                "detection_type": det.get("detection_type", ""),
                "rule_id": det.get("rule_id", ""),
                "rule_name": det.get("rule_name", ""),
                "resource_arn": resource_arn,
                "resource_type": det.get("resource_type", ""),
                "severity": det.get("severity", ""),
                "confidence": det.get("confidence", ""),
                "status": det.get("status", ""),
                "threat_category": det.get("threat_category", ""),
                "mitre_techniques": mitre_techniques if isinstance(mitre_techniques, list) else [],
                "mitre_tactics": mitre_tactics if isinstance(mitre_tactics, list) else [],
            }

            session.run("""
                MERGE (t:ThreatDetection {detection_id: $props.detection_id})
                SET t += $props
            """, props=props)

            # Link to affected resource
            if resource_arn:
                session.run("""
                    MATCH (t:ThreatDetection {detection_id: $det_id})
                    MATCH (r:Resource)
                    WHERE r.uid STARTS WITH $arn
                    MERGE (r)-[:HAS_THREAT]->(t)
                """, det_id=det_id, arn=resource_arn)

            count += 1

        return count

    def _create_finding_nodes(
        self, session, findings: List[Dict[str, Any]], tenant_id: str
    ) -> int:
        """Create Finding nodes from check_findings and link to Resources."""
        count = 0
        batch_size = 200

        for i in range(0, len(findings), batch_size):
            batch = findings[i:i + batch_size]
            params = []
            for f in batch:
                mitre_techs = f.get("mitre_techniques") or []
                if mitre_techs and isinstance(mitre_techs, list):
                    if mitre_techs and isinstance(mitre_techs[0], dict):
                        mitre_techs = [t.get("technique_id", str(t)) for t in mitre_techs]

                props = {
                    "finding_id": str(f["finding_id"]),
                    "tenant_id": tenant_id,
                    "rule_id": f.get("rule_id", ""),
                    "resource_uid": f.get("resource_uid", ""),
                    "severity": f.get("severity", ""),
                    "status": f.get("status", ""),
                    "title": f.get("title", ""),
                    "service": f.get("service", ""),
                    "domain": f.get("domain", ""),
                    "mitre_techniques": mitre_techs,
                }
                params.append(props)

            session.run("""
                UNWIND $batch AS p
                MERGE (f:Finding {finding_id: p.finding_id})
                SET f += p
            """, batch=params)

            # Link findings to resources
            for f in batch:
                resource_uid = f.get("resource_uid", "")
                if resource_uid:
                    try:
                        session.run("""
                            MATCH (f:Finding {finding_id: $fid})
                            MATCH (r:Resource)
                            WHERE r.uid STARTS WITH $ruid
                            MERGE (r)-[:HAS_FINDING]->(f)
                        """, fid=str(f["finding_id"]), ruid=resource_uid)
                    except Exception:
                        pass

            count += len(batch)

        return count

    def _create_analysis_edges(
        self, session, analyses: List[Dict[str, Any]]
    ) -> int:
        """Link ThreatDetection nodes with analysis risk data."""
        count = 0
        for a in analyses:
            det_id = str(a["detection_id"])
            risk_score = a.get("risk_score", 0)
            verdict = a.get("verdict", "")
            blast = a.get("analysis_results", {}).get("blast_radius", {})
            reachable_count = blast.get("reachable_count", 0)

            session.run("""
                MATCH (t:ThreatDetection {detection_id: $det_id})
                SET t.risk_score = $risk,
                    t.verdict = $verdict,
                    t.blast_radius = $blast,
                    t.analyzed = true
            """, det_id=det_id, risk=risk_score, verdict=verdict, blast=reachable_count)

            # Create ATTACK_PATH edges based on attack chain
            chain = a.get("attack_chain") or []
            for step in chain[1:]:  # Skip first step (initial compromise)
                hop_from = step.get("hop_from", "")
                hop_to = step.get("resource", "")
                if hop_from and hop_to:
                    try:
                        session.run("""
                            MATCH (a:Resource) WHERE a.uid STARTS WITH $from
                            MATCH (b:Resource) WHERE b.uid STARTS WITH $to
                            MERGE (a)-[r:ATTACK_PATH]->(b)
                            SET r.detection_id = $det_id,
                                r.step = $step,
                                r.action = $action
                        """, **{"from": hop_from, "to": hop_to},
                            det_id=det_id,
                            step=step.get("step", 0),
                            action=step.get("action", ""),
                        )
                        count += 1
                    except Exception:
                        pass

            count += 1

        return count

    def _infer_internet_exposure(self, session, tenant_id: str) -> int:
        """
        Infer internet exposure from Security Group rules and public resources.

        Connects Internet node → SecurityGroup → Resource for publicly exposed assets.
        """
        count = 0

        # SGs with 0.0.0.0/0 in configuration
        result = session.run("""
            MATCH (sg:SecurityGroup {tenant_id: $tid})
            WHERE sg.configuration IS NOT NULL
              AND sg.configuration CONTAINS '0.0.0.0/0'
            RETURN sg.uid as uid
        """, tid=tenant_id)

        for record in result:
            sg_uid = record["uid"]
            session.run("""
                MATCH (i:Internet {uid: 'INTERNET'})
                MATCH (sg:Resource {uid: $uid})
                MERGE (i)-[r:EXPOSES]->(sg)
                SET r.reason = 'inbound_0.0.0.0/0'
            """, uid=sg_uid)
            count += 1

        # Public S3 buckets (infer from findings with public access rules)
        result = session.run("""
            MATCH (r:S3Bucket {tenant_id: $tid})-[:HAS_FINDING]->(f:Finding)
            WHERE f.rule_id CONTAINS 'public' OR f.title CONTAINS 'public'
            RETURN DISTINCT r.uid as uid
        """, tid=tenant_id)

        for record in result:
            session.run("""
                MATCH (i:Internet {uid: 'INTERNET'})
                MATCH (r:Resource {uid: $uid})
                MERGE (i)-[e:EXPOSES]->(r)
                SET e.reason = 'public_access_finding'
            """, uid=record["uid"])
            count += 1

        logger.info(f"Inferred {count} internet exposure edges")
        return count

    # ── Main orchestrator ────────────────────────────────────────────────

    def build_graph(self, tenant_id: str) -> Dict[str, Any]:
        """
        Build complete security graph for a tenant.

        Loads data from all 3 PostgreSQL databases and creates the Neo4j graph.
        """
        logger.info(f"Building security graph for tenant {tenant_id}")
        stats: Dict[str, int] = {}

        # 1. Create constraints/indexes
        self._create_constraints()

        # 2. Clear existing graph for this tenant
        self._clear_graph(tenant_id)

        # 3. Load all PostgreSQL data
        logger.info("Loading inventory findings...")
        inv_findings = self._load_inventory_findings(tenant_id)
        logger.info(f"  → {len(inv_findings)} inventory resources")

        logger.info("Loading inventory relationships...")
        inv_rels = self._load_inventory_relationships(tenant_id)
        logger.info(f"  → {len(inv_rels)} relationships")

        logger.info("Loading threat detections...")
        detections = self._load_threat_detections(tenant_id)
        logger.info(f"  → {len(detections)} threat detections")

        logger.info("Loading check findings (FAIL only)...")
        check_findings = self._load_check_findings(tenant_id)
        logger.info(f"  → {len(check_findings)} failed check findings")

        logger.info("Loading threat analyses...")
        analyses = self._load_threat_analyses(tenant_id)
        logger.info(f"  → {len(analyses)} analyses")

        # 4. Build graph
        driver = self._get_driver()
        with driver.session() as session:
            # 4a. Virtual nodes (Internet, Accounts, Regions)
            accounts = set(f.get("account_id", "") for f in inv_findings if f.get("account_id"))
            regions = set(f.get("region", "") for f in inv_findings if f.get("region"))
            stats["virtual_nodes"] = self._create_virtual_nodes(session, tenant_id, accounts, regions)
            logger.info(f"  → {stats['virtual_nodes']} virtual nodes")

            # 4b. Resource nodes from inventory
            stats["resource_nodes"] = self._create_resource_nodes(session, inv_findings, tenant_id)
            logger.info(f"  → {stats['resource_nodes']} resource nodes")

            # 4c. Also create Resource nodes for any ARN referenced in threats
            # but not in inventory (so we don't lose threat→resource links)
            existing_uids = set(f["resource_uid"] for f in inv_findings)
            missing_resources = []
            for det in detections:
                arn = det.get("resource_arn", "")
                if arn and arn not in existing_uids:
                    existing_uids.add(arn)
                    missing_resources.append({
                        "asset_id": str(det["detection_id"]),
                        "resource_uid": arn,
                        "provider": det.get("provider", "aws"),
                        "account_id": det.get("account_id", ""),
                        "region": det.get("region", ""),
                        "resource_type": det.get("resource_type", ""),
                        "resource_id": det.get("resource_id", ""),
                        "name": arn.split(":::")[-1] if ":::" in arn else arn.split("/")[-1],
                        "compliance_status": "non_compliant",
                        "risk_score": 60,
                        "criticality": "high",
                    })
            if missing_resources:
                extra = self._create_resource_nodes(session, missing_resources, tenant_id)
                stats["resource_nodes"] += extra
                logger.info(f"  → +{extra} resource nodes from threat ARNs")

            # 4d. Resource relationships
            stats["resource_rels"] = self._create_resource_relationships(session, inv_rels)
            logger.info(f"  → {stats['resource_rels']} resource relationships")

            # 4e. Hierarchy (Account/Region → Resource)
            all_findings = inv_findings + missing_resources
            stats["hierarchy_rels"] = self._create_hierarchy_edges(session, all_findings)
            logger.info(f"  → {stats['hierarchy_rels']} hierarchy relationships")

            # 4f. ThreatDetection nodes
            stats["threat_nodes"] = self._create_threat_nodes(session, detections, tenant_id)
            logger.info(f"  → {stats['threat_nodes']} threat detection nodes")

            # 4g. Finding nodes
            stats["finding_nodes"] = self._create_finding_nodes(session, check_findings, tenant_id)
            logger.info(f"  → {stats['finding_nodes']} finding nodes")

            # 4h. Analysis enrichment + attack paths
            stats["analysis_edges"] = self._create_analysis_edges(session, analyses)
            logger.info(f"  → {stats['analysis_edges']} analysis/attack-path edges")

            # 4i. Infer internet exposure
            stats["exposure_edges"] = self._infer_internet_exposure(session, tenant_id)
            logger.info(f"  → {stats['exposure_edges']} internet exposure edges")

        # Summary
        total_nodes = stats.get("virtual_nodes", 0) + stats.get("resource_nodes", 0) + \
                      stats.get("threat_nodes", 0) + stats.get("finding_nodes", 0)
        total_rels = stats.get("resource_rels", 0) + stats.get("hierarchy_rels", 0) + \
                     stats.get("analysis_edges", 0) + stats.get("exposure_edges", 0)

        stats["total_nodes"] = total_nodes
        stats["total_relationships"] = total_rels

        logger.info(f"Security graph built: {total_nodes} nodes, {total_rels} relationships")
        return stats
