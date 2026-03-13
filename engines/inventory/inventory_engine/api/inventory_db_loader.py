"""
Inventory DB Loader

Loads assets, relationships, and drift records from PostgreSQL inventory DB.
Replaces file-based DataLoader for DB-first architecture.

=== DATABASE & TABLE MAP ===
Database: threat_engine_inventory (INVENTORY DB)
Env: INVENTORY_DB_HOST / INVENTORY_DB_PORT / INVENTORY_DB_NAME / INVENTORY_DB_USER / INVENTORY_DB_PASSWORD
     (connection URL passed from api_server.py via get_database_config)

Tables READ:
  - inventory_findings      : load_assets()       — SELECT with filters (tenant_id, scan_run_id,
                                                     provider, region, resource_type, account_id)
                               load_asset_by_uid() — SELECT WHERE tenant_id + resource_uid
  - inventory_relationships : load_relationships() — SELECT with filters (tenant_id, scan_run_id,
                                                     from_uid, to_uid, relation_type)
  - inventory_report        : (accessed via api_server, not directly here)

Tables WRITTEN: None (read-only loader for API queries)
===
"""

import os
import psycopg2
from psycopg2.extras import RealDictCursor
from typing import List, Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


# ── Resource categorisation for blast radius ──────────────────────────
# Maps resource_type prefix to a security-meaningful category.
_CATEGORY_MAP = {
    # COMPUTE — can execute code
    "ec2.instance": "compute", "lambda.function": "compute",
    "ecs.task": "compute", "ecs.service": "compute",
    "ecs.definition": "compute", "eks.cluster": "compute",
    "batch.compute-environment": "compute", "lightsail.instance": "compute",
    "ec2.image": "compute",
    # DATA STORAGE — holds unstructured data
    "s3.bucket": "storage", "efs.file-system": "storage",
    "ec2.volume": "storage", "ebs.volume": "storage",
    "ec2.snapshot": "storage", "glacier.vault": "storage",
    "backup.backup-vault": "storage",
    # DATABASE — structured data stores
    "rds.db-instance": "database", "rds.db-cluster": "database",
    "dynamodb.table": "database", "elasticache.cluster": "database",
    "elasticache.replication-group": "database", "es.domain": "database",
    "redshift.cluster": "database", "docdb.cluster": "database",
    # IDENTITY — permissions & access
    "iam.role": "identity", "iam.user": "identity",
    "iam.group": "identity", "iam.policy": "identity",
    "iam.instance-profile": "identity",
    # NETWORK — connectivity & boundaries
    "ec2.vpc": "network", "ec2.subnet": "network",
    "ec2.security-group": "network", "ec2.network-acl": "network",
    "ec2.route-table": "network", "ec2.internet-gateway": "network",
    "ec2.nat-gateway": "network", "ec2.transit-gateway": "network",
    "ec2.vpc-peering-connection": "network",
    "ec2.network-interface": "network",
    # LOAD BALANCING
    "elbv2.balancer": "load_balancer", "elbv2.target-group": "load_balancer",
    "elbv2.listener": "load_balancer",
    "elasticloadbalancing.load-balancer": "load_balancer",
    # ENCRYPTION & SECRETS
    "kms.key": "encryption", "kms.alias": "encryption",
    "acm.certificate": "encryption", "secretsmanager.secret": "encryption",
    # SERVERLESS / EVENT
    "events.rule": "serverless", "events.event-bus": "serverless",
    "states.state-machine": "serverless", "sqs.queue": "serverless",
    "sns.topic": "serverless", "kinesis.stream": "serverless",
    # LOGGING / MONITORING
    "logs.log-group": "logging", "cloudtrail.trail": "logging",
    "cloudwatch.alarm": "logging",
    # EXTERNAL SURFACE
    "cloudfront.distribution": "external", "apigateway.rest-api": "external",
    "waf.web-acl": "external",
}


def _categorize_resource(resource_type: str) -> str:
    """Map a resource_type like 'ec2.instance' to a security category."""
    if not resource_type:
        return "other"
    rt = resource_type.lower().strip()
    # Exact match first
    if rt in _CATEGORY_MAP:
        return _CATEGORY_MAP[rt]
    # Try prefix match (e.g. "ec2.instance" matches "ec2.instance-xxx")
    for key, cat in _CATEGORY_MAP.items():
        if rt.startswith(key):
            return cat
    return "other"


class InventoryDBLoader:
    """Loads inventory data from PostgreSQL database"""
    
    def __init__(self, db_url: str):
        """
        Initialize DB loader.
        
        Args:
            db_url: PostgreSQL connection URL
        """
        self.db_url = db_url
        self.conn = psycopg2.connect(db_url)
    
    def load_assets(
        self,
        tenant_id: str,
        scan_run_id: Optional[str] = None,
        provider: Optional[str] = None,
        region: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_type_prefix: Optional[str] = None,
        account_id: Optional[str] = None,
        account_ids: Optional[List[str]] = None,
        limit: int = 100,
        offset: int = 0
    ) -> tuple[List[Dict[str, Any]], int]:
        """
        Load assets from DB with filtering and pagination.
        
        Returns:
            Tuple of (assets list, total_count)
        """
        # Build WHERE clause
        where_parts = ["tenant_id = %s"]
        params = [tenant_id]
        
        if scan_run_id:
            where_parts.append("inventory_scan_id = %s")
            params.append(scan_run_id)

        if provider:
            where_parts.append("provider = %s")
            params.append(provider)
        
        if region:
            where_parts.append("region = %s")
            params.append(region)
        
        if resource_type:
            where_parts.append("resource_type = %s")
            params.append(resource_type)

        if resource_type_prefix:
            where_parts.append("resource_type LIKE %s")
            params.append(f"{resource_type_prefix}%")

        # Multi-account filter: merge account_ids list + single account_id
        effective_account_ids: Optional[List[str]] = None
        if account_ids:
            effective_account_ids = list(set(account_ids + ([account_id] if account_id else [])))
        elif account_id:
            effective_account_ids = [account_id]

        if effective_account_ids and len(effective_account_ids) == 1:
            where_parts.append("account_id = %s")
            params.append(effective_account_ids[0])
        elif effective_account_ids:
            where_parts.append("account_id = ANY(%s::text[])")
            params.append(effective_account_ids)

        where_clause = " AND ".join(where_parts)
        
        # Get total count
        count_query = f"SELECT COUNT(*) FROM inventory_findings WHERE {where_clause}"
        with self.conn.cursor() as cur:
            cur.execute(count_query, params)
            total = cur.fetchone()[0]
        
        # Get paginated results
        query = f"""
            SELECT
                asset_id, tenant_id, resource_uid, provider, account_id,
                region, resource_type, resource_id, name, tags,
                inventory_scan_id, latest_scan_run_id, updated_at,
                properties
            FROM inventory_findings
            WHERE {where_clause}
            ORDER BY resource_type, resource_uid
            LIMIT %s OFFSET %s
        """
        params.extend([limit, offset])

        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(query, params)
            rows = cur.fetchall()

        # Convert to asset schema format
        assets = []
        for row in rows:
            rt = row["resource_type"] or ""
            assets.append(self._row_to_asset(row, rt))

        # Back-fill last_scanned from scan_orchestration for assets missing it
        self._backfill_last_scanned(assets)

        return assets, total

    @staticmethod
    def _extract_service(resource_type: str) -> str:
        """Extract service name from resource_type (e.g., 's3.bucket' -> 's3')."""
        if "." in resource_type:
            return resource_type.split(".")[0]
        return resource_type

    @staticmethod
    def _row_to_asset(row: Dict[str, Any], resource_type: str) -> Dict[str, Any]:
        """Convert a DB row to the UI-ready asset schema."""
        updated = row.get("updated_at")
        tags = row.get("tags") or {}
        return {
            "schema_version": "cspm_asset.v1",
            "tenant_id": row["tenant_id"],
            "scan_run_id": row.get("inventory_scan_id") or row.get("latest_scan_run_id"),
            "provider": row["provider"],
            "account_id": row["account_id"],
            "region": row["region"] or "global",
            "scope": row["region"] or "global",
            "resource_type": resource_type,
            "resource_id": row["resource_id"],
            "resource_uid": row["resource_uid"],
            "name": row.get("name"),
            "resource_name": row.get("name") or row["resource_uid"].rsplit("/", 1)[-1],
            "service": InventoryDBLoader._extract_service(resource_type),
            "status": "active",
            "last_scanned": updated.isoformat() if updated else None,
            "tags": tags,
            "metadata": row.get("properties") or {},
        }
    
    @staticmethod
    def _backfill_last_scanned(assets: List[Dict[str, Any]]) -> None:
        """Resolve last_scanned for assets where updated_at was NULL.

        Looks up scan_orchestration.completed_at (or started_at) in the
        onboarding DB using each asset's inventory_scan_id.  A single
        batch query covers all distinct scan IDs in the page.
        """
        need = {
            a["scan_run_id"]
            for a in assets
            if not a.get("last_scanned") and a.get("scan_run_id")
        }
        if not need:
            return

        try:
            from engine_common.orchestration import _get_orchestration_conn
            conn = _get_orchestration_conn()
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT inventory_scan_id,
                               COALESCE(completed_at, started_at) AS ts
                        FROM scan_orchestration
                        WHERE inventory_scan_id = ANY(%s::text[])
                        """,
                        (list(need),),
                    )
                    ts_map = {r[0]: r[1] for r in cur.fetchall() if r[1]}
            finally:
                conn.close()
        except Exception as exc:
            logger.warning("Could not resolve last_scanned from scan_orchestration: %s", exc)
            return

        for a in assets:
            if not a.get("last_scanned") and a.get("scan_run_id"):
                ts = ts_map.get(a["scan_run_id"])
                if ts:
                    a["last_scanned"] = ts.isoformat()

    def load_asset_by_uid(
        self,
        tenant_id: str,
        resource_uid: str,
        scan_run_id: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Load a specific asset by resource_uid.
        
        Returns:
            Asset dictionary or None if not found
        """
        where_parts = ["tenant_id = %s", "resource_uid = %s"]
        params = [tenant_id, resource_uid]
        
        if scan_run_id:
            where_parts.append("inventory_scan_id = %s")
            params.append(scan_run_id)

        where_clause = " AND ".join(where_parts)

        query = f"""
            SELECT
                asset_id, tenant_id, resource_uid, provider, account_id,
                region, resource_type, resource_id, name, tags,
                inventory_scan_id, latest_scan_run_id, updated_at,
                configuration, properties
            FROM inventory_findings
            WHERE {where_clause}
            LIMIT 1
        """

        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(query, params)
            row = cur.fetchone()

        if not row:
            return None

        rt = row["resource_type"] or ""
        asset = self._row_to_asset(row, rt)
        # Asset detail gets extra fields not in list view
        asset["config"] = row.get("configuration") or row.get("properties") or {}
        return asset
    
    def load_relationships(
        self,
        tenant_id: str,
        scan_run_id: Optional[str] = None,
        from_uid: Optional[str] = None,
        to_uid: Optional[str] = None,
        relation_type: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> tuple[List[Dict[str, Any]], int]:
        """
        Load relationships from DB with filtering and pagination.
        
        Returns:
            Tuple of (relationships list, total_count)
        """
        where_parts = ["tenant_id = %s"]
        params = [tenant_id]

        # Resolve scan_run_id: if given but has 0 relationships, fall back to
        # the latest scan that actually produced relationships for this tenant.
        effective_scan = scan_run_id
        if effective_scan:
            with self.conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) FROM inventory_relationships WHERE tenant_id = %s AND inventory_scan_id = %s",
                    (tenant_id, effective_scan),
                )
                if cur.fetchone()[0] == 0:
                    cur.execute(
                        "SELECT inventory_scan_id FROM inventory_relationships WHERE tenant_id = %s "
                        "ORDER BY created_at DESC LIMIT 1",
                        (tenant_id,),
                    )
                    row = cur.fetchone()
                    effective_scan = row[0] if row else None

        if effective_scan:
            where_parts.append("inventory_scan_id = %s")
            params.append(effective_scan)

        if from_uid:
            where_parts.append("from_uid = %s")
            params.append(from_uid)

        if to_uid:
            where_parts.append("to_uid = %s")
            params.append(to_uid)

        if relation_type:
            where_parts.append("relation_type = %s")
            params.append(relation_type)

        where_clause = " AND ".join(where_parts)

        # Get total count
        count_query = f"SELECT COUNT(*) FROM inventory_relationships WHERE {where_clause}"
        with self.conn.cursor() as cur:
            cur.execute(count_query, params)
            total = cur.fetchone()[0]
        
        # Get paginated results
        query = f"""
            SELECT
                relationship_id, tenant_id, inventory_scan_id, provider,
                account_id, region, relation_type, from_uid, to_uid,
                properties, created_at
            FROM inventory_relationships
            WHERE {where_clause}
            ORDER BY relation_type, from_uid
            LIMIT %s OFFSET %s
        """
        params.extend([limit, offset])
        
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(query, params)
            rows = cur.fetchall()
        
        # Convert to relationship schema format
        relationships = []
        for row in rows:
            relationships.append({
                "schema_version": "cspm_relationship.v1",
                "tenant_id": row["tenant_id"],
                "scan_run_id": row["inventory_scan_id"],
                "provider": row["provider"],
                "account_id": row["account_id"],
                "region": row["region"] or "global",
                "relation_type": row["relation_type"],
                "from_uid": row["from_uid"],
                "to_uid": row["to_uid"],
                "properties": row["properties"] or {}
            })
        
        return relationships, total
    
    def get_scan_summary(
        self,
        tenant_id: str,
        scan_run_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get scan summary from inventory_report.

        Returns:
            Summary dict or None if not found
        """
        query = """
            SELECT
                inventory_scan_id, tenant_id, started_at, completed_at, status,
                total_assets, total_relationships,
                assets_by_provider, assets_by_resource_type, assets_by_region,
                providers_scanned, accounts_scanned, regions_scanned,
                errors_count
            FROM inventory_report
            WHERE tenant_id = %s AND inventory_scan_id = %s
        """

        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(query, (tenant_id, scan_run_id))
            row = cur.fetchone()

        if not row:
            return None

        result = dict(row)

        # Enrich with drift KPIs from inventory_drift
        try:
            drift_query = """
                SELECT change_type, COUNT(*) AS cnt
                FROM inventory_drift
                WHERE tenant_id = %s AND inventory_scan_id = %s
                GROUP BY change_type
            """
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(drift_query, (tenant_id, scan_run_id))
                drift_rows = cur.fetchall()
            added = 0
            removed = 0
            changed = 0
            for dr in drift_rows:
                ct = (dr.get("change_type") or "").lower()
                c = dr.get("cnt", 0)
                if "added" in ct or "new" in ct:
                    added += c
                elif "removed" in ct or "deleted" in ct:
                    removed += c
                else:
                    changed += c
            result["drift_summary"] = {
                "total_drift": added + removed + changed,
                "assets_added": added,
                "assets_removed": removed,
                "assets_changed": changed,
            }
        except Exception:
            result["drift_summary"] = {
                "total_drift": 0,
                "assets_added": 0,
                "assets_removed": 0,
                "assets_changed": 0,
            }

        return result

    def get_latest_scan_id(self, tenant_id: str) -> Optional[str]:
        """Get latest completed inventory_scan_id for tenant"""
        query = """
            SELECT inventory_scan_id FROM inventory_report
            WHERE tenant_id = %s AND status = 'completed'
            ORDER BY completed_at DESC LIMIT 1
        """
        with self.conn.cursor() as cur:
            cur.execute(query, (tenant_id,))
            row = cur.fetchone()
        return row[0] if row else None
    
    def load_asset_drift(
        self,
        tenant_id: str,
        resource_uid: str,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """Load drift history for a specific asset from inventory_drift table."""
        query = """
            SELECT drift_id, inventory_scan_id, previous_scan_id,
                   change_type, previous_state, current_state,
                   changes_summary, severity, detected_at
            FROM inventory_drift
            WHERE tenant_id = %s AND resource_uid = %s
            ORDER BY detected_at DESC
            LIMIT %s
        """
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(query, (tenant_id, resource_uid, limit))
                rows = cur.fetchall()
        except Exception as e:
            logger.warning(f"Asset drift query failed: {e}")
            return {"last_check": None, "has_drift": False, "changes": [], "total": 0}

        changes = []
        for r in rows:
            detected = r.get("detected_at")
            summary = r.get("changes_summary")
            if isinstance(summary, str):
                try:
                    import json
                    summary = json.loads(summary)
                except Exception:
                    summary = {}
            changes.append({
                "drift_id": str(r.get("drift_id", "")),
                "change_type": r.get("change_type", "modified"),
                "severity": r.get("severity", "medium"),
                "previous_state": r.get("previous_state") or {},
                "current_state": r.get("current_state") or {},
                "changes_summary": summary or {},
                "detected_at": detected.isoformat() if detected else None,
            })

        last_check = changes[0]["detected_at"] if changes else None
        return {
            "last_check": last_check,
            "has_drift": len(changes) > 0,
            "changes": changes,
            "total": len(changes),
        }

    def load_drift_records(
        self,
        tenant_id: str,
        scan_run_id: Optional[str] = None,
        provider: Optional[str] = None,
        change_type: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Load drift records with resource_name join and flattened values for the UI."""
        where_parts = ["d.tenant_id = %s"]
        params: list = [tenant_id]

        if scan_run_id:
            where_parts.append("d.inventory_scan_id = %s")
            params.append(scan_run_id)
        if provider:
            where_parts.append("d.provider = %s")
            params.append(provider)
        if change_type:
            where_parts.append("d.change_type = %s")
            params.append(change_type)

        where_clause = " AND ".join(where_parts)

        query = f"""
            SELECT
                d.drift_id, d.resource_uid, d.resource_type, d.change_type,
                d.changes_summary, d.severity, d.detected_at,
                d.provider,
                f.account_id, f.region,
                f.name AS resource_name
            FROM inventory_drift d
            LEFT JOIN inventory_findings f
                ON f.resource_uid = d.resource_uid AND f.tenant_id = d.tenant_id
            WHERE {where_clause}
            ORDER BY d.detected_at DESC
            LIMIT %s
        """
        params.append(limit)

        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(query, params)
                rows = cur.fetchall()
        except Exception as e:
            logger.warning(f"Drift records query failed: {e}")
            return []

        records = []
        for r in rows:
            detected = r.get("detected_at")
            summary = r.get("changes_summary")
            if isinstance(summary, str):
                try:
                    import json
                    summary = json.loads(summary)
                except Exception:
                    summary = {}
            # Flatten changes_summary into previous_value / new_value
            prev_val, new_val = "", ""
            if isinstance(summary, dict):
                # Could be {"field": {"before": X, "after": Y}} or list
                for field, change in summary.items():
                    if isinstance(change, dict):
                        prev_val = str(change.get("before", ""))
                        new_val = str(change.get("after", ""))
                        break
            elif isinstance(summary, list) and summary:
                entry = summary[0]
                if isinstance(entry, dict):
                    prev_val = str(entry.get("before", ""))
                    new_val = str(entry.get("after", ""))

            uid = r.get("resource_uid", "")
            records.append({
                "drift_id": str(r.get("drift_id", "")),
                "resource_uid": uid,
                "resource_name": r.get("resource_name") or uid.rsplit("/", 1)[-1],
                "resource_type": r.get("resource_type", ""),
                "drift_type": (r.get("change_type") or "modified").replace("_", " "),
                "previous_value": prev_val,
                "new_value": new_val,
                "severity": r.get("severity", "medium"),
                "timestamp": detected.isoformat() if detected else None,
                "provider": r.get("provider", ""),
                "account_id": r.get("account_id", ""),
                "region": r.get("region", ""),
            })
        return records

    def get_blast_radius(
        self,
        tenant_id: str,
        resource_uid: str,
        max_depth: int = 3,
        scan_run_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Compute blast radius — find all resources IMPACTED if the origin
        resource is compromised, misconfigured, or goes down.

        Traverses REVERSE direction: finds resources that DEPEND ON the
        origin (who points at me?).  For example:
          - VPC compromised → find everything contained_by this VPC
          - Security group compromised → find everything attached_to this SG
          - IAM role compromised → find everything that uses this role
          - KMS key compromised → find everything encrypted_by this key

        Returns resources grouped by security category (compute, database,
        storage, identity, network, etc.) with impact summary.
        """
        # Resolve effective scan (same fallback as load_relationships)
        effective_scan = scan_run_id
        if effective_scan:
            with self.conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) FROM inventory_relationships "
                    "WHERE tenant_id = %s AND inventory_scan_id = %s",
                    (tenant_id, effective_scan),
                )
                if cur.fetchone()[0] == 0:
                    cur.execute(
                        "SELECT inventory_scan_id FROM inventory_relationships "
                        "WHERE tenant_id = %s ORDER BY created_at DESC LIMIT 1",
                        (tenant_id,),
                    )
                    row = cur.fetchone()
                    effective_scan = row[0] if row else None
        else:
            with self.conn.cursor() as cur:
                cur.execute(
                    "SELECT inventory_scan_id FROM inventory_relationships "
                    "WHERE tenant_id = %s ORDER BY created_at DESC LIMIT 1",
                    (tenant_id,),
                )
                row = cur.fetchone()
                effective_scan = row[0] if row else None

        if not effective_scan:
            return self._empty_blast_response(resource_uid, max_depth)

        sf = "AND ir.inventory_scan_id = %(scan_id)s"

        # REVERSE traversal: find resources that DEPEND ON the origin.
        # We query WHERE to_uid = origin, and walk from_uid (the dependent)
        # outward.  This answers "who is impacted if origin fails?"
        query = f"""
            WITH RECURSIVE dependents AS (
                -- Hop 1: direct dependents (resources pointing AT origin)
                SELECT
                    ir.from_uid         AS dependent,
                    ir.from_resource_type AS dependent_type,
                    ir.relation_type,
                    1                   AS hop,
                    ARRAY[%(uid)s, ir.from_uid] AS path
                FROM inventory_relationships ir
                WHERE ir.to_uid = %(uid)s
                  AND ir.tenant_id = %(tenant_id)s {sf}

                UNION ALL

                -- Recursive: find resources depending on already-found dependents
                SELECT
                    ir.from_uid         AS dependent,
                    ir.from_resource_type AS dependent_type,
                    ir.relation_type,
                    d.hop + 1,
                    d.path || ir.from_uid
                FROM dependents d
                JOIN inventory_relationships ir
                  ON ir.to_uid = d.dependent
                WHERE ir.tenant_id = %(tenant_id)s {sf}
                  AND d.hop < %(max_depth)s
                  AND NOT (ir.from_uid = ANY(d.path))
            )
            SELECT dependent, dependent_type, relation_type, hop, path
            FROM dependents
            ORDER BY hop, dependent
            LIMIT 500
        """

        params = {
            "uid": resource_uid,
            "tenant_id": tenant_id,
            "max_depth": max_depth,
            "scan_id": effective_scan,
        }

        try:
            with self.conn.cursor() as cur:
                cur.execute(query, params)
                raw_rows = cur.fetchall()
        except Exception as e:
            logger.warning(f"Blast radius CTE failed: {e}")
            return self._empty_blast_response(resource_uid, max_depth)

        # Deduplicate nodes (keep shortest hop)
        node_map: Dict[str, Dict[str, Any]] = {}
        edges: List[Dict[str, Any]] = []
        paths: List[List[str]] = []

        for dependent, dep_type, rel_type, hop, path in raw_rows:
            if dependent not in node_map or hop < node_map[dependent]["hop"]:
                node_map[dependent] = {
                    "id": dependent,
                    "type": dep_type or "",
                    "hop": hop,
                    "relation_type": rel_type or "",
                }
            edges.append({
                "source": path[-2] if len(path) >= 2 else resource_uid,
                "target": dependent,
                "relation_type": rel_type or "",
                "hop": hop,
            })
            paths.append(list(path))

        # Enrich nodes from inventory_findings
        node_uids = list(node_map.keys())
        if node_uids:
            try:
                with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute(
                        "SELECT resource_uid, name, resource_type, provider, "
                        "account_id, region "
                        "FROM inventory_findings "
                        "WHERE tenant_id = %s AND resource_uid = ANY(%s)",
                        (tenant_id, node_uids),
                    )
                    for r in cur.fetchall():
                        uid = r["resource_uid"]
                        if uid in node_map:
                            rt = r.get("resource_type") or node_map[uid].get("type", "")
                            node_map[uid]["name"] = r.get("name") or uid.rsplit("/", 1)[-1]
                            node_map[uid]["type"] = rt
                            node_map[uid]["provider"] = r.get("provider") or ""
                            node_map[uid]["account_id"] = r.get("account_id") or ""
                            node_map[uid]["region"] = r.get("region") or "global"
            except Exception as e:
                logger.warning(f"Blast radius node enrichment failed: {e}")

        # Fill defaults & assign category
        for uid, node in node_map.items():
            if "name" not in node:
                node["name"] = uid.rsplit("/", 1)[-1]
            if "provider" not in node:
                node["provider"] = ""
            if "region" not in node:
                node["region"] = "global"
            rt = node.get("type", "")
            node["service"] = rt.split(".")[0] if "." in rt else rt
            node["category"] = _categorize_resource(rt)

        # Build impact summary by category
        impact_summary: Dict[str, int] = {}
        for node in node_map.values():
            cat = node["category"]
            impact_summary[cat] = impact_summary.get(cat, 0) + 1

        # Depth distribution
        depth_dist: Dict[str, int] = {}
        for n in node_map.values():
            h = str(n["hop"])
            depth_dist[h] = depth_dist.get(h, 0) + 1

        # Build layers (grouped by hop)
        layers: List[Dict[str, Any]] = []
        max_hop = max((n["hop"] for n in node_map.values()), default=0)
        for h in range(1, max_hop + 1):
            layer_nodes = [n for n in node_map.values() if n["hop"] == h]
            if layer_nodes:
                layers.append({"hop": h, "resources": layer_nodes})

        # Deduplicate edges
        seen_edges: set = set()
        unique_edges: List[Dict[str, Any]] = []
        for e in edges:
            key = (e["source"], e["target"], e["relation_type"])
            if key not in seen_edges:
                seen_edges.add(key)
                unique_edges.append(e)

        return {
            "origin": resource_uid,
            "max_depth": max_depth,
            "impact_summary": impact_summary,
            "layers": layers,
            "nodes": list(node_map.values()),
            "edges": unique_edges,
            "paths": paths,
            "total_impacted": len(node_map),
            "depth_distribution": depth_dist,
        }

    @staticmethod
    def _empty_blast_response(
        resource_uid: str, max_depth: int
    ) -> Dict[str, Any]:
        return {
            "origin": resource_uid,
            "max_depth": max_depth,
            "impact_summary": {},
            "layers": [],
            "nodes": [],
            "edges": [],
            "paths": [],
            "total_impacted": 0,
            "depth_distribution": {},
        }

    def close(self):
        """Close database connection"""
        try:
            self.conn.close()
        except Exception:
            pass
