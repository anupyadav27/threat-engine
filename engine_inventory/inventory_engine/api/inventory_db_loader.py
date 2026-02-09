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
        account_id: Optional[str] = None,
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
        
        if account_id:
            where_parts.append("account_id = %s")
            params.append(account_id)
        
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
                inventory_scan_id, latest_scan_run_id, updated_at
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
            assets.append({
                "schema_version": "cspm_asset.v1",
                "tenant_id": row["tenant_id"],
                "scan_run_id": row.get("inventory_scan_id") or row.get("latest_scan_run_id"),
                "provider": row["provider"],
                "account_id": row["account_id"],
                "region": row["region"] or "global",
                "scope": row["region"] or "global",
                "resource_type": row["resource_type"],
                "resource_id": row["resource_id"],
                "resource_uid": row["resource_uid"],
                "name": row["name"],
                "tags": row["tags"] or {},
                "metadata": {}
            })
        
        return assets, total
    
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
                inventory_scan_id, updated_at
            FROM inventory_findings
            WHERE {where_clause}
            LIMIT 1
        """
        
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(query, params)
            row = cur.fetchone()
        
        if not row:
            return None
        
        return {
            "schema_version": "cspm_asset.v1",
            "tenant_id": row["tenant_id"],
            "scan_run_id": row.get("inventory_scan_id") or row.get("latest_scan_run_id"),
            "provider": row["provider"],
            "account_id": row["account_id"],
            "region": row["region"] or "global",
            "scope": row["region"] or "global",
            "resource_type": row["resource_type"],
            "resource_id": row["resource_id"],
            "resource_uid": row["resource_uid"],
            "name": row["name"],
            "tags": row["tags"] or {},
            "metadata": {}
        }
    
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
        
        if scan_run_id:
            where_parts.append("scan_run_id = %s")
            params.append(scan_run_id)
        
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
                relationship_id, tenant_id, scan_run_id, provider,
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
                "scan_run_id": row["scan_run_id"],
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

        return dict(row)

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
    
    def close(self):
        """Close database connection"""
        try:
            self.conn.close()
        except Exception:
            pass
