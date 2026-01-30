"""
Index Writer

Writes searchable indexes to Postgres/DynamoDB for UI queries.
"""

import json
from typing import List, Dict, Any, Optional
from datetime import datetime
from ..schemas.asset_schema import Asset, generate_asset_id
from ..schemas.relationship_schema import Relationship
from ..schemas.summary_schema import ScanSummary


class IndexWriter:
    """Writes indexes to database"""
    
    def __init__(self, db_url: Optional[str] = None):
        self.db_url = db_url
    
    def write_scan_summary(self, summary: ScanSummary):
        """Write scan summary to inventory_run_index"""
        # TODO: Implement Postgres write
        pass
    
    def write_asset_index(self, assets: List[Asset]):
        """Write latest asset state to asset_index_latest"""
        # TODO: Implement Postgres/DynamoDB write
        pass
    
    def write_relationship_index(self, relationships: List[Relationship]):
        """Write relationship index (optional)"""
        # TODO: Implement if needed
        pass


def _db_url_with_search_path(url: str) -> str:
    """Append options=search_path to URL when DB_SCHEMA is set (consolidated DB)."""
    import os
    schema = (os.getenv("DB_SCHEMA") or "").strip()
    if not schema:
        return url
    sep = "&" if "?" in url else "?"
    opts = f"options=-c%20search_path%3D{schema.replace(',', '%2C')}"
    return f"{url}{sep}{opts}"


class PostgresIndexWriter(IndexWriter):
    """Postgres implementation of index writer"""

    def __init__(self, db_url: str):
        super().__init__(db_url)
        import psycopg2
        self.conn = psycopg2.connect(_db_url_with_search_path(db_url))
    
    def write_scan_summary(self, summary: ScanSummary):
        """Write to inventory_run_index table"""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO inventory_run_index (
                scan_run_id, tenant_id, started_at, completed_at, status,
                total_assets, total_relationships, assets_by_provider,
                assets_by_resource_type, assets_by_region, providers_scanned,
                accounts_scanned, regions_scanned, errors_count
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (scan_run_id) DO UPDATE SET
                completed_at = EXCLUDED.completed_at,
                status = EXCLUDED.status,
                total_assets = EXCLUDED.total_assets,
                total_relationships = EXCLUDED.total_relationships
        """, (
            summary.scan_run_id, summary.tenant_id,
            summary.started_at, summary.completed_at, summary.status,
            summary.total_assets, summary.total_relationships,
            json.dumps(summary.assets_by_provider),
            json.dumps(summary.assets_by_resource_type),
            json.dumps(summary.assets_by_region),
            json.dumps(summary.providers_scanned),
            json.dumps(summary.accounts_scanned),
            json.dumps(summary.regions_scanned),
            summary.errors_count
        ))
        self.conn.commit()
    
    def write_asset_index(self, assets: List[Asset]):
        """Write to asset_index_latest table"""
        import json
        cursor = self.conn.cursor()
        
        for asset in assets:
            asset_id = generate_asset_id(asset)
            cursor.execute("""
                INSERT INTO asset_index_latest (
                    asset_id, tenant_id, resource_uid, provider, account_id,
                    region, resource_type, resource_id, name, tags,
                    latest_scan_run_id, updated_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (asset_id) DO UPDATE SET
                    resource_type = EXCLUDED.resource_type,
                    resource_id = EXCLUDED.resource_id,
                    name = EXCLUDED.name,
                    tags = EXCLUDED.tags,
                    latest_scan_run_id = EXCLUDED.latest_scan_run_id,
                    updated_at = EXCLUDED.updated_at
            """, (
                asset_id, asset.tenant_id, asset.resource_uid,
                asset.provider.value, asset.account_id, asset.region,
                asset.resource_type, asset.resource_id, asset.name,
                json.dumps(asset.tags), asset.scan_run_id, datetime.utcnow()
            ))
        
        self.conn.commit()
    
    def write_relationship_index(self, relationships: List[Relationship]):
        """Write to relationship_index_latest table"""
        if not relationships:
            return
        
        cursor = self.conn.cursor()
        
        for rel in relationships:
            provider_val = rel.provider.value if hasattr(rel.provider, 'value') else str(rel.provider)
            cursor.execute("""
                INSERT INTO relationship_index_latest (
                    tenant_id, scan_run_id, provider, account_id, region,
                    relation_type, from_uid, to_uid, properties
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                rel.tenant_id, rel.scan_run_id, provider_val,
                rel.account_id, rel.region, rel.relation_type,
                rel.from_uid, rel.to_uid, json.dumps(rel.properties)
            ))
        
        self.conn.commit()

