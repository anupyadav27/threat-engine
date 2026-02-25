"""
Index Writer

Writes searchable indexes to Postgres/DynamoDB for UI queries.

=== DATABASE & TABLE MAP ===
Database: threat_engine_inventory (INVENTORY DB)
Env: INVENTORY_DB_HOST / INVENTORY_DB_PORT / INVENTORY_DB_NAME / INVENTORY_DB_USER / INVENTORY_DB_PASSWORD
     (connection URL passed from orchestrator via get_database_config)

Tables WRITTEN:
  - inventory_report        : write_scan_summary(ScanSummary)
                              — INSERT ... ON CONFLICT (inventory_scan_id) DO UPDATE
                              Columns: inventory_scan_id, tenant_id, started_at, completed_at,
                                       status, total_assets, total_relationships,
                                       assets_by_provider, assets_by_resource_type, assets_by_region,
                                       providers_scanned, accounts_scanned, regions_scanned, errors_count
  - inventory_findings      : write_asset_index(assets)
                              — INSERT ... ON CONFLICT (asset_id) DO UPDATE
                              Columns: asset_id, tenant_id, resource_uid, provider, account_id,
                                       region, resource_type, resource_id, name, tags, labels,
                                       properties, configuration (enrichment data),
                                       inventory_scan_id, latest_scan_run_id, updated_at
  - inventory_relationships : write_relationship_index(relationships)
                              — INSERT per relationship edge

Tables READ: None (write-only module)
===
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
        """Write scan summary to inventory_scans"""
        # TODO: Implement Postgres write
        pass
    
    def write_asset_index(self, assets: List[Asset]):
        """Write latest asset state to inventory_findings"""
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
    
    def _ensure_tenant(self, tenant_id: str) -> None:
        """Upsert tenant row to satisfy FK constraints on inventory tables."""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO tenants (tenant_id, tenant_name)
            VALUES (%s, %s)
            ON CONFLICT (tenant_id) DO NOTHING
        """, (tenant_id, tenant_id))
        self.conn.commit()

    def write_scan_summary(self, summary: ScanSummary):
        """Write to inventory_report table"""
        self._ensure_tenant(summary.tenant_id)
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO inventory_report (
                inventory_scan_id, tenant_id, started_at, completed_at, status,
                total_assets, total_relationships, assets_by_provider,
                assets_by_resource_type, assets_by_region, providers_scanned,
                accounts_scanned, regions_scanned, errors_count
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (inventory_scan_id) DO UPDATE SET
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
        """Write to inventory_findings table"""
        import json
        cursor = self.conn.cursor()

        def _serialize_value(obj):
            """Convert datetime and other non-JSON-serializable objects to strings"""
            if isinstance(obj, datetime):
                return obj.isoformat()
            elif isinstance(obj, dict):
                return {k: _serialize_value(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [_serialize_value(item) for item in obj]
            return obj

        for asset in assets:
            asset_id = generate_asset_id(asset)

            # Extract enrichment data from metadata
            configuration = asset.metadata.get('configuration', {}) if asset.metadata else {}
            labels = asset.metadata.get('labels', {}) if asset.metadata else {}
            properties = {k: v for k, v in asset.metadata.items() if k not in ['configuration', 'labels', 'raw_refs']} if asset.metadata else {}

            # Serialize datetime objects
            configuration = _serialize_value(configuration)
            labels = _serialize_value(labels)
            properties = _serialize_value(properties)

            cursor.execute("""
                INSERT INTO inventory_findings (
                    asset_id, tenant_id, resource_uid, provider, account_id,
                    region, resource_type, resource_id, name, tags, labels,
                    properties, configuration,
                    inventory_scan_id, latest_scan_run_id, updated_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (asset_id) DO UPDATE SET
                    resource_type = EXCLUDED.resource_type,
                    resource_id = EXCLUDED.resource_id,
                    name = EXCLUDED.name,
                    tags = EXCLUDED.tags,
                    labels = EXCLUDED.labels,
                    properties = EXCLUDED.properties,
                    configuration = EXCLUDED.configuration,
                    inventory_scan_id = EXCLUDED.inventory_scan_id,
                    latest_scan_run_id = EXCLUDED.latest_scan_run_id,
                    updated_at = EXCLUDED.updated_at
            """, (
                asset_id, asset.tenant_id, asset.resource_uid,
                asset.provider.value, asset.account_id, asset.region,
                asset.resource_type, asset.resource_id, asset.name,
                json.dumps(asset.tags), json.dumps(labels),
                json.dumps(properties), json.dumps(configuration),
                asset.scan_run_id, asset.scan_run_id,
                datetime.utcnow()
            ))

        self.conn.commit()
    
    def write_relationship_index(self, relationships: List[Relationship]):
        """Write to inventory_relationships table"""
        if not relationships:
            return
        
        cursor = self.conn.cursor()
        
        for rel in relationships:
            provider_val = rel.provider.value if hasattr(rel.provider, 'value') else str(rel.provider)
            cursor.execute("""
                INSERT INTO inventory_relationships (
                    tenant_id, inventory_scan_id, provider, account_id, region,
                    relation_type, from_uid, to_uid, from_resource_type, to_resource_type, properties
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                rel.tenant_id, rel.scan_run_id, provider_val,
                rel.account_id, rel.region, rel.relation_type,
                rel.from_uid, rel.to_uid,
                rel.from_resource_type, rel.to_resource_type,
                json.dumps(rel.properties)
            ))
        
        self.conn.commit()

