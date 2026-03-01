"""
Neo4j Graph Loader

Loads assets and relationships into Neo4j graph database.
Uses centralized Neo4j connection from consolidated_services/database.
"""

from typing import List, Optional
from .neo4j_connection import Neo4jConnection
from ..config.database_config import get_neo4j_config


class Neo4jGraphLoader:
    """Loads inventory data into Neo4j using centralized connection"""
    
    def __init__(self, neo4j_uri: Optional[str] = None, username: Optional[str] = None, password: Optional[str] = None):
        """
        Initialize Neo4j Graph Loader.
        
        Args:
            neo4j_uri: Optional override (uses consolidated config if None)
            username: Optional override (uses consolidated config if None)
            password: Optional override (uses consolidated config if None)
        """
        # Use consolidated Neo4j config (required)
        try:
            neo4j_config = get_neo4j_config()
            # Override if provided
            if neo4j_uri:
                neo4j_config.uri = neo4j_uri
            if username:
                neo4j_config.username = username
            if password:
                neo4j_config.password = password
            
            self._connection = Neo4jConnection(neo4j_config)
            self._driver = None
        except Exception as e:
            raise RuntimeError(f"Failed to get consolidated Neo4j config: {e}") from e
    
    def _get_driver(self):
        """Get Neo4j driver instance (synchronous for compatibility)"""
        if self._driver is None:
            try:
                from neo4j import GraphDatabase
                neo4j_config = get_neo4j_config()
                self._driver = GraphDatabase.driver(
                    neo4j_config.uri,
                    auth=(neo4j_config.username, neo4j_config.password)
                )
            except ImportError:
                raise ImportError("neo4j package not installed. Install with: pip install neo4j")
        return self._driver
    
    def load_assets(self, assets: List, scan_run_id: str):
        """
        Load assets into Neo4j as nodes.
        
        Creates/updates nodes with:
        - Label: Asset
        - Properties: resource_uid, resource_type, provider, account_id, region, etc.
        
        Args:
            assets: List of Asset objects
            scan_run_id: Scan run identifier
        """
        driver = self._get_driver()
        
        with driver.session() as session:
            # Create/update assets
            for asset in assets:
                session.run("""
                    MERGE (a:Asset {resource_uid: $resource_uid})
                    SET a.tenant_id = $tenant_id,
                        a.scan_run_id = $scan_run_id,
                        a.provider = $provider,
                        a.account_id = $account_id,
                        a.region = $region,
                        a.resource_type = $resource_type,
                        a.resource_id = $resource_id,
                        a.name = $name,
                        a.tags = $tags,
                        a.updated_at = datetime()
                """, {
                    "resource_uid": asset.resource_uid,
                    "tenant_id": asset.tenant_id,
                    "scan_run_id": scan_run_id,
                    "provider": asset.provider.value if hasattr(asset.provider, 'value') else str(asset.provider),
                    "account_id": asset.account_id,
                    "region": asset.region,
                    "resource_type": asset.resource_type,
                    "resource_id": asset.resource_id,
                    "name": asset.name or "",
                    "tags": asset.tags
                })
    
    def load_relationships(self, relationships: List):
        """
        Load relationships into Neo4j as edges.
        
        Creates edges with:
        - Type: relation_type
        - Properties: direction, protocol, port, etc.
        
        Args:
            relationships: List of Relationship objects
        """
        driver = self._get_driver()
        
        with driver.session() as session:
            for rel in relationships:
                # Create edge
                relation_type = rel.relation_type.value if hasattr(rel.relation_type, 'value') else str(rel.relation_type)
                session.run(f"""
                    MATCH (from:Asset {{resource_uid: $from_uid}})
                    MATCH (to:Asset {{resource_uid: $to_uid}})
                    MERGE (from)-[r:{relation_type}]->(to)
                    SET r.tenant_id = $tenant_id,
                        r.scan_run_id = $scan_run_id,
                        r.properties = $properties,
                        r.updated_at = datetime()
                """, {
                    "from_uid": rel.from_uid,
                    "to_uid": rel.to_uid,
                    "tenant_id": rel.tenant_id,
                    "scan_run_id": rel.scan_run_id,
                    "properties": rel.properties
                })
    
    def close(self):
        """Close Neo4j driver connection"""
        if self._driver:
            self._driver.close()
            self._driver = None
        if self._connection:
            # Connection cleanup handled by driver close
            pass
