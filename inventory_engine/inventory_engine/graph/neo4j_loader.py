"""
Neo4j Graph Loader

Loads assets and relationships into Neo4j graph database.
"""

from typing import List, Optional
from ..schemas.asset_schema import Asset
from ..schemas.relationship_schema import Relationship


class Neo4jGraphLoader:
    """Loads inventory data into Neo4j"""
    
    def __init__(self, neo4j_uri: str, username: str, password: str):
        self.neo4j_uri = neo4j_uri
        self.username = username
        self.password = password
        self._driver = None
    
    def _get_driver(self):
        """Get Neo4j driver instance"""
        if self._driver is None:
            try:
                from neo4j import GraphDatabase
                self._driver = GraphDatabase.driver(
                    self.neo4j_uri,
                    auth=(self.username, self.password)
                )
            except ImportError:
                raise ImportError("neo4j package not installed. Install with: pip install neo4j")
        return self._driver
    
    def load_assets(self, assets: List[Asset], scan_run_id: str):
        """
        Load assets into Neo4j as nodes.
        
        Creates/updates nodes with:
        - Label: Asset
        - Properties: resource_uid, resource_type, provider, account_id, region, etc.
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
                    "provider": asset.provider.value,
                    "account_id": asset.account_id,
                    "region": asset.region,
                    "resource_type": asset.resource_type,
                    "resource_id": asset.resource_id,
                    "name": asset.name or "",
                    "tags": asset.tags
                })
    
    def load_relationships(self, relationships: List[Relationship]):
        """
        Load relationships into Neo4j as edges.
        
        Creates edges with:
        - Type: relation_type
        - Properties: direction, protocol, port, etc.
        """
        driver = self._get_driver()
        
        with driver.session() as session:
            for rel in relationships:
                # Create edge
                session.run(f"""
                    MATCH (from:Asset {{resource_uid: $from_uid}})
                    MATCH (to:Asset {{resource_uid: $to_uid}})
                    MERGE (from)-[r:{rel.relation_type.value}]->(to)
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

