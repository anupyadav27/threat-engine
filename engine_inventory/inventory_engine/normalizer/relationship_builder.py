"""
Relationship Builder

Builds relationship edges from normalized assets using relationship rules.

=== DATABASE & TABLE MAP ===
Source of truth: threat_engine_pythonsdk (PYTHONSDK DB)
Local cache: config/{csp_id}_relationship_rules.json (synced from DB)

The sync_from_db() class method fetches rules from the DB and writes them
to local JSON cache files. At runtime, RelationshipBuilder reads from the
local cache only — no DB calls during scan execution.

Tables READ (by sync_from_db only, not at runtime):
  - relationship_rules : SELECT from_type, relation_type, to_type, source_field,
                                target_uid_pattern, source_field_item
                         FROM relationship_rules WHERE csp_id = %s
  - relation_types     : SELECT relation_id, category FROM relation_types

Tables WRITTEN: None (returns Relationship objects to callers)
===
"""

import json
import logging
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from ..schemas.asset_schema import Asset, Provider
from ..schemas.relationship_schema import Relationship, RelationType

logger = logging.getLogger(__name__)

# Cache directory for synced relationship data
_CONFIG_DIR = Path(__file__).parent.parent / "config"


class RelationshipBuilder:
    """Builds relationships between assets using locally-cached relationship rules"""

    def __init__(self, tenant_id: str, scan_run_id: str, csp_id: str = "aws"):
        self.tenant_id = tenant_id
        self.scan_run_id = scan_run_id
        self.csp_id = csp_id
        self.relationship_index = self._load_relationship_index()
        self.relation_types = self._load_relation_types()

    # ------------------------------------------------------------------
    # Sync: fetch from DB and cache locally (called once at startup/deploy)
    # ------------------------------------------------------------------

    @classmethod
    def sync_from_db(cls, csp_ids: Optional[List[str]] = None) -> Dict[str, int]:
        """
        Fetch relationship rules and relation types from the pythonsdk DB
        and write them to local JSON cache files.

        Call this once at service startup or via a management command.
        Returns dict of {csp_id: rule_count}.
        """
        conn = cls._get_db_connection()
        if not conn:
            logger.error("Cannot sync: no pythonsdk DB connection")
            return {}

        try:
            from psycopg2.extras import RealDictCursor
            result = {}

            # 1. Sync relation_types
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT relation_id, category FROM relation_types ORDER BY relation_id")
                type_rows = cur.fetchall()
            if type_rows:
                types_data = [dict(row) for row in type_rows]
                cache_file = _CONFIG_DIR / "relation_types_cache.json"
                cache_file.parent.mkdir(parents=True, exist_ok=True)
                with open(cache_file, 'w') as f:
                    json.dump(types_data, f)
                logger.info(f"Synced {len(types_data)} relation types to {cache_file}")

            # 2. Determine which CSPs to sync
            if not csp_ids:
                with conn.cursor() as cur:
                    cur.execute("SELECT DISTINCT csp_id FROM relationship_rules ORDER BY csp_id")
                    csp_ids = [row[0] for row in cur.fetchall()]

            # 3. Sync rules per CSP
            for csp_id in csp_ids:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        SELECT from_type, relation_type, to_type,
                               source_field, target_uid_pattern, source_field_item
                        FROM relationship_rules
                        WHERE csp_id = %s
                        ORDER BY from_type, relation_type
                    """, (csp_id,))
                    rows = cur.fetchall()

                if rows:
                    rules_data = [dict(row) for row in rows]
                    cache_file = _CONFIG_DIR / f"{csp_id}_relationship_rules.json"
                    with open(cache_file, 'w') as f:
                        json.dump(rules_data, f)
                    result[csp_id] = len(rules_data)
                    logger.info(f"Synced {len(rules_data)} rules for {csp_id} to {cache_file}")

            return result
        except Exception as e:
            logger.error(f"Error syncing from DB: {e}")
            return {}
        finally:
            try:
                conn.close()
            except Exception:
                pass

    @staticmethod
    def _get_db_connection():
        """Get a connection to the pythonsdk DB (used only for sync)."""
        try:
            from ..database.connection.database_config import get_database_config
            import psycopg2
            cfg = get_database_config("pythonsdk")
            return psycopg2.connect(
                host=cfg.host, port=cfg.port, dbname=cfg.database,
                user=cfg.username, password=cfg.password,
            )
        except Exception as e:
            logger.warning(f"Cannot connect to pythonsdk DB: {e}")
            return None

    # ------------------------------------------------------------------
    # Load: read from local cache files (fast, no DB calls)
    # ------------------------------------------------------------------

    def _load_relationship_index(self) -> Dict[str, Any]:
        """Load relationship rules from local JSON cache."""
        cache_file = _CONFIG_DIR / f"{self.csp_id}_relationship_rules.json"

        if not cache_file.exists():
            logger.warning(f"No cached relationship rules at {cache_file}. "
                           f"Run RelationshipBuilder.sync_from_db() first.")
            return {}

        try:
            with open(cache_file, 'r') as f:
                rules = json.load(f)

            by_resource_type: Dict[str, Dict] = {}
            for rule in rules:
                from_type = rule["from_type"]
                if from_type not in by_resource_type:
                    by_resource_type[from_type] = {"relationships": []}
                by_resource_type[from_type]["relationships"].append({
                    "relation_type": rule["relation_type"],
                    "target_type": rule["to_type"],
                    "source_field": rule["source_field"],
                    "target_uid_pattern": rule["target_uid_pattern"],
                    "source_field_item": rule.get("source_field_item"),
                })

            logger.info(f"Loaded {len(rules)} relationship rules from cache for {self.csp_id} "
                        f"({len(by_resource_type)} resource types)")
            return {
                "version": "cache",
                "source": "local_cache",
                "classifications": {
                    "by_resource_type": by_resource_type,
                    "by_discovery_operation": {},
                },
            }
        except Exception as e:
            logger.error(f"Error loading relationship rules from cache: {e}")
            return {}

    def _load_relation_types(self) -> Set[str]:
        """Load valid relation types from local JSON cache."""
        cache_file = _CONFIG_DIR / "relation_types_cache.json"

        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    types_data = json.load(f)
                return {t["relation_id"] for t in types_data}
            except Exception:
                pass

        # Fallback to enum values if no cache
        return {rt.value for rt in RelationType}
    
    def build_relationships(self, assets: List[Asset]) -> List[Relationship]:
        """
        Build relationships from assets using predefined relationship index.
        
        For each asset:
        1. Look up relationship patterns for its resource_type
        2. Extract relationship data from asset metadata
        3. Resolve target UIDs using patterns
        4. Create relationship edges
        """
        relationships = []
        
        # Group assets by type and UID for efficient lookup
        assets_by_uid = {asset.resource_uid: asset for asset in assets}
        assets_by_type = {}
        for asset in assets:
            asset_type = asset.resource_type
            if asset_type not in assets_by_type:
                assets_by_type[asset_type] = []
            assets_by_type[asset_type].append(asset)
        
        # Build relationships using index
        for asset in assets:
            asset_relationships = self._extract_relationships_from_asset(
                asset, assets_by_uid, assets_by_type
            )
            relationships.extend(asset_relationships)
        
        # Also build internet exposure relationships (special case)
        relationships.extend(self._build_internet_exposure(assets_by_type))
        
        return relationships
    
    def _extract_relationships_from_asset(
        self,
        asset: Asset,
        assets_by_uid: Dict[str, Asset],
        assets_by_type: Dict[str, List[Asset]]
    ) -> List[Relationship]:
        """Extract relationships for a single asset using relationship index"""
        relationships = []
        
        if not self.relationship_index:
            return relationships
        
        # Look up relationship patterns for this resource type
        by_resource = self.relationship_index.get("classifications", {}).get("by_resource_type", {})
        resource_patterns = by_resource.get(asset.resource_type, {}).get("relationships", [])
        
        if not resource_patterns:
            return relationships
        
        # For each relationship pattern, extract and create relationships
        for pattern in resource_patterns:
            rel_type_str = pattern.get("relation_type", "")
            if rel_type_str not in self.relation_types:
                continue
            
            try:
                rel_type = RelationType(rel_type_str)
            except ValueError:
                continue
            
            target_type = pattern.get("target_type", "")
            source_field = pattern.get("source_field", "")
            target_uid_pattern = pattern.get("target_uid_pattern", "")
            source_field_item = pattern.get("source_field_item")
            
            if not source_field or not target_uid_pattern:
                continue
            
            # Extract field value(s) from asset metadata
            field_values = self._extract_field_values(
                asset.metadata, source_field, source_field_item
            )
            
            # For each field value, create a relationship
            for field_value in field_values:
                if not field_value:
                    continue
                
                # Resolve target UID from pattern
                target_uid = self._resolve_target_uid(
                    target_uid_pattern, field_value, asset, target_type
                )
                
                if not target_uid:
                    continue
                
                # Create relationship
                relationships.append(Relationship(
                    tenant_id=self.tenant_id,
                    scan_run_id=self.scan_run_id,
                    provider=asset.provider.value,
                    account_id=asset.account_id,
                    region=asset.region,
                    relation_type=rel_type,
                    from_uid=asset.resource_uid,
                    to_uid=target_uid,
                    properties=self._extract_relationship_properties(
                        pattern, field_value, asset
                    )
                ))
        
        return relationships
    
    def _extract_field_values(
        self,
        metadata: Dict[str, Any],
        source_field: str,
        source_field_item: Optional[str] = None
    ) -> List[Any]:
        """
        Extract field value(s) from metadata.
        
        First tries emitted_fields in metadata (if stored by AssetNormalizer),
        then falls back to direct metadata fields.
        
        Handles:
        - Simple fields: "VpcId" -> emitted_fields.get("VpcId") or metadata.get("VpcId")
        - Nested fields: "IamInstanceProfile.Arn" -> nested access
        - Array fields: "Groups" -> array extraction
        - Array item fields: source_field="Groups", source_field_item="GroupId" -> extract GroupId from each item
        """
        if not source_field:
            return []
        
        # Try emitted_fields first (if stored in metadata)
        data_source = metadata.get("emitted_fields", metadata)
        
        # Handle nested field paths (e.g., "IamInstanceProfile.Arn")
        if "." in source_field and not source_field.endswith("[]"):
            parts = source_field.split(".")
            value = data_source
            for part in parts:
                if isinstance(value, dict):
                    value = value.get(part)
                else:
                    return []
                if value is None:
                    return []
            if value is None:
                return []

            # Support nested arrays (e.g., "VpcConfig.SubnetIds") and nested array item extraction
            if isinstance(value, list):
                if source_field_item:
                    values: List[Any] = []
                    for item in value:
                        if isinstance(item, dict):
                            iv = item.get(source_field_item)
                            if iv is not None:
                                values.append(iv)
                        elif isinstance(item, str):
                            values.append(item)
                    return values
                return value

            # Support nested dict + item extraction (e.g., "LoggingConfiguration.LogGroupArn" via source_field_item)
            if source_field_item and isinstance(value, dict):
                iv = value.get(source_field_item)
                return [iv] if iv is not None else []

            return [value]
        
        # Get base field value
        field_value = data_source.get(source_field)
        if field_value is None:
            return []
        
        # Handle array with item extraction
        if source_field_item and isinstance(field_value, list):
            values = []
            for item in field_value:
                if isinstance(item, dict):
                    item_value = item.get(source_field_item)
                    if item_value:
                        values.append(item_value)
                elif isinstance(item, str):
                    # Sometimes arrays contain strings directly
                    values.append(item)
            return values
        
        # Handle array without item extraction (return as-is for pattern matching)
        if isinstance(field_value, list):
            return field_value
        
        # Single value
        # If the value is a dict (e.g., Environment.Variables, Attributes.Policy), try to extract embedded ARNs/strings
        if isinstance(field_value, dict):
            results: List[Any] = []
            def collect_strings(obj):
                if isinstance(obj, dict):
                    for v in obj.values():
                        collect_strings(v)
                elif isinstance(obj, list):
                    for it in obj:
                        collect_strings(it)
                elif isinstance(obj, str):
                    results.append(obj)
            collect_strings(field_value)
            # Return unique strings
            return list(dict.fromkeys(results))

        # If value is a JSON string that may contain ARNs, try to parse it and extract strings
        if isinstance(field_value, str):
            s = field_value.strip()
            # quick JSON detect
            if (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]")):
                try:
                    parsed = json.loads(s)
                    results: List[Any] = []
                    def collect_parsed(obj):
                        if isinstance(obj, dict):
                            for v in obj.values():
                                collect_parsed(v)
                        elif isinstance(obj, list):
                            for it in obj:
                                collect_parsed(it)
                        elif isinstance(obj, str):
                            results.append(obj)
                    collect_parsed(parsed)
                    return list(dict.fromkeys(results))
                except Exception:
                    pass

        return [field_value]
    
    def _extract_account_from_uid(self, resource_uid: str) -> Optional[str]:
        """Extract account_id from resource_uid ARN"""
        if not resource_uid or not resource_uid.startswith("arn:aws:"):
            return None
        # ARN format: arn:aws:service:region:account:resource
        parts = resource_uid.split(":")
        if len(parts) >= 5:
            return parts[4]  # Account ID is 5th part
        return None

    def _extract_region_from_uid(self, resource_uid: str) -> Optional[str]:
        """Extract region from resource_uid ARN (if present)."""
        if not resource_uid or not resource_uid.startswith("arn:aws:"):
            return None
        # ARN format: arn:aws:service:region:account:resource
        parts = resource_uid.split(":")
        if len(parts) >= 4:
            region = parts[3]
            return region if region else None
        return None
    
    def _resolve_target_uid(
        self,
        pattern: str,
        field_value: Any,
        asset: Asset,
        target_type: str
    ) -> Optional[str]:
        """
        Resolve target UID from pattern.
        
        Patterns:
        - "arn:aws:ec2:{region}:{account_id}:vpc/{VpcId}" -> replace variables
        - "{Arn}" -> use field_value directly (if it's an ARN)
        - "arn:aws:iam::{account_id}:group/{GroupName}" -> construct ARN
        """
        if not pattern or not field_value:
            return None
        
        # Direct ARN pattern: {Arn} or {PolicyArn}
        if pattern.startswith("{") and pattern.endswith("}"):
            # Extract field name from pattern
            field_name = pattern[1:-1]
            # If field_value is already an ARN, use it
            if isinstance(field_value, str) and field_value.startswith("arn:aws:"):
                return field_value
            # Avoid turning dict/list into bogus UIDs
            if isinstance(field_value, (dict, list)):
                return None
            # Otherwise, field_value might be the ARN already
            return str(field_value) if field_value else None
        
        # ARN pattern with variables
        # Replace {region}, {account_id}, and field placeholders
        resolved = pattern
        
        # Extract account_id from from_uid (more accurate) or use asset.account_id
        account_id = self._extract_account_from_uid(asset.resource_uid) or asset.account_id
        region = self._extract_region_from_uid(asset.resource_uid) or asset.region or ""
        
        # Replace {region}
        resolved = resolved.replace("{region}", region)
        
        # Replace {account_id}
        resolved = resolved.replace("{account_id}", account_id)
        
        # Replace all field placeholders (e.g., {VpcId}, {GroupId})
        # Find all placeholders and replace them
        placeholders = re.findall(r'\{([^}]+)\}', resolved)
        for placeholder in placeholders:
            # Skip if it's a variable we already replaced
            if placeholder in ("region", "account_id"):
                continue
            # Replace with field_value (the actual value from the field)
            resolved = resolved.replace(f"{{{placeholder}}}", str(field_value))

        # If any placeholders remain, this is an invalid/incomplete UID pattern
        if "{" in resolved or "}" in resolved:
            return None
        
        # Handle special cases
        # For IAM groups: pattern might use GroupName but we have group ARN
        if "iam" in target_type and "group" in target_type:
            if isinstance(field_value, str) and not field_value.startswith("arn:"):
                # Construct ARN from group name using account from from_uid
                resolved = f"arn:aws:iam::{account_id}:group/{field_value}"
        
        return resolved if resolved and resolved != pattern else None
    
    def _extract_relationship_properties(
        self,
        pattern: Dict[str, Any],
        field_value: Any,
        asset: Asset
    ) -> Dict[str, Any]:
        """Extract additional properties for relationship edge"""
        properties = {}
        
        # Add direction for security group relationships
        if pattern.get("relation_type") == "attached_to" and "security-group" in pattern.get("target_type", ""):
            properties["direction"] = "inbound"
        
        # Add field value for debugging
        if isinstance(field_value, (str, int)):
            properties["source_field_value"] = str(field_value)
        
        return properties
    
    def _build_internet_exposure(self, assets_by_type: Dict[str, List[Asset]]) -> List[Relationship]:
        """Build internet exposure relationships (special case - not in index yet)"""
        relationships = []
        
        # Check for public IPs, public LBs, public buckets
        instances = assets_by_type.get("ec2.instance", [])
        for instance in instances:
            public_ip = instance.metadata.get("public_ip") or instance.metadata.get("PublicIpAddress")
            if public_ip:
                relationships.append(Relationship(
                    tenant_id=self.tenant_id,
                    scan_run_id=self.scan_run_id,
                    provider=instance.provider.value,
                    account_id=instance.account_id,
                    region=instance.region,
                    relation_type=RelationType.INTERNET_CONNECTED,
                    from_uid=instance.resource_uid,
                    to_uid="internet:0.0.0.0/0",
                    properties={"public_ip": public_ip}
                ))
        
        # Public S3 buckets
        buckets = assets_by_type.get("s3.bucket", [])
        for bucket in buckets:
            public_access = bucket.metadata.get("public_access") or bucket.tags.get("Public")
            if public_access:
                relationships.append(Relationship(
                    tenant_id=self.tenant_id,
                    scan_run_id=self.scan_run_id,
                    provider=bucket.provider.value,
                    account_id=bucket.account_id,
                    region=bucket.region,
                    relation_type=RelationType.INTERNET_CONNECTED,
                    from_uid=bucket.resource_uid,
                    to_uid="internet:0.0.0.0/0",
                    properties={"public_access": True}
                ))
        
        return relationships
