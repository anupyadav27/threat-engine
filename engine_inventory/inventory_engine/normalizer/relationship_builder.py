"""
Relationship Builder

Builds relationship edges from normalized assets using predefined relationship index.
"""

import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from ..schemas.asset_schema import Asset, Provider
from ..schemas.relationship_schema import Relationship, RelationType


class RelationshipBuilder:
    """Builds relationships between assets using predefined relationship index"""
    
    def __init__(self, tenant_id: str, scan_run_id: str):
        self.tenant_id = tenant_id
        self.scan_run_id = scan_run_id
        self.relationship_index = self._load_relationship_index()
        self.relation_types = self._load_relation_types()
    
    def _load_relationship_index(self) -> Dict[str, Any]:
        """Load predefined relationship index (supports both JSON and NDJSON formats)"""
        config_dir = Path(__file__).parent.parent / "config"
        
        # Try NDJSON format first (preferred for large files)
        ndjson_file = config_dir / "aws_relationship_index.ndjson"
        metadata_file = config_dir / "aws_relationship_index_metadata.json"
        
        if ndjson_file.exists() and metadata_file.exists():
            try:
                # Load metadata
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
                
                # Load relationships from NDJSON and rebuild structure
                by_resource_type = {}
                by_discovery_operation = {}
                
                with open(ndjson_file, 'r') as f:
                    for line in f:
                        if not line.strip():
                            continue
                        rel = json.loads(line)
                        
                        # Rebuild by_resource_type structure
                        from_type = rel.get("from_type")
                        if from_type:
                            if from_type not in by_resource_type:
                                by_resource_type[from_type] = {"relationships": []}
                            
                            by_resource_type[from_type]["relationships"].append({
                                "relation_type": rel.get("relation_type"),
                                "target_type": rel.get("to_type"),
                                "source_field": rel.get("source_field"),
                                "target_uid_pattern": rel.get("target_uid_pattern"),
                                "source_field_item": rel.get("source_field_item"),
                            })
                        
                        # Rebuild by_discovery_operation structure
                        from_discovery = rel.get("from_discovery")
                        if from_discovery:
                            if from_discovery not in by_discovery_operation:
                                by_discovery_operation[from_discovery] = {"relationships": []}
                            
                            by_discovery_operation[from_discovery]["relationships"].append({
                                "relation_type": rel.get("relation_type"),
                                "target_type": rel.get("to_type"),
                                "source_field": rel.get("source_field"),
                                "target_uid_pattern": rel.get("target_uid_pattern"),
                                "source_field_item": rel.get("source_field_item"),
                            })
                
                return {
                    "version": metadata.get("version"),
                    "generated_at": metadata.get("generated_at"),
                    "source": metadata.get("source"),
                    "classifications": {
                        "by_resource_type": by_resource_type,
                        "by_discovery_operation": by_discovery_operation,
                    },
                    "metadata": metadata.get("metadata", {}),
                }
            except Exception as e:
                # Fall back to JSON if NDJSON fails
                pass
        
        # Fallback to JSON format
        index_file = config_dir / "aws_relationship_index.json"
        if not index_file.exists():
            return {}
        try:
            with open(index_file, 'r') as f:
                return json.load(f)
        except Exception:
            return {}
    
    def _load_relation_types(self) -> Set[str]:
        """Load valid relation types"""
        config_dir = Path(__file__).parent.parent / "config"
        types_file = config_dir / "relation_types.json"
        if not types_file.exists():
            return {rt.value for rt in RelationType}
        try:
            with open(types_file, 'r') as f:
                data = json.load(f)
                return {rt.get("id", "") for rt in data.get("relation_types", [])}
        except Exception:
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
