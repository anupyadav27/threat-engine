#!/usr/bin/env python3
"""
Build Inventory Classification Index

Aggregates classification data from pythonsdk-database/aws into a single
classification index for the inventory engine.

The index maps:
- discovery_id patterns → should_inventory / use_for_enrichment
- service + resource_type → classification
- ARN patterns → classification
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Set
from collections import defaultdict
from datetime import datetime, timezone

# Paths
PROJECT_ROOT = Path(__file__).parent.parent.parent
PYTHONSDK_DB = PROJECT_ROOT / "pythonsdk-database" / "aws"
OUTPUT_DIR = PROJECT_ROOT / "engine_inventory" / "inventory_engine" / "config"
OUTPUT_FILE = OUTPUT_DIR / "aws_inventory_classification_index.json"


def normalize_discovery_id(discovery_id: str) -> str:
    """Normalize discovery ID to pattern (e.g., aws.service.operation)"""
    # Remove aws. prefix if present, keep service.operation
    if discovery_id.startswith("aws."):
        return discovery_id[4:]  # Remove "aws." prefix
    return discovery_id


def extract_service_from_discovery_id(discovery_id: str) -> Optional[str]:
    """Extract service name from discovery_id"""
    parts = discovery_id.split(".")
    if len(parts) >= 2:
        return parts[0] if not parts[0].startswith("aws") else parts[1]
    return None


def normalize_resource_type_name(service: str, resource_type: str) -> str:
    """
    Normalize verbose SDK resource type names to clean CSPM-standard names.
    
    Examples:
        iam.user_detail_list -> user
        ec2.security_group_security_group -> security-group
        iam.attached_policy_policy -> policy
        iam.group_group -> group
        iam.instance_profil_instance_profile -> instance-profile
    """
    # Remove duplicate/redundant words
    parts = resource_type.split("_")
    
    # Remove duplicates (e.g., security_group_security_group -> security_group)
    seen = set()
    unique_parts = []
    for part in parts:
        if part not in seen:
            seen.add(part)
            unique_parts.append(part)
        elif len(unique_parts) > 0 and unique_parts[-1] != part:
            # If we see a duplicate but it's not immediately after, keep it
            unique_parts.append(part)
    
    normalized = "_".join(unique_parts)
    
    # Service-specific normalization rules
    normalization_rules = {
        "iam": {
            "user_detail_list": "user",
            "user_detail": "user",
            "group_group": "group",
            "attached_policy_policy": "policy",
            "instance_profil_instance_profile": "instance-profile",
            "instance_profile": "instance-profile",
            "role_detail": "role",
            "role_list": "role"
        },
        "ec2": {
            "security_group_security_group": "security-group",
            "security_group": "security-group",
            "subnet_subnet": "subnet",
            "vpc_vpc": "vpc",
            "instance_instance": "instance",
            "volume_volume": "volume"
        },
        "kms": {
            "key_key": "key",
            "alias_alias": "alias"
        },
        "lambda": {
            "function_function": "function"
        },
        "dynamodb": {
            "table_table": "table"
        },
        "s3": {
            "bucket_bucket": "bucket"
        }
    }
    
    # Apply service-specific rules
    if service in normalization_rules:
        if normalized in normalization_rules[service]:
            return normalization_rules[service][normalized]
    
    # Generic normalization: remove common suffixes
    suffixes_to_remove = ["_list", "_detail", "_detail_list", "_metadata", "_summary"]
    for suffix in suffixes_to_remove:
        if normalized.endswith(suffix):
            normalized = normalized[:-len(suffix)]
            break
    
    # Convert underscores to hyphens for multi-word types (CSPM standard)
    if "_" in normalized and len(normalized.split("_")) > 1:
        # Keep single words as-is, convert multi-word to hyphenated
        normalized = normalized.replace("_", "-")
    
    return normalized


def load_resource_inventory_report(service_path: Path) -> Optional[Dict]:
    """Load resource_inventory_report.json if exists"""
    report_file = service_path / "resource_inventory_report.json"
    if report_file.exists():
        try:
            with open(report_file, 'r') as f:
                return json.load(f)
        except Exception:
            return None
    return None


def load_resource_operations_prioritized(service_path: Path) -> Optional[Dict]:
    """Load resource_operations_prioritized.json if exists"""
    ops_file = service_path / "resource_operations_prioritized.json"
    if ops_file.exists():
        try:
            with open(ops_file, 'r') as f:
                return json.load(f)
        except Exception:
            return None
    return None


def build_classification_index() -> Dict:
    """Build comprehensive classification index from database"""
    
    index = {
        "version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "pythonsdk-database/aws",
        "classifications": {
            "by_discovery_operation": {},  # discovery_id -> classification
            "by_service_resource": {},      # service.resource_type -> classification
            "by_service": {},                # service -> {primary, ephemeral, config, sub_resources}
            "by_arn_pattern": {},           # ARN pattern -> classification
            "ephemeral_operations": [],     # Operations that produce ephemeral resources
            "config_operations": [],       # Operations that produce config-only resources
            "sub_resource_operations": []  # Operations that produce sub-resources
        },
        "metadata": {
            "services_processed": 0,
            "resources_classified": 0,
            "operations_mapped": 0
        }
    }
    
    # Track what we've seen
    services_processed = set()
    resources_classified = 0
    operations_mapped = 0
    
    # Process each service directory
    if not PYTHONSDK_DB.exists():
        print(f"Error: PythonSDK database not found at {PYTHONSDK_DB}")
        return index
    
    for service_dir in sorted(PYTHONSDK_DB.iterdir()):
        if not service_dir.is_dir():
            continue
        
        service_name = service_dir.name
        
        # Skip non-service directories
        if service_name.startswith("_") or service_name in ["test_reports", "boto3_dependencies_with_python_names_fully_enriched.json"]:
            continue
        
        # Try to load both report types
        inventory_report = load_resource_inventory_report(service_dir)
        ops_prioritized = load_resource_operations_prioritized(service_dir)
        
        if not inventory_report and not ops_prioritized:
            continue
        
        services_processed.add(service_name)
        
        # Process resource_inventory_report.json
        if inventory_report:
            for resource in inventory_report.get("resources", []):
                resource_type = resource.get("resource_type", "")
                classification = resource.get("classification", "")
                should_inventory = resource.get("should_inventory", False)
                use_for_enrichment = resource.get("use_for_enrichment", False)
                
                # Map service.resource_type
                key = f"{service_name}.{resource_type}"
                normalized_type = normalize_resource_type_name(service_name, resource_type)
                index["classifications"]["by_service_resource"][key] = {
                    "classification": classification,
                    "should_inventory": should_inventory,
                    "use_for_enrichment": use_for_enrichment,
                    "has_arn": resource.get("has_arn", False),
                    "normalized_type": normalized_type
                }
                resources_classified += 1
                
                # Map operations to classification
                for op in resource.get("root_operations", []):
                    discovery_id = f"aws.{service_name}.{op.lower()}"
                    normalized = normalize_discovery_id(discovery_id)
                    
                    if not should_inventory:
                        if classification == "EPHEMERAL":
                            index["classifications"]["ephemeral_operations"].append(normalized)
                        elif classification == "CONFIGURATION":
                            index["classifications"]["config_operations"].append(normalized)
                        elif classification == "SUB_RESOURCE":
                            index["classifications"]["sub_resource_operations"].append(normalized)
                    
                    normalized_type = normalize_resource_type_name(service_name, resource_type)
                    index["classifications"]["by_discovery_operation"][normalized] = {
                        "classification": classification,
                        "should_inventory": should_inventory,
                        "use_for_enrichment": use_for_enrichment,
                        "service": service_name,
                        "resource_type": resource_type,
                        "normalized_type": normalized_type
                    }
                    operations_mapped += 1
        
        # Process resource_operations_prioritized.json
        if ops_prioritized:
            # Process primary resources
            for resource in ops_prioritized.get("primary_resources", []):
                resource_type = resource.get("resource_type", "")
                classification = resource.get("classification", "PRIMARY_RESOURCE")
                should_inventory = resource.get("should_inventory", True)
                use_for_enrichment = resource.get("use_for_enrichment", False)
                
                # Map service.resource_type
                key = f"{service_name}.{resource_type}"
                normalized_type = normalize_resource_type_name(service_name, resource_type)
                if key not in index["classifications"]["by_service_resource"]:
                    index["classifications"]["by_service_resource"][key] = {
                        "classification": classification,
                        "should_inventory": should_inventory,
                        "use_for_enrichment": use_for_enrichment,
                        "has_arn": resource.get("has_arn", False),
                        "normalized_type": normalized_type
                    }
                    resources_classified += 1
                
                # Map operations
                for op_list in resource.get("operations", {}).values():
                    for op in op_list:
                        discovery_id = f"aws.{service_name}.{op.lower()}"
                        normalized = normalize_discovery_id(discovery_id)
                        
                        if normalized not in index["classifications"]["by_discovery_operation"]:
                            index["classifications"]["by_discovery_operation"][normalized] = {
                                "classification": classification,
                                "should_inventory": should_inventory,
                                "use_for_enrichment": use_for_enrichment,
                                "service": service_name,
                                "resource_type": resource_type,
                                "normalized_type": normalized_type
                            }
                            operations_mapped += 1
    
    # Apply manual overrides for known issues
    # SecurityHub products should NOT be inventoried (marketplace products, not resources)
    index["classifications"]["ephemeral_operations"].extend([
        "securityhub.describe_products",
        "securityhub.describe_products_v2",
        "securityhub.get_findings",  # Findings are ephemeral
        "securityhub.get_findings_v2"
    ])
    
    # EC2 security-group-rules are sub-resources
    index["classifications"]["sub_resource_operations"].extend([
        "ec2.describe_security_group_rules"
    ])
    
    # Remove duplicates
    index["classifications"]["ephemeral_operations"] = sorted(list(set(index["classifications"]["ephemeral_operations"])))
    index["classifications"]["config_operations"] = sorted(list(set(index["classifications"]["config_operations"])))
    index["classifications"]["sub_resource_operations"] = sorted(list(set(index["classifications"]["sub_resource_operations"])))
    
    # Build service-level summary for easy lookup
    index["classifications"]["by_service"] = {}
    for key, val in index["classifications"]["by_service_resource"].items():
        if "." in key:
            service, resource_type = key.split(".", 1)
            if service not in index["classifications"]["by_service"]:
                index["classifications"]["by_service"][service] = {
                    "primary_resources": [],
                    "ephemeral_resources": [],
                    "config_resources": [],
                    "sub_resources": []
                }

            classification = val["classification"]
            if classification == "PRIMARY_RESOURCE":
                index["classifications"]["by_service"][service]["primary_resources"].append(resource_type)
            elif classification == "EPHEMERAL":
                index["classifications"]["by_service"][service]["ephemeral_resources"].append(resource_type)
            elif classification == "CONFIGURATION":
                index["classifications"]["by_service"][service]["config_resources"].append(resource_type)
            elif classification == "SUB_RESOURCE":
                index["classifications"]["by_service"][service]["sub_resources"].append(resource_type)

    # Sort resource lists for consistency
    for service_data in index["classifications"]["by_service"].values():
        for key in service_data:
            service_data[key] = sorted(list(set(service_data[key])))

    # Update metadata
    index["metadata"]["services_processed"] = len(services_processed)
    index["metadata"]["resources_classified"] = resources_classified
    index["metadata"]["operations_mapped"] = len(index["classifications"]["by_discovery_operation"])
    index["metadata"]["services_with_classifications"] = len(index["classifications"]["by_service"])
    
    return index


def main():
    """Main execution"""
    print("Building Inventory Classification Index...")
    print(f"Source: {PYTHONSDK_DB}")
    print(f"Output: {OUTPUT_FILE}")
    print()
    
    # Build index
    index = build_classification_index()
    
    # Create output directory
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    # Write index
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(index, f, indent=2)
    
    # Print summary
    print("=" * 80)
    print("Classification Index Built Successfully")
    print("=" * 80)
    print(f"Services Processed: {index['metadata']['services_processed']}")
    print(f"Resources Classified: {index['metadata']['resources_classified']}")
    print(f"Operations Mapped: {index['metadata']['operations_mapped']}")
    print()
    print(f"Ephemeral Operations: {len(index['classifications']['ephemeral_operations'])}")
    print(f"Config Operations: {len(index['classifications']['config_operations'])}")
    print(f"Sub-Resource Operations: {len(index['classifications']['sub_resource_operations'])}")
    print()
    print(f"Output written to: {OUTPUT_FILE}")
    print("=" * 80)


if __name__ == "__main__":
    main()
