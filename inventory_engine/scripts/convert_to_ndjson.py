#!/usr/bin/env python3
"""
Convert aws_relationship_index.json to NDJSON format

Splits into:
- aws_relationship_index_metadata.json (small metadata)
- aws_relationship_index.ndjson (one relationship per line)
"""

import json
from pathlib import Path
from typing import Dict, Any, List

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = PROJECT_ROOT / "inventory-engine" / "inventory_engine" / "config"
INPUT_FILE = CONFIG_DIR / "aws_relationship_index.json"
METADATA_FILE = CONFIG_DIR / "aws_relationship_index_metadata.json"
NDJSON_FILE = CONFIG_DIR / "aws_relationship_index.ndjson"

def convert_to_ndjson():
    """Convert JSON index to NDJSON format."""
    print(f"Loading {INPUT_FILE}...")
    with open(INPUT_FILE, "r") as f:
        data = json.load(f)
    
    # Extract metadata
    metadata = {
        "version": data.get("version"),
        "generated_at": data.get("generated_at"),
        "source": data.get("source"),
        "metadata": data.get("metadata", {}),
    }
    
    # Extract relationships and flatten
    relationships = []
    
    # From by_resource_type
    by_resource = data.get("classifications", {}).get("by_resource_type", {})
    for resource_type, info in by_resource.items():
        rels = info.get("relationships", [])
        for rel in rels:
            relationships.append({
                "from_type": resource_type,
                "relation_type": rel.get("relation_type"),
                "to_type": rel.get("target_type"),
                "source_field": rel.get("source_field"),
                "target_uid_pattern": rel.get("target_uid_pattern"),
                "source_field_item": rel.get("source_field_item"),
                "_source": "by_resource_type"
            })
    
    # From by_discovery_operation
    by_discovery = data.get("classifications", {}).get("by_discovery_operation", {})
    for discovery_id, info in by_discovery.items():
        rels = info.get("relationships", [])
        for rel in rels:
            relationships.append({
                "from_discovery": discovery_id,
                "relation_type": rel.get("relation_type"),
                "to_type": rel.get("target_type"),
                "source_field": rel.get("source_field"),
                "target_uid_pattern": rel.get("target_uid_pattern"),
                "source_field_item": rel.get("source_field_item"),
                "_source": "by_discovery_operation"
            })
    
    # From by_service (flatten nested structure)
    by_service = data.get("by_service", {})
    for service, categories in by_service.items():
        for category, rels in categories.items():
            for rel in rels:
                relationships.append({
                    "from_type": rel.get("from_type"),
                    "relation_type": rel.get("relation_type"),
                    "to_type": rel.get("to_type"),
                    "source_field": rel.get("source_field"),
                    "target_uid_pattern": rel.get("target_uid_pattern"),
                    "source_field_item": rel.get("source_field_item"),
                    "_source": f"by_service.{service}.{category}"
                })
    
    # Remove duplicates (keep first occurrence)
    seen = set()
    unique_rels = []
    for rel in relationships:
        key = (
            rel.get("from_type") or rel.get("from_discovery"),
            rel.get("relation_type"),
            rel.get("to_type"),
            rel.get("source_field")
        )
        if key not in seen:
            seen.add(key)
            unique_rels.append(rel)
    
    print(f"Extracted {len(unique_rels)} unique relationships")
    
    # Save metadata
    with open(METADATA_FILE, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"Saved metadata to: {METADATA_FILE}")
    
    # Save NDJSON (one relationship per line)
    with open(NDJSON_FILE, "w") as f:
        for rel in unique_rels:
            f.write(json.dumps(rel) + "\n")
    print(f"Saved {len(unique_rels)} relationships to: {NDJSON_FILE}")
    
    # Calculate sizes
    input_size = INPUT_FILE.stat().st_size
    metadata_size = METADATA_FILE.stat().st_size
    ndjson_size = NDJSON_FILE.stat().st_size
    
    print(f"\nSize comparison:")
    print(f"  Original JSON: {input_size:,} bytes")
    print(f"  Metadata JSON: {metadata_size:,} bytes")
    print(f"  NDJSON: {ndjson_size:,} bytes")
    print(f"  Total: {metadata_size + ndjson_size:,} bytes")
    print(f"  Savings: {input_size - (metadata_size + ndjson_size):,} bytes")

if __name__ == "__main__":
    convert_to_ndjson()
