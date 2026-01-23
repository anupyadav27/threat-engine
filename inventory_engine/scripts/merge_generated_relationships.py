#!/usr/bin/env python3
"""
Merge fixed generated relationships into CORE_RELATION_MAP

Reads fixed_relationships_*.json files and adds valid relationships to CORE_RELATION_MAP
in build_relationship_index.py
"""

import json
import re
from pathlib import Path
from typing import List, Dict, Any, Set

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = PROJECT_ROOT / "inventory-engine" / "inventory_engine" / "config"
BUILD_SCRIPT = PROJECT_ROOT / "inventory-engine" / "scripts" / "build_relationship_index.py"

def load_fixed_relationships() -> List[Dict[str, Any]]:
    """Load all fixed relationship files."""
    fixed_files = list(CONFIG_DIR.glob("fixed_relationships_*.json"))
    all_relationships = []
    
    for file_path in sorted(fixed_files):
        with open(file_path, "r") as f:
            data = json.load(f)
        
        relationships = data.get("relationships", [])
        service = data.get("service", "unknown")
        
        # Filter out relationships that need review
        valid_rels = [r for r in relationships if not r.get("_needs_review")]
        
        for rel in valid_rels:
            # Remove internal fields
            rel_clean = {k: v for k, v in rel.items() if not k.startswith("_")}
            rel_clean["_source"] = f"generated_{service}"
            all_relationships.append(rel_clean)
    
    return all_relationships

def format_relationship_for_code(rel: Dict[str, Any]) -> str:
    """Format a relationship as Python dict code."""
    from_type = rel.get("from_type", "")
    relation_type = rel.get("relation_type", "")
    to_type = rel.get("to_type", "")
    source_field = rel.get("source_field", "")
    target_uid_pattern = rel.get("target_uid_pattern", "")
    source_field_item = rel.get("source_field_item")
    
    lines = [
        f'    {{"from_type": "{from_type}", "relation_type": "{relation_type}", "to_type": "{to_type}",',
        f'     "source_field": "{source_field}", "target_uid_pattern": "{target_uid_pattern}"'
    ]
    
    if source_field_item:
        lines[1] = lines[1].rstrip() + ','
        lines.append(f'     "source_field_item": "{source_field_item}"')
    
    lines[-1] = lines[-1] + '},'
    
    return '\n'.join(lines)

def find_insertion_point(content: str) -> int:
    """Find where to insert new relationships in CORE_RELATION_MAP."""
    # Find the end of CORE_RELATION_MAP (before the closing bracket)
    pattern = r'(CORE_RELATION_MAP: List\[Dict\[str, Any\]\] = \[.*?)(\n\s*\]\s*#.*?End of CORE_RELATION_MAP)'
    match = re.search(pattern, content, re.DOTALL)
    
    if match:
        # Find the last entry before the closing bracket
        before_close = match.group(1)
        # Find last }, before the closing ]
        last_entry = before_close.rfind('},')
        if last_entry != -1:
            return last_entry + 2  # After the }, and newline
    
    # Fallback: find the last entry in CORE_RELATION_MAP
    lines = content.split('\n')
    in_map = False
    last_map_line = 0
    
    for i, line in enumerate(lines):
        if 'CORE_RELATION_MAP:' in line:
            in_map = True
        elif in_map and line.strip().startswith(']'):
            last_map_line = i - 1
            break
        elif in_map and line.strip().endswith('},'):
            last_map_line = i
    
    # Find the position after the last entry
    pos = 0
    for i in range(last_map_line + 1):
        pos += len(lines[i]) + 1
    
    return pos

def merge_relationships(relationships: List[Dict[str, Any]], existing_map: Set[tuple]) -> List[Dict[str, Any]]:
    """Merge new relationships, avoiding duplicates."""
    new_rels = []
    
    for rel in relationships:
        # Create unique key
        key = (
            rel.get("from_type"),
            rel.get("relation_type"),
            rel.get("to_type"),
            rel.get("source_field")
        )
        
        if key not in existing_map:
            new_rels.append(rel)
            existing_map.add(key)
    
    return new_rels

def main():
    """Merge fixed relationships into CORE_RELATION_MAP."""
    print("Loading fixed relationships...")
    all_relationships = load_fixed_relationships()
    print(f"Found {len(all_relationships)} total relationships")
    
    # Read current CORE_RELATION_MAP to find duplicates
    with open(BUILD_SCRIPT, "r") as f:
        content = f.read()
    
    # Extract existing relationships
    existing_map = set()
    map_match = re.search(r'CORE_RELATION_MAP: List\[Dict\[str, Any\]\] = \[(.*?)\]', content, re.DOTALL)
    if map_match:
        map_content = map_match.group(1)
        # Extract from_type, relation_type, to_type, source_field from existing entries
        entries = re.findall(r'\{"from_type":\s*"([^"]+)",\s*"relation_type":\s*"([^"]+)",\s*"to_type":\s*"([^"]+)",\s*"source_field":\s*"([^"]+)"', map_content)
        for entry in entries:
            existing_map.add(entry)
    
    print(f"Found {len(existing_map)} existing relationships in CORE_RELATION_MAP")
    
    # Merge new relationships
    new_rels = merge_relationships(all_relationships, existing_map)
    print(f"Adding {len(new_rels)} new relationships")
    
    if not new_rels:
        print("No new relationships to add!")
        return
    
    # Group by service for better organization
    by_service: Dict[str, List[Dict[str, Any]]] = {}
    for rel in new_rels:
        service = rel.get("from_type", "").split(".", 1)[0] if "." in rel.get("from_type", "") else "other"
        if service not in by_service:
            by_service[service] = []
        by_service[service].append(rel)
    
    # Format for insertion
    formatted_entries = []
    formatted_entries.append("\n    # ---------------------------------------------------------------------")
    formatted_entries.append("    # Generated relationships (from OpenAI agent)")
    formatted_entries.append("    # ---------------------------------------------------------------------")
    
    for service in sorted(by_service.keys()):
        formatted_entries.append(f"\n    # {service.upper()}")
        for rel in by_service[service]:
            formatted_entries.append(format_relationship_for_code(rel))
    
    new_code = "\n".join(formatted_entries)
    
    # Find insertion point
    insertion_point = find_insertion_point(content)
    
    # Insert new relationships
    new_content = content[:insertion_point] + "\n" + new_code + "\n" + content[insertion_point:]
    
    # Write back
    backup_file = BUILD_SCRIPT.with_suffix('.py.backup')
    with open(backup_file, "w") as f:
        f.write(content)
    print(f"Backup saved to: {backup_file}")
    
    with open(BUILD_SCRIPT, "w") as f:
        f.write(new_content)
    
    print(f"\n✅ Added {len(new_rels)} relationships to CORE_RELATION_MAP")
    print(f"   Services: {', '.join(sorted(by_service.keys()))}")
    print(f"\nNext steps:")
    print("1. Review the changes in build_relationship_index.py")
    print("2. Rebuild relationship index: python3 scripts/build_relationship_index.py")
    print("3. Test with a scan")

if __name__ == "__main__":
    main()
