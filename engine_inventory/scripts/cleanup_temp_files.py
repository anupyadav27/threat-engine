#!/usr/bin/env python3
"""
Clean up temporary generated relationship files

Removes:
- generated_relationships_*.json (original generated files)
- fixed_relationships_*.json (fixed versions - already merged)
- fix_summary.json (summary file)
- generation_summary.json (batch processing summary)

Keeps:
- aws_relationship_index.json (main index)
- relation_types.json (relation types)
- aws_inventory_classification_index.json (classification index)
"""

from pathlib import Path
import json

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = PROJECT_ROOT / "engine_inventory" / "inventory_engine" / "config"

def main():
    """Clean up temporary files."""
    files_to_remove = []
    
    # Generated files
    generated = list(CONFIG_DIR.glob("generated_relationships_*.json"))
    files_to_remove.extend(generated)
    
    # Fixed files (already merged)
    fixed = list(CONFIG_DIR.glob("fixed_relationships_*.json"))
    files_to_remove.extend(fixed)
    
    # Summary files
    summary_files = [
        CONFIG_DIR / "fix_summary.json",
        CONFIG_DIR / "generation_summary.json"
    ]
    for f in summary_files:
        if f.exists():
            files_to_remove.append(f)
    
    print(f"Found {len(files_to_remove)} temporary files to remove")
    
    if not files_to_remove:
        print("No temporary files to clean up!")
        return
    
    # Show what will be removed
    print("\nFiles to remove:")
    for f in sorted(files_to_remove):
        print(f"  - {f.name}")
    
    # Confirm
    response = input("\nRemove these files? (yes/no): ")
    if response.lower() != "yes":
        print("Cancelled.")
        return
    
    # Remove files
    removed = 0
    for f in files_to_remove:
        try:
            f.unlink()
            removed += 1
        except Exception as e:
            print(f"Error removing {f.name}: {e}")
    
    print(f"\n✅ Removed {removed} files")
    print(f"Config directory cleaned!")

if __name__ == "__main__":
    main()
