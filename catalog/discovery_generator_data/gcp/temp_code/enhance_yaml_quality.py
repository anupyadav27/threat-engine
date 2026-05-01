#!/usr/bin/env python3
"""
Enhance GCP discovery YAML files to match AWS reference quality.

For each discovery entry in a GCP service YAML:
- Find the matching operation in operation_registry.json (exact or snake->camel)
- Extract 'produces' fields with source='item' -> add as item: block
- Extract 'produces' field with source='output' -> fix items_for path
- Write back the enhanced YAML

Usage:
    python3 enhance_yaml_quality.py [--service SERVICE] [--dry-run]
"""

import os
import sys
import json
import re
import argparse
from pathlib import Path
from typing import Optional, Tuple, List

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML not installed. Run: pip3 install pyyaml")
    sys.exit(1)

GCP_DIR = Path(__file__).parent


def snake_to_camel(name: str) -> str:
    """Convert snake_case to camelCase."""
    return re.sub(r'_([a-z])', lambda m: m.group(1).upper(), name)


def find_operation(discovery_id: str, ops: dict) -> Optional[dict]:
    """Find operation in registry, trying exact match then snake->camel conversion."""
    # Exact match
    if discovery_id in ops:
        return ops[discovery_id]

    # Try converting last segment from snake_case to camelCase
    parts = discovery_id.split('.')
    last = parts[-1]
    camel_last = snake_to_camel(last)
    if camel_last != last:
        candidate = '.'.join(parts[:-1] + [camel_last])
        if candidate in ops:
            return ops[candidate]

    return None


def get_produces_fields(operation: dict) -> Tuple[Optional[str], List[Tuple[str, str]]]:
    """
    Returns (output_path, item_fields) where:
    - output_path: the response collection path (from source='output')
    - item_fields: list of (path, path) for source='item' entries
    """
    produces = operation.get("produces", [])
    output_path = None
    item_fields = []

    for p in produces:
        source = p.get("source", "")
        path = p.get("path", "")

        if source == "output":
            if output_path is None:  # Take the first output path
                output_path = path
        elif source == "item" and path:
            item_fields.append(path)

    return output_path, item_fields


def load_operation_registry(service_dir: Path) -> dict:
    reg_path = service_dir / "operation_registry.json"
    if not reg_path.exists():
        return {}
    with open(reg_path) as f:
        return json.load(f)


def enhance_yaml_content(content: dict, registry: dict) -> Tuple[dict, dict]:
    """
    Enhance a parsed YAML content dict in-place.
    Returns (modified_content, stats).
    """
    ops = registry.get("operations", {})
    stats = {"enhanced": 0, "no_match": 0, "no_produces": 0}

    for entry in content.get("discovery", []):
        discovery_id = entry.get("discovery_id", "")
        emit = entry.get("emit", {})

        operation = find_operation(discovery_id, ops)

        if operation is None:
            stats["no_match"] += 1
            continue

        output_path, item_fields = get_produces_fields(operation)

        if output_path:
            emit["items_for"] = "{{ response." + output_path + " }}"

        if item_fields:
            item_block = {}
            for field_path in item_fields:
                item_block[field_path] = "{{ item." + field_path + " }}"
            emit["item"] = item_block
            stats["enhanced"] += 1
        else:
            stats["no_produces"] += 1

    return content, stats


def write_yaml(yaml_path: Path, content: dict):
    """Write YAML with proper formatting matching the AWS reference style."""
    lines = []
    lines.append(f"version: '{content['version']}'")
    lines.append(f"provider: {content['provider']}")
    lines.append(f"service: {content['service']}")
    lines.append("services:")
    lines.append(f"  client: {content['services']['client']}")
    lines.append(f"  module: {content['services']['module']}")
    lines.append("discovery:")

    for entry in content.get("discovery", []):
        lines.append(f"- discovery_id: {entry['discovery_id']}")
        lines.append("  calls:")
        for call in entry.get("calls", []):
            lines.append(f"  - action: {call['action']}")
            lines.append(f"    save_as: {call['save_as']}")
            lines.append(f"    on_error: {call['on_error']}")
        emit = entry.get("emit", {})
        lines.append("  emit:")
        lines.append(f"    as: {emit.get('as', 'item')}")
        lines.append(f"    items_for: '{emit.get('items_for', '{{ response }}')}'" )

        if "item" in emit:
            lines.append("    item:")
            for field, tmpl in emit["item"].items():
                lines.append(f"      {field}: '{tmpl}'")

    lines.append("checks: []")
    lines.append("")

    with open(yaml_path, "w") as f:
        f.write("\n".join(lines))


def process_service(service_dir: Path, dry_run: bool = False) -> dict:
    """Process a single service directory."""
    service_name = service_dir.name
    yaml_path = service_dir / f"{service_name}_discovery.yaml"

    if not yaml_path.exists():
        return {"service": service_name, "status": "no_yaml", "enhanced": 0, "no_match": 0}

    registry = load_operation_registry(service_dir)
    if not registry:
        return {"service": service_name, "status": "no_registry", "enhanced": 0, "no_match": 0}

    with open(yaml_path) as f:
        content = yaml.safe_load(f)

    if not content or "discovery" not in content:
        return {"service": service_name, "status": "no_discovery", "enhanced": 0, "no_match": 0}

    content, stats = enhance_yaml_content(content, registry)

    if not dry_run:
        write_yaml(yaml_path, content)

    return {
        "service": service_name,
        "status": "done",
        "enhanced": stats["enhanced"],
        "no_match": stats["no_match"],
        "no_produces": stats.get("no_produces", 0),
    }


def main():
    parser = argparse.ArgumentParser(description="Enhance GCP YAML discovery files")
    parser.add_argument("--service", help="Only process this service (by folder name)")
    parser.add_argument("--dry-run", action="store_true", help="Don't write files")
    args = parser.parse_args()

    services_to_process = []

    if args.service:
        service_dir = GCP_DIR / args.service
        if not service_dir.is_dir():
            print(f"ERROR: Service directory not found: {service_dir}")
            sys.exit(1)
        services_to_process = [service_dir]
    else:
        for item in sorted(GCP_DIR.iterdir()):
            if item.is_dir() and not item.name.startswith("__") and not item.name.startswith("."):
                services_to_process.append(item)

    total = len(services_to_process)
    totals = {"done": 0, "no_yaml": 0, "no_registry": 0, "no_discovery": 0,
              "enhanced": 0, "no_match": 0, "no_produces": 0}

    prefix = "[DRY-RUN] " if args.dry_run else ""
    print(f"{prefix}Processing {total} service directories...")

    for i, service_dir in enumerate(services_to_process, 1):
        result = process_service(service_dir, dry_run=args.dry_run)
        status = result.get("status", "unknown")
        totals[status] = totals.get(status, 0) + 1
        totals["enhanced"] += result.get("enhanced", 0)
        totals["no_match"] += result.get("no_match", 0)
        totals["no_produces"] += result.get("no_produces", 0)

        # Print progress for non-done or every 50
        if status != "done" or (args.service):
            print(f"  {prefix}[{i}/{total}] {result['service']}: {status} | "
                  f"enhanced={result.get('enhanced',0)}, "
                  f"no_match={result.get('no_match',0)}, "
                  f"no_produces={result.get('no_produces',0)}")

    print(f"\n{'='*50}")
    print("Summary:")
    print(f"  Total dirs processed:   {total}")
    print(f"  Services done:          {totals.get('done', 0)}")
    print(f"  No YAML:                {totals.get('no_yaml', 0)}")
    print(f"  No operation registry:  {totals.get('no_registry', 0)}")
    print(f"  Entries enhanced:       {totals.get('enhanced', 0)}")
    print(f"  Entries no op match:    {totals.get('no_match', 0)}")
    print(f"  Entries no produces:    {totals.get('no_produces', 0)}")
    if args.dry_run:
        print("  [DRY RUN - no files written]")
    print(f"{'='*50}")


if __name__ == "__main__":
    main()
