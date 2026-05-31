#!/usr/bin/env python3
"""
Catalog search — grep over CSPM rule catalog and discovery data with structured output.

Usage:
  python3 .claude/scripts/catalog_search.py <query> [--csp aws|azure|gcp|oci|alicloud|ibm] [--type rule|discovery|all] [--limit 20]

Examples:
  python3 .claude/scripts/catalog_search.py "s3 encryption"
  python3 .claude/scripts/catalog_search.py "public access" --csp aws --type rule
  python3 .claude/scripts/catalog_search.py "rds" --type discovery --limit 5
  python3 .claude/scripts/catalog_search.py "internet exposed" --csp aws

Output: JSON lines, each: {"type": "rule"|"discovery", "csp": "aws", "file": "...", "rule_id": "...", "match": "..."}
"""

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
RULE_DIR = REPO_ROOT / "catalog" / "rule"
DISCOVERY_DIR = REPO_ROOT / "catalog" / "discovery_generator_data"

CSP_MAP = {
    "aws": ["aws", "amazon"],
    "azure": ["azure"],
    "gcp": ["gcp", "google"],
    "oci": ["oci", "oracle"],
    "alicloud": ["alicloud", "aliyun"],
    "ibm": ["ibm"],
}


def search_rules(query: str, csp: str | None, limit: int) -> list[dict]:
    results = []
    pattern = re.compile(query, re.IGNORECASE)

    glob_dirs = []
    if csp:
        glob_dirs = [RULE_DIR / f"{csp}_rule_check"]
    else:
        glob_dirs = [d for d in RULE_DIR.iterdir() if d.is_dir() and d.name.endswith("_rule_check")]

    for rule_dir in glob_dirs:
        if not rule_dir.exists():
            continue
        csp_name = rule_dir.name.replace("_rule_check", "")
        for yaml_file in sorted(rule_dir.rglob("*.yaml")):
            try:
                content = yaml_file.read_text(errors="replace")
            except OSError:
                continue
            matches = pattern.findall(content)
            if not matches:
                continue
            # extract rule_id from filename or first line
            rule_id = yaml_file.stem
            # try to extract title from YAML
            title_match = re.search(r'^title:\s*["\']?(.+?)["\']?\s*$', content, re.MULTILINE)
            title = title_match.group(1) if title_match else ""
            results.append({
                "type": "rule",
                "csp": csp_name,
                "file": str(yaml_file.relative_to(REPO_ROOT)),
                "rule_id": rule_id,
                "title": title,
                "match_count": len(matches),
                "first_match": matches[0] if matches else "",
            })
            if len(results) >= limit:
                return results
    return results


def search_discovery(query: str, csp: str | None, limit: int) -> list[dict]:
    results = []
    pattern = re.compile(query, re.IGNORECASE)

    if csp:
        search_dirs = [DISCOVERY_DIR / csp]
    else:
        search_dirs = [d for d in DISCOVERY_DIR.iterdir() if d.is_dir()] if DISCOVERY_DIR.exists() else []

    for disc_dir in search_dirs:
        if not disc_dir.exists():
            continue
        csp_name = disc_dir.name
        for yaml_file in sorted(disc_dir.rglob("*.yaml")):
            try:
                content = yaml_file.read_text(errors="replace")
            except OSError:
                continue
            matches = pattern.findall(content)
            if not matches:
                continue
            results.append({
                "type": "discovery",
                "csp": csp_name,
                "file": str(yaml_file.relative_to(REPO_ROOT)),
                "rule_id": yaml_file.stem,
                "title": "",
                "match_count": len(matches),
                "first_match": matches[0] if matches else "",
            })
            if len(results) >= limit:
                return results
    return results


def main():
    parser = argparse.ArgumentParser(description="Search CSPM rule + discovery catalog")
    parser.add_argument("query", help="Search term (regex supported)")
    parser.add_argument("--csp", choices=["aws", "azure", "gcp", "oci", "alicloud", "ibm"], default=None)
    parser.add_argument("--type", choices=["rule", "discovery", "all"], default="all", dest="search_type")
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--json", action="store_true", help="Output as JSON array instead of NDJSON")
    args = parser.parse_args()

    results = []
    if args.search_type in ("rule", "all"):
        results.extend(search_rules(args.query, args.csp, args.limit))
    if args.search_type in ("discovery", "all"):
        results.extend(search_discovery(args.query, args.csp, args.limit - len(results)))

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print(json.dumps(r))

    print(f"\n# {len(results)} result(s) for query={args.query!r} csp={args.csp} type={args.search_type}",
          file=sys.stderr)


if __name__ == "__main__":
    main()