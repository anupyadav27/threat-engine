#!/usr/bin/env python3
"""
Generate .claude/context/data_flow.ndjson from live code sources.

Reads:
  - shared/api_gateway/bff/__init__.py        (view → file mapping from comments)
  - shared/api_gateway/main.py                (SERVICE_ROUTES engine → prefix)
  - frontend/src/lib/constants.js             (ENGINE_ENDPOINTS + NAV_ITEMS)
  - shared/api_gateway/bff/*.py               (engine URLs called per view)

Writes:
  - .claude/context/data_flow.ndjson          (one line per UI page/view)

Run after any change to:
  - shared/api_gateway/bff/*.py
  - frontend/src/lib/constants.js ENGINE_ENDPOINTS
  - shared/api_gateway/main.py SERVICE_ROUTES

Usage:
  python3 scripts/generate_data_flow.py
  python3 scripts/generate_data_flow.py --dry-run
"""

import json
import re
import sys
import os
from datetime import date
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
BFF_DIR = REPO_ROOT / "shared/api_gateway/bff"
BFF_INIT = BFF_DIR / "__init__.py"
MAIN_PY = REPO_ROOT / "shared/api_gateway/main.py"
CONSTANTS_JS = REPO_ROOT / "frontend/src/lib/constants.js"
OUTPUT = REPO_ROOT / ".claude/context/data_flow.ndjson"


def parse_bff_view_map() -> dict[str, str]:
    """Extract view_name → bff_file from __init__.py comment block."""
    view_map = {}
    text = BFF_INIT.read_text()
    # Match lines like: "        dashboard.py   -- /views/dashboard"
    pattern = re.compile(r"(\w[\w_]+\.py)\s+--\s+(/views/[\w/\-{}]+)")
    for match in pattern.finditer(text):
        bff_file, view_path = match.group(1), match.group(2)
        # Normalise: /views/threats/attack-paths → threats/attack-paths
        view_key = view_path.replace("/views/", "")
        view_map[view_key] = f"bff/{bff_file}"
    return view_map


def parse_service_routes() -> dict[str, dict]:
    """Extract SERVICE_ROUTES engine → url/prefixes from main.py."""
    text = MAIN_PY.read_text()
    engines = {}
    # Find each engine block between quotes
    block_pattern = re.compile(
        r'"([\w\-]+)":\s*\{[^}]*?"url":\s*os\.getenv\([^,]+,\s*"([^"]+)"\)'
        r'[^}]*?"prefix(?:es)?":\s*(\[[^\]]+\]|"[^"]+")',
        re.DOTALL,
    )
    for m in block_pattern.finditer(text):
        name, url, prefixes_raw = m.group(1), m.group(2), m.group(3)
        if prefixes_raw.startswith("["):
            prefixes = re.findall(r'"([^"]+)"', prefixes_raw)
        else:
            prefixes = [prefixes_raw.strip('"')]
        engines[name] = {"url": url, "prefixes": prefixes}
    return engines


def scan_engine_calls(bff_file: str) -> list[str]:
    """Grep bff file for engine service URL references (engine-* hostnames)."""
    path = BFF_DIR.parent / bff_file  # relative to shared/api_gateway/
    # Also try just bff_file relative to bff/
    alt_path = BFF_DIR.parent / "bff" / Path(bff_file).name
    if not path.exists() and alt_path.exists():
        path = alt_path
    if not path.exists():
        return []
    text = path.read_text()
    # Match engine service hostnames: engine-*, or env var names like THREAT_ENGINE_URL
    engine_refs = set()
    # Pattern 1: http://engine-* direct URL references
    for m in re.finditer(r'engine-([\w\-]+)', text):
        engine_refs.add(m.group(1))
    # Pattern 2: os.getenv("X_ENGINE_URL") references
    for m in re.finditer(r'getenv\("(\w+)_ENGINE_URL', text):
        name = m.group(1).lower().replace("_", "-")
        engine_refs.add(name)
    # Pattern 3: httpx/aiohttp calls to service variables
    for m in re.finditer(r'(THREAT|CHECK|COMPLIANCE|IAM|DATASEC|RISK|NETWORK|CDR|VULN|BILLING)\w*_URL', text):
        name = m.group(1).lower()
        engine_refs.add(name)
    return sorted(engine_refs)


def build_ui_page_map() -> list[dict]:
    """
    Static UI page → BFF view mapping derived from NAV_ITEMS + known patterns.
    Kept here rather than parsed from JS (JSX parsing is fragile).
    Update this dict when adding new nav items or page routes.
    """
    return [
        {"ui_page": "/dashboard",             "ui_fn": "fetchView",      "bff_view": "dashboard",                "note": "cross-engine summary"},
        {"ui_page": "/inventory",             "ui_fn": "fetchView",      "bff_view": "inventory",               "note": "asset list + KPIs"},
        {"ui_page": "/threats-v1",            "ui_fn": "fetchView",      "bff_view": "threats_v1",              "note": "T1/T2 incidents"},
        {"ui_page": "/threats/graph",         "ui_fn": "fetchView",      "bff_view": "threats/graph",           "note": "Neo4j graph data"},
        {"ui_page": "/threats/trends",        "ui_fn": "fetchView",      "bff_view": "threat-posture-delta",    "note": "90-day posture trend"},
        {"ui_page": "/threats (old)",         "ui_fn": "fetchView",      "bff_view": "threats",                 "note": "legacy threat view"},
        {"ui_page": "/misconfig",             "ui_fn": "fetchView",      "bff_view": "misconfig",               "note": "check findings summary + KPIs"},
        {"ui_page": "/misconfig (table)",     "ui_fn": "getFromEngine",  "engine_key": "check",                 "engine_path": "/api/v1/check/findings", "note": "paginated raw findings"},
        {"ui_page": "/compliance",            "ui_fn": "fetchView",      "bff_view": "compliance",              "note": "framework scores"},
        {"ui_page": "/compliance/matrix",     "ui_fn": "getFromEngine",  "engine_key": "compliance",            "engine_path": "/api/v1/compliance/matrix"},
        {"ui_page": "/iam",                   "ui_fn": "fetchView",      "bff_view": "iam",                     "note": "IAM posture KPIs"},
        {"ui_page": "/network-security",      "ui_fn": "fetchView",      "bff_view": "network-security"},
        {"ui_page": "/encryption",            "ui_fn": "fetchView",      "bff_view": "encryption"},
        {"ui_page": "/container-security",    "ui_fn": "fetchView",      "bff_view": "container-security"},
        {"ui_page": "/ai-security",           "ui_fn": "fetchView",      "bff_view": "ai-security"},
        {"ui_page": "/cdr",                   "ui_fn": "fetchView",      "bff_view": "cdr"},
        {"ui_page": "/cwpp",                  "ui_fn": "fetchView",      "bff_view": "cwpp"},
        {"ui_page": "/datasec",               "ui_fn": "fetchView",      "bff_view": "datasec"},
        {"ui_page": "/database-security",     "ui_fn": "fetchView",      "bff_view": "database-security"},
        {"ui_page": "/risk",                  "ui_fn": "fetchView",      "bff_view": "risk"},
        {"ui_page": "/vulnerability",         "ui_fn": "fetchView",      "bff_view": "vulnerability"},
        {"ui_page": "/vulnerability (table)", "ui_fn": "getFromEngine",  "engine_key": "vulnerability",        "engine_path": "/api/v1/vulnerabilities"},
        {"ui_page": "/secops",                "ui_fn": "fetchView",      "bff_view": "secops"},
        {"ui_page": "/rules",                 "ui_fn": "fetchView",      "bff_view": "rules",                   "note": "rules library: config+cdr+threat+custom+suppressions"},
        {"ui_page": "/scans",                 "ui_fn": "fetchView",      "bff_view": "scans"},
        {"ui_page": "/onboarding",            "ui_fn": "fetchView",      "bff_view": "onboarding/schedules"},
        {"ui_page": "/reports",               "ui_fn": "fetchView",      "bff_view": "reports"},
        {"ui_page": "/admin/billing",         "ui_fn": "fetchView",      "bff_view": "billing",                 "note": "org_admin+ only"},
        {"ui_page": "/admin/dashboard",       "ui_fn": "fetchView",      "bff_view": "platform-admin",          "note": "platform_admin only"},
        {"ui_page": "/settings/users",        "ui_fn": "fetchView",      "bff_view": "users",                   "note": "org_admin+"},
        {"ui_page": "/settings/groups",       "ui_fn": "fetchView",      "bff_view": "groups",                  "note": "org_admin+"},
    ]


def generate(dry_run: bool = False) -> None:
    print("Reading BFF view map...")
    view_map = parse_bff_view_map()
    print(f"  Found {len(view_map)} BFF views")

    print("Reading SERVICE_ROUTES...")
    service_routes = parse_service_routes()
    print(f"  Found {len(service_routes)} engine routes")

    print("Building UI page entries...")
    ui_pages = build_ui_page_map()

    lines = []
    meta = {
        "_meta": {
            "v": "1.1",
            "refreshed_at": str(date.today()),
            "tied_to": "shared/api_gateway/bff/__init__.py shared/api_gateway/main.py frontend/src/lib/constants.js",
            "stale_after_days": 7,
            "generated_by": "scripts/generate_data_flow.py",
        }
    }
    lines.append(json.dumps(meta, separators=(",", ":")))

    for page in ui_pages:
        entry = dict(page)

        if entry.get("ui_fn") == "fetchView":
            bff_view = entry["bff_view"]
            # Find bff file
            bff_file = view_map.get(bff_view, f"bff/{bff_view.replace('-', '_')}.py")
            entry["bff_file"] = bff_file
            # Scan for engine calls
            engines_called = scan_engine_calls(bff_file)
            entry["engines_called"] = engines_called
            entry["gateway_path"] = f"/api/v1/views/{bff_view}"

        elif entry.get("ui_fn") in ("getFromEngine", "postToEngine"):
            engine_key = entry.get("engine_key", "")
            route = service_routes.get(engine_key, {})
            entry["engine_url"] = route.get("url", "unknown")
            entry["engine_prefixes"] = route.get("prefixes", [])

        lines.append(json.dumps(entry, separators=(",", ":")))

    output_text = "\n".join(lines) + "\n"

    if dry_run:
        print("\n--- DRY RUN OUTPUT ---")
        print(output_text)
        return

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(output_text)
    print(f"\nWrote {len(lines)} lines to {OUTPUT}")
    print("Done. Update bff_contract.ndjson if BFF view response shapes changed.")


if __name__ == "__main__":
    dry_run = "--dry-run" in sys.argv
    generate(dry_run=dry_run)
