"""DCAT-01 cleanup — strip envelope-only fields from emit.item blocks.

When emit.item has BOTH:
  KeyMetadata: '{{ response.KeyMetadata }}'        ← captures whole sub-object
  KeySpec:     '{{ response.KeyMetadata.KeySpec }}' ← lifts inner field

The first line produces a nested key in discovery_findings. Lifted fields are
already at the top level, so the envelope-only line is redundant AND breaks
flat-shape. Remove the envelope-only lines.

Definition of envelope-only:
  - field name X
  - template = `{{ response.X }}` (or `{{ item.X }}`)
  - AND there exists at least one OTHER field with template `{{ response.X.Y }}`

Run:
  python3 strip_envelope_keys.py --provider aws --apply
"""
import argparse
import re
import sys
from pathlib import Path
import yaml

ROOT = Path("/Users/apple/Desktop/threat-engine")
CATALOG = ROOT / "catalog/discovery_generator_data"


def find_envelope_keys(item: dict) -> list:
    if not isinstance(item, dict):
        return []
    envelopes = []
    for field, tmpl in item.items():
        if not isinstance(tmpl, str):
            continue
        # Match "{{ response.<field> }}" or "{{ item.<field> }}"
        m = re.match(r"^\s*\{\{\s*(response|item|context)\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}\s*$", tmpl)
        if not m:
            continue
        prefix, captured = m.group(1), m.group(2)
        if captured != field:
            continue
        # Check if any other field lifts inner from this envelope
        inner_pattern = re.compile(rf"\{{\{{\s*{prefix}\.{re.escape(field)}\.")
        for other_field, other_tmpl in item.items():
            if other_field == field or not isinstance(other_tmpl, str):
                continue
            if inner_pattern.search(other_tmpl):
                envelopes.append(field)
                break
    return envelopes


def process_file(path: Path, apply: bool) -> int:
    try:
        with path.open() as f:
            data = yaml.safe_load(f) or {}
    except Exception:
        return 0
    if not isinstance(data.get("discovery"), list):
        return 0
    stripped_total = 0
    for disc in data["discovery"]:
        emit = disc.get("emit") or {}
        item = emit.get("item")
        envelopes = find_envelope_keys(item)
        if envelopes:
            for env_key in envelopes:
                del item[env_key]
                stripped_total += 1
    if stripped_total and apply:
        with path.open("w") as f:
            yaml.safe_dump(data, f, sort_keys=False, default_flow_style=False)
    return stripped_total


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--provider", required=True)
    p.add_argument("--service")
    p.add_argument("--apply", action="store_true")
    args = p.parse_args()

    provider_dir = CATALOG / args.provider
    if args.service:
        services = [args.service]
    else:
        services = [d.name for d in provider_dir.iterdir() if d.is_dir()]

    total = 0
    files_touched = 0
    for svc in sorted(services):
        svc_dir = provider_dir / svc
        if not svc_dir.is_dir():
            continue
        for yaml_path in svc_dir.glob("step6_*.discovery.yaml"):
            stripped = process_file(yaml_path, args.apply)
            if stripped:
                files_touched += 1
                total += stripped
                print(f"  {svc}: stripped {stripped} envelope keys ({yaml_path.name})")
    action = "applied" if args.apply else "DRY-RUN"
    print(f"\n=== {action}: stripped {total} envelope keys across {files_touched} files ===")


if __name__ == "__main__":
    sys.exit(main())
