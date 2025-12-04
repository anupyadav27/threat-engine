#!/usr/bin/env python3
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SERVICES_ROOT = ROOT / "azure_compliance_python_engine" / "services"

HEADER_PROVIDER_RE = re.compile(r'^provider:\s*azure\s*$', re.IGNORECASE)
HEADER_SERVICE_RE = re.compile(r'^service:\s*([A-Za-z0-9._-]+)\s*$')


def normalize_file(path: Path):
    text = path.read_text(encoding='utf-8')
    lines = text.splitlines()
    # Determine service from path (services/<service>/(metadata|rules)/file.yaml)
    try:
        service = path.parts[-3]
    except Exception:
        return False

    # Strip any leading BOM or whitespace-only lines
    i = 0
    while i < len(lines) and lines[i].strip() == '':
        i += 1

    # Remove any repeating provider/service headers at the top (with optional blank lines between)
    j = i
    removed_any = False
    while j < len(lines):
        line = lines[j].strip()
        if line == '':
            j += 1
            continue
        if HEADER_PROVIDER_RE.match(line) or HEADER_SERVICE_RE.match(line):
            removed_any = True
            j += 1
            continue
        break

    remaining = lines[j:]

    header = [f"provider: azure", f"service: {service}"]
    new_lines = header + [''] + remaining

    new_text = "\n".join(new_lines).rstrip() + "\n"

    if new_text != text:
        path.write_text(new_text, encoding='utf-8')
        return True
    return False


def main():
    changed = 0
    scanned = 0
    for pattern in ('metadata/*.yaml', 'rules/*.yaml'):
        for p in SERVICES_ROOT.rglob(pattern):
            scanned += 1
            try:
                if normalize_file(p):
                    changed += 1
            except Exception:
                # Skip problematic files silently for now
                pass
    print(f"SUMMARY: normalized_files={changed}, scanned_files={scanned}")

if __name__ == '__main__':
    main()
