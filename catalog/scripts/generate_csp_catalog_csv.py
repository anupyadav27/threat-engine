#!/usr/bin/env python3
"""
Generate one CSV containing:
  - CSP (aws/gcp/azure)
  - service
  - python client + module (from step6_*.discovery.yaml header)
  - a best-effort resource identifier field (from YAML emit keys, or AWS step2 registry when present)
  - the full discovery YAML serialized into a single CSV cell
"""

from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional


WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
PROVIDERS = ("aws", "gcp", "azure")


@dataclass(frozen=True)
class ServiceRow:
    csp: str
    service: str
    python_client: str
    python_module: str
    python_client_expr: str
    resource_identifier: str
    yaml_path: str
    yaml: str


def _read_text(path: Path) -> str:
    # Most files are plain UTF-8; fall back defensively.
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="replace")


def _escape_yaml_for_single_cell(yaml_text: str) -> str:
    # Keep one CSV row per service; represent newlines explicitly.
    return yaml_text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\\n")


def _first_match_in_header(lines: list[str], pattern: re.Pattern[str]) -> str:
    for line in lines:
        m = pattern.search(line)
        if m:
            return m.group(1).strip().strip('"').strip("'")
    return ""


def _extract_header_fields(yaml_text: str) -> tuple[str, str, str, str]:
    """
    Returns: provider, service, services.client, services.module
    Best-effort: only inspects early lines to avoid matching nested keys.
    """
    header_lines = yaml_text.splitlines()[:120]
    provider = _first_match_in_header(header_lines, re.compile(r"^\s*provider:\s*(.+?)\s*$"))
    service = _first_match_in_header(header_lines, re.compile(r"^\s*service:\s*(.+?)\s*$"))

    # Extract the services block content within the header slice.
    client = ""
    module = ""
    in_services = False
    for line in header_lines:
        if re.match(r"^\s*services:\s*$", line):
            in_services = True
            continue
        if in_services:
            # services block ends when indentation returns to 0 (or blank line after services keys)
            if line.strip() == "":
                # allow blank lines inside header
                continue
            if re.match(r"^\S", line):
                break
            m_client = re.match(r"^\s*client:\s*(.+?)\s*$", line)
            if m_client and not client:
                client = m_client.group(1).strip().strip('"').strip("'")
                continue
            m_module = re.match(r"^\s*module:\s*(.+?)\s*$", line)
            if m_module and not module:
                module = m_module.group(1).strip().strip('"').strip("'")
                continue

    return provider, service, client, module


def _python_client_expr(client: str, module: str) -> str:
    mod = (module or "").strip()
    cli = (client or "").strip()
    if not mod and not cli:
        return ""
    # If the module itself is already a call/expression, keep it.
    if "(" in mod and ")" in mod:
        return mod
    if mod.startswith("boto3.client"):
        return f"boto3.client('{cli}')"
    if mod.startswith("googleapiclient.discovery.build"):
        # already an expression in this repo
        return mod
    # If module looks like a plain dotted module path, don't invent a call.
    if re.fullmatch(r"[A-Za-z_][\w.]*", mod or ""):
        return mod
    # generic fallback
    if cli:
        return f"{mod}({cli})" if mod else cli
    return mod


def _aws_identifier_from_step2(service_dir: Path) -> Optional[str]:
    step2 = service_dir / "step2_resource_operations_registry.json"
    if not step2.exists():
        return None
    try:
        data = json.loads(_read_text(step2))
    except Exception:
        return None

    # Prefer an explicit ARN entity if any primary/other resource has it.
    for section in ("primary_resources", "other_resources"):
        items = data.get(section) or []
        if not isinstance(items, list):
            continue
        for r in items:
            if not isinstance(r, dict):
                continue
            if r.get("has_arn") is True and r.get("arn_entity"):
                return f"arn_entity:{r['arn_entity']}"

    # Otherwise, fall back to first primary resource type.
    prim = data.get("primary_resources") or []
    if isinstance(prim, list) and prim:
        rt = prim[0].get("resource_type")
        if rt:
            return f"resource_type:{rt}"
    return None


def _best_identifier_from_yaml(yaml_text: str) -> str:
    """
    Best-effort identifier field name from emitted item mappings.
    Priority:
      _full_id, any *Arn, id, selfLink, name
    """
    # Fast checks first (whole text, but simple regex).
    if re.search(r"^\s*_full_id\s*:", yaml_text, flags=re.M):
        return "_full_id"

    m_arn = re.search(r"^\s*([A-Za-z_][\w]*Arn)\s*:", yaml_text, flags=re.M)
    if m_arn:
        return m_arn.group(1)

    if re.search(r"^\s*id\s*:", yaml_text, flags=re.M):
        return "id"

    if re.search(r"^\s*selfLink\s*:", yaml_text, flags=re.M):
        return "selfLink"

    if re.search(r"^\s*name\s*:", yaml_text, flags=re.M):
        return "name"

    # Fallback: first key under any "item:" block (if present).
    # Looks for:
    #   item:
    #     key: ...
    m_item = re.search(r"(?m)^\s*item:\s*\n(\s+)([A-Za-z_][\w]*)\s*:", yaml_text)
    if m_item:
        return m_item.group(2)

    return ""


def _iter_discovery_yamls(provider_root: Path) -> Iterable[Path]:
    # Most services are one directory deep, but keep ** for safety.
    yield from sorted(provider_root.glob("**/step6_*.discovery.yaml"))


def _service_dir_from_yaml_path(yaml_path: Path) -> Path:
    # .../<provider>/<service>/step6_<service>.discovery.yaml
    return yaml_path.parent


def build_rows() -> Iterable[ServiceRow]:
    for csp in PROVIDERS:
        provider_root = WORKSPACE_ROOT / csp
        if not provider_root.exists():
            continue

        for yaml_path in _iter_discovery_yamls(provider_root):
            yaml_text = _read_text(yaml_path)
            provider, service, client, module = _extract_header_fields(yaml_text)

            # Hard fallbacks if header extraction fails.
            if not provider:
                provider = csp
            if not service:
                service = yaml_path.parent.name
            if not client:
                client = service

            resource_identifier = ""
            if provider == "aws":
                rid = _aws_identifier_from_step2(_service_dir_from_yaml_path(yaml_path))
                if rid:
                    resource_identifier = rid
            if not resource_identifier:
                resource_identifier = _best_identifier_from_yaml(yaml_text)
            if not resource_identifier and provider == "azure":
                resource_identifier = "id"
            if not resource_identifier and provider == "gcp":
                resource_identifier = "_full_id"

            yield ServiceRow(
                csp=provider,
                service=service,
                python_client=client,
                python_module=module,
                python_client_expr=_python_client_expr(client, module),
                resource_identifier=resource_identifier,
                yaml_path=str(yaml_path.relative_to(WORKSPACE_ROOT)),
                yaml=_escape_yaml_for_single_cell(yaml_text),
            )


def main() -> None:
    out_path = WORKSPACE_ROOT / "csp_services_clients_resources.csv"
    fieldnames = [
        "csp",
        "service",
        "python_client",
        "python_module",
        "python_client_expr",
        "resource_identifier",
        "yaml_path",
        "yaml",
    ]

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()
        for row in build_rows():
            writer.writerow(
                {
                    "csp": row.csp,
                    "service": row.service,
                    "python_client": row.python_client,
                    "python_module": row.python_module,
                    "python_client_expr": row.python_client_expr,
                    "resource_identifier": row.resource_identifier,
                    "yaml_path": row.yaml_path,
                    "yaml": row.yaml,
                }
            )

    print(f"Wrote: {out_path}")


if __name__ == "__main__":
    main()

