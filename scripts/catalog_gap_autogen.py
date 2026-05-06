#!/usr/bin/env python3
"""DCAT-01 Phase A0.5 — Catalog Gap Auto-Suggester.

For each (provider, service):
  1. Load SDK type stubs (boto3 / azure / gcp / oci / aliyun / k8s / ibm)
     → flat list of every field path AWS/etc. could return per API operation.
  2. Load catalog YAML emit.item declarations
     → list of fields the catalog says it captures.
  3. Diff → bucket each gap into Class I/II/III/IV.
  4. Auto-fix Class I/II/III locally (deterministic).
  5. For Class IV (judgment calls), ask DeepSeek for a structured
     recommendation; queue to review/.
  6. Output:
     - catalog_patches/{csp}/{svc}.patch.yaml   (auto-applied changes)
     - catalog_review/{csp}/{svc}.review.md     (Class IV decisions)
     - SUMMARY.md                               (top-level report)

Env vars:
  DEEPSEEK_API_KEY     — required to enable Class IV LLM calls
  DEEPSEEK_BASE_URL    — optional, default https://api.deepseek.com
  DEEPSEEK_MODEL       — optional, default deepseek-chat
  CATALOG_GAP_NO_LLM=1 — skip Class IV LLM calls (offline mode)
  CATALOG_GAP_DRY_RUN=1 — don't write patches, only print

Cache:
  Class IV responses cached at .cache/catalog_gap/<sha>.json — reruns reuse.

Usage:
  python3 scripts/catalog_gap_autogen.py --provider aws --service kms
  python3 scripts/catalog_gap_autogen.py --provider aws --all
  python3 scripts/catalog_gap_autogen.py --all-providers
"""

from __future__ import annotations

import argparse
import dataclasses
import difflib
import hashlib
import json
import logging
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml


# ── Config ──────────────────────────────────────────────────────────────────


ROOT = Path("/Users/apple/Desktop/threat-engine")
CATALOG_ROOT = ROOT / "catalog/discovery_generator_data"
PATCH_ROOT = ROOT / "catalog/_dcat_patches"
REVIEW_ROOT = ROOT / "catalog/_dcat_review"
CACHE_DIR = ROOT / ".cache/catalog_gap"

PROVIDERS = ["aws", "azure", "gcp", "oci", "alicloud", "k8s", "ibm"]

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("catalog_gap")


# ── Data classes ────────────────────────────────────────────────────────────


@dataclass
class FieldGap:
    """A single field-level gap between SDK supply and catalog declaration."""

    discovery_id: str
    field_path: str  # e.g. "KeyMetadata.KeySpec"
    gap_class: str  # "missing" | "typo" | "rename" | "judgment" | "unknown"
    sdk_type: Optional[str] = None
    suggested_template: Optional[str] = None
    nearest_match: Optional[str] = None
    confidence: str = "unknown"
    rationale: str = ""


@dataclass
class CatalogPatch:
    """Auto-generated patch for a service."""

    provider: str
    service: str
    additions: Dict[str, Dict[str, str]] = field(default_factory=dict)
    renames: Dict[str, Dict[str, str]] = field(default_factory=dict)
    review_items: List[FieldGap] = field(default_factory=list)


# ── SDK introspection ──────────────────────────────────────────────────────


def load_aws_field_tree(service: str, operation: str) -> Optional[Dict[str, str]]:
    """Walk boto3 service-2.json shapes for a given (service, operation).

    Returns: {"KeyMetadata.KeySpec": "string", "KeyMetadata.Arn": "string", ...}
    or None if the operation isn't found.
    """
    try:
        import botocore.loaders
        import botocore.session
    except ImportError:
        log.warning("botocore not available — cannot introspect AWS SDK")
        return None

    try:
        loader = botocore.loaders.create_loader()
        api_versions = loader.list_api_versions(service, "service-2") or []
        if not api_versions:
            return None
        latest = sorted(api_versions)[-1]
        model = loader.load_service_model(service, "service-2", latest)
    except Exception as exc:
        log.debug(f"AWS SDK load failed for {service}: {exc}")
        return None

    operations = model.get("operations", {})
    op_name = _aws_op_pascal_case(operation)
    op = operations.get(op_name)
    if not op:
        return None

    output_shape_name = op.get("output", {}).get("shape")
    if not output_shape_name:
        return None

    shapes = model.get("shapes", {})
    fields: Dict[str, str] = {}
    _walk_shape(shapes, output_shape_name, "", fields, max_depth=6)
    return fields


def _aws_op_pascal_case(snake: str) -> str:
    """list_keys → ListKeys, describe_key → DescribeKey."""
    return "".join(p.capitalize() for p in snake.split("_"))


def _walk_shape(
    shapes: Dict[str, Any],
    shape_name: str,
    prefix: str,
    out: Dict[str, str],
    *,
    seen: Optional[Set[str]] = None,
    max_depth: int = 6,
) -> None:
    """Recursively walk a botocore shape, recording every leaf field path."""
    if seen is None:
        seen = set()
    if max_depth <= 0:
        return
    if shape_name in seen:
        return
    seen = seen | {shape_name}

    shape = shapes.get(shape_name)
    if not shape:
        return

    shape_type = shape.get("type", "structure")

    if shape_type == "structure":
        members = shape.get("members") or {}
        for member_name, member_def in members.items():
            path = f"{prefix}.{member_name}" if prefix else member_name
            target = member_def.get("shape")
            if not target:
                continue
            target_shape = shapes.get(target, {})
            target_type = target_shape.get("type", "structure")
            if target_type in ("structure", "list", "map"):
                _walk_shape(shapes, target, path, out, seen=seen, max_depth=max_depth - 1)
            else:
                out[path] = target_type
    elif shape_type == "list":
        member = shape.get("member", {}).get("shape")
        if member:
            # Use [] notation to indicate iteration but don't recurse infinitely
            list_prefix = f"{prefix}[]"
            _walk_shape(shapes, member, list_prefix, out, seen=seen, max_depth=max_depth - 1)
    elif shape_type == "map":
        # Maps are typically free-form key-value; skip enumerating
        out[prefix] = "map"


# ── Catalog YAML loading ───────────────────────────────────────────────────


def load_catalog_emit_blocks(provider: str, service: str) -> Dict[str, Dict[str, Any]]:
    """Load all discovery_id → emit.item blocks for a service.

    Walks the per-service folder for the `step6_*.discovery.yaml` (preferred)
    or `final_discovery_v1.yaml` (fallback).

    Returns: {discovery_id: {field_name: jinja_template_str, ...}}
    """
    svc_dir = CATALOG_ROOT / provider / service
    if not svc_dir.is_dir():
        return {}

    candidates = sorted(
        list(svc_dir.glob("step6_*.discovery.yaml"))
        + list(svc_dir.glob("final_discovery_v1.yaml")),
        key=lambda p: 0 if p.name.startswith("step6_") else 1,
    )
    if not candidates:
        return {}

    yaml_path = candidates[0]
    try:
        with yaml_path.open() as f:
            data = yaml.safe_load(f) or {}
    except Exception as exc:
        log.warning(f"Failed to load {yaml_path}: {exc}")
        return {}

    out: Dict[str, Dict[str, Any]] = {}
    for disc in data.get("discovery", []):
        did = disc.get("discovery_id", "")
        if not did:
            continue
        emit = disc.get("emit") or {}
        item = emit.get("item") or {}
        if isinstance(item, dict):
            out[did] = dict(item)
    return out


# ── Diff & classify ────────────────────────────────────────────────────────


def classify_gaps(
    sdk_fields: Dict[str, str],
    catalog_item: Dict[str, str],
    discovery_id: str,
) -> List[FieldGap]:
    """Compare SDK truth with catalog declaration; bucket each gap."""
    gaps: List[FieldGap] = []
    declared_paths = set()

    # Extract paths from catalog templates: '{{ response.X.Y }}' → 'X.Y'
    for field_name, tmpl in catalog_item.items():
        if not isinstance(tmpl, str) or "{{" not in tmpl:
            continue
        path = _extract_jinja_path(tmpl)
        if path:
            declared_paths.add(path)

    sdk_paths = {p for p in sdk_fields.keys() if not p.endswith("[]")}

    # Class I: missing — in SDK, not in catalog
    missing = sdk_paths - declared_paths
    for p in sorted(missing):
        # Skip overly deep / metadata-only paths
        depth = p.count(".")
        if depth > 4:
            continue
        # Skip pagination tokens
        leaf = p.split(".")[-1]
        if leaf in ("NextToken", "NextMarker", "Marker", "ResponseMetadata", "$metadata"):
            continue
        gaps.append(FieldGap(
            discovery_id=discovery_id,
            field_path=p,
            gap_class="missing",
            sdk_type=sdk_fields.get(p),
            suggested_template=f"{{{{ response.{p} }}}}",
            confidence="high",
        ))

    # Class II: typo — in catalog but not SDK, fuzzy-match to nearest
    extra = declared_paths - sdk_paths
    for p in sorted(extra):
        candidates = difflib.get_close_matches(p, list(sdk_paths), n=1, cutoff=0.85)
        if candidates:
            gaps.append(FieldGap(
                discovery_id=discovery_id,
                field_path=p,
                gap_class="typo",
                nearest_match=candidates[0],
                confidence="medium",
                rationale=f"Catalog references '{p}', closest SDK match is '{candidates[0]}'",
            ))
        else:
            # Class IV: catalog has it, SDK doesn't, no fuzzy match → judgment
            gaps.append(FieldGap(
                discovery_id=discovery_id,
                field_path=p,
                gap_class="judgment",
                confidence="low",
                rationale=f"Catalog declares '{p}' but no SDK match; may be deprecated, renamed, or vendor extension",
            ))

    return gaps


def _extract_jinja_path(template_str: str) -> str:
    """Pull X.Y.Z from '{{ response.X.Y.Z }}' / '{{ item.X.Y }}'."""
    inner = template_str.strip()
    if inner.startswith("{{"):
        inner = inner[2:]
    if inner.endswith("}}"):
        inner = inner[:-2]
    inner = inner.strip()
    # Strip leading 'response.' or 'item.'
    for prefix in ("response.", "item.", "context."):
        if inner.startswith(prefix):
            return inner[len(prefix):]
    return inner


# ── DeepSeek (Class IV) ────────────────────────────────────────────────────


def deepseek_review(gap: FieldGap, provider: str, service: str) -> Dict[str, Any]:
    """Ask DeepSeek for a structured recommendation on a Class IV gap.

    Cached on disk by hash(provider, service, discovery_id, field_path).
    Returns the parsed JSON response or a stub if disabled/cached.
    """
    cache_key = hashlib.sha256(
        f"{provider}|{service}|{gap.discovery_id}|{gap.field_path}".encode()
    ).hexdigest()[:16]
    cache_file = CACHE_DIR / f"{cache_key}.json"

    if cache_file.exists():
        try:
            with cache_file.open() as f:
                return json.load(f)
        except Exception:
            pass

    if os.getenv("CATALOG_GAP_NO_LLM") in ("1", "true"):
        return {"recommendation": "skip", "rationale": "LLM disabled", "confidence": "n/a"}

    api_key = os.getenv("DEEPSEEK_API_KEY")
    if not api_key:
        return {
            "recommendation": "review",
            "rationale": "DEEPSEEK_API_KEY not set; manual review needed",
            "confidence": "n/a",
        }

    base_url = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
    model = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")

    prompt = f"""You are auditing a Cloud Security Posture Management (CSPM) catalog for {provider.upper()}.

Catalog declares this field for `{gap.discovery_id}`:
  field path:    {gap.field_path}
  template:      {gap.suggested_template or '(not yet templated)'}
  rationale:     {gap.rationale}

Question: Is this field something a CSPM should capture? Decide:
  - "add"        : add to catalog with the suggested path
  - "rename_to:<new_path>" : catalog has wrong path; correct it
  - "skip"       : not security-relevant or vendor-specific noise
  - "investigate": ambiguous — escalate to human

Reply ONLY with JSON:
{{
  "recommendation": "add|rename_to:NEW|skip|investigate",
  "rationale": "<one sentence>",
  "confidence": "high|medium|low",
  "suggested_template": "{{{{ response.X.Y }}}}"
}}
"""
    try:
        # Lazy import — only needed if we actually call the API
        try:
            from openai import OpenAI
        except ImportError:
            try:
                import urllib.request as _ur
            except ImportError:
                return {"recommendation": "investigate", "rationale": "openai package not installed and urllib unavailable", "confidence": "n/a"}
            return _deepseek_via_urllib(base_url, api_key, model, prompt, cache_file)

        client = OpenAI(api_key=api_key, base_url=base_url)
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You return only valid JSON, no prose."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.0,
            max_tokens=300,
        )
        body = resp.choices[0].message.content
        parsed = _parse_json_loose(body)
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        with cache_file.open("w") as f:
            json.dump(parsed, f, indent=2)
        return parsed
    except Exception as exc:
        log.warning(f"DeepSeek call failed for {gap.field_path}: {exc}")
        return {"recommendation": "investigate", "rationale": f"LLM error: {exc}", "confidence": "n/a"}


def _deepseek_via_urllib(
    base_url: str, api_key: str, model: str, prompt: str, cache_file: Path
) -> Dict[str, Any]:
    """Fallback: hit DeepSeek's OpenAI-compatible endpoint with stdlib only."""
    import urllib.request
    import urllib.error

    req = urllib.request.Request(
        f"{base_url}/v1/chat/completions",
        data=json.dumps({
            "model": model,
            "messages": [
                {"role": "system", "content": "You return only valid JSON, no prose."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.0,
            "max_tokens": 300,
        }).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
        body = data["choices"][0]["message"]["content"]
        parsed = _parse_json_loose(body)
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        with cache_file.open("w") as f:
            json.dump(parsed, f, indent=2)
        return parsed
    except urllib.error.HTTPError as exc:
        return {"recommendation": "investigate", "rationale": f"HTTP {exc.code}", "confidence": "n/a"}
    except Exception as exc:
        return {"recommendation": "investigate", "rationale": str(exc)[:120], "confidence": "n/a"}


def _parse_json_loose(text: str) -> Dict[str, Any]:
    """Tolerate code-fenced or prefixed JSON."""
    if not text:
        return {}
    text = text.strip()
    if text.startswith("```"):
        # Strip code fence
        lines = text.split("\n")
        text = "\n".join(l for l in lines if not l.startswith("```"))
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Find first { and last }
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                pass
    return {"recommendation": "investigate", "rationale": "could not parse LLM JSON", "confidence": "n/a", "raw": text[:200]}


# ── Patch builders + writers ────────────────────────────────────────────────


def build_patch(provider: str, service: str) -> CatalogPatch:
    """Run the full pipeline for one (provider, service)."""
    patch = CatalogPatch(provider=provider, service=service)

    catalog = load_catalog_emit_blocks(provider, service)
    if not catalog:
        log.info(f"  {provider}/{service}: no catalog YAML — skipping")
        return patch

    log.info(f"  {provider}/{service}: {len(catalog)} discoveries in catalog")

    for discovery_id, item_template in catalog.items():
        # Parse "aws.kms.describe_key" → ("kms", "describe_key")
        parts = discovery_id.split(".")
        if len(parts) < 3:
            continue
        operation = parts[-1]

        sdk_fields: Optional[Dict[str, str]] = None
        if provider == "aws":
            sdk_fields = load_aws_field_tree(service, operation)

        # GCP / Azure / OCI / etc. introspection: stubs for now (TODO)
        if not sdk_fields:
            continue

        gaps = classify_gaps(sdk_fields, item_template, discovery_id)

        for gap in gaps:
            if gap.gap_class == "missing":
                patch.additions.setdefault(discovery_id, {})[
                    gap.field_path.replace(".", "_")
                ] = gap.suggested_template or f"{{{{ response.{gap.field_path} }}}}"
            elif gap.gap_class == "typo":
                patch.renames.setdefault(discovery_id, {})[gap.field_path] = gap.nearest_match or ""
            elif gap.gap_class == "judgment":
                # Send to DeepSeek
                review = deepseek_review(gap, provider, service)
                gap.rationale = review.get("rationale", gap.rationale)
                gap.confidence = review.get("confidence", "low")
                rec = review.get("recommendation", "investigate")
                if rec == "skip":
                    continue
                if rec == "add":
                    patch.additions.setdefault(discovery_id, {})[
                        gap.field_path.replace(".", "_")
                    ] = review.get("suggested_template") or f"{{{{ response.{gap.field_path} }}}}"
                else:
                    patch.review_items.append(gap)

    return patch


def write_patch(patch: CatalogPatch) -> None:
    """Write the patch file to catalog/_dcat_patches/{csp}/{svc}.patch.yaml."""
    if os.getenv("CATALOG_GAP_DRY_RUN") in ("1", "true"):
        log.info(f"DRY: would write patch for {patch.provider}/{patch.service}")
        return

    if not patch.additions and not patch.renames and not patch.review_items:
        return

    out_dir = PATCH_ROOT / patch.provider
    out_dir.mkdir(parents=True, exist_ok=True)

    patch_path = out_dir / f"{patch.service}.patch.yaml"
    with patch_path.open("w") as f:
        f.write(f"# Auto-generated catalog patch for {patch.provider}/{patch.service}\n")
        f.write(f"# Generated by scripts/catalog_gap_autogen.py (DCAT-01)\n\n")
        if patch.additions:
            f.write("additions:\n")
            yaml.safe_dump(patch.additions, f, default_flow_style=False, sort_keys=True)
            f.write("\n")
        if patch.renames:
            f.write("renames:\n")
            yaml.safe_dump(patch.renames, f, default_flow_style=False, sort_keys=True)
            f.write("\n")

    if patch.review_items:
        review_dir = REVIEW_ROOT / patch.provider
        review_dir.mkdir(parents=True, exist_ok=True)
        review_path = review_dir / f"{patch.service}.review.md"
        with review_path.open("w") as f:
            f.write(f"# Class IV Review — {patch.provider}/{patch.service}\n\n")
            f.write(
                "These gaps need human (or LLM-assisted) judgment. Each row "
                "is the LLM's recommendation; review and approve/reject.\n\n"
            )
            f.write("| discovery_id | field_path | confidence | rationale |\n")
            f.write("|---|---|---|---|\n")
            for g in patch.review_items:
                f.write(
                    f"| {g.discovery_id} | `{g.field_path}` | {g.confidence} | {g.rationale[:100]} |\n"
                )

    log.info(
        f"  ✓ wrote patch: {patch.service} "
        f"+{sum(len(v) for v in patch.additions.values())} additions, "
        f"{sum(len(v) for v in patch.renames.values())} renames, "
        f"{len(patch.review_items)} review items"
    )


# ── CLI ────────────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(description="DCAT-01 catalog gap auto-suggester")
    parser.add_argument("--provider", help="single CSP (aws/gcp/azure/oci/alicloud/k8s/ibm)")
    parser.add_argument("--service", help="single service within provider")
    parser.add_argument("--all", action="store_true", help="all services for the given provider")
    parser.add_argument("--all-providers", action="store_true", help="every CSP, every service")
    args = parser.parse_args()

    if args.all_providers:
        targets = [(p, None) for p in PROVIDERS]
    elif args.provider and args.all:
        targets = [(args.provider, None)]
    elif args.provider and args.service:
        targets = [(args.provider, args.service)]
    else:
        parser.print_help()
        return 1

    summary: List[Tuple[str, str, int, int, int]] = []
    for provider, single_service in targets:
        provider_dir = CATALOG_ROOT / provider
        if not provider_dir.is_dir():
            log.warning(f"no catalog dir for {provider}: {provider_dir}")
            continue

        services = (
            [single_service]
            if single_service
            else [d.name for d in provider_dir.iterdir() if d.is_dir()]
        )
        log.info(f"=== {provider} ({len(services)} services) ===")
        for svc in services:
            try:
                patch = build_patch(provider, svc)
            except Exception as exc:
                log.error(f"  ✗ {provider}/{svc}: {exc}")
                continue
            write_patch(patch)
            summary.append(
                (
                    provider,
                    svc,
                    sum(len(v) for v in patch.additions.values()),
                    sum(len(v) for v in patch.renames.values()),
                    len(patch.review_items),
                )
            )

    # Top-level summary
    PATCH_ROOT.mkdir(parents=True, exist_ok=True)
    summary_path = PATCH_ROOT / "SUMMARY.md"
    with summary_path.open("w") as f:
        f.write("# DCAT-01 Catalog Gap Audit — Summary\n\n")
        f.write("| provider | service | additions | renames | review |\n")
        f.write("|---|---|---|---|---|\n")
        for provider, svc, adds, ren, rev in sorted(summary):
            if adds or ren or rev:
                f.write(f"| {provider} | {svc} | {adds} | {ren} | {rev} |\n")
        f.write("\n")
        total_a = sum(s[2] for s in summary)
        total_r = sum(s[3] for s in summary)
        total_v = sum(s[4] for s in summary)
        f.write(f"**Totals:** {total_a} auto-add, {total_r} auto-rename, {total_v} need review\n")

    log.info(f"Summary written to {summary_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
