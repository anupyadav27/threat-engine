#!/usr/bin/env python3
"""
Local Discovery + Check Validator
===================================
Run AWS discoveries locally, store results, then evaluate check rules.
No database required — results saved as JSON files.

Usage:
  python local_validator.py --services s3 iam ec2        # specific services
  python local_validator.py --services all               # all 104 services
  python local_validator.py --from-cache                 # skip discovery, reuse last run
  python local_validator.py --services s3 --region eu-west-1

Output:
  /tmp/local_validator/
    discovery_data.json   — raw discovery results per discovery_id
    check_results.json    — PASS/FAIL per rule
    summary.txt           — human-readable report
"""

import sys
import re
import json
import time
import yaml
import boto3
import logging
import argparse
from pathlib import Path
from typing import Any, Dict, List, Optional
from collections import defaultdict
from botocore.exceptions import ClientError, EndpointResolutionError, OperationNotPageableError

# ── Paths ─────────────────────────────────────────────────────────────────
REPO_ROOT    = Path(__file__).parent
CATALOG_ROOT = REPO_ROOT / "catalog" / "aws"
CHECKS_ROOT  = REPO_ROOT / "engines" / "check" / "engine_check_aws" / "services"
OUT_DIR      = Path("/tmp/local_validator")

# ── Reuse existing condition evaluator ────────────────────────────────────
# Add check engine common path so we can import the shared condition evaluator
_check_common = str(REPO_ROOT / "engines" / "check" / "common")
if _check_common not in sys.path:
    sys.path.insert(0, _check_common)

import importlib as _il  # noqa: E402
_ce = _il.import_module("utils.condition_evaluator")
extract_value: Any = _ce.extract_value  # type: ignore[assignment]
evaluate_condition: Any = _ce.evaluate_condition  # type: ignore[assignment]

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
log = logging.getLogger("local_validator")


def _parse_json_strings(obj: Any) -> Any:
    """
    Recursively parse any JSON string values found inside a dict/list.
    Enables path traversal into fields like S3 Policy (stored as JSON string).
    """
    if isinstance(obj, dict):
        return {k: _parse_json_strings(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_parse_json_strings(v) for v in obj]
    if isinstance(obj, str) and (obj.startswith("{") or obj.startswith("[")):
        try:
            return _parse_json_strings(json.loads(obj))
        except json.JSONDecodeError:
            pass
    return obj

# ── Catalog service name → boto3 client name ─────────────────────────────
# Catalog uses logical names; some map to a shared boto3 client
CATALOG_TO_BOTO3 = {
    "eip":             "ec2",
    "vpc":             "ec2",
    "vpcflowlogs":     "ec2",
    "ebs":             "ec2",
    "fargate":         "ecs",
    "parameterstore":  "ssm",
    "directoryservice":"ds",
    "costexplorer":    "ce",
    "timestream":      "timestream-query",
    "identitycenter":  "sso-admin",
    "sso":             "sso-admin",
    "kinesisvideostreams": "kinesisvideo",
    "networkfirewall": "network-firewall",
    "macie":           "macie2",
    "elasticfilesystem":"efs",
    "workflows":       "stepfunctions",
    "lakeformation":   "lakeformation",
    "securityhub":     "securityhub",
    "inspector":       "inspector",
}

def boto3_client_name(catalog_svc: str) -> str:
    return CATALOG_TO_BOTO3.get(catalog_svc, catalog_svc)


# ── Default param overrides for ops that return too much data without filters ──
# The production FilterEngine adds owner/self filters; we replicate the important ones here.
DEFAULT_PARAM_OVERRIDES: Dict[str, Dict] = {
    # Without owner filter, describe_snapshots returns ALL public snapshots in the region
    "describe_snapshots": {"OwnerIds": ["self"]},
    # Without owner filter, describe_images returns all public AMIs in the marketplace
    "describe_images": {"Owners": ["self"]},
}

# ── Template resolver ({{ item.Field }} → value) ─────────────────────────
def resolve(template: Any, context: Dict) -> Any:
    if not isinstance(template, str) or "{{" not in template:
        return template
    # Full-template case: "{{ item.Name }}" → return actual value
    m = re.fullmatch(r"\{\{\s*([\w.\[\]]+)\s*\}\}", template.strip())
    if m:
        return extract_value(context, m.group(1))
    # Embedded template: "prefix-{{ item.Id }}-suffix" → string
    def _sub(match):
        val = extract_value(context, match.group(1).strip())
        return str(val) if val is not None else ""
    return re.sub(r"\{\{\s*(.*?)\s*\}\}", _sub, template)

def resolve_params(params: Dict, item: Dict) -> Dict:
    """Resolve all param templates against the parent item."""
    context = {"item": item, "response": item}
    return {k: resolve(v, context) for k, v in (params or {}).items()}

# ── Extract items from a boto3 response using emit block ─────────────────
def extract_emit_items(response: Dict, emit: Dict, parent_item: Optional[Dict] = None) -> List[Dict]:
    """
    Given a boto3 response and the emit block from the catalog op,
    return a list of item dicts with emitted fields filled in.
    """
    if not emit:
        return [response]

    context = {"response": response, "item": parent_item or {}}

    items_for_tpl = emit.get("items_for", "")
    item_template  = emit.get("item", {})

    # Determine the list of raw items
    if items_for_tpl:
        raw_items = resolve(items_for_tpl, context)
        if not isinstance(raw_items, list):
            raw_items = [raw_items] if raw_items is not None else []
    else:
        # Flat emit — the whole response is the single item
        raw_items = [response]

    results = []
    for raw in raw_items:
        if raw is None:
            continue
        if item_template:
            # Apply template dict to raw item
            item_ctx = {"response": response, "item": raw}
            emitted = {k: resolve(v, item_ctx) for k, v in item_template.items()}
        else:
            emitted = raw if isinstance(raw, dict) else {"_value": raw}
        results.append(emitted)

    return results

# ── Discovery runner ──────────────────────────────────────────────────────
class DiscoveryRunner:
    def __init__(self, region: str, profile: Optional[str] = None):
        self.region  = region
        self.profile = profile
        self._clients: Dict[str, Any] = {}

    def _client(self, svc_name: str):
        boto_name = boto3_client_name(svc_name)
        key = boto_name
        if key not in self._clients:
            session = boto3.Session(profile_name=self.profile) if self.profile else boto3.Session()
            try:
                self._clients[key] = session.client(boto_name, region_name=self.region)
            except Exception as e:
                log.warning(f"Cannot create client '{boto_name}': {e}")
                self._clients[key] = None
        return self._clients[key]

    def _call_action(self, client, action: str, params: Dict) -> Optional[Dict]:  # noqa: C901
        """Call a boto3 action, using paginator if available."""
        if client is None:
            return None
        # Apply default param overrides (e.g., owner filters for describe_snapshots)
        if action in DEFAULT_PARAM_OVERRIDES:
            overrides = DEFAULT_PARAM_OVERRIDES[action]
            params = {**overrides, **params}  # caller params win over defaults
        try:
            # Try paginator first (handles NextToken automatically)
            try:
                paginator = client.get_paginator(action)
                pages = paginator.paginate(**params)
                merged: Dict = {}
                for page in pages:
                    for k, v in page.items():
                        if k in ("ResponseMetadata", "NextToken"):
                            continue
                        if isinstance(v, list) and isinstance(merged.get(k), list):
                            merged[k].extend(v)
                        else:
                            merged[k] = v
                return merged
            except OperationNotPageableError:
                pass  # no paginator — fall through to direct call
            except Exception:
                pass  # paginator error — fall through to direct call

            # Direct call
            method = getattr(client, action)
            return method(**params)

        except ClientError as e:
            code = e.response["Error"]["Code"]
            # Expected "not available in region" or "not enabled" errors
            # Expected "not configured" or "not available" codes — log at debug only
            SILENT_CODES = {
                "AccessDeniedException", "NotImplementedException",
                "UnsupportedOperation", "InvalidClientTokenId",
                "AuthFailure", "UnauthorizedOperation",
                "AWSOrganizationsNotInUseException", "NoSuchEntityException",
                "ResourceNotFoundException", "ServiceUnavailable", "OptInRequired",
                # S3 "feature not configured on this bucket" codes
                "NoSuchBucketPolicy", "NoSuchLifecycleConfiguration",
                "NoSuchWebsiteConfiguration", "NoSuchCORSConfiguration",
                "ObjectLockConfigurationNotFoundError", "ReplicationConfigurationNotFoundError",
                "ServerSideEncryptionConfigurationNotFoundError",
                "NoSuchTagSet", "NoSuchPublicAccessBlockConfiguration",
                # General "not configured" / catalog quality issues
                "NotFoundException", "NoSuchConfiguration",
                "MissingParameter", "InvalidParameterCombination",
            }
            if code in SILENT_CODES:
                log.debug(f"  SKIP {action}: {code}")
            else:
                log.warning(f"  ERROR {action}: {code} — {e.response['Error']['Message'][:80]}")
            return None
        except EndpointResolutionError:
            log.debug(f"  SKIP {action}: no endpoint in region {self.region}")
            return None
        except Exception as e:
            err_str = str(e)
            etype = type(e).__name__
            # Suppress expected catalog quality issues (missing params, non-existent methods)
            if "ParamValidationError" in etype or "Missing required parameter" in err_str:
                log.debug(f"  SKIP {action}: missing required params (catalog op incomplete)")
            elif isinstance(e, AttributeError) and "has no attribute" in err_str:
                log.debug(f"  SKIP {action}: method not found in boto3 (catalog outdated)")
            else:
                log.warning(f"  ERROR {action}: {etype}: {err_str[:80]}")
            return None

    def run_service(self, svc: str, catalog_file: Path) -> Dict[str, List[Dict]]:
        """
        Run all ops in a catalog file for one service.
        Returns {discovery_id: [list of emitted items]}.
        """
        try:
            catalog = yaml.safe_load(catalog_file.read_text())
        except Exception as e:
            log.error(f"Cannot parse {catalog_file}: {e}")
            return {}

        ops = catalog.get("discovery", []) if isinstance(catalog, dict) else []
        if not ops:
            return {}

        # Topological sort: independent ops first
        def topo_order(ops_list):
            remaining = list(ops_list)
            done = set()
            ordered = []
            max_passes = len(remaining) + 1
            for _ in range(max_passes):
                if not remaining:
                    break
                progress = False
                for op in list(remaining):
                    fe = op.get("for_each", "")
                    if not fe or fe in done:
                        ordered.append(op)
                        done.add(op["discovery_id"])
                        remaining.remove(op)
                        progress = True
                if not progress:
                    # Circular or unresolved — add rest as-is
                    ordered.extend(remaining)
                    break
            return ordered

        ordered_ops = topo_order(ops)
        results: Dict[str, List[Dict]] = {}
        client = self._client(svc)

        for op in ordered_ops:
            did    = op.get("discovery_id", "")
            fe     = op.get("for_each", "")
            calls  = op.get("calls", [])
            emit   = op.get("emit", {})

            if not calls:
                continue

            call_def = calls[0]  # use first call def
            action   = call_def.get("action", "")
            tpl_params = call_def.get("params", {})

            # Determine parent items (from for_each)
            if fe and fe in results:
                parent_items = results[fe]
            elif fe:
                # Parent not available (different service, etc.) — skip
                log.debug(f"  SKIP {did}: parent {fe} not in results")
                continue
            else:
                parent_items = [{}]  # independent op — single run with no parent

            op_items: List[Dict] = []
            for parent_item in parent_items:
                params = resolve_params(tpl_params, parent_item)
                # Remove None params
                params = {k: v for k, v in params.items() if v is not None}

                response = self._call_action(client, action, params)
                if response is None:
                    continue

                items = extract_emit_items(response, emit, parent_item)
                op_items.extend(items)

            results[did] = op_items
            log.debug(f"  {did}: {len(op_items)} items")

        total = sum(len(v) for v in results.values())
        log.info(f"[{svc}] {len(results)} ops → {total} items")
        return results

# ── Condition evaluator for check rules ──────────────────────────────────
def evaluate_rule_conditions(conditions: Any, item: Dict) -> bool:
    """Recursively evaluate rule conditions against an item."""
    if not conditions:
        return True

    if isinstance(conditions, dict):
        if "all" in conditions:
            return all(evaluate_rule_conditions(c, item) for c in conditions["all"])
        if "any" in conditions:
            return any(evaluate_rule_conditions(c, item) for c in conditions["any"])
        if "not" in conditions:
            return not evaluate_rule_conditions(conditions["not"], item)
        if "var" in conditions:
            var_path  = conditions["var"]
            op        = conditions.get("op", "exists")
            expected  = conditions.get("value")
            # Resolve expected if it's a template
            if isinstance(expected, str) and "{{" in expected:
                expected = resolve(expected, {"item": item})
            value = extract_value({"item": item}, var_path)
            return evaluate_condition(value, op, expected)

    return True

# ── Check evaluator ───────────────────────────────────────────────────────
def run_checks(discovery_data: Dict[str, List[Dict]]) -> List[Dict]:
    """Evaluate all check rules against discovery data."""
    results = []

    for svc_dir in sorted(CHECKS_ROOT.iterdir()):
        if not svc_dir.is_dir():
            continue
        check_dir = svc_dir / "checks" / "default"
        if not check_dir.exists():
            continue

        for cf in sorted(check_dir.glob("*.yaml")):
            try:
                data = yaml.safe_load(cf.read_text())
            except Exception:
                continue

            for rule in (data.get("checks", []) if isinstance(data, dict) else []):
                rule_id   = rule.get("rule_id", "?")
                for_each  = rule.get("for_each", "")
                conditions = rule.get("conditions", {})

                items = discovery_data.get(for_each, [])

                if not items:
                    results.append({
                        "rule_id":   rule_id,
                        "for_each":  for_each,
                        "status":    "NO_DATA",
                        "pass":      0,
                        "fail":      0,
                        "resources": [],
                    })
                    continue

                rule_pass, rule_fail, failed_resources = 0, 0, []
                for item in items:
                    # Auto-parse any JSON string values in the item before evaluation
                    item = _parse_json_strings(item)
                    passed = evaluate_rule_conditions(conditions, item)
                    if passed:
                        rule_pass += 1
                    else:
                        rule_fail += 1
                        # Capture identifying fields
                        uid = (item.get("Name") or item.get("Id") or item.get("Arn")
                               or item.get("BucketName") or item.get("FunctionName")
                               or item.get("InstanceId") or item.get("RoleId")
                               or str(item)[:60])
                        failed_resources.append(uid)

                results.append({
                    "rule_id":   rule_id,
                    "for_each":  for_each,
                    "status":    "FAIL" if rule_fail > 0 else "PASS",
                    "pass":      rule_pass,
                    "fail":      rule_fail,
                    "resources": failed_resources[:10],  # cap at 10 per rule
                })

    return results

# ── Main ──────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Local discovery + check validator")
    parser.add_argument("--services", nargs="+", default=["s3"],
                        help="Service(s) to run, or 'all'")
    parser.add_argument("--region",   default="ap-south-1")
    parser.add_argument("--profile",  default=None, help="AWS profile name")
    parser.add_argument("--from-cache", action="store_true",
                        help="Skip discovery, use cached discovery_data.json")
    parser.add_argument("--checks-only", action="store_true",
                        help="Only run check evaluation (requires --from-cache data)")
    args = parser.parse_args()

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    cache_file = OUT_DIR / "discovery_data.json"

    # ── Step 1: Discovery ────────────────────────────────────────────────
    if args.from_cache and cache_file.exists():
        log.info(f"Loading discovery data from cache: {cache_file}")
        discovery_data = json.loads(cache_file.read_text())
        log.info(f"Loaded {len(discovery_data)} discovery_ids from cache")
    else:
        runner = DiscoveryRunner(region=args.region, profile=args.profile)
        discovery_data: Dict[str, List[Dict]] = {}

        # Determine which services to run
        if args.services == ["all"]:
            catalog_files = sorted(CATALOG_ROOT.rglob("step6_*_discoveries_minimum.yaml"))
        else:
            catalog_files = []
            for svc in args.services:
                # Try minimum file first, fall back to full step6
                f = CATALOG_ROOT / svc / f"step6_{svc}_discoveries_minimum.yaml"
                if not f.exists():
                    f = CATALOG_ROOT / svc / f"step6_{svc}.discovery.yaml"
                if f.exists():
                    catalog_files.append(f)
                else:
                    log.warning(f"No catalog file found for service: {svc}")

        log.info(f"Running discovery for {len(catalog_files)} service(s)...")
        t0 = time.time()

        for cf in catalog_files:
            svc = cf.parent.name
            svc_data = runner.run_service(svc, cf)
            discovery_data.update(svc_data)

        elapsed = time.time() - t0
        total_items = sum(len(v) for v in discovery_data.values())
        log.info(f"Discovery complete: {len(discovery_data)} ops, {total_items} items in {elapsed:.1f}s")

        # Save to cache
        cache_file.write_text(json.dumps(discovery_data, indent=2, default=str))
        log.info(f"Discovery data saved: {cache_file}")

    # ── Step 2: Check evaluation ─────────────────────────────────────────
    log.info("Evaluating check rules...")
    check_results = run_checks(discovery_data)
    (OUT_DIR / "check_results.json").write_text(json.dumps(check_results, indent=2))

    # ── Step 3: Summary ──────────────────────────────────────────────────
    total      = len(check_results)
    passed     = sum(1 for r in check_results if r["status"] == "PASS")
    failed     = sum(1 for r in check_results if r["status"] == "FAIL")
    no_data    = sum(1 for r in check_results if r["status"] == "NO_DATA")

    # Group by service
    by_svc: Dict[str, Dict] = defaultdict(lambda: {"pass": 0, "fail": 0, "no_data": 0})
    for r in check_results:
        svc = r["rule_id"].split(".")[1] if "." in r["rule_id"] else "unknown"
        by_svc[svc][r["status"].lower() if r["status"] != "NO_DATA" else "no_data"] += 1

    lines = [
        "=" * 60,
        "LOCAL VALIDATOR SUMMARY",
        "=" * 60,
        f"  Total rules   : {total}",
        f"  PASS          : {passed}",
        f"  FAIL          : {failed}",
        f"  NO_DATA       : {no_data}  (service not used / no resources found)",
        "",
        f"{'Service':<25} {'PASS':>6} {'FAIL':>6} {'NO_DATA':>8}",
        "-" * 50,
    ]
    for svc in sorted(by_svc):
        s = by_svc[svc]
        lines.append(f"  {svc:<23} {s['pass']:>6} {s['fail']:>6} {s['no_data']:>8}")

    if failed > 0:
        lines += ["", "FAILED RULES (first 20):", "-" * 50]
        for r in [r for r in check_results if r["status"] == "FAIL"][:20]:
            lines.append(f"  {r['rule_id']}")
            lines.append(f"    for_each: {r['for_each']}")
            lines.append(f"    fail={r['fail']} pass={r['pass']}")
            if r["resources"]:
                lines.append(f"    failing resources: {r['resources'][:3]}")

    lines += [
        "",
        f"Output files:",
        f"  {OUT_DIR}/discovery_data.json",
        f"  {OUT_DIR}/check_results.json",
        f"  {OUT_DIR}/summary.txt",
        "=" * 60,
    ]

    summary = "\n".join(lines)
    print(summary)
    (OUT_DIR / "summary.txt").write_text(summary)


if __name__ == "__main__":
    main()
