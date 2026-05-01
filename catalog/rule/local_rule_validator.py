#!/usr/bin/env python3
"""
Local Rule-Catalog Validator  —  Discovery → Inventory → Check
===============================================================
Reads everything from catalog/rule/{csp}_rule_check/:
  • {service}/{service}.discovery.yaml  (or step6_{service}.discovery.yaml)
  • {service}/{service}.checks.yaml

Three phases:
  1. DISCOVERY  – call real cloud API, emit items per discovery_id
  2. INVENTORY  – validate identifier fields against resource_inventory_identifier (RDS)
  3. CHECK      – evaluate every check rule against emitted data

Supports: aws (boto3), azure (azure-mgmt-*), gcp (google-api-python-client), k8s (kubernetes)

Usage:
  # AWS – specific services
  python local_rule_validator.py --csp aws --services s3 iam ec2

  # AWS – all 103 services
  python local_rule_validator.py --csp aws --services all --region ap-south-1

  # AWS – skip discovery, reuse cache, run checks only
  python local_rule_validator.py --csp aws --services all --from-cache

  # Azure
  python local_rule_validator.py --csp azure --services compute network keyvault

  # K8s
  python local_rule_validator.py --csp k8s --services all

  # Multiple CSPs
  python local_rule_validator.py --csp aws k8s --services all

Output: /tmp/rule_validator/{csp}/
  discovery_data.json   — {discovery_id: [items]}
  inventory_report.json — {service: {total, identified, missing_id_fields}}
  check_results.json    — [{rule_id, status, pass, fail, resources}]
  summary.txt           — human-readable report
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

# ── Paths ─────────────────────────────────────────────────────────────────────
REPO_ROOT  = Path(__file__).resolve().parents[2]   # catalog/rule/../../  = repo root
RULE_ROOT  = REPO_ROOT / "catalog" / "rule"
OUT_BASE   = Path("/tmp/rule_validator")

# ── Condition evaluator (shared with check engine) ────────────────────────────
_check_common = str(REPO_ROOT / "engines" / "check" / "common")
if _check_common not in sys.path:
    sys.path.insert(0, _check_common)
try:
    import importlib as _il
    _ce = _il.import_module("utils.condition_evaluator")
    _extract_value    = _ce.extract_value       # type: ignore[attr-defined]
    _evaluate_cond    = _ce.evaluate_condition  # type: ignore[attr-defined]
    _HAS_EVALUATOR = True
except Exception:
    _HAS_EVALUATOR = False

logging.basicConfig(level=logging.WARNING, format="%(levelname)-5s  %(message)s")
log = logging.getLogger("rule_validator")


# ─────────────────────────────────────────────────────────────────────────────
# Generic helpers
# ─────────────────────────────────────────────────────────────────────────────

_TMPL_RE = re.compile(r"\{\{\s*(.+?)\s*\}\}")

def _extract(obj: Any, path: str) -> Any:
    if _HAS_EVALUATOR:
        return _extract_value(obj, path)
    # Simple fallback
    parts = path.split(".")
    cur = obj
    for p in parts:
        if cur is None:
            return None
        if isinstance(cur, dict):
            cur = cur.get(p)
        elif isinstance(cur, list) and p.isdigit():
            cur = cur[int(p)] if int(p) < len(cur) else None
        else:
            return None
    return cur

def _resolve(tpl: Any, ctx: Dict) -> Any:
    if not isinstance(tpl, str) or "{{" not in tpl:
        return tpl
    m = re.fullmatch(r"\{\{\s*([\w.\[\]]+)\s*\}\}", tpl.strip())
    if m:
        return _extract(ctx, m.group(1))
    def _sub(match):
        v = _extract(ctx, match.group(1).strip())
        return str(v) if v is not None else ""
    return _TMPL_RE.sub(_sub, tpl)

def _parse_json_strings(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _parse_json_strings(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_parse_json_strings(v) for v in obj]
    if isinstance(obj, str) and obj and obj[0] in "{[":
        try:
            return _parse_json_strings(json.loads(obj))
        except Exception:
            pass
    return obj

def _extract_emit_items(response: Dict, emit: Dict,
                         parent: Optional[Dict] = None) -> List[Dict]:
    if not emit:
        return [response]
    ctx = {"response": response, "item": parent or {}}
    tpl = emit.get("items_for", "")
    raw_list = _resolve(tpl, ctx) if tpl else [response]
    if not isinstance(raw_list, list):
        raw_list = [raw_list] if raw_list is not None else []
    item_tpl = emit.get("item", {})
    results = []
    for raw in raw_list:
        if raw is None:
            continue
        if item_tpl:
            ictx = {"response": response, "item": raw}
            emitted = {k: _resolve(v, ictx) for k, v in item_tpl.items()}
            # If template produced only None values or only keys with [] suffix
            # (auto-generated GCP YAMLs often have this pattern), fall back to raw item.
            _useful = {k: v for k, v in emitted.items()
                       if v is not None and not k.endswith("[]")}
            if not _useful and isinstance(raw, dict):
                emitted = raw
            else:
                # Auto-include standard resource identity fields if absent in template
                if isinstance(raw, dict):
                    for _std in ("id", "name", "type", "resource_id"):
                        if _std not in emitted and _std in raw:
                            emitted[_std] = raw[_std]
        else:
            emitted = raw if isinstance(raw, dict) else {"_value": raw}
        results.append(emitted)
    return results

def _topo_sort(ops: List[Dict]) -> List[Dict]:
    remaining = list(ops)
    done: set = set()
    ordered: List[Dict] = []
    for _ in range(len(remaining) + 1):
        if not remaining:
            break
        progress = False
        for op in list(remaining):
            fe = op.get("for_each", "")
            if not fe or fe in done:
                ordered.append(op)
                done.add(op.get("discovery_id", ""))
                remaining.remove(op)
                progress = True
        if not progress:
            ordered.extend(remaining)
            break
    return ordered

def _find_discovery_yaml(svc_dir: Path, svc: str) -> Optional[Path]:
    """Prefer {service}.discovery.yaml, fall back to step6_{service}.discovery.yaml."""
    candidates = [
        svc_dir / f"{svc}.discovery.yaml",
        svc_dir / f"step6_{svc}.discovery.yaml",
        # Any .discovery.yaml in the dir
    ]
    for c in candidates:
        if c.exists():
            return c
    for f in svc_dir.glob("*.discovery.yaml"):
        return f
    return None

def _find_checks_yaml(svc_dir: Path, svc: str) -> Optional[Path]:
    candidates = [
        svc_dir / f"{svc}.checks.yaml",
        svc_dir / "checks.yaml",
    ]
    for c in candidates:
        if c.exists():
            return c
    for f in svc_dir.glob("*.checks.yaml"):
        return f
    return None

def _eval_rule(conditions: Any, item: Dict) -> bool:
    if not conditions:
        return True
    if isinstance(conditions, dict):
        if "all" in conditions:
            return all(_eval_rule(c, item) for c in conditions["all"])
        if "any" in conditions:
            return any(_eval_rule(c, item) for c in conditions["any"])
        if "not" in conditions:
            return not _eval_rule(conditions["not"], item)
        if "var" in conditions:
            path     = conditions["var"]
            op       = conditions.get("op", "exists")
            expected = conditions.get("value")
            val      = _extract({"item": item}, path)
            # Handle operators missing from the shared evaluator
            if op == "is_true":   return bool(val)
            if op == "is_false":  return not bool(val)
            if op == "is_null":   return val is None
            if op == "is_not_null": return val is not None
            if _HAS_EVALUATOR:
                return _evaluate_cond(val, op, expected)
            # Minimal fallback
            if op == "exists":     return val is not None
            if op == "not_exists": return val is None
            if op == "equals":     return val == expected
            if op == "not_equals": return val != expected
            if op == "not_empty":  return bool(val)
            if op == "is_empty":   return not bool(val)
            return True
    return True


# ─────────────────────────────────────────────────────────────────────────────
# AWS runner
# ─────────────────────────────────────────────────────────────────────────────

AWS_CLIENT_ALIASES = {
    "eip": "ec2", "vpc": "ec2", "vpcflowlogs": "ec2", "ebs": "ec2",
    "fargate": "ecs", "parameterstore": "ssm", "directoryservice": "ds",
    "costexplorer": "ce", "timestream": "timestream-query",
    "identitycenter": "sso-admin", "sso": "sso-admin",
    "kinesisvideostreams": "kinesisvideo", "networkfirewall": "network-firewall",
    "macie": "macie2", "elasticfilesystem": "efs",
    "workflows": "stepfunctions", "drs": "drs",
    "controltower": "controltower", "lakeformation": "lakeformation",
    # boto3 name differences
    "cognito": "cognito-idp",
    "eventbridge": "events",
    "edr": "security-ir",
    "elasticloadbalancing": "elb",
    "elasticloadbalancingv2": "elbv2",
    "cloudhsm": "cloudhsmv2",
    "waf": "wafv2",
    "cloudwatchlogs": "logs",
    "cloudwatchevents": "events",
    "route53domains": "route53domains",
    "acm": "acm",
    "appmesh": "appmesh",
    "apprunner": "apprunner",
    "codeguruprofiler": "codeguruprofiler",
    "elastictranscoder": "elastictranscoder",
    "transfer": "transfer",
    "fsx": "fsx",
    "datasync": "datasync",
}

AWS_DEFAULT_PARAMS: Dict[str, Dict] = {
    "describe_snapshots": {"OwnerIds": ["self"]},
    "describe_images":    {"Owners": ["self"]},
}

def _aws_runner(svc: str, yaml_path: Path, region: str,
                profile: Optional[str]) -> Dict[str, List[Dict]]:
    try:
        import boto3
        from botocore.config import Config as BotocoreConfig
        from botocore.exceptions import ClientError, EndpointResolutionError, OperationNotPageableError
    except ImportError:
        log.error("boto3 not installed — pip install boto3")
        return {}

    boto_name = AWS_CLIENT_ALIASES.get(svc, svc)
    session   = boto3.Session(profile_name=profile) if profile else boto3.Session()
    _cfg      = BotocoreConfig(read_timeout=30, connect_timeout=10, retries={"max_attempts": 1})
    try:
        client = session.client(boto_name, region_name=region, config=_cfg)
    except Exception as e:
        log.warning(f"[aws/{svc}] cannot create client '{boto_name}': {e}")
        return {}

    try:
        catalog = yaml.safe_load(yaml_path.read_text())
    except Exception as e:
        log.error(f"[aws/{svc}] cannot parse {yaml_path}: {e}")
        return {}

    ops = catalog.get("discovery", []) if isinstance(catalog, dict) else []
    results: Dict[str, List[Dict]] = {}

    for op in _topo_sort(ops):
        did    = op.get("discovery_id", "")
        fe     = op.get("for_each", "")
        calls  = op.get("calls", [])
        emit   = op.get("emit", {})
        if not calls:
            continue

        call0   = calls[0]
        action  = call0.get("action", "")
        tpl_p   = call0.get("params", {}) or {}

        parents = results.get(fe, [{}]) if fe else [{}]

        op_items: List[Dict] = []
        for par in parents:
            params = {k: _resolve(v, {"item": par}) for k, v in tpl_p.items()}
            params = {k: v for k, v in params.items() if v is not None}
            if action in AWS_DEFAULT_PARAMS:
                params = {**AWS_DEFAULT_PARAMS[action], **params}

            try:
                try:
                    pag = client.get_paginator(action)
                    merged: Dict = {}
                    for page in pag.paginate(**params):
                        for k, v in page.items():
                            if k in ("ResponseMetadata", "NextToken"):
                                continue
                            if isinstance(v, list) and isinstance(merged.get(k), list):
                                merged[k].extend(v)
                            else:
                                merged[k] = v
                    resp = merged
                except OperationNotPageableError:
                    resp = getattr(client, action)(**params)
                except Exception:
                    resp = getattr(client, action)(**params)
            except Exception as e:
                code = getattr(getattr(e, "response", {}), "get", lambda *a: "")("Error", {}).get("Code", type(e).__name__)
                SILENT = {"AccessDeniedException","NotImplementedException","UnsupportedOperation",
                          "InvalidClientTokenId","AuthFailure","UnauthorizedOperation",
                          "AWSOrganizationsNotInUseException","NoSuchEntityException",
                          "ResourceNotFoundException","ServiceUnavailable","OptInRequired",
                          "NoSuchBucketPolicy","NoSuchLifecycleConfiguration","NotFoundException",
                          "NoSuchConfiguration","MissingParameter","InvalidParameterCombination",
                          "InvalidParameterValue"}
                if code not in SILENT:
                    log.info(f"  [aws/{svc}] {action}: {e!s:.80s}")
                continue

            items = _extract_emit_items(resp, emit, par)
            op_items.extend(items)

        results[did] = op_items
        log.debug(f"  [aws/{svc}] {did}: {len(op_items)} items")

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Azure runner  (reuses DISCOVERY_CLIENT_MAP from local_azure_e2e_validator)
# ─────────────────────────────────────────────────────────────────────────────

AZURE_CLIENT_MAP: Dict[str, Tuple[str, str]] = {
    "compute":          ("azure.mgmt.compute",          "ComputeManagementClient"),
    "network":          ("azure.mgmt.network",           "NetworkManagementClient"),
    "storage":          ("azure.mgmt.storage",           "StorageManagementClient"),
    "keyvault":         ("azure.mgmt.keyvault",          "KeyVaultManagementClient"),
    "sql":              ("azure.mgmt.sql",                "SqlManagementClient"),
    "authorization":    ("azure.mgmt.authorization",     "AuthorizationManagementClient"),
    "iam":              ("azure.mgmt.authorization",     "AuthorizationManagementClient"),
    "rbac":             ("azure.mgmt.authorization",     "AuthorizationManagementClient"),
    "policy":           ("azure.mgmt.authorization",     "AuthorizationManagementClient"),
    "security":         ("azure.mgmt.security",          "SecurityCenter"),
    "resource":         ("azure.mgmt.resource",          "ResourceManagementClient"),
    "containerservice": ("azure.mgmt.containerservice",  "ContainerServiceClient"),
    "aks":              ("azure.mgmt.containerservice",  "ContainerServiceClient"),
    "web":              ("azure.mgmt.web",                "WebSiteManagementClient"),
    "webapp":           ("azure.mgmt.web",                "WebSiteManagementClient"),
    "appservice":       ("azure.mgmt.web",                "WebSiteManagementClient"),
    "monitor":          ("azure.mgmt.monitor",           "MonitorManagementClient"),
    "cosmosdb":         ("azure.mgmt.cosmosdb",          "CosmosDBManagementClient"),
    "dns":              ("azure.mgmt.dns",                "DnsManagementClient"),
    "eventhub":         ("azure.mgmt.eventhub",          "EventHubManagementClient"),
    "automation":       ("azure.mgmt.automation",        "AutomationClient"),
    "management":       ("azure.mgmt.managementgroups",  "ManagementGroupsAPI"),
    "mysql":            ("azure.mgmt.rdbms.mysql",       "MySQLManagementClient"),
    "postgresql":       ("azure.mgmt.rdbms.postgresql",  "PostgreSQLManagementClient"),
    "mariadb":          ("azure.mgmt.rdbms.mariadb",     "MariaDBManagementClient"),
    "containerregistry":("azure.mgmt.containerregistry", "ContainerRegistryManagementClient"),
    "recoveryservices": ("azure.mgmt.recoveryservices",  "RecoveryServicesClient"),
    "redis":            ("azure.mgmt.redis",             "RedisManagementClient"),
    "cdn":              ("azure.mgmt.cdn",                "CdnManagementClient"),
    "servicebus":       ("azure.mgmt.servicebus",        "ServiceBusManagementClient"),
    "batch":            ("azure.mgmt.batch",             "BatchManagementClient"),
    "subscription":     ("azure.mgmt.subscription",     "SubscriptionClient"),
    "databricks":       ("azure.mgmt.databricks",        "AzureDatabricksManagementClient"),
    "purview":          ("azure.mgmt.purview",           "PurviewManagementClient"),
    "synapse":          ("azure.mgmt.synapse",           "SynapseManagementClient"),
    "datafactory":      ("azure.mgmt.datafactory",       "DataFactoryManagementClient"),
    "loganalytics":     ("azure.mgmt.loganalytics",      "LogAnalyticsManagementClient"),
    "iothub":           ("azure.mgmt.iothub",            "IotHubClient"),
    "cognitiveservices":("azure.mgmt.cognitiveservices", "CognitiveServicesManagementClient"),
    "containerinstance":("azure.mgmt.containerinstance", "ContainerInstanceManagementClient"),
    "eventgrid":        ("azure.mgmt.eventgrid",         "EventGridManagementClient"),
    "signalr":          ("azure.mgmt.signalr",           "SignalRManagementClient"),
}

def _azure_runner(svc: str, yaml_path: Path, subscription_id: str) -> Dict[str, List[Dict]]:
    try:
        from azure.identity import DefaultAzureCredential
    except ImportError:
        log.error("azure-identity not installed")
        return {}

    try:
        catalog = yaml.safe_load(yaml_path.read_text())
    except Exception as e:
        log.error(f"[azure/{svc}] cannot parse {yaml_path}: {e}")
        return {}

    ops = catalog.get("discovery", []) if isinstance(catalog, dict) else []
    cred = DefaultAzureCredential()
    _clients: Dict[str, Any] = {}
    results: Dict[str, List[Dict]] = {}

    def _get_client(seg: str):
        if seg in _clients:
            return _clients[seg]
        entry = AZURE_CLIENT_MAP.get(seg)
        if not entry:
            _clients[seg] = None
            return None
        mod_name, cls_name = entry
        try:
            mod = __import__(mod_name, fromlist=[cls_name])
            cls = getattr(mod, cls_name)
            try:
                c = cls(cred, subscription_id)
            except TypeError:
                c = cls(cred)
            _clients[seg] = c
        except Exception as e:
            log.debug(f"  [azure/{svc}] cannot load {mod_name}.{cls_name}: {e}")
            _clients[seg] = None
        return _clients[seg]

    for op in _topo_sort(ops):
        did    = op.get("discovery_id", "")
        fe     = op.get("for_each", "")
        calls  = op.get("calls", [])
        emit   = op.get("emit", {})
        if not calls:
            continue

        action = calls[0].get("action", "")
        # discovery_id format: azure.{sdk_service}.{resource_type}.{method}
        parts = did.split(".")
        seg   = parts[1] if len(parts) > 1 else svc
        client = _get_client(seg) or _get_client(svc)
        if client is None:
            continue

        parents = results.get(fe, [{}]) if fe else [{}]
        op_items: List[Dict] = []

        for par in parents:
            try:
                # Walk the action dot-path on the client
                obj = client
                for attr in action.split("."):
                    obj = getattr(obj, attr)
                raw_objs = list(obj())
                # Convert Azure SDK objects → dicts so templates can navigate them
                def _to_dict(o: Any) -> Any:
                    if isinstance(o, dict):
                        return o
                    if hasattr(o, "as_dict"):
                        try:
                            return o.as_dict()
                        except Exception:
                            pass
                    if hasattr(o, "__dict__"):
                        return {k: _to_dict(v) for k, v in vars(o).items()
                                if not k.startswith("_")}
                    return o

                def _enrich_azure(d: Any) -> Any:
                    """Inject subscriptionId/resourceGroupName from the 'id' field."""
                    if not isinstance(d, dict):
                        return d
                    rid = d.get("id", "")
                    if rid and isinstance(rid, str) and "/subscriptions/" in rid:
                        orig_parts = rid.split("/")
                        parts = rid.lower().split("/")
                        if not d.get("subscriptionId"):
                            try:
                                idx = parts.index("subscriptions") + 1
                                if idx < len(orig_parts):
                                    d["subscriptionId"] = orig_parts[idx]
                            except ValueError:
                                pass
                        if not d.get("resourceGroupName"):
                            try:
                                idx = parts.index("resourcegroups") + 1
                                if idx < len(orig_parts):
                                    d["resourceGroupName"] = orig_parts[idx]
                            except ValueError:
                                pass
                    return d

                raw = [_to_dict(x) for x in raw_objs]
                resp = {"value": raw}
            except Exception as e:
                log.debug(f"  [azure/{svc}] {action}: {e!s:.60s}")
                continue
            items = _extract_emit_items(resp, emit, par)
            # Enrich emitted items with subscriptionId/resourceGroupName from id
            items = [_enrich_azure(it) for it in items]
            op_items.extend(items)

        results[did] = op_items
        log.debug(f"  [azure/{svc}] {did}: {len(op_items)} items")

    return results


# ─────────────────────────────────────────────────────────────────────────────
# K8s runner
# ─────────────────────────────────────────────────────────────────────────────

K8S_CLIENT_MAP = {
    "pod":           ("CoreV1Api",       "list_namespaced_pod"),
    "deployment":    ("AppsV1Api",       "list_namespaced_deployment"),
    "service":       ("CoreV1Api",       "list_namespaced_service"),
    "configmap":     ("CoreV1Api",       "list_namespaced_config_map"),
    "secret":        ("CoreV1Api",       "list_namespaced_secret"),
    "node":          ("CoreV1Api",       "list_node"),
    "namespace":     ("CoreV1Api",       "list_namespace"),
    "serviceaccount":("CoreV1Api",       "list_namespaced_service_account"),
    "pvc":           ("CoreV1Api",       "list_namespaced_persistent_volume_claim"),
    "pv":            ("CoreV1Api",       "list_persistent_volume"),
    "rbac":          ("RbacAuthorizationV1Api", "list_cluster_role_binding"),
    "clusterrole":   ("RbacAuthorizationV1Api", "list_cluster_role"),
    "ingress":       ("NetworkingV1Api", "list_namespaced_ingress"),
    "networkpolicy": ("NetworkingV1Api", "list_namespaced_network_policy"),
    "cronjob":       ("BatchV1Api",      "list_namespaced_cron_job"),
    "job":           ("BatchV1Api",      "list_namespaced_job"),
    "daemonset":     ("AppsV1Api",       "list_namespaced_daemon_set"),
    "statefulset":   ("AppsV1Api",       "list_namespaced_stateful_set"),
    "replicaset":    ("AppsV1Api",       "list_namespaced_replica_set"),
    "storageclass":  ("StorageV1Api",    "list_storage_class"),
}

def _k8s_runner(svc: str, yaml_path: Path, kubeconfig: Optional[str]) -> Dict[str, List[Dict]]:
    try:
        from kubernetes import client as k8s_client, config as k8s_config
    except ImportError:
        log.error("kubernetes not installed — pip install kubernetes")
        return {}

    try:
        if kubeconfig:
            k8s_config.load_kube_config(config_file=kubeconfig)
        else:
            k8s_config.load_kube_config()
    except Exception as e:
        log.error(f"K8s config load failed: {e}")
        return {}

    try:
        catalog = yaml.safe_load(yaml_path.read_text())
    except Exception as e:
        log.error(f"[k8s/{svc}] cannot parse {yaml_path}: {e}")
        return {}

    ops = catalog.get("discovery", []) if isinstance(catalog, dict) else []
    results: Dict[str, List[Dict]] = {}
    NS = "default"

    for op in _topo_sort(ops):
        did   = op.get("discovery_id", "")
        fe    = op.get("for_each", "")
        calls = op.get("calls", [])
        emit  = op.get("emit", {})
        if not calls:
            continue

        action = calls[0].get("action", "")
        hint = K8S_CLIENT_MAP.get(svc, ("CoreV1Api", action))
        api_cls_name = hint[0] if hint else "CoreV1Api"

        try:
            api_cls = getattr(k8s_client, api_cls_name)
            api = api_cls()
            method = getattr(api, action, None)
            if method is None:
                continue
            try:
                resp_obj = method(namespace=NS)
            except TypeError:
                resp_obj = method()
            # K8s list responses have .items; single objects become a 1-item list
            if hasattr(resp_obj, "items"):
                items_raw = resp_obj.items
            else:
                items_raw = [resp_obj]
            # Convert K8s SDK objects → plain dicts (camelCase keys preserved)
            def _k8s_to_dict(o: Any) -> Any:
                if hasattr(o, "to_dict"):
                    return o.to_dict()
                return o if isinstance(o, dict) else {}
            raw_list = [_k8s_to_dict(i) for i in items_raw]
            # K8s YAMLs use items_for: '{{ response }}' — pass the list as response
            resp = raw_list
        except Exception as e:
            log.debug(f"  [k8s/{svc}] {action}: {e!s:.60s}")
            results[did] = []
            continue

        items = _extract_emit_items(resp, emit, {})
        results[did] = items
        log.debug(f"  [k8s/{svc}] {did}: {len(items)} items")

    return results


# ─────────────────────────────────────────────────────────────────────────────
# GCP runner
# ─────────────────────────────────────────────────────────────────────────────

# Map catalog GCP service name → (real_api_name, version)
# Keys are the `services.client` values from the YAML files
GCP_API_MAP: Dict[str, tuple] = {
    # Standard — same name, version override
    "compute":                  ("compute",                  "v1"),
    "storage":                  ("storage",                  "v1"),
    "container":                ("container",                "v1"),
    "iam":                      ("iam",                      "v1"),
    "monitoring":               ("monitoring",               "v3"),
    "dns":                      ("dns",                      "v1"),
    "redis":                    ("redis",                    "v1"),
    "spanner":                  ("spanner",                  "v1"),
    "pubsub":                   ("pubsub",                   "v1"),
    "dataproc":                 ("dataproc",                 "v1"),
    "secretmanager":            ("secretmanager",            "v1"),
    "composer":                 ("composer",                 "v1"),
    "aiplatform":               ("aiplatform",               "v1"),
    "networkmanagement":        ("networkmanagement",        "v1"),
    "cloudasset":               ("cloudasset",               "v1"),
    "accesscontextmanager":     ("accesscontextmanager",     "v1"),
    "certificatemanager":       ("certificatemanager",       "v1"),
    "backupdr":                 ("backupdr",                 "v1"),
    "cloudidentity":            ("cloudidentity",            "v1"),
    # Name remaps (catalog name ≠ real API name)
    "billing":                  ("cloudbilling",             "v1"),
    "bigquery":                 ("bigquery",                 "v2"),
    "bigtable":                 ("bigtableadmin",            "v2"),
    "cloudsql":                 ("sqladmin",                 "v1"),
    "sql":                      ("sqladmin",                 "v1"),
    "cloudrun":                 ("run",                      "v2"),
    "run":                      ("run",                      "v2"),
    "function":                 ("cloudfunctions",           "v2"),
    "cloudfunctions":           ("cloudfunctions",           "v2"),
    "gke":                      ("container",                "v1"),
    "gke_audit":                ("container",                "v1"),
    "kms":                      ("cloudkms",                 "v1"),
    "cloudkms":                 ("cloudkms",                 "v1"),
    "logging":                  ("logging",                  "v2"),
    "dlp":                      ("dlp",                      "v2"),
    "scc":                      ("securitycenter",           "v1"),
    "security_command_center":  ("securitycenter",           "v1"),
    "securitycenter":           ("securitycenter",           "v1"),
    "resourcemanager":          ("cloudresourcemanager",     "v3"),
    "cloudresourcemanager":     ("cloudresourcemanager",     "v3"),
    "filestore":                ("file",                     "v1"),
    "endpoints":                ("servicemanagement",        "v1"),
    "services":                 ("serviceusage",             "v1"),
    "orgpolicy":                ("orgpolicy",                "v2"),
    "dataflow":                 ("dataflow",                 "v1b3"),
    "trace":                    ("cloudtrace",               "v2"),
    "lb":                       ("compute",                  "v1"),   # load balancer → compute
    "apikeys":                  ("apikeys",                  "v2"),
    "datastudio":               ("datastudio",               "v1"),
    # No real discovery API — skip
    "audit":                    None,
    "ciem":                     None,
    "data_access":              None,
    "flow":                     None,
    "datastudio":               None,   # deprecated/removed from discovery
}

def _gcp_runner(svc: str, yaml_path: Path, project_id: str) -> Dict[str, List[Dict]]:
    try:
        import google.auth
        from googleapiclient import discovery as gcp_discovery
        from googleapiclient.errors import HttpError
    except ImportError:
        log.error("google-api-python-client not installed — pip install google-api-python-client google-auth")
        return {}

    try:
        catalog = yaml.safe_load(yaml_path.read_text())
    except Exception as e:
        log.error(f"[gcp/{svc}] cannot parse {yaml_path}: {e}")
        return {}

    ops = catalog.get("discovery", []) if isinstance(catalog, dict) else []
    if not ops:
        return {}

    # Get credentials
    try:
        creds, detected_project = google.auth.default()
        if not project_id:
            project_id = detected_project or ""
    except Exception as e:
        log.warning(f"[gcp/{svc}] auth failed: {e}")
        return {}

    # Determine API name and version
    svc_info = catalog.get("services", {})
    module_str = svc_info.get("module", "")
    catalog_client = svc_info.get("client", svc)

    # Check GCP_API_MAP first (explicit overrides)
    map_entry = GCP_API_MAP.get(catalog_client) or GCP_API_MAP.get(svc)
    if map_entry is None and (catalog_client in GCP_API_MAP or svc in GCP_API_MAP):
        # Explicitly mapped to None = no real API, skip
        return {}

    if map_entry:
        api_name, api_ver = map_entry
    else:
        # Fall back to parsing module string
        import re as _re
        api_name = catalog_client
        api_ver  = "v1"
        m = _re.search(r"build\(['\"]([^'\"]+)['\"],\s*['\"]([^'\"]+)['\"]", module_str)
        if m:
            api_name = m.group(1)
            api_ver  = m.group(2)

    try:
        service = gcp_discovery.build(api_name, api_ver, credentials=creds,
                                      cache_discovery=False)
    except Exception as e:
        log.warning(f"[gcp/{svc}] cannot build client for {api_name} {api_ver}: {e!s:.60s}")
        return {}

    results: Dict[str, List[Dict]] = {}

    for op in _topo_sort(ops):
        did   = op.get("discovery_id", "")
        fe    = op.get("for_each", "")
        calls = op.get("calls", [])
        emit  = op.get("emit", {})
        if not calls:
            continue

        action = calls[0].get("action", "")
        tpl_p  = calls[0].get("params", {}) or {}

        parents = results.get(fe, [{}]) if fe else [{}]
        op_items: List[Dict] = []

        for par in parents:
            params = {k: _resolve(v, {"item": par}) for k, v in tpl_p.items()}
            params = {k: v for k, v in params.items() if v is not None}
            # GCP param injection: different APIs use different resource path params.
            # Storage uses "project", BigQuery uses "projectId", most others use "parent" or "name".
            # We try progressively until one succeeds without TypeError.
            _needs_inject = (project_id and
                             "project" not in params and "projectId" not in params and
                             "name" not in params and "parent" not in params)
            if _needs_inject:
                _auto_params = [
                    dict(params, parent=f"projects/{project_id}"),
                    dict(params, name=f"projects/{project_id}"),
                    dict(params, projectId=project_id),
                    dict(params, project=project_id),
                    dict(params),
                ]
            elif project_id and "projectId" not in params and "project" not in params and \
                 ("datasetId" in params or "tableId" in params):
                # BigQuery sub-resource calls also need projectId
                _auto_params = [
                    dict(params, projectId=project_id),
                    dict(params),
                ]
            else:
                _auto_params = [dict(params)]

            try:
                # Navigate the dot-path on the service resource
                parts = action.split(".")
                obj   = service
                for part in parts[:-1]:
                    obj = getattr(obj, part)()
                method_name = parts[-1]
                method = getattr(obj, method_name)

                # Try each param variant; stop at first that doesn't TypeError
                working_params = params
                for _candidate in _auto_params:
                    try:
                        method(**_candidate).execute()   # dry probe
                        working_params = _candidate
                        break
                    except TypeError:
                        continue
                    except Exception:
                        working_params = _candidate
                        break

                # Full paginated call with working params
                all_items: Dict = {}
                page_token: Optional[str] = None
                while True:
                    call_params = dict(working_params)
                    if page_token:
                        call_params["pageToken"] = page_token
                    try:
                        resp_obj = method(**call_params)
                        resp = resp_obj.execute()
                    except HttpError as e:
                        if e.resp.status in (403, 404, 400):
                            resp = {}
                        else:
                            raise
                    # Merge response pages
                    for k, v in resp.items():
                        if k in ("nextPageToken", "kind", "etag"):
                            continue
                        if isinstance(v, list) and isinstance(all_items.get(k), list):
                            all_items[k].extend(v)
                        else:
                            all_items[k] = v
                    page_token = resp.get("nextPageToken")
                    if not page_token:
                        break

                items = _extract_emit_items(all_items, emit, par)
                op_items.extend(items)
            except Exception as e:
                log.debug(f"  [gcp/{svc}] {action}: {e!s:.80s}")
                continue

        results[did] = op_items
        log.debug(f"  [gcp/{svc}] {did}: {len(op_items)} items")

    return results


# ─────────────────────────────────────────────────────────────────────────────
# OCI runner
# ─────────────────────────────────────────────────────────────────────────────

# Maps YAML service name → (oci_module, ClientClass)
OCI_CLIENT_MAP: Dict[str, Optional[tuple]] = {
    "ai_anomaly_detection": ("oci.ai_anomaly_detection", "AnomalyDetectionClient"),
    "ai_language":          ("oci.ai_language",          "AIServiceLanguageClient"),
    "analytics":            ("oci.analytics",            "AnalyticsClient"),
    "apigateway":           ("oci.apigateway",           "ApiGatewayClient"),
    "artifacts":            ("oci.artifacts",            "ArtifactsClient"),
    "audit":                ("oci.audit",                "AuditClient"),
    "bds":                  ("oci.bds",                  "BdsClient"),
    "block_storage":        ("oci.core",                 "BlockstorageClient"),
    "certificates":         ("oci.certificates_management", "CertificatesManagementClient"),
    "cloud_guard":          ("oci.cloud_guard",          "CloudGuardClient"),
    "compute":              ("oci.core",                 "ComputeClient"),
    "container_engine":     ("oci.container_engine",     "ContainerEngineClient"),
    "container_instances":  ("oci.container_instances",  "ContainerInstanceClient"),
    "data_catalog":         ("oci.data_catalog",         "DataCatalogClient"),
    "data_flow":            ("oci.data_flow",            "DataFlowClient"),
    "data_integration":     ("oci.data_integration",     "DataIntegrationClient"),
    "data_safe":            ("oci.data_safe",            "DataSafeClient"),
    "data_science":         ("oci.data_science",         "DataScienceClient"),
    "database":             ("oci.database",             "DatabaseClient"),
    "devops":               ("oci.devops",               "DevopsClient"),
    "dns":                  ("oci.dns",                  "DnsClient"),
    "edge_services":        None,
    "events":               ("oci.events",               "EventsClient"),
    "file_storage":         ("oci.file_storage",         "FileStorageClient"),
    "functions":            ("oci.functions",            "FunctionsManagementClient"),
    "identity":             ("oci.identity",             "IdentityClient"),
    "key_management":       ("oci.key_management",       "KmsVaultClient"),
    "load_balancer":        ("oci.load_balancer",        "LoadBalancerClient"),
    "logging":              ("oci.logging",              "LoggingManagementClient"),
    "monitoring":           ("oci.monitoring",           "MonitoringClient"),
    "mysql":                ("oci.mysql",                "DbSystemClient"),
    "network_firewall":     ("oci.network_firewall",     "NetworkFirewallClient"),
    "nosql":                ("oci.nosql",                "NosqlClient"),
    "object_storage":       ("oci.object_storage",       "ObjectStorageClient"),
    "ons":                  ("oci.ons",                  "NotificationControlPlaneClient"),
    "queue":                ("oci.queue",                "QueueAdminClient"),
    "redis":                ("oci.redis",                "RedisClusterClient"),
    "resource_manager":     ("oci.resource_manager",     "ResourceManagerClient"),
    "streaming":            ("oci.streaming",            "StreamAdminClient"),
    "vault":                ("oci.vault",                "VaultsClient"),
    "virtual_network":      ("oci.core",                 "VirtualNetworkClient"),
    "waf":                  ("oci.waf",                  "WafClient"),
}


def _oci_to_dict(obj: Any) -> Any:
    """Convert OCI SDK model → plain dict."""
    try:
        import oci.util as oci_util
        return oci_util.to_dict(obj)
    except Exception:
        pass
    if hasattr(obj, "__dict__"):
        return {k: _oci_to_dict(v) for k, v in vars(obj).items()
                if not k.startswith("_")}
    if isinstance(obj, list):
        return [_oci_to_dict(i) for i in obj]
    return obj


def _oci_runner(svc: str, yaml_path: Path, compartment_id: str,
                oci_config_file: str = "~/.oci/config") -> Dict[str, List[Dict]]:
    try:
        import oci as _oci
        import importlib as _il
    except ImportError:
        log.error("oci SDK not installed — pip install oci")
        return {}

    try:
        cfg = _oci.config.from_file(os.path.expanduser(oci_config_file))
    except Exception as e:
        log.warning(f"[oci/{svc}] cannot load OCI config: {e}")
        return {}

    tenancy_id = cfg.get("tenancy", compartment_id)
    comp_id    = compartment_id or tenancy_id

    # Resolve client class
    entry = OCI_CLIENT_MAP.get(svc)
    if entry is None:
        # Unknown service or explicitly skipped
        return {}
    mod_path, cls_name = entry
    try:
        mod    = _il.import_module(mod_path)
        client = getattr(mod, cls_name)(cfg)
    except Exception as e:
        log.warning(f"[oci/{svc}] cannot build client {mod_path}.{cls_name}: {e!s:.60s}")
        return {}

    # Special: object_storage needs namespace
    os_namespace: Optional[str] = None
    if svc == "object_storage":
        try:
            os_namespace = client.get_namespace().data
        except Exception:
            pass

    try:
        catalog = yaml.safe_load(yaml_path.read_text())
    except Exception as e:
        log.error(f"[oci/{svc}] cannot parse {yaml_path}: {e}")
        return {}

    ops     = catalog.get("discovery", []) if isinstance(catalog, dict) else []
    results: Dict[str, List[Dict]] = {}

    for op in _topo_sort(ops):
        did   = op.get("discovery_id", "")
        fe    = op.get("for_each", "")
        calls = op.get("calls", [])
        emit  = op.get("emit", {})
        if not calls:
            continue

        action  = calls[0].get("action", "")
        tpl_p   = calls[0].get("params", {}) or {}
        parents = results.get(fe, [{}]) if fe else [{}]
        op_items: List[Dict] = []

        for par in parents:
            params = {k: _resolve(v, {"item": par}) for k, v in tpl_p.items()}
            params = {k: v for k, v in params.items() if v is not None}

            # Inject standard OCI params if not already set
            if "compartment_id" not in params:
                # identity.list_users / audit.get_configuration need tenancy_id
                if svc == "identity" or svc == "audit":
                    params["compartment_id"] = tenancy_id
                else:
                    params["compartment_id"] = comp_id
            if svc == "object_storage" and os_namespace and "namespace_name" not in params:
                params["namespace_name"] = os_namespace

            method = getattr(client, action, None)
            if method is None:
                log.debug(f"  [oci/{svc}] method not found: {action}")
                continue

            try:
                # Paginated call
                all_data: List[Any] = []
                page: Optional[str] = None
                while True:
                    call_kw = dict(params)
                    if page:
                        call_kw["page"] = page
                    resp = method(**call_kw)
                    raw = resp.data
                    if isinstance(raw, list):
                        all_data.extend(raw)
                    else:
                        all_data.append(raw)
                    # OCI pagination: resp.headers["opc-next-page"]
                    page = resp.headers.get("opc-next-page") if hasattr(resp, "headers") else None
                    if not page:
                        break

                # Convert OCI SDK models → plain dicts
                dict_data = [_oci_to_dict(i) for i in all_data]
                resp_dict = {"data": dict_data}
                items = _extract_emit_items(resp_dict, emit, par)
                op_items.extend(items)
                log.debug(f"  [oci/{svc}] {did}: {len(items)} items")
            except Exception as e:
                log.debug(f"  [oci/{svc}] {action}: {e!s:.80s}")
                continue

        results[did] = op_items

    return results


# ─────────────────────────────────────────────────────────────────────────────
# AliCloud runner  (uses aliyun-python-sdk-core or CLI subprocess fallback)
# ─────────────────────────────────────────────────────────────────────────────

# Maps YAML service name → Alibaba Cloud product/endpoint name
ALICLOUD_PRODUCT_MAP: Dict[str, Optional[str]] = {
    "ecs":           "Ecs",
    "vpc":           "Vpc",
    "oss":           "Oss",
    "rds":           "Rds",
    "ack":           "CS",           # Container Service
    "ram":           "Ram",
    "kms":           "Kms",
    "sls":           "Sls",          # Log Service
    "waf":           "Waf-openapi",
    "cdn":           "Cdn",
    "oss":           "Oss",
    "slb":           "Slb",
    "eip":           "Vpc",
    "nat":           "Vpc",
    "sg":            "Ecs",
    "apigateway":    "CloudAPI",
    "mns":           "Mns-open",
    "sas":           "Sas",          # Security Center
    "actiontrail":   "Actiontrail",
    "cloudfw":       "cloudfw",
    "cas":           "cas",
    "dns":           "Alidns",
    "polardb":       "polardb",
    "mongodb":       "Dds",          # ApsaraDB for MongoDB
    "apsaradb":      "Rds",
    "apsaramq":      "Ons",
    "alb":           "Alb",
    "nlb":           "Nlb",
    "cen":           "Cbn",
    "sms":           "Dysmsapi",
    "fc":            "FC-Open",
    "cr":            "cr",           # Container Registry
    "dts":           "Dts",
    "datalake":      "DLF",
    "analyticdb":    "adb",
    "accessanalyzer":"accessanalyzer",
    "api":           "CloudAPI",
    "apikeys":       "CloudAPI",
    "ack":           "CS",
}


def _alicloud_runner(svc: str, yaml_path: Path, region: str,
                     access_key: str, secret_key: str) -> Dict[str, List[Dict]]:
    """
    Call Alibaba Cloud APIs via aliyunsdkcore (sync) or subprocess aliyun CLI.
    Falls back gracefully if neither available.
    """
    import subprocess, json as _json

    try:
        catalog = yaml.safe_load(yaml_path.read_text())
    except Exception as e:
        log.error(f"[alicloud/{svc}] cannot parse {yaml_path}: {e}")
        return {}

    ops = catalog.get("discovery", []) if isinstance(catalog, dict) else []
    if not ops:
        return {}

    # Try SDK first
    _sdk_ok = False
    try:
        from aliyunsdkcore.client import AcsClient as _AcsClient
        from aliyunsdkcore.request import CommonRequest as _CommonReq
        _ali_client = _AcsClient(access_key, secret_key, region)
        _sdk_ok = True
    except ImportError:
        _ali_client = None

    def _call_action(action: str, product: str, params: dict) -> dict:
        if _sdk_ok and _ali_client:
            try:
                req = _CommonReq()
                req.set_method("GET")
                req.set_domain(f"{product.lower()}.aliyuncs.com")
                req.set_version("2014-05-26")  # generic; overridden per product below
                req.set_action_name(action)
                for k, v in params.items():
                    req.add_query_param(k, str(v))
                resp = _ali_client.do_action_with_exception(req)
                return _json.loads(resp)
            except Exception as e:
                log.debug(f"  [alicloud/{svc}] SDK call {action} failed: {e!s:.80s}")
                return {}
        elif access_key:
            # Subprocess fallback via aliyun CLI
            try:
                cmd = ["aliyun", product, "--region", region,
                       "--access-key-id", access_key,
                       "--access-key-secret", secret_key,
                       action]
                for k, v in params.items():
                    cmd += [f"--{k}", str(v)]
                out = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                return _json.loads(out.stdout) if out.returncode == 0 else {}
            except Exception as e:
                log.debug(f"  [alicloud/{svc}] CLI call {action} failed: {e!s:.80s}")
                return {}
        return {}

    product = ALICLOUD_PRODUCT_MAP.get(svc, svc)
    if product is None:
        return {}

    results: Dict[str, List[Dict]] = {}

    for op in _topo_sort(ops):
        did   = op.get("discovery_id", "")
        fe    = op.get("for_each", "")
        calls = op.get("calls", [])
        emit  = op.get("emit", {})
        if not calls:
            continue

        action  = calls[0].get("action", "")
        tpl_p   = calls[0].get("params", {}) or {}
        parents = results.get(fe, [{}]) if fe else [{}]
        op_items: List[Dict] = []

        for par in parents:
            params = {k: _resolve(v, {"item": par}) for k, v in tpl_p.items()}
            params = {k: v for k, v in params.items() if v is not None}
            if region and "RegionId" not in params:
                params["RegionId"] = region

            resp = _call_action(action, product, params)
            items = _extract_emit_items(resp, emit, par)
            op_items.extend(items)

        results[did] = op_items
        log.debug(f"  [alicloud/{svc}] {did}: {len(op_items)} items")

    return results


# ─────────────────────────────────────────────────────────────────────────────
# IBM Cloud runner  (uses IBM Cloud Python SDK or REST via API key)
# ─────────────────────────────────────────────────────────────────────────────

IBM_SERVICE_MAP: Dict[str, Optional[str]] = {
    "iam":                  "iam-identity",
    "kms":                  "ibm-key-protect-api",
    "containers":           "containers-kubernetes",
    "iks":                  "containers-kubernetes",
    "cos":                  "cos",
    "block_storage":        "is.volume",
    "databases":            "databases-for-postgresql",
    "certificate_manager":  "certificate-manager",
    "code_engine":          "ibmce",
    "container_registry":   "container-registry",
    "context_based_restrictions": "context-based-restrictions",
    "ciem":                 None,
    "db":                   "databases-for-postgresql",
    "event_streams":        "messagehub",
    "functions":            "functions",
    "monitoring":           "sysdig-monitor",
    "secrets_manager":      "secrets-manager",
    "scc":                  "compliance",
    "vpc":                  "is",
    "activity_tracker":     "logdna",
    "dns":                  "dns-svcs",
    "load_balancer":        "is.load-balancer",
}


def _ibm_runner(svc: str, yaml_path: Path, api_key: str,
                region: str = "us-south") -> Dict[str, List[Dict]]:
    """
    Call IBM Cloud APIs via ibm-cloud-sdk-core / requests with IAM token.
    """
    import requests as _req

    try:
        catalog = yaml.safe_load(yaml_path.read_text())
    except Exception as e:
        log.error(f"[ibm/{svc}] cannot parse {yaml_path}: {e}")
        return {}

    ops = catalog.get("discovery", []) if isinstance(catalog, dict) else []
    if not ops:
        return {}

    # Get IAM token
    _token: Optional[str] = None

    def _get_token() -> Optional[str]:
        nonlocal _token
        if _token:
            return _token
        if not api_key:
            return None
        try:
            r = _req.post(
                "https://iam.cloud.ibm.com/identity/token",
                data={"grant_type": "urn:ibm:params:oauth:grant-type:apikey",
                      "apikey": api_key},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=15,
            )
            _token = r.json().get("access_token")
        except Exception as e:
            log.debug(f"  [ibm] IAM token fetch failed: {e!s:.60s}")
        return _token

    def _rest_call(action: str, params: dict) -> dict:
        token = _get_token()
        if not token:
            return {}
        # action is a URL path like "GET /v2/clusters" or just method name
        method, _, path = action.partition(" ")
        if not path:
            path, method = method, "GET"
        base_url = f"https://{region}.containers.cloud.ibm.com"
        try:
            resp = _req.request(
                method.upper(),
                f"{base_url}{path}",
                headers={"Authorization": f"Bearer {token}",
                         "X-Region": region},
                params={k: v for k, v in params.items() if k != "RegionId"},
                timeout=20,
            )
            if resp.status_code in (401, 403, 404):
                return {}
            return resp.json() if resp.text else {}
        except Exception as e:
            log.debug(f"  [ibm/{svc}] REST {action}: {e!s:.60s}")
            return {}

    results: Dict[str, List[Dict]] = {}

    for op in _topo_sort(ops):
        did   = op.get("discovery_id", "")
        fe    = op.get("for_each", "")
        calls = op.get("calls", [])
        emit  = op.get("emit", {})
        if not calls:
            continue

        action  = calls[0].get("action", "")
        tpl_p   = calls[0].get("params", {}) or {}
        parents = results.get(fe, [{}]) if fe else [{}]
        op_items: List[Dict] = []

        for par in parents:
            params = {k: _resolve(v, {"item": par}) for k, v in tpl_p.items()}
            params = {k: v for k, v in params.items() if v is not None}

            resp = _rest_call(action, params)
            items = _extract_emit_items(resp, emit, par)
            op_items.extend(items)

        results[did] = op_items
        log.debug(f"  [ibm/{svc}] {did}: {len(op_items)} items")

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Inventory validator  (connects to RDS via env / --db-url)
# ─────────────────────────────────────────────────────────────────────────────

def _load_rii(csp: str, db_url: str) -> Dict[str, List[Dict]]:
    """Load resource_inventory_identifier rows for the given CSP, grouped by service."""
    try:
        import psycopg2
        import psycopg2.extras
    except ImportError:
        log.warning("psycopg2 not installed — inventory phase skipped")
        return {}
    try:
        conn = psycopg2.connect(db_url)
        conn.autocommit = True
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT service, resource_type, identifier_pattern, identifier_type,
                   root_ops, primary_param, classification
            FROM resource_inventory_identifier
            WHERE csp = %s AND should_inventory = TRUE
        """, (csp,))
        rows = cur.fetchall()
        cur.close()
        conn.close()
        by_svc: Dict[str, List[Dict]] = defaultdict(list)
        for r in rows:
            by_svc[r["service"]].append(dict(r))
        return dict(by_svc)
    except Exception as e:
        log.warning(f"Cannot load RII from DB: {e}")
        return {}

def _inventory_validate(svc: str, discovery_data: Dict[str, List[Dict]],
                         rii_rows: List[Dict]) -> Dict:
    """
    For each emitted item, check whether the resource can be uniquely identified.

    Identifier fields come in two kinds:
      ${Partition} / ${Region} / ${Account}  — injected by inventory engine (always available)
      {FieldName}                             — must be present in the emitted item

    We only validate the item-level fields (without $-prefix and not in
    CONTEXT_FIELDS).  An item is "identified" if it has at least one meaningful
    identity field (Arn, Name, Id, resource_uid, *Arn, *Name, *Id, etc.).
    """
    CONTEXT_FIELDS = {"Partition", "Region", "Account", "partition", "region", "account"}
    # Common identity field patterns
    ID_PATTERNS    = re.compile(r"(Arn|ARN|arn|Id$|ID$|Name$|Uid$|uid$|resource_uid)", re.IGNORECASE)

    total_items  = sum(len(v) for v in discovery_data.values())
    identified   = 0
    need_fields: Dict[str, int] = defaultdict(int)   # field → count missing
    unidentified_samples: List[Dict] = []
    items_checked = 0

    for row in rii_rows:
        pattern = row.get("identifier_pattern") or ""
        # Item-level fields: {FieldName} but NOT ${FieldName}
        item_fields = [f for f in re.findall(r"(?<!\$)\{([^}]+)\}", pattern)
                       if f not in CONTEXT_FIELDS]

        for op_entry in (row.get("root_ops") or []):
            op = op_entry.get("operation") or op_entry.get("op") or ""
            if not op:
                continue
            items = discovery_data.get(op, [])
            for item in items:
                items_checked += 1
                # Strategy 1: check required item_fields
                if item_fields:
                    missing = [f for f in item_fields
                               if _extract({"item": item}, f"item.{f}") is None]
                    if not missing:
                        identified += 1
                        continue
                    for f in missing:
                        need_fields[f] += 1
                else:
                    # Strategy 2: check for any identity-like field
                    has_id = any(ID_PATTERNS.search(k) and item.get(k) is not None
                                 for k in item.keys())
                    if has_id:
                        identified += 1
                        continue

                if len(unidentified_samples) < 3:
                    unidentified_samples.append({
                        "op":        op,
                        "expected":  item_fields[:5],
                        "item_keys": list(item.keys())[:10],
                    })

    top_missing = sorted(need_fields.items(), key=lambda x: -x[1])[:10]
    return {
        "total_items":        total_items,
        "items_checked":      items_checked,
        "identified":         identified,
        "unidentified":       max(0, items_checked - identified),
        "top_missing_fields": [f for f, _ in top_missing],
        "samples":            unidentified_samples,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Check evaluator
# ─────────────────────────────────────────────────────────────────────────────

def _run_checks(checks_yaml: Path, discovery_data: Dict[str, List[Dict]]) -> List[Dict]:
    try:
        data = yaml.safe_load(checks_yaml.read_text())
    except Exception as e:
        log.error(f"Cannot parse {checks_yaml}: {e}")
        return []

    results = []
    for rule in (data.get("checks", []) if isinstance(data, dict) else []):
        rule_id    = rule.get("rule_id", "?")
        for_each   = rule.get("for_each", "")
        conditions = rule.get("conditions", {})

        items = discovery_data.get(for_each, [])
        if not items:
            results.append({"rule_id": rule_id, "for_each": for_each,
                             "status": "NO_DATA", "pass": 0, "fail": 0, "resources": []})
            continue

        r_pass = r_fail = 0
        failed_resources: List[str] = []
        for item in items:
            if item is None:
                continue
            item = _parse_json_strings(item)
            try:
                passed = _eval_rule(conditions, item)
            except Exception:
                passed = True   # evaluation error → treat as pass (data gap, not a failure)
            if passed:
                r_pass += 1
            else:
                r_fail += 1
                _m = item if isinstance(item, dict) else {}
                uid = (_m.get("Name") or _m.get("Id") or _m.get("Arn")
                       or _m.get("BucketName") or _m.get("FunctionName")
                       or _m.get("InstanceId") or (_m.get("metadata") or {}).get("name")
                       or str(item)[:60])
                failed_resources.append(str(uid))

        results.append({
            "rule_id":   rule_id,
            "for_each":  for_each,
            "status":    "FAIL" if r_fail > 0 else "PASS",
            "pass":      r_pass,
            "fail":      r_fail,
            "resources": failed_resources[:10],
        })
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Per-CSP orchestrator
# ─────────────────────────────────────────────────────────────────────────────

def run_csp(csp: str, args: argparse.Namespace, rii: Dict[str, List[Dict]]) -> Dict:
    check_root = RULE_ROOT / f"{csp}_rule_check"
    out_dir    = OUT_BASE / csp
    out_dir.mkdir(parents=True, exist_ok=True)
    cache_file = out_dir / "discovery_data.json"

    # Determine which services to run
    all_svcs = sorted(
        e.name for e in check_root.iterdir()
        if e.is_dir() and not e.name.startswith(".")
    )
    skip_set = set(args.skip_services)
    if args.services == ["all"]:
        services = [s for s in all_svcs if s not in skip_set]
    else:
        services = [s for s in args.services if s in {e.name for e in check_root.iterdir() if e.is_dir()} and s not in skip_set]
        unknown  = [s for s in args.services if s not in {e.name for e in check_root.iterdir() if e.is_dir()}]
        if unknown:
            log.warning(f"[{csp}] Unknown services (skipped): {unknown}")

    print(f"\n{'='*64}")
    print(f"  CSP: {csp.upper()}   services: {len(services)}")
    print(f"{'='*64}")

    # ── Phase 1: Discovery ───────────────────────────────────────────────
    if args.from_cache and cache_file.exists():
        print(f"[1] DISCOVERY — loading from cache: {cache_file}")
        discovery_data: Dict[str, List[Dict]] = json.loads(cache_file.read_text())
        print(f"    Loaded {len(discovery_data)} discovery_ids")
    else:
        print(f"[1] DISCOVERY — running {len(services)} services …")
        t0 = time.time()
        discovery_data = {}
        disc_stats: Dict[str, int] = defaultdict(int)

        for svc in services:
            svc_dir   = check_root / svc
            yaml_path = _find_discovery_yaml(svc_dir, svc)
            if yaml_path is None:
                disc_stats["no_yaml"] += 1
                continue

            if csp == "aws":
                svc_data = _aws_runner(svc, yaml_path, args.region, args.profile)
            elif csp == "azure":
                sub_id = (args.subscription
                          or os.getenv("AZURE_SUBSCRIPTION_ID")
                          or os.getenv("SUBSCRIPTION_ID", ""))
                svc_data = _azure_runner(svc, yaml_path, sub_id)
            elif csp == "k8s":
                svc_data = _k8s_runner(svc, yaml_path, args.kubeconfig)
            elif csp == "gcp":
                proj = (args.project
                        or os.getenv("GOOGLE_CLOUD_PROJECT")
                        or os.getenv("GCLOUD_PROJECT", ""))
                svc_data = _gcp_runner(svc, yaml_path, proj)
            elif csp == "oci":
                comp = (args.compartment
                        or os.getenv("OCI_COMPARTMENT_ID", ""))
                svc_data = _oci_runner(svc, yaml_path, comp,
                                       getattr(args, "oci_config", "~/.oci/config"))
            elif csp == "alicloud":
                ak  = (args.access_key or os.getenv("ALICLOUD_ACCESS_KEY_ID", "")
                       or os.getenv("ALICLOUD_ACCESS_KEY", ""))
                sk  = (args.secret_key or os.getenv("ALICLOUD_SECRET_ACCESS_KEY", "")
                       or os.getenv("ALICLOUD_SECRET_KEY", ""))
                rgn = (args.region or os.getenv("ALICLOUD_REGION", "cn-hangzhou"))
                svc_data = _alicloud_runner(svc, yaml_path, rgn, ak, sk)
            elif csp == "ibm":
                ibm_key = (args.ibm_api_key or os.getenv("IBM_CLOUD_API_KEY", ""))
                rgn     = (args.region or os.getenv("IBM_CLOUD_REGION", "us-south"))
                svc_data = _ibm_runner(svc, yaml_path, ibm_key, rgn)
            else:
                svc_data = {}

            items_total = sum(len(v) for v in svc_data.values())
            if items_total > 0:
                disc_stats["with_data"] += 1
                print(f"    ✓ {svc:<30}  {len(svc_data)} ops  {items_total} items")
            else:
                disc_stats["empty"] += 1
                log.debug(f"    - {svc}: 0 items")

            discovery_data.update(svc_data)

        elapsed    = time.time() - t0
        total_ops  = len(discovery_data)
        total_items = sum(len(v) for v in discovery_data.values())
        print(f"\n    Done in {elapsed:.1f}s — {total_ops} ops, {total_items} items")
        print(f"    Services with data: {disc_stats['with_data']}  empty: {disc_stats['empty']}  no_yaml: {disc_stats['no_yaml']}")
        cache_file.write_text(json.dumps(discovery_data, indent=2, default=str))
        print(f"    Cached → {cache_file}")

    # ── Phase 2: Inventory ───────────────────────────────────────────────
    print(f"\n[2] INVENTORY — validating identifier fields …")
    inv_report: Dict[str, Dict] = {}
    inv_total = inv_ok = inv_miss = 0

    for svc in services:
        rows = rii.get(svc, [])
        if not rows:
            continue
        svc_disc = {k: v for k, v in discovery_data.items()
                    if len(k.split(".")) > 1 and k.split(".")[1] == svc}
        # Also include discovery_ids that belong to this service's ops
        op_ids = set()
        for row in rows:
            for op_entry in (row.get("root_ops") or []):
                op = op_entry.get("operation") or op_entry.get("op") or ""
                if op:
                    op_ids.add(op)
        svc_disc = {k: v for k, v in discovery_data.items() if k in op_ids}
        if not svc_disc:
            continue

        report = _inventory_validate(svc, svc_disc, rows)
        inv_report[svc] = report
        inv_total += report["total_items"]
        inv_ok    += report["identified"]
        inv_miss  += report["unidentified"]

        status = "✓" if report["unidentified"] == 0 else "⚠"
        print(f"    {status} {svc:<28} items={report['total_items']:>4}  "
              f"identified={report['identified']:>4}  "
              f"missing_id={report['unidentified']:>4}")
        if report["top_missing_fields"]:
            print(f"      missing fields: {report['top_missing_fields'][:5]}")

    print(f"\n    Total: {inv_total} items  identified: {inv_ok}  missing-id: {inv_miss}")

    # ── Phase 3: Check ───────────────────────────────────────────────────
    print(f"\n[3] CHECK — evaluating rules …")
    check_results: List[Dict] = []
    check_stats: Dict[str, int] = defaultdict(int)

    for svc in services:
        svc_dir    = check_root / svc
        checks_yaml = _find_checks_yaml(svc_dir, svc)
        if checks_yaml is None:
            continue

        results = _run_checks(checks_yaml, discovery_data)
        check_results.extend(results)
        for r in results:
            check_stats[r["status"]] += 1

    total_rules = len(check_results)
    r_pass   = check_stats["PASS"]
    r_fail   = check_stats["FAIL"]
    r_nodata = check_stats["NO_DATA"]
    print(f"    Rules: {total_rules}  PASS: {r_pass}  FAIL: {r_fail}  NO_DATA: {r_nodata}")

    # ── Save outputs ─────────────────────────────────────────────────────
    (out_dir / "inventory_report.json").write_text(json.dumps(inv_report, indent=2))
    (out_dir / "check_results.json").write_text(json.dumps(check_results, indent=2, default=str))

    return {
        "csp": csp,
        "services": len(services),
        "discovery": {"ops": len(discovery_data),
                      "items": sum(len(v) for v in discovery_data.values())},
        "inventory": {"total": inv_total, "identified": inv_ok, "missing_id": inv_miss},
        "checks":    {"total": total_rules, "pass": r_pass,
                      "fail": r_fail, "no_data": r_nodata},
        "check_results": check_results,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Summary printer
# ─────────────────────────────────────────────────────────────────────────────

def _print_summary(all_results: List[Dict], out_dir: Path) -> None:
    lines = [
        "",
        "═" * 72,
        "RULE VALIDATOR SUMMARY  —  Discovery → Inventory → Check",
        "═" * 72,
        f"  {'CSP':<8} {'Svcs':>5} {'Ops':>6} {'Items':>7}  "
        f"{'ID-ok':>7}  {'Rules':>6} {'PASS':>6} {'FAIL':>6} {'NODATA':>7}",
        "─" * 72,
    ]
    for r in all_results:
        lines.append(
            f"  {r['csp']:<8} {r['services']:>5} {r['discovery']['ops']:>6} "
            f"{r['discovery']['items']:>7}  {r['inventory']['identified']:>7}  "
            f"{r['checks']['total']:>6} {r['checks']['pass']:>6} "
            f"{r['checks']['fail']:>6} {r['checks']['no_data']:>7}"
        )
    lines.append("─" * 72)

    # Failed rules detail
    for r in all_results:
        fails = [c for c in r["check_results"] if c["status"] == "FAIL"][:20]
        if fails:
            lines.append(f"\n  [{r['csp'].upper()}] FAILED RULES ({len(fails)} shown):")
            for c in fails:
                lines.append(f"    ✗ {c['rule_id']}")
                lines.append(f"      for_each: {c['for_each']}  fail={c['fail']} pass={c['pass']}")
                if c["resources"]:
                    lines.append(f"      failing: {c['resources'][:3]}")

    lines += ["", f"  Output: {out_dir}/", "═" * 72, ""]
    summary = "\n".join(lines)
    print(summary)
    (out_dir / "summary.txt").write_text(summary)


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    p = argparse.ArgumentParser(description="Local Discovery → Inventory → Check validator")
    p.add_argument("--csp",      nargs="+", default=["aws"],
                   choices=["aws", "azure", "gcp", "k8s", "oci", "alicloud", "ibm"],
                   help="CSP(s) to validate")
    p.add_argument("--services", nargs="+", default=["all"],
                   help="Service(s) to run (or 'all')")
    p.add_argument("--skip-services", nargs="+", default=[],
                   metavar="SVC", help="Services to skip (useful to skip known-slow ones)")
    p.add_argument("--region",   default="ap-south-1", help="AWS/AliCloud/IBM region")
    p.add_argument("--profile",  default=None,          help="AWS profile")
    p.add_argument("--subscription", default=None,      help="Azure subscription ID")
    p.add_argument("--project",      default=None,      help="GCP project ID")
    p.add_argument("--kubeconfig",   default=None,      help="K8s kubeconfig path")
    # OCI
    p.add_argument("--compartment",  default=None,      help="OCI compartment OCID (default: tenancy root)")
    p.add_argument("--oci-config",   default="~/.oci/config", dest="oci_config",
                   help="OCI config file path")
    # AliCloud
    p.add_argument("--access-key",   default=None, dest="access_key",
                   help="AliCloud Access Key ID")
    p.add_argument("--secret-key",   default=None, dest="secret_key",
                   help="AliCloud Secret Access Key")
    # IBM
    p.add_argument("--ibm-api-key",  default=None, dest="ibm_api_key",
                   help="IBM Cloud API key")
    p.add_argument("--db-url",   default=None,
                   help="PostgreSQL URL for inventory DB (default: auto-detect)")
    p.add_argument("--from-cache", action="store_true",
                   help="Skip discovery, load cached discovery_data.json")
    p.add_argument("--no-inventory", action="store_true",
                   help="Skip inventory validation phase")
    p.add_argument("--no-checks", action="store_true",
                   help="Skip check evaluation phase")
    p.add_argument("--verbose", action="store_true", help="Debug logging")
    args = p.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.WARNING)

    # ── DB URL ─────────────────────────────────────────────────────────────
    db_url = args.db_url or os.getenv("INVENTORY_DB_URL") or (
        f"postgresql://postgres:jtv2BkJF8qoFtAKP@localhost:5433/threat_engine_inventory?sslmode=require"
    )

    # ── Load RII from DB ───────────────────────────────────────────────────
    rii: Dict[str, Dict[str, List[Dict]]] = {}
    if not args.no_inventory:
        print("Loading resource_inventory_identifier from DB …")
        for csp in args.csp:
            rii[csp] = _load_rii(csp, db_url)
            enabled_svcs = len(rii[csp])
            print(f"  {csp}: {enabled_svcs} services with enabled RII")

    # ── Run per CSP ─────────────────────────────────────────────────────────
    OUT_BASE.mkdir(parents=True, exist_ok=True)
    all_results: List[Dict] = []
    for csp in args.csp:
        result = run_csp(csp, args, rii.get(csp, {}))
        all_results.append(result)

    _print_summary(all_results, OUT_BASE)


if __name__ == "__main__":
    main()
