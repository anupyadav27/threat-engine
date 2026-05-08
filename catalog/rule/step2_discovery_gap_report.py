#!/usr/bin/env python3
"""
step2_discovery_gap_report.py
=============================
Phase 2: For every CONFIG rule in the CSV:
  1. Find the best matching discovery_id (for_each) from the step6 catalog.
  2. Find the best emit field (conditions.var) from that discovery's emit block.
  3. If no discovery exists for the service → flag as GAP, generate a stub
     discovery entry to be added to the step6 YAML.

Outputs:
  catalog/rule/discovery_resolution.json  — rule_id → {for_each, var, status}
  catalog/rule/discovery_gaps_report.yaml — grouped list of gaps with stubs
  catalog/discovery_generator_data/{csp}/{svc}/step6_{svc}.discovery.yaml
      (patched with stub entry if --patch-stubs is passed)

Usage:
    python3 catalog/rule/step2_discovery_gap_report.py             # report only
    python3 catalog/rule/step2_discovery_gap_report.py --patch-stubs  # also write stubs
    python3 catalog/rule/step2_discovery_gap_report.py --csp ibm   # one CSP
"""
from __future__ import annotations

import csv
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Optional

import yaml

ROOT     = Path(__file__).resolve().parent.parent.parent
RULE_DIR = Path(__file__).resolve().parent
DGD      = ROOT / "catalog" / "discovery_generator_data"
CSV_PATH = ROOT / "complaince_csv" / "new_rules_deduplicated.csv"

PATCH_STUBS = "--patch-stubs" in sys.argv
FILTER_CSP  = None
for i, a in enumerate(sys.argv):
    if a == "--csp" and i + 1 < len(sys.argv):
        FILTER_CSP = sys.argv[i + 1].lower()

# ─────────────────────────────────────────────────────────────────────────────
# Load step6 discovery catalog into two indexes
# ─────────────────────────────────────────────────────────────────────────────

def load_discovery_index() -> tuple[
    dict[str, list[str]],          # (csp, svc) → [discovery_ids]
    dict[str, list[str]],          # discovery_id → [emit field names]
    dict[str, Path],               # (csp, svc) → path to step6 yaml
]:
    id_index:    dict[str, list[str]] = {}   # (csp,svc) key → [ids]
    field_index: dict[str, list[str]] = {}   # discovery_id → [fields]
    path_index:  dict[str, Path]      = {}   # (csp,svc) key → yaml path

    for f in DGD.rglob("step6_*.yaml"):
        csp = f.parts[-3]
        svc = f.parts[-2]
        key = f"{csp}|{svc}"
        path_index[key] = f
        try:
            data = yaml.safe_load(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(data, dict) or not data.get("discovery"):
            continue
        ids: list[str] = []
        for d in (data["discovery"] or []):
            if not isinstance(d, dict):
                continue
            did    = d.get("discovery_id", "")
            emit   = d.get("emit", {})
            if did:
                ids.append(did)
            fields: list[str] = []
            if isinstance(emit, dict):
                item = emit.get("item", {})
                if isinstance(item, dict):
                    fields = list(item.keys())
            field_index[did] = fields
        id_index[key] = ids

    return id_index, field_index, path_index


print("Loading step6 discovery catalog ...")
ID_INDEX, FIELD_INDEX, PATH_INDEX = load_discovery_index()
print(f"  {len(FIELD_INDEX):,} discovery_ids across {len(ID_INDEX)} services")

# ─────────────────────────────────────────────────────────────────────────────
# Service name normalisation: CSV rule_id → discovery catalog service key
# ─────────────────────────────────────────────────────────────────────────────

# Maps rule_id part[1] → actual catalog service directory
_SVC_ALIAS: dict[str, dict[str, str]] = {
    "alicloud": {
        "actiontrail":    "actiontrail",
        "ecs":            "ecs",
        "ram":            "ram",
        "oos":            "oos",
        "sas":            "sas",                # security center
        "securitycenter": "sas",
        "threatdetection":"sas",
        "api":            "apigateway",
        "slb":            "slb",
        "voicenavigator": "voicenavigator",
        "resourcemanager":"resourcemanager",
        "tablestore":     "tablestore",
        "vpn":            "vpn",
    },
    "aws": {
        "cloudtrail": "cloudtrail",
        "ec2":        "ec2",
        "iam":        "iam",
        "ssm":        "ssm",
        "chime":      "chime",
        "qldb":       "qldb",
        "vpn":        "vpn",
        "media_import_export": "importexport",
    },
    "azure": {
        "aad":            "aad",
        "compute":        "compute",
        "vm":             "compute",
        "monitor":        "monitor",
        "communication":  "communication",
        "aks":            "aks",
        "backup":         "backup",
        "cr":             "containerregistry",
        "devops":         "devops",
        "entra":          "aad",
        "functionapp":    "functions",
        "iam":            "aad",
        "managementgroup":"managementgroup",
        "netappfiles":    "netapp",
        "rbac":           "authorization",
        "securitycenter": "security",
        "vpn":            "vpn",
    },
    "gcp": {
        "cloudaudit":      "logging",
        "compute":         "compute",
        "iam":             "iam",
        "logging":         "logging",
        "osconfig":        "osconfig",
        "contactcenterinsights": "contactcenterinsights",
        "app":             "appengine",
        "cloud_security_scanner": "websecurityscanner",
        "gcr":             "containerregistry",
        "gke":             "container",
        "kms":             "cloudkms",
        "loadbalancing":   "compute",
        "organization_policy": "orgpolicy",
        "resourcemanager": "cloudresourcemanager",
        "sql":             "sqladmin",
        "vpn":             "compute",
    },
    "ibm": {
        "activity_tracker": "activity_tracker",
        "activitytracker":  "activity_tracker",
        "cloudant":         "cloudant",
        "codeengine":       "code_engine",
        "functions":        "functions",
        "iam":              "iam_identity",
        "is":               "vpc",
        "schematics":       "schematics",
        "security_advisor": "security_advisor",
        "securityadvisor":  "security_advisor",
        "vpc":              "vpc",
        "watson":           "natural_language_understanding",
        "api":              "api_gateway",
        "cis":              "internet_services",
        "cloud":            "resource_controller",
        "cloud_databases":  "databases",
        "code":             "code_engine",
        "config":           "resource_controller",
        "cos":              "s3transfer",
        "event":            "event_notifications",
        "iks":              "container",
        "kafka":            "eventstreams",
        "kms":              "key_protect",
        "load":             "load_balancer",
        "logdna":           "security_advisor",
        "mq":               "mqcloud",
        "network":          "direct_link",
        "ocp":              "container",
        "openshift":        "container",
        "scc":              "security_compliance_center",
        "security_and_compliance_center": "security_compliance_center",
        "vsi":              "vpc",
    },
    "k8s": {
        "apiserver":     "k8s_apiserver",
        "audit":         "k8s_audit",
        "container":     "container",
        "core":          "core",
        "falco":         "falco",
        "kube_apiserver":"k8s_apiserver",
        "kubeconfig":    "kubeconfig",
        "authentication":"authentication",
        "compute":       "compute",
        "node":          "node",
    },
    "oci": {
        "announcements": "announcements",
        "audit":         "audit",
        "compute":       "compute",
        "iam":           "identity",
        "kms":           "keymanagement",
        "network":       "core",
        "oke":           "containerengine",
        "vcn":           "core",
        "containerregistry": "artifacts",
    },
}

def resolve_catalog_svc(csp: str, raw_svc: str) -> Optional[str]:
    """Map CSV service token → catalog service directory name."""
    alias_map = _SVC_ALIAS.get(csp, {})
    # direct alias
    if raw_svc in alias_map:
        return alias_map[raw_svc]
    # exact in catalog
    if f"{csp}|{raw_svc}" in ID_INDEX:
        return raw_svc
    # normalised match (strip hyphens/underscores)
    raw_clean = raw_svc.replace("_", "").replace("-", "").lower()
    for key in ID_INDEX:
        k_csp, k_svc = key.split("|", 1)
        if k_csp == csp:
            if k_svc.replace("_", "").replace("-", "").lower() == raw_clean:
                return k_svc
    return None

# ─────────────────────────────────────────────────────────────────────────────
# Field scoring: pick best emit field for a given check name
# ─────────────────────────────────────────────────────────────────────────────

_FIELD_SCORE_PATTERNS: list[tuple[list[str], list[str], int]] = [
    # (check keywords, preferred field keywords, score)
    (["encrypt", "kms", "cmk"], ["encrypted", "kms_key_id", "encryption"], 100),
    (["log", "logging", "audit", "trail"], ["logging_enabled", "log_enabled", "enabled"], 100),
    (["enabled", "active", "status"], ["logging_enabled", "enabled", "status"], 90),
    (["mfa", "multi_factor"], ["mfa_enabled", "mfa"], 100),
    (["ssl", "tls", "https", "cert"], ["ssl_enabled", "min_tls_version", "certificate"], 100),
    (["public", "internet", "facing"], ["internet_facing", "public_ip_address"], 100),
    (["backup", "snapshot"], ["backup_enabled", "snapshot_enabled"], 100),
    (["versioning"], ["versioning_enabled"], 100),
    (["permission", "access", "privilege"], ["permissions", "acl"], 90),
    (["tag", "label"], ["tags", "labels"], 90),
    (["retention"], ["retention_days", "retention_period", "logging_enabled"], 85),
    (["organization", "multi_account"], ["logging_enabled", "enabled"], 80),
    (["config", "configuration"], ["status", "enabled", "logging_enabled"], 70),
]

_COMMON_PREFERRED = ["logging_enabled", "enabled", "status", "encrypted",
                     "ssl_enabled", "mfa_enabled", "backup_enabled"]

def pick_best_field(check_name: str, emit_fields: list[str]) -> tuple[str, str, Any]:
    """
    Returns (var, op, value) for the conditions block.
    var = 'item.<field>'
    """
    if not emit_fields:
        return "item.enabled", "is_true", None

    check_lower = check_name.lower()
    best_field  = None
    best_score  = -1

    for check_kws, field_kws, score in _FIELD_SCORE_PATTERNS:
        if any(k in check_lower for k in check_kws):
            for fkw in field_kws:
                for ef in emit_fields:
                    if fkw in ef.lower():
                        if score > best_score:
                            best_score  = score
                            best_field  = ef

    # Fallback: prefer common fields
    if best_field is None:
        for pref in _COMMON_PREFERRED:
            for ef in emit_fields:
                if pref in ef.lower():
                    best_field = ef
                    break
            if best_field:
                break

    # Last resort: first field that isn't id/name
    if best_field is None:
        for ef in emit_fields:
            if ef not in ("id", "name", "region", "resource_type"):
                best_field = ef
                break
        if best_field is None and emit_fields:
            best_field = emit_fields[0]

    # Determine op + value
    field_lower = best_field.lower() if best_field else ""
    if any(k in field_lower for k in ["enabled", "active", "mfa"]):
        op, value = "is_true", None
    elif "encrypted" in field_lower or "kms_key_id" in field_lower:
        op, value = "not_empty", None
    elif "internet_facing" in field_lower or "public" in field_lower:
        op, value = "not_equals", "true"
    elif "permissions" in field_lower or "acl" in field_lower:
        op, value = "not_contains", "*"
    elif "status" in field_lower:
        op, value = "equals", "Active"
    else:
        op, value = "is_true", None

    return f"item.{best_field}", op, value

# ─────────────────────────────────────────────────────────────────────────────
# Pick best discovery_id for a given rule
# ─────────────────────────────────────────────────────────────────────────────

def score_discovery_id(discovery_id: str, rule_id: str, check_name: str) -> int:
    """Score a discovery_id for relevance to the rule."""
    score = 0
    did_lower = discovery_id.lower()
    ck_lower  = check_name.lower().replace("_", " ")
    rid_lower = rule_id.lower()

    # Prefer IDs that share tokens with check name
    for token in re.split(r"[._\s]+", ck_lower):
        if len(token) > 3 and token in did_lower:
            score += 5

    # Prefer IDs with "list" or "describe" for resource rules
    if "list" in did_lower or "describe" in did_lower:
        score += 3
    if "get" in did_lower:
        score += 1

    # Prefer IDs that share the resource token from rule_id
    rule_parts = rid_lower.split(".")
    if len(rule_parts) > 2:
        resource_token = rule_parts[2].replace("_", "")
        if resource_token in did_lower.replace("_", "").replace("-", ""):
            score += 10

    return score

def pick_best_discovery_id(
    csp: str, cat_svc: str, rule_id: str, check_name: str
) -> Optional[str]:
    key = f"{csp}|{cat_svc}"
    ids = ID_INDEX.get(key, [])
    if not ids:
        return None
    scored = sorted(ids, key=lambda d: score_discovery_id(d, rule_id, check_name),
                    reverse=True)
    return scored[0]

# ─────────────────────────────────────────────────────────────────────────────
# Stub discovery generator (for missing services)
# ─────────────────────────────────────────────────────────────────────────────

_STANDARD_EMIT_FIELDS = {
    "id":                   "{{ item.Id }}",
    "name":                 "{{ item.Name }}",
    "resource_type":        "'{{ resource_type }}'",
    "region":               "{{ region }}",
    "encrypted":            "{{ item.Encrypted }}",
    "kms_key_id":           "{{ item.KMSKeyId }}",
    "status":               "{{ item.Status }}",
    "enabled":              "{{ item.Enabled }}",
    "logging_enabled":      "{{ item.LoggingEnabled }}",
    "mfa_enabled":          "{{ item.MfaEnabled }}",
    "ssl_enabled":          "{{ item.SslEnabled }}",
    "internet_facing":      "{{ item.InternetFacing }}",
    "public_ip_address":    "{{ item.PublicIpAddress }}",
    "tags":                 "{{ item.Tags }}",
    "permissions":          "{{ item.Permissions }}",
    "backup_enabled":       "{{ item.BackupEnabled }}",
    "versioning_enabled":   "{{ item.VersioningEnabled }}",
    "retention_days":       "{{ item.RetentionDays }}",
    "min_tls_version":      "{{ item.MinTlsVersion }}",
}

_CSP_CLIENT_MAP: dict[str, dict[str, str]] = {
    "alicloud": {
        "sas": "alibabacloud_sas20181203",
        "securitycenter": "alibabacloud_sas20181203",
        "threatdetection": "alibabacloud_sas20181203",
        "api": "alibabacloud_cloudapi20160714",
        "tablestore": "alibabacloud_tablestore20201209",
        "vpn": "alibabacloud_vpc20160428",
    },
    "aws": {
        "qldb": "boto3.client('qldb')",
        "vpn": "boto3.client('ec2')",
        "media_import_export": "boto3.client('importexport')",
    },
    "azure": {
        "aad": "azure.mgmt.graphrbac",
        "entra": "azure.mgmt.graphrbac",
        "backup": "azure.mgmt.recoveryservicesbackup",
        "aks": "azure.mgmt.containerservice",
        "devops": "azure.devops",
        "functionapp": "azure.mgmt.web",
        "managementgroup": "azure.mgmt.managementgroups",
        "netappfiles": "azure.mgmt.netapp",
        "rbac": "azure.mgmt.authorization",
        "securitycenter": "azure.mgmt.security",
        "vpn": "azure.mgmt.network",
        "cr": "azure.mgmt.containerregistry",
    },
    "gcp": {
        "app": "googleapiclient.appengine",
        "cloud_security_scanner": "google.cloud.websecurityscanner",
        "gcr": "google.cloud.artifactregistry",
        "gke": "google.cloud.container",
        "kms": "google.cloud.kms",
        "organization_policy": "googleapiclient.orgpolicy",
        "resourcemanager": "googleapiclient.cloudresourcemanager",
        "sql": "googleapiclient.sqladmin",
        "vpn": "googleapiclient.compute",
        "loadbalancing": "googleapiclient.compute",
    },
    "ibm": {
        "api": "ibm_platform_services.ApiGatewayControllerApiV1",
        "cis": "ibm_platform_services.GlobalCatalogV1",
        "cloud": "ibm_platform_services.ResourceControllerV2",
        "cloud_databases": "ibm_cloud_databases.CloudDatabasesV5",
        "code": "ibm_code_engine.CodeEngineV2",
        "config": "ibm_platform_services.ResourceControllerV2",
        "cos": "ibm_platform_services.ResourceControllerV2",
        "event": "ibm_eventnotifications.EventNotificationsV1",
        "iks": "ibm_container_registry.ContainerRegistryV1",
        "kafka": "ibm_eventstreams_sdk.AdminrestV1",
        "kms": "ibm_platform_services.GlobalCatalogV1",
        "load": "ibm_vpc.VpcV1",
        "logdna": "ibm_logdna_sdk.LogDnaV0",
        "mq": "ibm_mqcloud.MqcloudV1",
        "network": "ibm_platform_services.GlobalCatalogV1",
        "ocp": "ibm_container_registry.ContainerRegistryV1",
        "openshift": "ibm_container_registry.ContainerRegistryV1",
        "scc": "ibm_scc.SecurityAndComplianceCenterApiV3",
        "security_and_compliance_center": "ibm_scc.SecurityAndComplianceCenterApiV3",
        "vsi": "ibm_vpc.VpcV1",
    },
    "k8s": {
        "authentication": "kubernetes.client.AuthenticationV1Api",
        "compute":        "kubernetes.client.CoreV1Api",
        "container":      "kubernetes.client.CoreV1Api",
        "core":           "kubernetes.client.CoreV1Api",
        "falco":          "kubernetes.client.CustomObjectsApi",
        "kube_apiserver": "kubernetes.client.CoreV1Api",
        "kubeconfig":     "kubernetes.client.CoreV1Api",
        "node":           "kubernetes.client.CoreV1Api",
    },
    "oci": {
        "containerregistry": "oci.artifacts",
        "iam":               "oci.identity",
        "kms":               "oci.key_management",
        "network":           "oci.core",
        "oke":               "oci.container_engine",
        "vcn":               "oci.core",
    },
}

def _infer_action(raw_svc: str, rule_ids: list[str]) -> str:
    """Infer a sensible list API action name for a stub."""
    svc_lower = raw_svc.lower()
    # Common list/describe patterns
    patterns = [
        ("trail",    "DescribeTrails"),
        ("instance", "DescribeInstances"),
        ("user",     "ListUsers"),
        ("key",      "ListKeys"),
        ("bucket",   "ListBuckets"),
        ("cluster",  "ListClusters"),
        ("database", "ListDatabases"),
        ("gateway",  "ListGateways"),
        ("function", "ListFunctions"),
        ("policy",   "ListPolicies"),
        ("group",    "ListGroups"),
        ("role",     "ListRoles"),
        ("rule",     "ListRules"),
        ("volume",   "ListVolumes"),
        ("network",  "ListNetworks"),
        ("vpc",      "ListVpcs"),
    ]
    for kw, action in patterns:
        if kw in svc_lower:
            return action
    return "ListResources"

def build_stub_discovery(
    csp: str, raw_svc: str, rule_ids: list[str]
) -> dict:
    """Build a stub discovery entry block for insertion into step6 YAML."""
    discovery_id = f"{csp}.{raw_svc}.list_{raw_svc}s"
    action       = _infer_action(raw_svc, rule_ids)
    client       = _CSP_CLIENT_MAP.get(csp, {}).get(raw_svc, f"{csp}_{raw_svc}_client")

    return {
        "_stub":        True,
        "discovery_id": discovery_id,
        "_note":        f"STUB — generated by step2, needs real SDK review for {csp}.{raw_svc}",
        "_rules":       rule_ids,
        "_client":      client,
        "calls": [{"action": action, "save_as": "response", "on_error": "continue"}],
        "emit": {
            "as": "item",
            "items_for": "{{ response }}",
            "item": _STANDARD_EMIT_FIELDS,
        },
    }

# ─────────────────────────────────────────────────────────────────────────────
# Main resolution loop
# ─────────────────────────────────────────────────────────────────────────────

def norm_csp(c: str) -> str:
    return "oci" if c == "oracle" else c

def main() -> None:
    with open(CSV_PATH, newline="") as f:
        rows = list(csv.DictReader(f))

    config_rows = [r for r in rows if r["rule_type"] == "config"]
    if FILTER_CSP:
        config_rows = [r for r in config_rows
                       if norm_csp(r["csp"]) == FILTER_CSP or r["csp"] == FILTER_CSP]

    print(f"Resolving {len(config_rows)} config rules ...")

    resolution:    dict[str, dict]         = {}   # rule_id → resolution
    gap_by_csp_svc: dict[str, list[str]]   = defaultdict(list)  # "csp|raw_svc" → [rule_ids]

    for row in config_rows:
        rule_id    = row["suggested_rule_id"].strip()
        csp        = norm_csp(row["csp"].strip())
        raw_svc    = rule_id.split(".")[1] if "." in rule_id else "unknown"
        check_name = rule_id.split(".")[-1].replace("_", " ")

        cat_svc = resolve_catalog_svc(csp, raw_svc)

        if cat_svc:
            disc_id = pick_best_discovery_id(csp, cat_svc, rule_id, check_name)
            if disc_id:
                emit_fields = FIELD_INDEX.get(disc_id, [])
                var, op, value = pick_best_field(check_name, emit_fields)
                resolution[rule_id] = {
                    "status":       "resolved",
                    "for_each":     disc_id,
                    "var":          var,
                    "op":           op,
                    "value":        value,
                    "csp":          csp,
                    "catalog_svc":  cat_svc,
                    "emit_fields":  emit_fields,
                }
            else:
                resolution[rule_id] = {
                    "status":       "no_discovery_id",
                    "catalog_svc":  cat_svc,
                    "csp":          csp,
                }
                gap_by_csp_svc[f"{csp}|{raw_svc}"].append(rule_id)
        else:
            resolution[rule_id] = {
                "status":  "no_catalog_service",
                "raw_svc": raw_svc,
                "csp":     csp,
            }
            gap_by_csp_svc[f"{csp}|{raw_svc}"].append(rule_id)

    # ── Stats
    by_status: dict[str, int] = defaultdict(int)
    for v in resolution.values():
        by_status[v["status"]] += 1

    print(f"\nResolution summary:")
    print(f"  resolved           : {by_status.get('resolved', 0)}")
    print(f"  no_discovery_id    : {by_status.get('no_discovery_id', 0)}")
    print(f"  no_catalog_service : {by_status.get('no_catalog_service', 0)}")
    total_gaps = (by_status.get("no_discovery_id", 0) +
                  by_status.get("no_catalog_service", 0))
    print(f"  TOTAL gaps         : {total_gaps}")
    print(f"\nGap services ({len(gap_by_csp_svc)}):")
    for key, rids in sorted(gap_by_csp_svc.items()):
        print(f"  {key}: {len(rids)} rules")

    # ── Write resolution index
    res_path = RULE_DIR / "discovery_resolution.json"
    res_path.write_text(json.dumps(resolution, indent=2), encoding="utf-8")
    print(f"\nWrote: {res_path}")

    # ── Write gap report YAML
    stubs: list[dict] = []
    for key, rule_ids in sorted(gap_by_csp_svc.items()):
        csp_s, raw_svc_s = key.split("|", 1)
        stub = build_stub_discovery(csp_s, raw_svc_s, rule_ids)
        stubs.append({
            "csp":         csp_s,
            "raw_service": raw_svc_s,
            "rule_count":  len(rule_ids),
            "rule_ids":    rule_ids,
            "action_needed": (
                f"Add a real discovery entry for {csp_s}.{raw_svc_s} in "
                f"catalog/discovery_generator_data/{csp_s}/{raw_svc_s}/step6_*.yaml"
            ),
            "stub_discovery": stub,
        })

    gap_report = {
        "summary": {
            "total_config_rules": len(config_rows),
            "resolved": by_status.get("resolved", 0),
            "gaps": total_gaps,
            "gap_services": len(gap_by_csp_svc),
        },
        "gaps": stubs,
    }

    gap_path = RULE_DIR / "discovery_gaps_report.yaml"
    gap_path.write_text(
        yaml.dump(gap_report, allow_unicode=True, sort_keys=False,
                  default_flow_style=False),
        encoding="utf-8",
    )
    print(f"Wrote: {gap_path}")

    # ── Optionally patch step6 YAMLs with stub entries
    if PATCH_STUBS:
        print("\nPatching step6 YAMLs with stubs ...")
        patched = 0
        for key, rule_ids in gap_by_csp_svc.items():
            csp_s, raw_svc_s = key.split("|", 1)
            # Find or create the step6 yaml
            svc_dir = DGD / csp_s / raw_svc_s
            step6_candidates = list(svc_dir.glob("step6_*.yaml")) if svc_dir.exists() else []
            if step6_candidates:
                step6_path = step6_candidates[0]
                try:
                    data = yaml.safe_load(step6_path.read_text(encoding="utf-8")) or {}
                except Exception:
                    data = {}
            else:
                svc_dir.mkdir(parents=True, exist_ok=True)
                step6_path = svc_dir / f"step6_{raw_svc_s}.discovery.yaml"
                data = {
                    "version": "1.0", "provider": csp_s, "service": raw_svc_s,
                    "discovery": [],
                }

            stub = build_stub_discovery(csp_s, raw_svc_s, rule_ids)
            # Only add if not already present
            existing_ids = {d.get("discovery_id", "") for d in data.get("discovery", [])}
            if stub["discovery_id"] not in existing_ids:
                data.setdefault("discovery", []).append(stub)
                step6_path.write_text(
                    yaml.dump(data, allow_unicode=True, sort_keys=False,
                              default_flow_style=False),
                    encoding="utf-8",
                )
                print(f"  Patched: {step6_path.relative_to(ROOT)}")
                patched += 1
        print(f"  {patched} files patched.")
    else:
        print("\nTip: pass --patch-stubs to also write stub entries into step6 YAMLs.")

    # ── Sample resolved rules
    print("\nSample resolutions:")
    shown = 0
    for rid, res in resolution.items():
        if res["status"] == "resolved" and shown < 5:
            print(f"  {rid}")
            print(f"    for_each : {res['for_each']}")
            print(f"    var      : {res['var']}")
            print(f"    op/value : {res['op']} / {res['value']}")
            shown += 1


if __name__ == "__main__":
    main()
