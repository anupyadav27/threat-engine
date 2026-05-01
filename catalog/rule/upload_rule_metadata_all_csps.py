#!/usr/bin/env python3
"""
upload_rule_metadata_all_csps.py
=================================
Upload ALL rule metadata (check + CIEM) for every CSP into the rule_metadata DB table.

Sources read:
  catalog/rule/{csp}_rule_metadata/{svc}/{rule_id}.yaml   ← check rule metadata
  catalog/rule/{csp}_rule_ciem/**/{rule_id}.yaml           ← CIEM rule metadata

Engine scope JSONB columns computed here are the SINGLE SOURCE OF TRUTH.
No hard-coded lists in engine Python code.

Columns populated:
  iam_security, network_security, data_security,
  encryption_security, container_security, database_security, ai_security

Usage:
  python upload_rule_metadata_all_csps.py --dry-run          # count only
  python upload_rule_metadata_all_csps.py                    # upload all CSPs
  python upload_rule_metadata_all_csps.py --csp aws azure    # specific CSPs
  python upload_rule_metadata_all_csps.py --type check       # check rules only
  python upload_rule_metadata_all_csps.py --type ciem        # CIEM rules only
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import psycopg2
from psycopg2.extras import Json, RealDictCursor
import yaml

ROOT     = Path(__file__).resolve().parents[2]
RULE_DIR = ROOT / "catalog" / "rule"

CSPS = ["aws", "azure", "gcp", "oci", "ibm", "alicloud", "k8s"]

# ── Engine scope mappings (single source of truth) ────────────────────────────

_IAM_DOMAIN = "identity_and_access_management"
_IAM_MODULES_BY_SUBCATEGORY = {
    "authentication":       ["mfa", "access_control"],
    "authorization":        ["least_privilege", "access_control"],
    "least_privilege":      ["least_privilege", "policy_analysis"],
    "identity_federation":  ["role_management", "access_control"],
    "access_control":       ["access_control"],
    "policy_enforcement":   ["policy_analysis"],
    "password_policy":      ["password_policy"],
}
_IAM_MODULES_BY_RULE_KEYWORD = [
    ("mfa",           "mfa"),
    ("multi_factor",  "mfa"),
    ("hardware_mfa",  "mfa"),
    ("password",      "password_policy"),
    ("rbac",          "least_privilege"),
    ("least_priv",    "least_privilege"),
    ("role",          "role_management"),
    ("policy",        "policy_analysis"),
    ("assume",        "role_management"),
    ("federation",    "identity_federation"),
    ("saml",          "identity_federation"),
    ("oidc",          "identity_federation"),
]

_NETWORK_DOMAIN = "network_security_and_connectivity"
_NETWORK_SERVICES = frozenset({
    # AWS
    "vpc", "ec2", "waf", "wafv2", "shield", "cloudfront", "route53",
    "elb", "elbv2", "alb", "nlb", "globalaccelerator", "apigateway",
    "apigatewayv2", "network-firewall", "networkfirewall",
    "vpn", "directconnect", "transit-gateway", "transitgateway",
    # Azure
    "virtualnetwork", "networksecuritygroup", "applicationgateway",
    "firewall", "loadbalancer", "publicipaddress", "frontdoor",
    "expressroute", "networkwatcher", "ddosprotection",
    "network", "security", "waf",                        # Azure service names in rule_metadata
    # GCP
    "compute", "dns", "armor",
    "lb", "gke", "container",                            # GCP network/k8s services
    # OCI
    "core", "virtual_network", "vcn", "network_firewall", "network",
    # AliCloud
    "slb", "ecs_vpc", "nat_gateway",
    "vpc", "ecs",                                        # AliCloud VPC + security groups in ecs
    "alb", "security_center",                            # AliCloud network-adjacent
    # K8s
    "networkpolicy", "ingress", "service", "network",
})

_DATA_SECURITY_DOMAINS = frozenset({
    "data_protection_and_privacy",
    "storage_and_database_security",
    "secrets_and_key_management",
    "cryptography_and_key_management",
})
_DATA_MODULES_BY_DOMAIN = {
    "data_protection_and_privacy":     ["data_protection_encryption", "data_access_governance", "data_classification"],
    "storage_and_database_security":   ["data_protection_encryption", "data_access_governance"],
    "secrets_and_key_management":      ["data_protection_encryption"],
    "cryptography_and_key_management": ["data_protection_encryption"],
}
_DATA_CATEGORIES_BY_DOMAIN = {
    "data_protection_and_privacy":     ["data_protection", "privacy", "sensitive_data_protection"],
    "storage_and_database_security":   ["storage_security", "database_security"],
    "secrets_and_key_management":      ["encryption", "key_management", "secrets"],
    "cryptography_and_key_management": ["encryption", "cryptography"],
}

_ENCRYPTION_SERVICES = frozenset({
    "kms", "acm", "acm-pca", "secretsmanager",
    "keyvault", "certificates",
    "cloudkms",
    "vault", "key_management",
    "kms_openapi",
})
_ENCRYPTION_DOMAINS = frozenset({
    "secrets_and_key_management",
    "cryptography_and_key_management",
})

_CONTAINER_SERVICES = frozenset({
    "eks", "ecs", "ecr", "fargate", "lambda", "container",
    "aks", "containerregistry", "containerinstance", "containerapp",
    "artifactregistry", "run",
    "containerengine", "artifacts",
    "pod", "deployment", "namespace", "networkpolicy",
    "serviceaccount", "rbac", "clusterrole", "clusterrolebinding",
})
_CONTAINER_DOMAINS = frozenset({"container_and_kubernetes_security"})

_DATABASE_SERVICES = frozenset({
    "rds", "dynamodb", "redshift", "elasticache", "neptune", "docdb",
    "documentdb", "opensearch", "timestream", "keyspaces", "dax",
    "sql", "sqlserver", "cosmosdb", "redis", "postgresql", "mysql",
    "mariadb", "synapse",
    "sqladmin", "spanner", "bigtable", "datastore", "firestore",
    "memorystore", "alloydb",
    "database", "nosql", "autonomousdatabase",
    "polardb", "mongodb", "kvstore", "gpdb",
})
_DATABASE_DOMAINS = frozenset({"storage_and_database_security"})

_AI_SERVICES = frozenset({
    "sagemaker", "sagemaker-runtime", "sagemaker-edge", "sagemaker-featurestore-runtime",
    "bedrock", "bedrock-runtime", "bedrock-agent", "bedrock-agent-runtime",
    "comprehend", "comprehendmedical", "textract", "translate", "transcribe",
    "rekognition", "polly", "personalize", "forecast", "frauddetector",
    "machinelearning", "lookoutmetrics", "lookoutequipment", "lookoutvision", "kendra",
    "cognitiveservices", "machinelearningservices", "openai",
    "aiplatform", "automl", "videointelligence", "vision", "naturallanguage",
    "generative_ai", "ai_language", "ai_vision",
})


def _derive_iam_modules(rule_id: str, subcategory: str) -> List[str]:
    modules = list(_IAM_MODULES_BY_SUBCATEGORY.get(subcategory or "", []))
    text = rule_id.lower()
    for keyword, module in _IAM_MODULES_BY_RULE_KEYWORD:
        if keyword in text and module not in modules:
            modules.append(module)
    return modules or ["access_control"]


def compute_engine_scopes(service: str, domain: str, rule_id: str, subcategory: str = "") -> Dict[str, Any]:
    """Return all 7 engine scope JSONB dicts for a rule."""
    svc = (service or "").lower()
    dom = (domain  or "").lower()
    rid = (rule_id or "").lower()

    # iam_security
    if dom == _IAM_DOMAIN:
        iam_sec = {"applicable": True, "modules": _derive_iam_modules(rid, subcategory)}
    else:
        iam_sec = {"applicable": False, "modules": []}

    # network_security
    net_sec = {"applicable": True} if (dom == _NETWORK_DOMAIN or svc in _NETWORK_SERVICES) else {}

    # data_security
    if dom in _DATA_SECURITY_DOMAINS:
        data_sec = {
            "applicable": True,
            "modules":    _DATA_MODULES_BY_DOMAIN.get(dom, ["data_protection_encryption"]),
            "categories": _DATA_CATEGORIES_BY_DOMAIN.get(dom, ["data_protection"]),
            "priority":   "critical" if dom == "secrets_and_key_management" else "high",
        }
    else:
        data_sec = {}

    enc_sec = {"applicable": True} if (svc in _ENCRYPTION_SERVICES or dom in _ENCRYPTION_DOMAINS) else {}
    ctr_sec = {"applicable": True} if (svc in _CONTAINER_SERVICES  or dom in _CONTAINER_DOMAINS)  else {}
    db_sec  = {"applicable": True} if (svc in _DATABASE_SERVICES   or dom in _DATABASE_DOMAINS)   else {}
    ai_sec  = {"applicable": True} if svc in _AI_SERVICES else {}

    return {
        "iam_security":        iam_sec,
        "network_security":    net_sec,
        "data_security":       data_sec,
        "encryption_security": enc_sec,
        "container_security":  ctr_sec,
        "database_security":   db_sec,
        "ai_security":         ai_sec,
    }


# ── YAML parsing ──────────────────────────────────────────────────────────────

def _parse_yaml(path: Path) -> Optional[Dict[str, Any]]:
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            return None
        return data
    except Exception as e:
        print(f"  WARN: cannot parse {path}: {e}")
        return None


def _coerce_list(val) -> list:
    if isinstance(val, list):
        return val
    if isinstance(val, str) and val.strip():
        return [val]
    return []


def _coerce_dict(val) -> dict:
    if isinstance(val, dict):
        return val
    return {}


def build_record(data: Dict[str, Any], csp: str, source_type: str) -> Optional[Dict[str, Any]]:
    """
    Build a rule_metadata DB record from a raw YAML dict.
    source_type: 'check' | 'ciem'
    """
    rule_id = (data.get("rule_id") or data.get("assertion_id") or "").strip()
    if not rule_id:
        return None

    service    = (data.get("service")     or "").lower().strip()
    domain     = (data.get("domain")      or "").lower().strip()
    subcategory= (data.get("subcategory") or "").lower().strip()
    provider   = (data.get("provider")    or csp).lower().strip()

    scopes = compute_engine_scopes(service, domain, rule_id, subcategory)

    # For CIEM rules that already have explicit iam_security/data_security, trust them
    # if they say applicable=true (don't downgrade computed True to YAML False)
    for col in ("iam_security", "data_security"):
        yaml_val = _coerce_dict(data.get(col))
        if yaml_val.get("applicable") is True:
            scopes[col] = yaml_val  # YAML has richer modules info, keep it

    compliance = data.get("compliance_frameworks") or data.get("compliance") or []
    if isinstance(compliance, dict):
        compliance_json = compliance
    else:
        compliance_json = {"frameworks": _coerce_list(compliance)} if compliance else {}

    return {
        "rule_id":              rule_id,
        "service":              service,
        "provider":             provider,
        "resource":             data.get("resource", ""),
        "severity":             data.get("severity", "medium"),
        "title":                data.get("title", ""),
        "description":          data.get("description", ""),
        "remediation":          data.get("remediation", ""),
        "rationale":            data.get("rationale", ""),
        "domain":               domain,
        "subcategory":          subcategory,
        "requirement":          data.get("requirement", ""),
        "assertion_id":         data.get("assertion_id", ""),
        "scope":                data.get("scope", ""),
        "scope_category":       data.get("scope_category", ""),
        "posture_category":     data.get("posture_category", ""),
        "compliance_frameworks":compliance_json,
        "references":           _coerce_list(data.get("references")),
        "mitre_tactics":        _coerce_list(data.get("mitre_tactics")),
        "mitre_techniques":     _coerce_list(data.get("mitre_techniques")),
        "threat_category":      data.get("threat_category", ""),
        "threat_tags":          _coerce_list(data.get("threat_tags")),
        "risk_score":           int(data.get("risk_score") or 50),
        "risk_indicators":      _coerce_dict(data.get("risk_indicators")),
        "action_category":      data.get("action_category", ""),
        "metadata_source":      source_type,
        "source":               data.get("source", source_type),
        "generated_by":         data.get("generated_by", "upload_script"),
        # Engine scopes
        "iam_security":         scopes["iam_security"],
        "network_security":     scopes["network_security"],
        "data_security":        scopes["data_security"],
        "encryption_security":  scopes["encryption_security"],
        "container_security":   scopes["container_security"],
        "database_security":    scopes["database_security"],
        "ai_security":          scopes["ai_security"],
    }


# ── File collectors ───────────────────────────────────────────────────────────

def collect_check_metadata(csp: str):
    """Yield (path, data) for check rule metadata YAMLs."""
    base = RULE_DIR / f"{csp}_rule_metadata"
    if not base.is_dir():
        return
    for svc_dir in sorted(base.iterdir()):
        if not svc_dir.is_dir():
            continue
        for yaml_path in sorted(svc_dir.glob("*.yaml")):
            data = _parse_yaml(yaml_path)
            if data:
                yield yaml_path, data


def collect_ciem_metadata(csp: str):
    """Yield (path, data) for CIEM rule YAMLs."""
    base = RULE_DIR / f"{csp}_rule_ciem"
    if not base.is_dir():
        return
    for yaml_path in sorted(base.rglob("*.yaml")):
        if yaml_path.name.startswith("."):
            continue
        data = _parse_yaml(yaml_path)
        if data:
            yield yaml_path, data


# ── DB upsert ─────────────────────────────────────────────────────────────────

_UPSERT_SQL = """
INSERT INTO rule_metadata (
    rule_id, service, provider, resource, severity, title,
    description, remediation, rationale, domain, subcategory,
    requirement, assertion_id, scope, scope_category, posture_category,
    compliance_frameworks, "references",
    mitre_tactics, mitre_techniques, threat_category, threat_tags,
    risk_score, risk_indicators, action_category,
    metadata_source, source, generated_by,
    iam_security, network_security, data_security,
    encryption_security, container_security, database_security, ai_security
) VALUES (
    %(rule_id)s, %(service)s, %(provider)s, %(resource)s, %(severity)s, %(title)s,
    %(description)s, %(remediation)s, %(rationale)s, %(domain)s, %(subcategory)s,
    %(requirement)s, %(assertion_id)s, %(scope)s, %(scope_category)s, %(posture_category)s,
    %(compliance_frameworks)s, %(references)s,
    %(mitre_tactics)s, %(mitre_techniques)s, %(threat_category)s, %(threat_tags)s,
    %(risk_score)s, %(risk_indicators)s, %(action_category)s,
    %(metadata_source)s, %(source)s, %(generated_by)s,
    %(iam_security)s, %(network_security)s, %(data_security)s,
    %(encryption_security)s, %(container_security)s, %(database_security)s, %(ai_security)s
)
ON CONFLICT (rule_id) WHERE customer_id IS NULL AND tenant_id IS NULL DO UPDATE SET
    service              = EXCLUDED.service,
    provider             = EXCLUDED.provider,
    resource             = EXCLUDED.resource,
    severity             = EXCLUDED.severity,
    title                = EXCLUDED.title,
    description          = EXCLUDED.description,
    remediation          = EXCLUDED.remediation,
    rationale            = EXCLUDED.rationale,
    domain               = EXCLUDED.domain,
    subcategory          = EXCLUDED.subcategory,
    requirement          = EXCLUDED.requirement,
    assertion_id         = EXCLUDED.assertion_id,
    scope                = EXCLUDED.scope,
    scope_category       = EXCLUDED.scope_category,
    posture_category     = EXCLUDED.posture_category,
    compliance_frameworks= EXCLUDED.compliance_frameworks,
    "references"         = EXCLUDED."references",
    mitre_tactics        = EXCLUDED.mitre_tactics,
    mitre_techniques     = EXCLUDED.mitre_techniques,
    threat_category      = EXCLUDED.threat_category,
    threat_tags          = EXCLUDED.threat_tags,
    risk_score           = EXCLUDED.risk_score,
    risk_indicators      = EXCLUDED.risk_indicators,
    action_category      = EXCLUDED.action_category,
    metadata_source      = EXCLUDED.metadata_source,
    iam_security         = EXCLUDED.iam_security,
    network_security     = EXCLUDED.network_security,
    data_security        = EXCLUDED.data_security,
    encryption_security  = EXCLUDED.encryption_security,
    container_security   = EXCLUDED.container_security,
    database_security    = EXCLUDED.database_security,
    ai_security          = EXCLUDED.ai_security,
    updated_at           = NOW()
"""


def _get_conn():
    return psycopg2.connect(
        host=os.getenv("CHECK_DB_HOST", "localhost"),
        port=int(os.getenv("CHECK_DB_PORT", "5432")),
        database=os.getenv("CHECK_DB_NAME", "threat_engine_check"),
        user=os.getenv("CHECK_DB_USER", "check_user"),
        password=os.getenv("CHECK_DB_PASSWORD", "check_password"),
    )


def _jsonb(val) -> Json:
    return Json(val if val else {})


def upload_records(records: List[Dict], dry_run: bool) -> int:
    if dry_run:
        return len(records)

    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            for rec in records:
                params = dict(rec)
                for col in ("iam_security", "network_security", "data_security",
                            "encryption_security", "container_security",
                            "database_security", "ai_security",
                            "compliance_frameworks", "risk_indicators"):
                    params[col] = _jsonb(params[col])
                for col in ("references", "mitre_tactics", "mitre_techniques", "threat_tags"):
                    params[col] = Json(params[col])
                # customer_id / tenant_id not set → NULL (matches UNIQUE constraint default)
                params.setdefault("customer_id", None)
                params.setdefault("tenant_id", None)
                cur.execute(_UPSERT_SQL, params)
        conn.commit()
    finally:
        conn.close()
    return len(records)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Upload rule metadata for all CSPs to rule_metadata table")
    parser.add_argument("--csp",      nargs="+", default=CSPS, help="CSPs to process (default: all)")
    parser.add_argument("--type",     choices=["check", "ciem", "all"], default="all")
    parser.add_argument("--dry-run",  action="store_true", help="Count only, no DB writes")
    args = parser.parse_args()

    if args.dry_run:
        print("*** DRY RUN — no DB writes ***\n")

    total_inserted = 0
    total_skipped  = 0

    for csp in args.csp:
        records: List[Dict] = []
        seen_ids: set = set()

        def add(path, data, src_type):
            nonlocal total_skipped
            rec = build_record(data, csp, src_type)
            if rec is None:
                total_skipped += 1
                return
            if rec["rule_id"] in seen_ids:
                return
            seen_ids.add(rec["rule_id"])
            records.append(rec)

        if args.type in ("check", "all"):
            for path, data in collect_check_metadata(csp):
                add(path, data, "check")

        if args.type in ("ciem", "all"):
            for path, data in collect_ciem_metadata(csp):
                add(path, data, "ciem")

        n = upload_records(records, args.dry_run)
        total_inserted += n

        # Scope summary
        iam_count  = sum(1 for r in records if r["iam_security"].get("applicable"))
        net_count  = sum(1 for r in records if r["network_security"].get("applicable"))
        data_count = sum(1 for r in records if r["data_security"].get("applicable"))
        enc_count  = sum(1 for r in records if r["encryption_security"].get("applicable"))
        ctr_count  = sum(1 for r in records if r["container_security"].get("applicable"))
        db_count   = sum(1 for r in records if r["database_security"].get("applicable"))
        ai_count   = sum(1 for r in records if r["ai_security"].get("applicable"))

        action = "counted" if args.dry_run else "uploaded"
        print(
            f"{csp:12s}  {action} {n:5d} rules"
            f"  | iam={iam_count} net={net_count} data={data_count}"
            f" enc={enc_count} ctr={ctr_count} db={db_count} ai={ai_count}"
        )

    print(f"\nTotal: {total_inserted} rules uploaded, {total_skipped} skipped (no rule_id)")


if __name__ == "__main__":
    main()
