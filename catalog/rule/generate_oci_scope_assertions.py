#!/usr/bin/env python3
"""
Generate catalog/rule/oci_rule_check/1_oci_full_scope_assertions.yaml

Reads all oci_rule_metadata/{service}/{rule_id}.yaml files and builds a
hierarchical scope-assertion catalog grouped by:
    service → resource_type → [assertion entries]

Format mirrors aws_full_scope_assertions.yaml / azure equivalent.

Also prints a per-service + per-domain summary so you can decide which
services / rules to disable (is_active: false).
"""

from __future__ import annotations
import yaml
from collections import defaultdict
from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE      = Path("/Users/apple/Desktop/threat-engine")
META_ROOT = BASE / "catalog/rule/oci_rule_metadata"
OUT_FILE  = BASE / "catalog/rule/oci_rule_check/1_oci_full_scope_assertions.yaml"

# ── Domain → short prefix for assertion_id ────────────────────────────────────
DOMAIN_PREFIX = {
    "identity_and_access_management":          "iam",
    "data_protection_and_privacy":             "data_protection",
    "network_security_and_connectivity":       "network_security",
    "logging_monitoring_and_alerting":         "logging_monitoring",
    "logging_and_monitoring":                  "logging_monitoring",
    "configuration_and_change_management":     "configuration",
    "compute_host_security":                   "compute_security",
    "software_security":                       "software_security",
    "supply_chain_security":                   "supply_chain",
    "incident_response":                       "incident_response",
    "encryption_and_key_management":           "encryption",
    "backup_and_recovery":                     "backup_recovery",
    "storage_and_database_security":           "storage_security",
    "threat_detection_and_incident_response":  "threat_detection",
    "resilience_and_disaster_recovery":        "resilience",
    "secrets_and_key_management":              "secrets_key_mgmt",
    "ai_ml_and_model_security":                "ai_ml_security",
    "container_and_kubernetes_security":       "container_security",
    "compliance_and_governance":               "compliance",
    "application_and_api_security":            "app_api_security",
}

# ── Severity order (for sorting within resource group) ────────────────────────
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# ── Custom YAML dumper: keep None as null ─────────────────────────────────────
def _none_repr(dumper, _):
    return dumper.represent_scalar("tag:yaml.org,2002:null", "null")
yaml.add_representer(type(None), _none_repr)


def assertion_id(domain: str, subcategory: str, service: str,
                 resource: str, check_name: str) -> str:
    prefix = DOMAIN_PREFIX.get(domain, domain.replace(" ", "_").lower())
    subcat = (subcategory or domain).replace(" ", "_").lower()
    return f"{prefix}.{subcat}.{service}_{resource}_{check_name}"


def scope_type_from_subcategory(subcategory: str) -> str:
    """Map subcategory → a short scope-type label."""
    sc = subcategory.lower()
    if any(x in sc for x in ("encryption", "kms", "cmek", "key")):
        return "encryption"
    if any(x in sc for x in ("network", "access_control", "firewall", "vpn")):
        return "network"
    if any(x in sc for x in ("authentication", "mfa", "identity", "iam", "rbac")):
        return "authentication"
    if any(x in sc for x in ("logging", "audit", "monitoring")):
        return "logging"
    if any(x in sc for x in ("backup", "recovery", "retention")):
        return "backup"
    if any(x in sc for x in ("data", "privacy", "classification")):
        return "data_protection"
    return "configuration"


def main() -> None:
    # ── Collect all metadata ──────────────────────────────────────────────────
    # Structure: {service: {resource: [entry, ...]}}
    catalog: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    domain_counts:   dict[str, int] = defaultdict(int)
    severity_counts: dict[str, int] = defaultdict(int)
    service_counts:  dict[str, int] = defaultdict(int)
    total = 0

    for meta_file in sorted(META_ROOT.rglob("*.yaml")):
        raw = yaml.safe_load(meta_file.read_text()) or {}
        rule_id    = raw.get("rule_id", "")
        service    = raw.get("program", "").split(".")[0] if raw.get("program") else ""
        resource   = raw.get("resource_class", "")
        domain     = raw.get("domain", "configuration_and_change_management")
        subcategory = raw.get("assertion_id", "").split(".")[0] if raw.get("assertion_id") else ""
        severity   = raw.get("severity", "medium")
        scope_raw  = raw.get("scope", f"{service}.{resource}.configuration")

        if not rule_id:
            continue

        # Derive resource key (snake_case from resource_class PascalCase)
        resource_key = "".join(
            f"_{c.lower()}" if c.isupper() and i > 0 else c.lower()
            for i, c in enumerate(resource)
        ) if resource else "resource"

        # Derive scope type from scope or subcategory
        scope_parts = scope_raw.split(".")
        scope_type  = scope_parts[-1] if len(scope_parts) >= 3 else scope_type_from_subcategory(subcategory)

        # Derive check_name from rule_id
        check_name = rule_id.split(".")[-1]

        aid = assertion_id(domain, subcategory, service, resource_key, check_name)
        scope = f"{service}.{resource_key}.{scope_type}"

        entry = {
            "assertion_id": aid,
            "domain":       domain,
            "rule_id":      rule_id,
            "scope":        scope,
            "severity":     severity,
            "is_active":    True,
        }

        catalog[service][resource_key].append(entry)
        domain_counts[domain] += 1
        severity_counts[severity] += 1
        service_counts[service] += 1
        total += 1

    # ── Sort entries within each resource group by severity ───────────────────
    for svc in catalog:
        for res in catalog[svc]:
            catalog[svc][res].sort(key=lambda e: SEV_ORDER.get(e["severity"], 99))

    # ── Build output dict (sorted by service, then resource) ─────────────────
    out: dict = {}
    for svc in sorted(catalog):
        out[svc] = {}
        for res in sorted(catalog[svc]):
            out[svc][res] = catalog[svc][res]

    # ── Compose header comment ────────────────────────────────────────────────
    sev_str = ", ".join(
        f"{k}={v}" for k, v in
        sorted(severity_counts.items(), key=lambda x: SEV_ORDER.get(x[0], 99))
    )
    domain_rows = "\n".join(
        f"# │ {d:<51} │ {c:>17} │"
        for d, c in sorted(domain_counts.items(), key=lambda x: -x[1])
    )
    svc_rows = "\n".join(
        f"#   {s:<40} {c:>5} rules"
        for s, c in sorted(service_counts.items(), key=lambda x: -x[1])
    )

    header = f"""\
# ═══════════════════════════════════════════════════════════════════════════
# OCI SECURITY ASSERTIONS — Full Scope Catalog
# ═══════════════════════════════════════════════════════════════════════════
#
# Naming convention mirrors aws_full_scope_assertions.yaml
# Total Services  : {len(catalog)}
# Total Rules     : {total}
#
# ┌─────────────────────────────────────────────────────┬───────────────────┐
# │ RULES PER SECURITY DOMAIN                           │ Rules             │
# ├─────────────────────────────────────────────────────┼───────────────────┤
{domain_rows}
# ├─────────────────────────────────────────────────────┼───────────────────┤
# │ TOTAL                                               │ {total:>17} │
# └─────────────────────────────────────────────────────┴───────────────────┘
#
# Severity: {sev_str}
#
# Field schema:
#   assertion_id  — unique assertion identifier
#   domain        — security domain
#   rule_id       — oci.<service>.<resource>.<check>
#   scope         — <service>.<resource>.<scope_type>
#   severity      — critical | high | medium | low
#   is_active     — set to false to disable a rule from evaluation
#
# RULES PER SERVICE:
{svc_rows}
#
"""

    # ── Write output ──────────────────────────────────────────────────────────
    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    body = yaml.dump(out, default_flow_style=False,
                     sort_keys=False, allow_unicode=True)
    OUT_FILE.write_text(header + body)

    print(f"Written: {OUT_FILE.relative_to(BASE)}")
    print(f"  Services : {len(catalog)}")
    print(f"  Rules    : {total}")
    print(f"  Severity : {sev_str}")
    print()
    print("Rules per domain:")
    for d, c in sorted(domain_counts.items(), key=lambda x: -x[1]):
        print(f"  {d:<55} {c:>5}")
    print()
    print("Rules per service (top 15):")
    for s, c in sorted(service_counts.items(), key=lambda x: -x[1])[:15]:
        print(f"  {s:<40} {c:>5}")


if __name__ == "__main__":
    main()
