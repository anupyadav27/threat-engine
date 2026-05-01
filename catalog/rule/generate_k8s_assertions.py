#!/usr/bin/env python3
"""
Generate 1_k8s_full_scope_assertions.yaml from all k8s_rule_check + k8s_rule_metadata files.

Structure mirrors gcp_full_scope_assertions.yaml:
  <service>:
    <resource>:
    - assertion_id: <domain_prefix>.<check_pattern>
      domain:       <security_domain>
      rule_id:      k8s.<service>.<resource>.<requirement>
      scope:        <service>.<resource>.<scope_type>
      severity:     critical | high | medium | low
"""

import yaml
from pathlib import Path
from collections import defaultdict

CHECK_ROOT = Path("/Users/apple/Desktop/threat-engine/catalog/rule/k8s_rule_check")
META_ROOT  = Path("/Users/apple/Desktop/threat-engine/catalog/rule/k8s_rule_metadata")
OUT_FILE   = Path("/Users/apple/Desktop/threat-engine/catalog/rule/k8s_rule_check/1_k8s_full_scope_assertions.yaml")

# ── domain → assertion_id prefix ────────────────────────────────────────────
DOMAIN_PREFIX = {
    "identity_and_access_management":        "identity_access",
    "infrastructure_security":               "container_security",
    "network_security_and_connectivity":     "network_security",
    "data_security":                         "data_protection",
    "logging_monitoring_and_alerting":       "logging_monitoring",
    "configuration_and_change_management":   "configuration_management",
    "threat_detection_and_incident_response":"threat_detection",
    "resilience_and_disaster_recovery":      "resilience",
    "secrets_and_key_management":            "secrets_management",
    "compliance_and_governance":             "compliance_governance",
}

# ── subcategory → scope_type suffix ─────────────────────────────────────────
SCOPE_TYPE = {
    "least_privilege":          "access_control",
    "privilege_escalation":     "access_control",
    "access_segregation":       "access_control",
    "access_review":            "access_control",
    "data_access_control":      "access_control",
    "data_access_governance":   "access_control",
    "credential_management":    "credential_management",
    "container_security":       "container_hardening",
    "container_isolation":      "container_hardening",
    "supply_chain_security":    "supply_chain",
    "network_segmentation":     "network_policy",
    "network_access_control":   "network_policy",
    "network_isolation":        "network_policy",
    "resource_management":      "resource_quota",
    "encryption_at_rest":       "encryption",
    "data_protection":          "data_protection",
    "configuration_management": "configuration",
}

def domain_prefix(domain: str) -> str:
    return DOMAIN_PREFIX.get(domain, domain.replace("_and_", "_").replace("_", "_"))

def scope_type(subcategory: str) -> str:
    return SCOPE_TYPE.get(subcategory, subcategory)

def make_assertion_id(domain: str, resource: str, requirement: str) -> str:
    prefix = domain_prefix(domain)
    # e.g. container_security.privileged_disabled  or identity_access.wildcard_verbs_restricted
    slug = requirement.lower().replace(" ", "_")
    return f"{prefix}.{resource}_{slug}"

def make_scope(service: str, resource: str, subcategory: str) -> str:
    st = scope_type(subcategory)
    return f"{service}.{resource}.{st}"

def load_metadata(rule_id: str) -> dict:
    """Load metadata for a rule_id from k8s_rule_metadata."""
    # rule_id = k8s.<service>.<resource>.<requirement...>
    parts   = rule_id.split(".")
    service = parts[1] if len(parts) > 1 else "unknown"
    fname   = f"{rule_id}.yaml"
    path    = META_ROOT / service / fname
    if path.exists():
        with open(path) as f:
            return yaml.safe_load(f) or {}
    return {}

def build_assertions() -> dict:
    """Walk all k8s_rule_check service dirs, build assertions dict."""
    # structure: {service: {resource: [entry, ...]}}
    assertions = defaultdict(lambda: defaultdict(list))

    for check_file in sorted(CHECK_ROOT.glob("*/**.checks.yaml")):
        if check_file.name.startswith("1_"):
            continue
        with open(check_file) as f:
            doc = yaml.safe_load(f)

        service = doc.get("service", check_file.parent.name)
        for check in doc.get("checks", []):
            rule_id = check.get("rule_id", "")
            if not rule_id:
                continue

            meta = load_metadata(rule_id)
            resource    = meta.get("resource", rule_id.split(".")[2] if len(rule_id.split(".")) > 2 else "resource")
            requirement = meta.get("requirement", rule_id.split(".")[-1])
            domain      = meta.get("domain", "infrastructure_security")
            subcategory = meta.get("subcategory", "configuration_management")
            severity    = meta.get("severity", "medium")

            entry = {
                "assertion_id": make_assertion_id(domain, resource, requirement),
                "domain":       domain,
                "rule_id":      rule_id,
                "scope":        make_scope(service, resource, subcategory),
                "severity":     severity,
            }
            assertions[service][resource].append(entry)

    # Convert defaultdicts to plain dicts for yaml dump
    return {
        svc: {res: entries for res, entries in sorted(resources.items())}
        for svc, resources in sorted(assertions.items())
    }

def build_header(assertions: dict) -> str:
    total_rules    = sum(len(entries) for svc in assertions.values() for entries in svc.values())
    total_services = len(assertions)
    severity_counts = defaultdict(int)
    domain_counts   = defaultdict(int)
    for svc in assertions.values():
        for entries in svc.values():
            for e in entries:
                severity_counts[e["severity"]] += 1
                domain_counts[e["domain"]]     += 1

    domain_lines = "\n".join(
        f"# │ {d:<55} │ {c:>6} │"
        for d, c in sorted(domain_counts.items(), key=lambda x: -x[1])
    )
    sev_str = ", ".join(f"{s}={severity_counts[s]}" for s in ["critical","high","medium","low"])

    return f"""\
# ═══════════════════════════════════════════════════════════════════════════
# K8S SECURITY ASSERTIONS — Full Scope Catalog
# ═══════════════════════════════════════════════════════════════════════════
#
# Naming convention matches: aws/azure/gcp_full_scope_assertions.yaml
# Total Services:          {total_services}
# Total Rules:             {total_rules}
#
# ┌──────────────────────────────────────────────────────────────────────────┐
# │ RULES PER SECURITY DOMAIN                                               │
# ├───────────────────────────────────────────────────────────┬─────────────┤
{domain_lines}
# ├───────────────────────────────────────────────────────────┼─────────────┤
# │ TOTAL                                                     │ {total_rules:>11} │
# └───────────────────────────────────────────────────────────┴─────────────┘
#
# Severity: {sev_str}
#
# Field schema (matches aws/azure/gcp_full_scope_assertions.yaml):
#   assertion_id  — unique assertion identifier
#   domain        — security domain
#   rule_id       — k8s.<service>.<resource>.<check>
#   scope         — <service>.<resource>.<scope_type>
#   severity      — critical | high | medium | low
# ═══════════════════════════════════════════════════════════════════════════
"""

def main():
    print("Building k8s full scope assertions...")
    assertions = build_assertions()

    header  = build_header(assertions)
    content = yaml.dump(assertions, default_flow_style=False, sort_keys=False, allow_unicode=True)

    OUT_FILE.write_text(header + "\n" + content)

    total = sum(len(e) for svc in assertions.values() for e in svc.values())
    print(f"Done: {total} rules across {len(assertions)} services → {OUT_FILE.name}")

if __name__ == "__main__":
    main()
