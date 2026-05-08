#!/usr/bin/env python3
"""
Generate YAML check rule files for 352 new rules from new_352_rules_need_checks.csv.

For each rule, the script:
  1. Resolves the best `for_each` discovery_id from the service's discoveries.yaml
  2. Parses the description to derive PASS conditions (inverted from NON_COMPLIANT)
  3. Groups rules by service and writes/appends to the check YAML file
  4. Reports services with missing catalogs or discoveries that need manual attention
"""

import csv
import re
import yaml
from collections import defaultdict
from pathlib import Path

# ─── Paths ────────────────────────────────────────────────────────────────────
BASE          = Path("/Users/apple/Desktop/threat-engine")
CSV_PATH      = BASE / "catalog/rule/new_352_rules_need_checks.csv"
CHECK_DIR     = BASE / "engines/check/engine_check_aws/services"
CATALOG_DIR   = BASE / "catalog/python_field_generator/aws"

# ─── Per-service resource→discovery_id overrides ─────────────────────────────
# When heuristic matching fails, use these explicit mappings.
# Format: { service: { resource: discovery_id } }
RESOURCE_DISCOVERY_OVERRIDES: dict[str, dict[str, str]] = {
    "apigateway": {
        "associated":  "aws.apigateway.get_stages",
        "cache":       "aws.apigateway.get_stages",
        "execution":   "aws.apigateway.get_stages",
        "ssl":         "aws.apigateway.get_domain_names",
        "stage":       "aws.apigateway.get_stages",
        "xray":        "aws.apigateway.get_stages",
        "endpoint":    "aws.apigateway.get_rest_apis",
        "rest":        "aws.apigateway.get_rest_apis",
    },
    "apigatewayv2": {
        "access":          "aws.apigatewayv2.get_stage",
        "authorization":   "aws.apigatewayv2.get_stage",
        "stage":           "aws.apigatewayv2.get_stage",
        "integration":     "aws.apigatewayv2.get_integration",
    },
    "appsync": {
        "associated":     "aws.appsync.list_graphql_apis",
        "authorization":  "aws.appsync.list_graphql_apis",
        "cache":          "aws.appsync.get_api_cache",
        "graphql":        "aws.appsync.get_graphql_api",
    },
    "autoscaling": {
        "launch_config":    "aws.autoscaling.describe_auto_scaling_groups",
        "launchconfig":     "aws.autoscaling.describe_auto_scaling_groups",
        "launch_template":  "aws.autoscaling.describe_auto_scaling_groups",
    },
    "cognito": {
        "identity_pool":  "aws.cognito.list_identity_pools",
        "user_pool":      "aws.cognito.list_user_pools",
    },
    "ec2": {
        "attached":        "aws.ec2.describe_instances",
        "capacity":        "aws.ec2.describe_capacity_reservations",
        "carrier_gateway": "aws.ec2.describe_carrier_gateways",
        "dhcp_options":    "aws.ec2.describe_dhcp_options",
        "enis":            "aws.ec2.describe_network_interfaces",
        "fleet":           "aws.ec2.describe_fleets",
        "ipamscope":       "aws.ec2.describe_ipam_scopes",
        "managedinstance": "aws.ec2.describe_instances",
        "meets":           "aws.ec2.describe_instances",
        "optimized":       "aws.ec2.describe_instances",
        "prefix_list":     "aws.ec2.describe_managed_prefix_lists",
        "resources":       "aws.ec2.describe_instances",
        "token":           "aws.ec2.describe_instances",
        "transit_gateway": "aws.ec2.describe_transit_gateway_multicast_domains",
    },
    "ecs": {
        "awsvpc":             "aws.ecs.list_task_definitions",
        "capacity_provider":  "aws.ecs.describe_capacity_providers",
        "fargate":            "aws.ecs.list_services",
        "service":            "aws.ecs.list_services",
    },
    "efs": {
        "automatic":   "aws.efs.describe_file_systems",
        "encrypted":   "aws.efs.describe_file_systems",
        "file":        "aws.efs.describe_file_systems",
        "meets":       "aws.efs.describe_file_systems",
        "resources":   "aws.efs.describe_file_systems",
    },
    "elb": {
        "cross":     "aws.elb.describe_load_balancers",
        "desync":    "aws.elb.describe_load_balancers",
        "internal":  "aws.elb.describe_load_balancers",
        "multiple":  "aws.elb.describe_load_balancers",
        "tagged":    "aws.elb.describe_load_balancers",
    },
    "elbv2": {
        "cross":     "aws.elbv2.describe_load_balancers",
        "desync":    "aws.elbv2.describe_load_balancers",
        "http":      "aws.elbv2.describe_load_balancers",
        "internal":  "aws.elbv2.describe_load_balancers",
        "listener":  "aws.elbv2.describe_listeners",
        "logging":   "aws.elbv2.describe_load_balancers",
        "tagged":    "aws.elbv2.describe_load_balancers",
        "waf":       "aws.elbv2.describe_load_balancers",
    },
    "guardduty": {
        "ec2":      "aws.guardduty.list_detectors",
        "ecs":      "aws.guardduty.list_detectors",
        "enabled":  "aws.guardduty.list_detectors",
        "lambda":   "aws.guardduty.list_detectors",
        "malware":  "aws.guardduty.list_detectors",
        "rds":      "aws.guardduty.list_detectors",
        "runtime":  "aws.guardduty.list_detectors",
        "s3":       "aws.guardduty.list_detectors",
    },
    "iam": {
        "keys":  "aws.iam.list_users",
        "oidc":  "aws.iam.list_open_id_connect_providers",
        "saml":  "aws.iam.list_saml_providers",
    },
    "kms": {
        "backing": "aws.kms.describe_key",
    },
    "s3": {
        "access_point":  "aws.s3.list_buckets",
        "bucket":        "aws.s3.list_buckets",
        "event":         "aws.s3.list_buckets",
        "last":          "aws.s3.list_buckets",
        "meets":         "aws.s3.list_buckets",
        "resources":     "aws.s3.list_buckets",
    },
    "vpc": {
        "auto":        "aws.ec2.describe_subnets",
        "common":      "aws.ec2.describe_security_groups",
        "gateway":     "aws.ec2.describe_internet_gateways",
        "no":          "aws.ec2.describe_network_acls",
        "sg":          "aws.ec2.describe_security_groups",
        "ssh":         "aws.ec2.describe_security_groups",
        "unrestricted":"aws.ec2.describe_route_tables",
    },
    "transfer": {
        "agreement":   "aws.transfer.list_agreements",
        "certificate": "aws.transfer.list_certificates",
        "connector":   "aws.transfer.list_connectors",
        "profile":     "aws.transfer.list_profiles",
        "workflow":    "aws.transfer.list_workflows",
    },
    "route53": {
        "control":    "aws.route53.list_clusters",
        "firewall":   "aws.route53resolver.list_firewall_domain_lists",
        "readiness":  "aws.route53.list_cells",
        "resolver":   "aws.route53resolver.list_resolver_endpoints",
    },
    "stepfunctions": {
        "state_machine": "aws.stepfunctions.list_state_machines",
    },
    "mq": {
        "automatic":  "aws.mq.list_brokers",
        "cloudwatch": "aws.mq.list_brokers",
        "supported":  "aws.mq.list_brokers",
    },
    "rds": {
        "event":     "aws.rds.describe_event_subscriptions",
        "last":      "aws.rds.describe_db_instances",
        "meets":     "aws.rds.describe_db_instances",
        "mysql":     "aws.rds.describe_db_clusters",
        "option":    "aws.rds.describe_option_groups",
        "publish":   "aws.rds.describe_db_instances",
        "resources": "aws.rds.describe_db_instances",
    },
    "emr": {
        "kerberos":  "aws.emr.list_clusters",
        "security":  "aws.emr.list_security_configurations",
    },
    "networkfirewall": {
        "logging":    "aws.networkfirewall.list_firewalls",
        "multi":      "aws.networkfirewall.list_firewalls",
        "policy":     "aws.networkfirewall.list_firewall_policies",
        "stateless":  "aws.networkfirewall.list_rule_groups",
        "subnet":     "aws.networkfirewall.list_firewalls",
    },
    "opensearch": {
        "in":      "aws.opensearch.list_domain_names",
        "logs":    "aws.opensearch.list_domain_names",
        "node":    "aws.opensearch.list_domain_names",
        "update":  "aws.opensearch.list_domain_names",
    },
    # ── Formerly-missing services ────────────────────────────────────────────
    "acmpca": {
        "certificate": "aws.acmpca.list_certificate_authorities",
    },
    "approved": {
        "amis": "aws.approved.describe_instances",
    },
    "codegurureviewer": {
        "repository_association": "aws.codegurureviewer.list_repository_associations",
    },
    "custom": {
        "eventbus": "aws.custom.list_event_buses",
        "schema":   "aws.custom.list_event_buses",  # schemas needs separate client; use event bus as proxy
    },
    "customerprofiles": {
        "domain":      "aws.customerprofiles.list_domains",
        "object_type": "aws.customerprofiles.list_profile_object_types",
    },
    "desired": {
        "instance": "aws.desired.describe_instances",
    },
    "event": {
        "data": "aws.event.list_event_data_stores",
    },
    "eventschemas": {
        "discoverer": "aws.eventschemas.list_discoverers",
        "registry":   "aws.eventschemas.list_registries",
    },
    "iotdevicedefender": {
        "custom_metric": "aws.iotdevicedefender.list_custom_metrics",
    },
    "msk": {
        "cluster":    "aws.msk.list_clusters_v2",
        "connect":    "aws.msk.list_clusters_v2",  # MSK Connect needs kafkaconnect client; proxy for now
        "enhanced":   "aws.msk.list_clusters_v2",
        "in":         "aws.msk.describe_cluster",
        "unrestricted": "aws.msk.describe_cluster",
    },
    "required": {
        "tags": "aws.required.get_resources",
    },
    "s3express": {
        "dir": "aws.s3express.list_directory_buckets",
    },
    "service": {
        "catalog": "aws.service.list_portfolios",
    },
    "virtualmachine": {
        "last":      "aws.virtualmachine.list_virtual_machines",
        "resources": "aws.virtualmachine.list_virtual_machines",
    },
}

# ─── Helpers ──────────────────────────────────────────────────────────────────

def load_discoveries(service: str) -> dict[str, dict]:
    """Return {discovery_id: discovery_dict} from the service's discoveries.yaml."""
    p = CHECK_DIR / service / "discoveries" / f"{service}.discoveries.yaml"
    if not p.exists():
        return {}
    with open(p) as fh:
        data = yaml.safe_load(fh)
    result = {}
    for d in (data or {}).get("discovery", []):
        did = d.get("discovery_id", "")
        if did:
            result[did] = d
    return result


def best_for_each(service: str, resource: str, discoveries: dict[str, dict]) -> str:
    """Heuristically pick the best discovery_id for (service, resource)."""
    # Check explicit overrides first
    svc_overrides = RESOURCE_DISCOVERY_OVERRIDES.get(service, {})
    if resource in svc_overrides:
        return svc_overrides[resource]

    if not discoveries:
        # Fabricate a plausible default
        return f"aws.{service}.list_{resource}s"

    ids = list(discoveries.keys())

    # Normalise resource for matching (remove underscores, lowercase)
    res_norm = resource.replace("_", "").lower()
    res_parts = resource.lower().split("_")

    # Scoring: prefer ids that contain the resource token and use get_ or describe_ over list_
    def score(did: str) -> int:
        dl = did.lower()
        s = 0
        if res_norm in dl.replace("_", "").replace(".", ""):
            s += 10
        for part in res_parts:
            if part in dl:
                s += 3
        # prefer get_ > describe_ > list_  (more complete data)
        if ".get_" in dl:
            s += 2
        elif ".describe_" in dl:
            s += 1
        # penalise secondary/child operations
        for penalise in ["create", "delete", "update", "put", "tag", "untag"]:
            if penalise in dl:
                s -= 20
        return s

    ranked = sorted(ids, key=score, reverse=True)
    best = ranked[0]

    # If best score is < 3, fall back to the first list_ or describe_ call for the service
    if score(best) < 3:
        for did in ids:
            dl = did.lower()
            if ".list_" in dl or ".describe_" in dl:
                return did
        return ids[0]

    return best


# ─── Description → Condition parser ──────────────────────────────────────────

def _extract_field(description: str) -> str | None:
    """
    Extract the field path from 'configuration.X.Y' patterns in description.
    Returns 'item.X.Y' (replacing 'configuration.' prefix with 'item.').
    Also handles bare property names like "the CloudWatchLogsLogGroupArn property".
    """
    # Primary: Match configuration.Field[.SubField ...]
    m = re.search(r"configuration\.([A-Za-z0-9_.[\]]+)", description)
    if m:
        path = m.group(1).rstrip(".")
        return f"item.{path}"

    # Secondary: "the 'XFieldName' attribute" or "the XFieldName property"
    m = re.search(r"the\s+['\"]?([A-Z][A-Za-z0-9]+)['\"]?\s+(?:attribute|property)", description)
    if m:
        return f"item.{m.group(1)}"

    return None


def parse_condition(rule_id: str, description: str) -> dict:
    """
    Derive a PASS condition from the NON_COMPLIANT description.

    Returns a dict suitable for the 'conditions:' key in check YAML.
    Falls back to an 'exists' check when the pattern cannot be parsed.
    """
    desc_lower = description.lower()

    # ── Tags check ────────────────────────────────────────────────────────────
    if "tagged" in rule_id or "no tags" in desc_lower or "there are no tags" in desc_lower:
        return {"var": "item.Tags", "op": "not_empty", "value": None}

    field = _extract_field(description)

    # ── Pattern: does not exist (± or is an empty string) ────────────────────
    if "does not exist" in desc_lower:
        if field:
            return {"var": field, "op": "exists", "value": None}

    # ── Pattern: NON_COMPLIANT if X is false ─────────────────────────────────
    m = re.search(r"configuration\.[A-Za-z0-9_.[\]]+\s+is\s+false", description, re.I)
    if m and field:
        return {"var": field, "op": "equals", "value": "true"}

    # ── Pattern: NON_COMPLIANT if X is true / is True / is set to true ───────
    m = re.search(r"configuration\.[A-Za-z0-9_.[\]]+\s+is\s+(set\s+to\s+)?['\"]?true['\"]?", description, re.I)
    if m and field:
        return {"var": field, "op": "equals", "value": "false"}

    # ── Pattern: NON_COMPLIANT if X is equal to 'Y' ──────────────────────────
    m = re.search(r"configuration\.[A-Za-z0-9_.[\]]+\s+is\s+(set\s+to\s+)?['\"]([^'\"]+)['\"]", description, re.I)
    if m and field:
        expected_val = m.group(2)
        return {"var": field, "op": "not_equals", "value": expected_val}

    # ── Pattern: NON_COMPLIANT if X is not 'Y' / not equal to 'Y' ───────────
    m = re.search(r"configuration\.[A-Za-z0-9_.[\]]+\s+is\s+not\s+(?:equal\s+to\s+)?['\"]([^'\"]+)['\"]", description, re.I)
    if m and field:
        expected_val = m.group(1)
        return {"var": field, "op": "equals", "value": expected_val}

    # ── Pattern: is an empty array/list → NON_COMPLIANT → PASS when not_empty ─
    if ("is an empty" in desc_lower or "is empty" in desc_lower) and field:
        return {"var": field, "op": "not_empty", "value": None}

    # ── Pattern: is not an empty list → NON_COMPLIANT → PASS when is_empty ───
    if "is not an empty" in desc_lower and field:
        return {"var": field, "op": "is_empty", "value": None}

    # ── Pattern: NON_COMPLIANT if X is 'DISABLED' / equals DISABLED ──────────
    m = re.search(r"['\"]?DISABLED['\"]?", description)
    if m and field:
        return {"var": field, "op": "not_equals", "value": "DISABLED"}

    # ── Pattern: "is not set to 'Y'" without configuration prefix ─────────────
    # e.g. "is not set to 'ENABLED'" → `field equals ENABLED`
    m = re.search(r"is\s+not\s+set\s+to\s+['\"]([^'\"]+)['\"]", description, re.I)
    if m and field:
        return {"var": field, "op": "equals", "value": m.group(1)}

    # ── Pattern: "status attribute is not set to 'ENABLED'" (no config prefix) ─
    m = re.search(r"['\"]?status['\"]?\s+(?:attribute\s+)?is\s+not\s+set\s+to\s+['\"]([^'\"]+)['\"]", description, re.I)
    if m:
        return {"var": "item.status", "op": "equals", "value": m.group(1)}

    # ── Pattern: "NetworkMode ... not set to 'awsvpc'" (task def) ─────────────
    m = re.search(r"is\s+not\s+set\s+to\s+['\"]([^'\"]+)['\"]", description, re.I)
    if m:
        # Try to extract resource attribute from context
        resource_m = re.search(r"\b([A-Z][A-Za-z0-9]+(?:[A-Z][a-z]+)+)\b", description)
        if resource_m:
            return {"var": f"item.{resource_m.group(1)}", "op": "equals", "value": m.group(1)}

    # ── Pattern: "property X is empty" → X should exist ─────────────────────
    m = re.search(r"property\s+is\s+empty|property\s+of\s+the.*is\s+empty", description, re.I)
    if m and field:
        return {"var": field, "op": "exists", "value": None}

    # ── Pattern: "X is disabled" (without config prefix) ────────────────────
    if "protection is not enabled" in desc_lower or "is not enabled" in desc_lower:
        if field:
            return {"var": field, "op": "exists", "value": None}

    # ── Pattern: "retention period is less than N" → gte N ───────────────────
    m = re.search(r"retention.{0,20}less than.*?(\d+)", description, re.I)
    if m and field:
        return {"var": field, "op": "gte", "value": int(m.group(1))}

    # ── Pattern: field simply mentioned — use exists ──────────────────────────
    if field:
        return {"var": field, "op": "exists", "value": None}

    # ── Ultimate fallback ─────────────────────────────────────────────────────
    # Use a generic condition: rule passes when the resource itself exists
    return {"var": "item", "op": "exists", "value": None}


def build_check_entry(rule_id: str, for_each: str, condition: dict) -> dict:
    """Build a single check YAML dict."""
    entry = {
        "rule_id": rule_id,
        "for_each": for_each,
        "conditions": condition,
    }
    return entry


# ─── Existing check YAML helpers ──────────────────────────────────────────────

def load_existing_checks(service: str) -> list[dict]:
    """Load existing check entries from the service's checks YAML, or []."""
    p = CHECK_DIR / service / "checks" / "default" / f"{service}.checks.yaml"
    if not p.exists():
        return []
    with open(p) as fh:
        data = yaml.safe_load(fh)
    return (data or {}).get("checks", [])


def existing_rule_ids(checks: list[dict]) -> set[str]:
    return {c.get("rule_id", "") for c in checks}


def write_checks_yaml(service: str, checks: list[dict]) -> None:
    """Write the checks YAML file (creates dirs if needed)."""
    out_dir = CHECK_DIR / service / "checks" / "default"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{service}.checks.yaml"
    doc = {
        "version": "1.0",
        "provider": "aws",
        "service": service,
        "checks": checks,
    }
    with open(out_path, "w") as fh:
        yaml.dump(doc, fh, default_flow_style=False, sort_keys=False, allow_unicode=True)
    print(f"  Written: {out_path.relative_to(BASE)}")


# ─── Custom YAML representer (keep None as empty, not 'null') ─────────────────

def _represent_none(dumper, data):
    return dumper.represent_scalar("tag:yaml.org,2002:null", "null")

yaml.add_representer(type(None), _represent_none)


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    rows_by_service: dict[str, list[dict]] = defaultdict(list)
    with open(CSV_PATH) as fh:
        for row in csv.DictReader(fh):
            rows_by_service[row["service"]].append(row)

    report_missing_catalog: list[str] = []
    report_missing_discovery: list[tuple[str, str]] = []  # (service, discovery_id used)
    report_new_rules: list[tuple[str, str]] = []  # (service, rule_id)
    report_skipped: list[tuple[str, str]] = []   # (service, rule_id) — already exists

    for service, rows in sorted(rows_by_service.items()):
        print(f"\n── {service} ({len(rows)} rules) ──")

        # Check if catalog directory exists
        catalog_svc_dir = CATALOG_DIR / service
        if not catalog_svc_dir.exists():
            # Try hyphenated variants (e.g. acm_pca → acm-pca)
            alt = service.replace("_", "-")
            if (CATALOG_DIR / alt).exists():
                catalog_svc_dir = CATALOG_DIR / alt
            else:
                report_missing_catalog.append(service)
                print(f"  [WARN] No catalog directory found for '{service}'")

        # Load discovery IDs from the check engine's discoveries.yaml
        discoveries = load_discoveries(service)
        if not discoveries:
            report_missing_discovery.append((service, f"aws.{service}.*"))
            print(f"  [WARN] No discoveries.yaml found for '{service}'")

        # Load existing checks to avoid duplicates
        existing = load_existing_checks(service)
        existing_ids = existing_rule_ids(existing)
        new_checks = list(existing)  # start with existing entries

        for row in rows:
            rule_id    = row["rule_id"].strip()
            resource   = row["resource"].strip()
            description = row["description"].strip()

            if rule_id in existing_ids:
                report_skipped.append((service, rule_id))
                print(f"  [SKIP] {rule_id} (already exists)")
                continue

            for_each  = best_for_each(service, resource, discoveries)
            condition = parse_condition(rule_id, description)
            entry     = build_check_entry(rule_id, for_each, condition)

            new_checks.append(entry)
            existing_ids.add(rule_id)
            report_new_rules.append((service, rule_id))
            print(f"  [ADD] {rule_id}  →  {for_each}")

        write_checks_yaml(service, new_checks)

    # ── Summary Report ────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("GENERATION REPORT")
    print("=" * 70)
    print(f"  New rules generated : {len(report_new_rules)}")
    print(f"  Rules skipped       : {len(report_skipped)}")
    print(f"  Services processed  : {len(rows_by_service)}")
    print()

    if report_missing_catalog:
        print("Services with MISSING catalog (no step6 YAML):")
        for s in sorted(set(report_missing_catalog)):
            print(f"  - {s}")
        print()

    if report_missing_discovery:
        print("Services with MISSING discoveries.yaml (check engine):")
        for s, did in sorted(set(report_missing_discovery)):
            print(f"  - {s}  (placeholder used: {did})")
        print()

    if report_skipped:
        print("Skipped (already exist):")
        for svc, rid in report_skipped:
            print(f"  - [{svc}] {rid}")


if __name__ == "__main__":
    main()
