#!/usr/bin/env python3
"""
Regenerate k8s rule checks using k8s_master_field_catalog.csv as ground truth.

For each rule check:
  1. Parse rule_id keywords → find matching field in catalog for that service
  2. producing_op  → for_each  (guaranteed-correct API operation)
  3. item_var_path → var       (validated field path from catalog)
  4. operators     → valid op  (constrained by field's actual type)
  5. Derive value  from field_type + rule intent keywords

Outputs:
  - Corrected *.checks.yaml files (in-place, backup saved)
  - catalog_validation_report.json  (per-check match result)
"""

import csv
import json
import re
import yaml
from collections import defaultdict
from pathlib import Path

CATALOG_CSV  = Path("/Users/apple/Desktop/threat-engine/catalog/discovery_generator/k8s/k8s_master_field_catalog.csv")
CHECKS_ROOT  = Path("/Users/apple/Desktop/threat-engine/catalog/rule/k8s_rule_check")
REPORT_FILE  = CHECKS_ROOT / "catalog_validation_report.json"

# ── Keyword → field-path patterns (ordered: most specific first) ─────────────
# Keys are substrings found in a rule requirement slug (after splitting on '_')
# Values are ordered substrings to search in catalog field_path
FIELD_PATTERNS: list[tuple[str, list[str]]] = [
    # container-level security context (most specific)
    ("privileged",           ["securityContext.privileged"]),
    ("allowprivilegeescalation", ["allowPrivilegeEscalation"]),
    ("allow_privilege",      ["allowPrivilegeEscalation"]),
    ("privilege_escalation", ["allowPrivilegeEscalation"]),
    ("capabilities",         ["securityContext.capabilities", "capabilities.drop", "capabilities.add"]),
    ("drop_capabilities",    ["capabilities.drop"]),
    ("readonlyrootfilesystem", ["readOnlyRootFilesystem"]),
    ("readonly_root",        ["readOnlyRootFilesystem"]),
    ("read_only",            ["readOnlyRootFilesystem"]),
    ("runasnonroot",         ["securityContext.runAsNonRoot", "runAsNonRoot"]),
    ("run_as_non_root",      ["securityContext.runAsNonRoot", "runAsNonRoot"]),
    ("runasuser",            ["securityContext.runAsUser", "runAsUser"]),
    ("run_as_user",          ["securityContext.runAsUser", "runAsUser"]),
    ("runasgroup",           ["securityContext.runAsGroup", "runAsGroup"]),
    ("selinux",              ["seLinuxOptions"]),
    ("seccomp",              ["seccompProfile"]),
    ("apparmor",             ["appArmorProfile"]),
    ("sysctls",              ["sysctls"]),
    # pod-level host isolation
    ("hostnetwork",          ["spec.hostNetwork", "hostNetwork"]),
    ("host_network",         ["spec.hostNetwork", "hostNetwork"]),
    ("hostpid",              ["spec.hostPID", "hostPID"]),
    ("host_pid",             ["spec.hostPID", "hostPID"]),
    ("hostipc",              ["spec.hostIPC", "hostIPC"]),
    ("host_ipc",             ["spec.hostIPC", "hostIPC"]),
    ("hostpath",             ["hostPath", "volumes"]),
    # service account / RBAC
    ("automount",            ["automountServiceAccountToken"]),
    ("sa_token",             ["automountServiceAccountToken"]),
    ("service_account",      ["serviceAccountName", "automountServiceAccountToken"]),
    ("wildcard_verb",        ["rules[].verbs"]),
    ("wildcard",             ["rules[].verbs", "rules[].resources"]),
    ("cluster_admin",        ["roleRef.name", "roleRef"]),
    # image
    ("image_pull",           ["imagePullPolicy", "imagePullSecrets"]),
    ("pull_policy",          ["imagePullPolicy"]),
    ("image_tag",            ["image"]),
    ("latest_tag",           ["image"]),
    # resource management
    ("resource_limit",       ["resources.limits", "spec.resources.limits"]),
    ("resource_request",     ["resources.requests"]),
    ("resource_quota",       ["spec.hard", "hard"]),
    ("limit_range",          ["spec.limits", "limits"]),
    # network policy
    ("default_deny",         ["spec.ingress", "spec.egress", "ingress", "egress"]),
    ("ingress",              ["spec.ingress", "ingress"]),
    ("egress",               ["spec.egress", "egress"]),
    ("policy_type",          ["spec.policyTypes", "policyTypes"]),
    ("no_allow_all",         ["spec.ingress", "spec.egress"]),
    ("allow_all",            ["spec.ingress", "spec.egress"]),
    # storage
    ("encryption_enabled",   ["parameters", "spec.parameters"]),
    ("reclaim",              ["reclaimPolicy"]),
    ("binding_mode",         ["volumeBindingMode"]),
    ("volume_binding",       ["volumeBindingMode"]),
    ("access_mode",          ["spec.accessModes", "accessModes"]),
    # logging / audit
    ("logging",              ["metadata.annotations", "annotations"]),
    ("audit",                ["metadata.annotations", "annotations"]),
    # general
    ("annotation",           ["metadata.annotations"]),
    ("label",                ["metadata.labels"]),
    ("replicas",             ["spec.replicas", "replicas"]),
    ("revision",             ["spec.revisionHistoryLimit"]),
    # fallback: any security-impact field
    ("",                     []),   # sentinel
]

# ── Operator inference ───────────────────────────────────────────────────────
def infer_op_and_value(requirement: str, field_type: str, operators: str, field_path: str):
    """Return (op, value) for a check given rule intent + field metadata."""
    ops_set = set(o.strip() for o in operators.split(","))
    slug = requirement.lower()

    # Boolean fields
    if field_type == "boolean":
        if "is_false" in ops_set:
            if any(k in slug for k in ("disabled","deny","deny_all","restrict","false")):
                return "is_false", None
            if any(k in slug for k in ("enabled","configured","true","non_root","nonroot")):
                return "is_true", None
        # fallback to equals
        if "equals" in ops_set:
            if any(k in slug for k in ("disabled","deny","false","no_")):
                return "equals", "false"
            return "equals", "true"

    # Existence checks (object/array fields)
    if field_type in ("object", "array"):
        if "not_empty" in ops_set and any(k in slug for k in ("configured","enabled","exists","has_")):
            return "not_empty", None
        return "exists", None

    # String enum fields (specific values)
    if field_type == "string":
        # Specific known patterns
        if "reclaimpolicy" in field_path.lower() or "reclaim" in slug:
            return "equals", "Retain"
        if "volumebindingmode" in field_path.lower() or "binding_mode" in slug:
            return "equals", "WaitForFirstConsumer"
        if "imagepullpolicy" in field_path.lower() or "pull_policy" in slug:
            return "equals", "Always"
        if "not_equals" in ops_set and any(k in slug for k in ("disabled","deny","restrict")):
            return "not_equals", "latest"
        if "exists" in ops_set:
            return "exists", None

    # Integer fields
    if field_type == "integer":
        if "run_as_user" in slug or "runasuser" in slug:
            return "not_equals", "0"
        return "exists", None

    # Default
    return "exists", None


# ── Field search in catalog ──────────────────────────────────────────────────
def find_best_field(requirement: str, svc_catalog: dict[str, dict]) -> dict | None:
    """
    Given a rule requirement slug and the service's catalog fields,
    return the best matching catalog row.
    Strategy: match requirement keywords against FIELD_PATTERNS,
    then score candidates by specificity.
    """
    slug = requirement.lower().replace("-", "_")

    candidates = []
    for keyword, patterns in FIELD_PATTERNS:
        if keyword and keyword not in slug:
            continue
        for pat in patterns:
            pat_lower = pat.lower()
            for field_path, row in svc_catalog.items():
                if pat_lower in field_path.lower():
                    # Score: longer pattern match = more specific
                    score = len(pat) + (10 if keyword in slug else 0)
                    # Prefer non-nested paths that directly contain the pattern
                    score += 5 if field_path.lower().endswith(pat_lower) else 0
                    candidates.append((score, field_path, row))

    if not candidates:
        return None

    # Return highest-score candidate
    candidates.sort(key=lambda x: -x[0])
    return candidates[0][2]


# ── Build producing-op index for a service ──────────────────────────────────
def get_primary_list_op(svc_catalog: dict[str, dict]) -> str | None:
    """Get the primary 'list' producing_op for a service."""
    for row in svc_catalog.values():
        op = row.get("producing_op", "")
        if op.endswith(".list"):
            return op
    # fallback: any producing_op
    for row in svc_catalog.values():
        op = row.get("producing_op", "")
        if op:
            return op
    return None


# ── Load catalog ─────────────────────────────────────────────────────────────
def load_catalog() -> dict[str, dict[str, dict]]:
    """Returns {service: {field_path: row_dict}}.

    Prefers is_independent=Yes (list op) rows over get op rows for each
    (service, field_path) combination. Rule checks iterate over all resources
    so they must use the list producing_op in for_each.
    """
    catalog: dict[str, dict[str, dict]] = {}
    with open(CATALOG_CSV) as f:
        for row in csv.DictReader(f):
            svc  = row["service"]
            path = row["field_path"]
            existing = catalog.setdefault(svc, {}).get(path)
            if existing is None:
                catalog[svc][path] = row
            elif row.get("is_independent", "Yes") == "Yes" and existing.get("is_independent") == "No":
                # Prefer list (independent) row over get (dependent) row
                catalog[svc][path] = row
    return catalog


# ── Main processing ──────────────────────────────────────────────────────────
def process_checks(catalog: dict) -> dict:
    """
    Walk all k8s_rule_check YAML files, validate + correct each check.
    Returns report dict.
    """
    report = {
        "total": 0,
        "catalog_matched": 0,
        "already_correct": 0,
        "corrected": 0,
        "no_match": 0,
        "details": [],
    }

    for check_file in sorted(CHECKS_ROOT.glob("*/*.checks.yaml")):
        if check_file.name.startswith("1_"):
            continue

        with open(check_file) as f:
            doc = yaml.safe_load(f)

        svc = doc.get("service", check_file.parent.name)
        svc_catalog = catalog.get(svc, {})
        primary_list_op = get_primary_list_op(svc_catalog)

        changed = False
        new_checks = []

        for check in doc.get("checks", []):
            report["total"] += 1
            rule_id = check.get("rule_id", "")
            # requirement is the last segment: k8s.svc.resource.requirement
            parts = rule_id.split(".")
            requirement = parts[-1] if len(parts) >= 4 else ""

            current_fe  = check.get("for_each", "")
            cond        = check.get("conditions", {})
            is_simple   = isinstance(cond, dict) and "var" in cond
            current_var = cond.get("var", "") if is_simple else ""
            current_op  = cond.get("op", "")  if is_simple else ""

            detail = {
                "rule_id": rule_id,
                "service": svc,
                "original_for_each": current_fe,
                "original_var": current_var,
                "original_op": current_op,
                "status": "",
                "new_for_each": None,
                "new_var": None,
                "new_op": None,
                "new_value": None,
                "matched_field": None,
            }

            if not svc_catalog:
                # No catalog for this service — keep as-is
                detail["status"] = "no_catalog"
                new_checks.append(check)
                report["no_match"] += 1
                report["details"].append(detail)
                continue

            # Find best field from catalog for this rule
            best = find_best_field(requirement, svc_catalog)

            if best is None:
                # Could not match — keep original but fix for_each if wrong
                detail["status"] = "no_field_match"
                report["no_match"] += 1

                new_check = dict(check)
                if primary_list_op and current_fe != primary_list_op:
                    new_check["for_each"] = primary_list_op
                    detail["new_for_each"] = primary_list_op
                    changed = True

                new_checks.append(new_check)
                report["details"].append(detail)
                continue

            # Derive correct values from catalog row
            correct_fe    = best["producing_op"]
            correct_var   = best["item_var_path"]       # e.g. item.spec.template.spec.hostIPC
            operators_str = best["operators"]
            field_type    = best["field_type"]

            correct_op, correct_value = infer_op_and_value(
                requirement, field_type, operators_str, best["field_path"]
            )

            detail["matched_field"]  = best["field_path"]
            detail["new_for_each"]   = correct_fe
            detail["new_var"]        = correct_var
            detail["new_op"]         = correct_op
            detail["new_value"]      = correct_value

            # Check if already correct
            already_ok = (
                current_fe  == correct_fe  and
                current_var == correct_var and
                current_op  == correct_op
            )

            if already_ok:
                detail["status"] = "ok"
                report["already_correct"] += 1
                new_checks.append(check)
            else:
                detail["status"] = "corrected"
                report["catalog_matched"] += 1
                report["corrected"] += 1
                changed = True

                new_cond: dict = {"var": correct_var, "op": correct_op}
                if correct_value is not None:
                    new_cond["value"] = str(correct_value)

                new_checks.append({
                    "rule_id":   rule_id,
                    "for_each":  correct_fe,
                    "conditions": new_cond,
                })

            report["details"].append(detail)

        # Write corrected file if anything changed
        if changed:
            backup = check_file.with_suffix(".yaml.bak")
            backup.write_text(check_file.read_text())

            doc["checks"] = new_checks
            with open(check_file, "w") as f:
                yaml.dump(doc, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
            print(f"  Updated: {check_file.parent.name}/{check_file.name}")
        else:
            print(f"  OK:      {check_file.parent.name}/{check_file.name}")

    return report


def print_summary(report: dict):
    print()
    print("=" * 60)
    print("K8S CHECK CATALOG VALIDATION REPORT")
    print("=" * 60)
    print(f"  Total checks       : {report['total']}")
    print(f"  Already correct    : {report['already_correct']}")
    print(f"  Corrected          : {report['corrected']}")
    print(f"  No catalog match   : {report['no_match']}")
    print()

    # Show corrected examples
    corrected = [d for d in report["details"] if d["status"] == "corrected"]
    print(f"Sample corrections ({min(10,len(corrected))}/{len(corrected)}):")
    for d in corrected[:10]:
        print(f"  [{d['rule_id']}]")
        print(f"    for_each:  {d['original_for_each']!r} → {d['new_for_each']!r}")
        print(f"    var:       {d['original_var']!r} → {d['new_var']!r}")
        print(f"    op:        {d['original_op']!r} → {d['new_op']!r}")
        print(f"    field:     {d['matched_field']!r}")
        print()

    # Show no-match cases
    no_match = [d for d in report["details"] if d["status"] in ("no_field_match","no_catalog")]
    if no_match:
        print(f"No-match cases ({len(no_match)}):")
        for d in no_match[:10]:
            print(f"  {d['rule_id']}  (svc_catalog={'present' if catalog.get(d['service']) else 'MISSING'})")


def main():
    global catalog
    print("Loading k8s master field catalog...")
    catalog = load_catalog()
    print(f"  {sum(len(v) for v in catalog.values()):,} fields across {len(catalog)} services")
    print()

    print("Processing k8s rule checks...")
    report = process_checks(catalog)

    # Save report
    REPORT_FILE.write_text(json.dumps(report, indent=2, default=str))
    print(f"\nReport saved → {REPORT_FILE.name}")
    print_summary(report)


if __name__ == "__main__":
    main()
