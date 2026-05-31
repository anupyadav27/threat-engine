"""Tag untagged IAM rule YAML files with MITRE ATT&CK techniques.

Reads all YAML files in catalog/rule/aws_rule_metadata/iam/, skips any that
already have mitre_techniques set, applies keyword-based technique mapping,
and writes the updated YAML back in-place.

Usage:
    python catalog/rule/tag_mitre_iam.py
"""

import re
import sys
from pathlib import Path

import yaml

IAM_DIR = Path("/Users/apple/Desktop/threat-engine/catalog/rule/aws_rule_metadata/iam")

# Tactic → threat_category mapping
TACTIC_TO_CATEGORY = {
    "privilege-escalation": "privilege_escalation",
    "credential-access": "credential_access",
    "persistence": "persistence",
    "initial-access": "initial_access",
    "discovery": "discovery",
    "defense-evasion": "defense_evasion",
}


def classify(rule_id: str, title: str) -> tuple[str, str, list[str]]:
    """Return (technique_id, tactic_dash, mitre_techniques_list) for a rule.

    Priority order follows the story mapping table:
    1. root            → T1078.004, privilege-escalation
    2. mfa / mfa-related → T1556, credential-access
    3. access_key / access-key → T1098.001, persistence
    4. policy + (admin|wildcard|*) → T1548.005, privilege-escalation
    5. cross / assume / trust → T1199, initial-access
    6. unused / inactive / old / stale → T1087.004, discovery
    7. user + create → T1136.003, persistence
    8. default → T1078.004, defense-evasion

    Additional refinements from the story technique mapping table are applied
    inline before the generic priority rules.
    """
    key = (rule_id + " " + title).lower()

    # --- Refinements from the authoritative mapping table ---

    # Privilege-escalation chains
    if "chain.guest_to_privileged" in rule_id or "chain.role_assignment_evasion" in rule_id:
        return "T1548.002", "privilege-escalation", ["T1548", "T1548.002"]

    # Activity-log rules (CloudTrail-sourced detections)
    if "activity_log.deactivate_mfa" in rule_id or "activity_log.delete_policy_version" in rule_id:
        return "T1548", "privilege-escalation", ["T1548"]

    if "activity_log.failed_auth" in rule_id:
        return "T1110", "credential-access", ["T1110"]

    if "activity_log.guest_user_creation" in rule_id:
        return "T1136.003", "persistence", ["T1136.003"]

    if "activity_log.role_assignment_modify" in rule_id:
        return "T1098.001", "persistence", ["T1098.001"]

    if "activity_log.assume_role" in rule_id:
        return "T1098.001", "persistence", ["T1098.001"]

    if "activity_log.replay_attempt" in rule_id:
        return "T1078", "credential-access", ["T1078", "T1078.004"]

    # CloudTrail audit rules
    if "audit.delete_malware_protection_role" in rule_id:
        return "T1562.001", "defense-evasion", ["T1562.001"]

    # CloudTrail cloudtrail.* rules — map by action
    if "cloudtrail." in rule_id:
        ct_action = rule_id.split("cloudtrail.")[-1] if "cloudtrail." in rule_id else ""

        if any(kw in ct_action for kw in ("attach_role_policy", "attach_group_policy", "attach_user_policy",
                                           "put_group_policy", "put_user_policy", "create_policy_version",
                                           "set_default_policy_version", "org_attach_policy",
                                           "org_update_policy", "org_create_policy")):
            return "T1548", "privilege-escalation", ["T1548"]

        if any(kw in ct_action for kw in ("deactivate_mfa_device", "delete_virtual_mfa_device",
                                           "update_login_profile")):
            return "T1556", "credential-access", ["T1556"]

        if any(kw in ct_action for kw in ("delete_access_key", "update_access_key_disable",
                                           "get_access_key_last_used")):
            return "T1098.001", "persistence", ["T1098.001"]

        if any(kw in ct_action for kw in ("delete_user", "delete_role", "delete_policy",
                                           "org_remove_account", "org_leave_organization",
                                           "delete_login_profile")):
            return "T1531", "impact", ["T1531"]

        if any(kw in ct_action for kw in ("add_user_to_group", "remove_user_from_group")):
            return "T1098.001", "persistence", ["T1098.001"]

        if any(kw in ct_action for kw in ("org_create_account", "sso_create_account_assignment",
                                           "sso_create_permission_set")):
            return "T1136.003", "persistence", ["T1136.003"]

        if any(kw in ct_action for kw in ("sts_assume_role", "sts_get_federation_token",
                                           "sts_get_session_token", "sts_decode_authorization")):
            return "T1550.001", "defense-evasion", ["T1550.001"]

        if any(kw in ct_action for kw in ("delete_oidc_provider", "delete_saml_provider",
                                           "delete_access_analyzer")):
            return "T1562.001", "defense-evasion", ["T1562.001"]

        if any(kw in ct_action for kw in ("sso_delete_account_assignment", "sso_delete_permission_set",
                                           "sso_provision_permission_set")):
            return "T1098.001", "persistence", ["T1098.001"]

        if any(kw in ct_action for kw in ("update_oidc_provider", "archive_access_analyzer",
                                           "enable_mfa_device")):
            return "T1556", "credential-access", ["T1556"]

        if "update_account_password_policy" in ct_action or "delete_account_password_policy" in ct_action:
            return "T1556", "credential-access", ["T1556"]

        # Generic cloudtrail fallback
        return "T1078.004", "defense-evasion", ["T1078.004"]

    # --- Priority-ordered keyword rules ---

    # 1. root
    if "root" in key:
        return "T1078.004", "privilege-escalation", ["T1078.004"]

    # 2. mfa / multi-factor
    if "mfa" in key or "multi-factor" in key or "multi_factor" in key:
        return "T1556", "credential-access", ["T1556"]

    # 3. access_key / access-key
    if "access_key" in key or "access-key" in key or "accesskey" in key:
        return "T1098.001", "persistence", ["T1098.001"]

    # 4. policy + (admin|wildcard|*)
    if "policy" in key and any(kw in key for kw in ("admin", "wildcard", "administrator",
                                                      "full_access", "fullaccess",
                                                      "administrative_privileges",
                                                      "no_action_star", "action_star")):
        return "T1548.005", "privilege-escalation", ["T1548.005"]

    # privilege escalation signals
    if any(kw in key for kw in ("privilege_escalation", "allows_privilege_escalation",
                                  "admin_star", "admin star", "no_admin")):
        return "T1548.005", "privilege-escalation", ["T1548.005"]

    # 5. cross / assume / trust
    if any(kw in key for kw in ("cross", "assume", "trust", "external_id",
                                  "external_accounts", "workload_identity", "federation")):
        return "T1199", "initial-access", ["T1199"]

    # 6. unused / inactive / old / stale / credentials_unused / rotation
    if any(kw in key for kw in ("unused", "inactive", "old", "stale",
                                  "rotation", "rotate", "key_age", "max_age",
                                  "not_rotated", "90_days", "45_days",
                                  "credentials_unused", "not_used")):
        return "T1087.004", "discovery", ["T1087.004"]

    # 7. user + create
    if "user" in key and "create" in key:
        return "T1136.003", "persistence", ["T1136.003"]

    # 8. Default fallback
    return "T1078.004", "defense-evasion", ["T1078.004"]


def build_mitre_block(technique_id: str, tactic_dash: str, techniques_list: list[str]) -> dict:
    """Build the MITRE fields dict to merge into the YAML data."""
    tactic_underscore = tactic_dash.replace("-", "_")
    category = TACTIC_TO_CATEGORY.get(tactic_dash, tactic_underscore)

    # threat_tags: deduplicated union of techniques + tactic
    threat_tags = list(dict.fromkeys(techniques_list + [tactic_underscore]))

    return {
        "mitre_tactics": [tactic_underscore],
        "mitre_techniques": techniques_list,
        "threat_tags": threat_tags,
        "threat_category": category,
    }


def validate_technique_ids(techniques: list[str]) -> bool:
    """Validate all technique IDs match T\\d{4}(\\.\\d{3})? pattern."""
    pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
    return all(pattern.match(tid) for tid in techniques)


def tag_file(yaml_path: Path) -> str:
    """Tag a single YAML file. Returns 'tagged', 'skipped', or 'error:<msg>'."""
    try:
        text = yaml_path.read_text(encoding="utf-8")
        data = yaml.safe_load(text)
    except Exception as exc:
        return f"error:parse:{exc}"

    if not isinstance(data, dict):
        return "error:not_a_dict"

    # Idempotency check — skip if already tagged
    if "mitre_techniques" in data:
        return "skipped"

    rule_id = data.get("rule_id", yaml_path.stem)
    title = data.get("title", "")

    technique_id, tactic_dash, techniques_list = classify(rule_id, title)

    # Validate technique IDs
    if not validate_technique_ids(techniques_list):
        return f"error:invalid_technique_ids:{techniques_list}"

    # Merge MITRE fields into data dict (append at end to preserve all existing fields)
    mitre_block = build_mitre_block(technique_id, tactic_dash, techniques_list)
    data.update(mitre_block)

    try:
        yaml_path.write_text(
            yaml.dump(data, default_flow_style=False, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )
    except Exception as exc:
        return f"error:write:{exc}"

    return "tagged"


def main() -> None:
    """Entry point: tag all untagged IAM YAML files."""
    if not IAM_DIR.is_dir():
        print(f"ERROR: Directory not found: {IAM_DIR}", file=sys.stderr)
        sys.exit(1)

    yaml_files = sorted(IAM_DIR.glob("*.yaml"))
    if not yaml_files:
        print("ERROR: No YAML files found in directory.", file=sys.stderr)
        sys.exit(1)

    tagged = 0
    skipped = 0
    errors = 0

    for yaml_path in yaml_files:
        result = tag_file(yaml_path)
        if result == "tagged":
            tagged += 1
        elif result == "skipped":
            skipped += 1
        else:
            errors += 1
            print(f"  ERROR [{yaml_path.name}]: {result}", file=sys.stderr)

    print(f"Tagged: {tagged}, Skipped (already tagged): {skipped}, Errors: {errors}")

    if errors > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
