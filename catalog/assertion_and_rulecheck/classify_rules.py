"""
Phase 0 — Rule Triage Classifier (heuristic, no LLM)

Classifies every rule_id into one of:
  SCAN_ABLE      — Provable via a single CSP API response field
  MULTI_OP       — Needs list + describe (detected by common patterns)
  POLICY_ATTEST  — Governance attestation, no API field exists
  EVENT          — Threat-detection event (audit log, not posture scan)
  AMBIGUOUS      — Rule text insufficient; needs LLM/human review

Design principle: be PERMISSIVE toward SCAN_ABLE — the LLM and fixture
harness in Phase 3 will catch bad generations anyway. Here we only need
to filter out rules that have NO hope of being code-generated.

Output:
  - In-place YAML updates: adds `implementable:` field to every rule
  - triage_report.csv  — per-CSP × class counts
  - triage_report.md   — human-readable summary
  - samples_by_class.txt — representative rule_ids per class/CSP
"""

from __future__ import annotations
import csv
from collections import defaultdict
from pathlib import Path
from typing import Literal

import yaml

ROOT = Path(__file__).parent
FILES = sorted(ROOT.glob("[0-9]_*_full_scope_assertions.yaml"))

Label = Literal["SCAN_ABLE", "MULTI_OP", "POLICY_ATTEST", "EVENT", "AMBIGUOUS"]


# ═════════════════════════════════════════════════════════════════════
# Signal tokens — strong evidence for one class
# ═════════════════════════════════════════════════════════════════════

# These strongly indicate "no API field exists" — pure governance/attestation
# IMPORTANT: avoid generic words that collide with ML/AI resource names
# (e.g. "_training_" would match "training_job" which is a scannable ML resource).
POLICY_ATTEST_TOKENS = {
    "_documented",
    "_reviewed",
    "_maintained",
    "_staff_trained",
    "_personnel_trained",
    "_user_training_completed",
    "_security_awareness",
    "_personnel_",
    "_culture_",
    "_process_defined",
    "_procedure_defined",
    "_procedures_documented",
    "_runbook_",
    "_playbook_",
    "_tabletop_",
    "_drill_",
    "_incident_response_plan",
    "_breach_notification_plan",
    "_recovery_plan_documented",
    "_continuity_plan_documented",
    "_separation_of_duties",
    "_vendor_review",
    "_third_party_review",
    "_privacy_notice",
    "_data_subject_request",
    "_business_impact_analysis",
    "_risk_assessment_documented",
    # AliCloud governance patterns (no API field — human/process only)
    "_compliance_standards_met",
    "_risks_mitigated",
    "_modern_architecture_required",
    "_patching_enforced",
}

# These indicate a threat-detection event (audit log event, not posture)
EVENT_TOKENS = {
    "_deleted",
    "_created",
    "_modified",
    "_updated",
    "_removed",
    "_changed",
    "_started",
    "_stopped",
    "_terminated",
    "_launched",
    "_failed_login",
    "_unauthorized_access",
    "_policy_change",
    "_permission_change",
    "_role_change",
    "_console_login",
    "_api_call",
}

# Strong scan-able tech hints — any of these in the rule_id → SCAN_ABLE
# NOTE: tokens are matched against the DOT-NORMALIZED form of the rule_id
#       (dots replaced with underscores) so that Azure dot-separated rules
#       like "public.network.access" match "public_network" correctly.
SCAN_HINT_TOKENS = {
    # AMBIGUOUS resolution: 2 vague-leaf rules resolved to SCAN_ABLE
    "admin",                   # azure.monitor.admin.account.usage.check
    "recovery",                # azure.site.recovery.configured
    # Encryption
    "encryption", "encrypted", "kms", "cmek", "hsm", "tls", "ssl", "https",
    "tde",                   # Azure SQL Transparent Data Encryption
    "soft_delete",           # Azure soft-delete on storage/keyvault
    # Access / Identity
    "password_policy", "mfa", "rbac", "privilege", "role", "policy",
    "iam", "auth", "authn", "authz", "oidc", "saml", "token",
    "guest_user", "service_account", "managed_identity", "identity",
    "restriction",           # access restriction checks
    "lockout",               # account lockout threshold/duration
    "notification",          # security notification settings
    "contact",               # security contact email checks
    # Network
    "public_access", "publicly_accessible", "private_endpoint",
    "private_networking", "network_acl", "security_group",
    "ingress", "egress", "flow_log", "vpc", "subnet", "firewall",
    "waf", "ddos", "public_network", "public_ip", "eip",
    "nsg",                   # Azure Network Security Group
    "rdp",                   # RDP port-open checks
    "udp",                   # UDP port-open checks
    "http",                  # HTTP (non-TLS) access checks
    "internet",              # internet-accessible resource checks
    "vnet",                  # Azure VNet integration
    "bastion",               # Azure Bastion host existence
    "watcher",               # Azure Network Watcher per-region
    "redundancy",            # geo/zone redundancy settings
    # Logging / Monitoring
    "cloudtrail", "cloudwatch", "audit_log", "access_log", "log_sink",
    "log_retention", "flow_logging", "logs_enabled", "logging",
    "alarm", "diagnostic_settings", "diagnostic",
    # Data protection
    "backup", "snapshot", "versioning", "retention", "deletion_protection",
    "immutable", "worm", "lifecycle", "pitr",
    "lock",                  # Azure resource locks (delete/readonly)
    "rotation",              # key / secret rotation checks
    "shared_key",            # Azure storage shared-key access
    "root_squash",           # Azure NFS root-squash setting
    # Config thresholds (numeric)
    "min_length", "max_age", "minimum", "maximum", "threshold",
    "quota", "limit", "rate_limit", "burst_limit", "ttl", "timeout",
    # Status/state
    "enabled", "disabled", "active", "status",
    # Certificates
    "certificate", "key_length", "key_rotation", "expiration", "expired",
    # Tags/metadata
    "tag_required", "label_required", "tagged",
    # ML/AI resources (all scannable via describe ops)
    "ml_", "ai_", "model_", "training_job", "inference", "endpoint",
    "feature_store", "pipeline_iam",
    # AKS / container specifics
    "kubelet", "cni", "runtime_class", "admission",
    # App service / runtime
    "ftps", "http_version", "runtime_version", "managed_identity_configured",
    "client_cert",
    "debugging",             # remote debugging on/off (App Service / Functions)
    # VM / compute
    "extension",             # VM extensions approved/security checks
    "disk",                  # managed disk checks
    "vtpm",                  # Azure Trusted Launch vTPM
    "secure_boot",           # Azure Trusted Launch Secure Boot
    # Pricing / licensing (Defender for Cloud tier checks)
    "pricing",
    # Configurable resources — if the word "configured" appears with any noun
    "autoscaling", "scaling",
    # Additional nouns commonly scannable
    "access_key", "access_keys", "security_group", "securitygroup",
    "multi_az", "multi_region", "alert", "alerts", "metric_filter",
    "namespace", "label", "labeling", "annotation", "deployment",
    "signin", "sign_in", "shodan", "exposure", "console_login",
    "runtime", "api_version", "version",
    "bucket_policy", "bucket", "container", "volume",
    # Vulnerability / patch (AliCloud Security Center checks)
    "vulnerability_scan", "ssm_agent", "fingerprint",
    # Azure-specific extras caught in second pass
    "virtual_network",       # App Service / Functions VNet integration
    "os_update",             # Defender for Cloud VM OS patch setting
    "ad_admin",              # Azure SQL / Synapse AD administrator
    "owner",                 # Subscription owner count / RBAC
    "insights",              # Application Insights configuration
    "monitoring",            # Network Watcher / K8s monitoring
    "finding",               # Security Center findings count
    "vault",                 # Key Vault / backup vault configuration
    "deny",                  # network.access.deny.by.default
    "bypass",                # network.rule.trusted.services bypass
    "trusted_service",       # storage networkAcls.bypass = AzureServices
}

# ── MULTI_OP detection (strict: only when CHECK CONDITION fields span 2+ ops) ──
#
# REMOVED (single-op reads — the full data is returned in ONE API call):
#   _attached           → resource describe returns "attached" state directly
#   _bucket_policy      → s3:GetBucketPolicy / az storage container policy show
#   _resource_policy    → single GetResourcePolicy call returns the policy
#   _access_policy      → single GetAccessPolicy call
#   _role_assignment    → az role assignment list returns assignments directly
#   _policy_bindings    → gcloud/oci get-iam-policy returns bindings directly
#
# ALWAYS MULTI_OP (condition fields come from different ops regardless of wording)
MULTI_OP_ALWAYS = {
    "_attached_users",          # IAM: ListAttachedUsers + GetUser policies
}

# CONDITIONAL MULTI_OP: MULTI_OP only when a content-check keyword is also present
# (i.e. the check inspects the *content* of the policy, not just its existence)
MULTI_OP_WITH_CONTENT_CHECK = {
    "_attached_policies",       # MULTI_OP when checking admin/privilege content
    "_inline_policy",           # MULTI_OP when checking inline policy content
    "_instance_profile",        # MULTI_OP when checking least_privilege on profile
}

# Keywords that signal a content-inspection check (triggers conditional MULTI_OP)
CONTENT_CHECK_KEYWORDS = {
    "not_admin", "no_admin", "admin_star", "least_privilege",
    "no_administrative", "not_administrative", "privileged",
    "admin",                    # covers *_not_admin and admin-in-leaf cases
}

# Leaves that are genuinely too vague to classify
VAGUE_LEAVES = {"check", "standard", "configured", "present"}

# If the FULL normalized rule_id ends with any of these, it's a posture check
# even if it contains an EVENT token in the middle.
# (Examples: "change_logging_enabled", "change_detection_enabled",
#  "terminated_pod_gc_threshold_check", "unused_policies_removed_configured")
POSTURE_OVERRIDE_SUFFIXES = (
    "_enabled", "_disabled", "_configured", "_check",
    "_logging_enabled", "_detection_enabled", "_audit_enabled",
    "_threshold_check", "_threshold", "_logging", "_monitoring",
    "_logged",          # "change_events_logged" = posture check on audit policy
    "_changes",         # "network_policy_changes" = does audit policy capture this?
    "_removed_configured",  # unused_policies_removed_configured
)


# ═════════════════════════════════════════════════════════════════════
# Classifier
# ═════════════════════════════════════════════════════════════════════

def classify(rule_id: str) -> tuple[Label, str]:
    """Return (label, reason).

    Token matching uses the DOT-NORMALIZED form (dots replaced with underscores)
    so that Azure dot-separated rules like "public.network.access" match the
    token "public_network" just as well as underscore-separated variants.
    """
    lower = rule_id.lower()
    lower_norm = lower.replace(".", "_")   # normalize for dot-separated CSPs
    leaf = rule_id.split(".")[-1].lower()

    # 1. Event-type rules (audit log events, not posture scans)
    #    These are handled by the threat engine, not the check engine.
    #    Override: if the rule_id ends with a posture-check suffix (e.g.
    #    "_enabled", "_configured", "_threshold_check"), the rule is checking
    #    WHETHER a monitoring/detection control is in place — not the event itself.
    for tok in EVENT_TOKENS:
        if tok in lower_norm:
            if not any(lower_norm.endswith(sfx) for sfx in POSTURE_OVERRIDE_SUFFIXES):
                return "EVENT", f"contains '{tok}'"

    # 2. Policy attestation — strong governance tokens (human/process only)
    for tok in POLICY_ATTEST_TOKENS:
        if tok in lower_norm:
            return "POLICY_ATTEST", f"contains '{tok}'"

    # 3. Scan hint present anywhere in rule_id → SCAN_ABLE (or MULTI_OP if warranted)
    #    Check this BEFORE vague-leaf fallback, because rules like
    #    "azure.aks.cluster.private.endpoint.and.public.access.check"
    #    have scannable content despite the ".check" leaf.
    for tok in SCAN_HINT_TOKENS:
        if tok in lower_norm:
            # Always-MULTI_OP tokens override SCAN_ABLE
            for mop_tok in MULTI_OP_ALWAYS:
                if mop_tok in lower_norm:
                    return "MULTI_OP", f"scan hint '{tok}' + always-multi-op '{mop_tok}'"
            # Conditional MULTI_OP — only when a content-check keyword is also present
            for mop_tok in MULTI_OP_WITH_CONTENT_CHECK:
                if mop_tok in lower_norm:
                    for ck in CONTENT_CHECK_KEYWORDS:
                        if ck in lower_norm:
                            return "MULTI_OP", f"scan hint '{tok}' + multi-op '{mop_tok}' + content-check '{ck}'"
            return "SCAN_ABLE", f"contains scan hint '{tok}'"

    # 4. Multi-op (without a scan hint — pure existence checks that need 2+ ops)
    for tok in MULTI_OP_ALWAYS:
        if tok in lower_norm:
            return "MULTI_OP", f"contains always-multi-op '{tok}'"
    for tok in MULTI_OP_WITH_CONTENT_CHECK:
        if tok in lower_norm:
            for ck in CONTENT_CHECK_KEYWORDS:
                if ck in lower_norm:
                    return "MULTI_OP", f"contains conditional-multi-op '{tok}' + content-check '{ck}'"

    # 5. Genuinely vague leaves with no signal anywhere
    if leaf in VAGUE_LEAVES:
        return "AMBIGUOUS", f"vague leaf '{leaf}' with no scan hint"

    # 6. Default — be permissive. The Phase 3 fixture harness will catch
    #    un-implementable rules by failing to extract a non-null value.
    return "SCAN_ABLE", "default permissive"


# ═════════════════════════════════════════════════════════════════════
# YAML walker (handles arbitrary nesting depth)
# ═════════════════════════════════════════════════════════════════════

def walk_and_classify(node, counts: dict, samples: dict) -> int:
    """
    Recursively walk a YAML structure. Whenever we hit a dict with
    `rule_id`, add `implementable:`. Returns total rules seen.
    """
    seen = 0
    if isinstance(node, dict):
        if "rule_id" in node and isinstance(node["rule_id"], str):
            label, reason = classify(node["rule_id"])
            node["implementable"] = label
            node["classify_reason"] = reason
            counts[label] += 1
            if len(samples[label]) < 20:
                samples[label].append(node["rule_id"])
            seen += 1
        else:
            for v in node.values():
                seen += walk_and_classify(v, counts, samples)
    elif isinstance(node, list):
        for item in node:
            seen += walk_and_classify(item, counts, samples)
    return seen


def write_yaml_preserving_header(path: Path, data) -> None:
    """Rewrite the YAML file, keeping the existing top-of-file comment block."""
    text = path.read_text()
    lines = text.splitlines()
    header_end = 0
    for i, line in enumerate(lines):
        if line.startswith("#") or line.strip() == "":
            header_end = i + 1
        else:
            break
    header = "\n".join(lines[:header_end])

    body = yaml.safe_dump(data, sort_keys=False, default_flow_style=False,
                          allow_unicode=True, width=200)

    path.write_text(header.rstrip() + "\n\n" + body)


def classify_file(path: Path) -> tuple[int, dict, dict]:
    data = yaml.safe_load(path.read_text())
    counts: dict[Label, int] = defaultdict(int)
    samples: dict[Label, list[str]] = defaultdict(list)
    total = walk_and_classify(data, counts, samples)
    write_yaml_preserving_header(path, data)
    return total, dict(counts), dict(samples)


# ═════════════════════════════════════════════════════════════════════
# Reports
# ═════════════════════════════════════════════════════════════════════

LABELS: list[Label] = ["SCAN_ABLE", "MULTI_OP", "POLICY_ATTEST", "EVENT", "AMBIGUOUS"]


def write_report(all_counts: dict[str, dict[Label, int]]) -> None:
    csv_path = ROOT / "triage_report.csv"
    md_path = ROOT / "triage_report.md"

    totals = defaultdict(int)

    # CSV
    with open(csv_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["csp", *LABELS, "total", "scan_pct"])
        for csp, counts in all_counts.items():
            row_total = sum(counts.values())
            scan = counts.get("SCAN_ABLE", 0) + counts.get("MULTI_OP", 0)
            pct = f"{100 * scan / row_total:.1f}%" if row_total else "0%"
            w.writerow([csp] + [counts.get(lbl, 0) for lbl in LABELS] +
                       [row_total, pct])
            for lbl in LABELS:
                totals[lbl] += counts.get(lbl, 0)
        grand = sum(totals.values())
        scan = totals["SCAN_ABLE"] + totals["MULTI_OP"]
        pct = f"{100 * scan / grand:.1f}%" if grand else "0%"
        w.writerow(["TOTAL", *[totals[lbl] for lbl in LABELS], grand, pct])

    # Markdown
    lines = [
        "# Triage Report — Implementability Classification",
        "",
        "Generated by `classify_rules.py` (heuristic-only, no LLM).",
        "",
        "## Classes",
        "- **SCAN_ABLE** — Provable via a single CSP API response field",
        "- **MULTI_OP** — Needs list + describe (2+ API calls)",
        "- **POLICY_ATTEST** — Governance attestation, skip code-gen",
        "- **EVENT** — Threat-detection event (audit log, not posture)",
        "- **AMBIGUOUS** — Rule text insufficient; needs LLM/human review",
        "",
        "## Counts per CSP",
        "",
        "| CSP | SCAN_ABLE | MULTI_OP | POLICY_ATTEST | EVENT | AMBIGUOUS | Total | Scannable % |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for csp, counts in all_counts.items():
        t = sum(counts.values())
        scan = counts.get("SCAN_ABLE", 0) + counts.get("MULTI_OP", 0)
        pct = f"{100 * scan / t:.1f}%" if t else "0%"
        lines.append(
            f"| {csp} "
            f"| {counts.get('SCAN_ABLE', 0)} "
            f"| {counts.get('MULTI_OP', 0)} "
            f"| {counts.get('POLICY_ATTEST', 0)} "
            f"| {counts.get('EVENT', 0)} "
            f"| {counts.get('AMBIGUOUS', 0)} "
            f"| {t} | {pct} |"
        )
    grand = sum(totals.values())
    scan = totals["SCAN_ABLE"] + totals["MULTI_OP"]
    pct = f"{100 * scan / grand:.1f}%" if grand else "0%"
    lines.append(
        f"| **Total** "
        f"| **{totals['SCAN_ABLE']}** | **{totals['MULTI_OP']}** "
        f"| **{totals['POLICY_ATTEST']}** | **{totals['EVENT']}** "
        f"| **{totals['AMBIGUOUS']}** | **{grand}** | **{pct}** |"
    )
    lines += [
        "",
        "## Next steps",
        "- **SCAN_ABLE + MULTI_OP** → Phase 3 code generation target",
        "- **EVENT** → handled by threat engine, not check engine (route separately)",
        "- **POLICY_ATTEST** → mark as 'attestation-only' in rule DB, skip code-gen",
        "- **AMBIGUOUS** → optional LLM reclassification or human review",
        "",
    ]
    md_path.write_text("\n".join(lines) + "\n")


def write_samples(all_samples: dict[str, dict[Label, list[str]]]) -> None:
    out = ROOT / "samples_by_class.txt"
    lines = []
    for csp, by_label in all_samples.items():
        lines.append(f"\n{'═' * 70}\n{csp}\n{'═' * 70}")
        for lbl in LABELS:
            rules = by_label.get(lbl, [])
            if not rules:
                continue
            lines.append(f"\n--- {lbl} (showing {len(rules)}) ---")
            lines.extend(rules)
    out.write_text("\n".join(lines))


# ═════════════════════════════════════════════════════════════════════
# Main
# ═════════════════════════════════════════════════════════════════════

def main() -> None:
    all_counts: dict[str, dict[Label, int]] = {}
    all_samples: dict[str, dict[Label, list[str]]] = {}

    for path in FILES:
        csp = path.stem.split("_")[1].upper()
        print(f"[{csp}] classifying {path.name} …")
        total, counts, samples = classify_file(path)
        all_counts[csp] = counts
        all_samples[csp] = samples
        pretty = "  ".join(f"{k}={v}" for k, v in counts.items())
        print(f"  → total={total}  {pretty}")

    write_report(all_counts)
    write_samples(all_samples)
    print("\nReports written:")
    print(f"  {ROOT / 'triage_report.csv'}")
    print(f"  {ROOT / 'triage_report.md'}")
    print(f"  {ROOT / 'samples_by_class.txt'}")


if __name__ == "__main__":
    main()
