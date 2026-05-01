#!/usr/bin/env python3
"""
fix_k8s_check_conditions.py
============================
Fixes duplicate check_conditions in k8s_field_rule_catalog.csv where multiple
rules in the same service share identical (var, op, value) — which is wrong
because different rules have different security intents.

Two fix strategies:

1. EXPLICIT FIELD OVERRIDES (curated dict)
   Rules that check real K8s spec/rules fields get precise sub-field conditions.
   e.g. k8s.clusterrole.permission.wildcard_verbs_restricted
        → item.rules[].verbs  not_equals  ["*"]  (not just "item.rules exists")

2. ANNOTATION KEY DERIVATION (automatic)
   Rules that conceptually need annotation-based evidence (backup, compliance,
   monitoring, change-management, etc.) get a unique CSPM annotation key derived
   from their rule_id.
   e.g. k8s.pod.backup.annotations_configured
        → item.metadata.annotations.cspm.k8s.io/backup-annotations-configured  exists

Rules that remain duplicated after both passes are flagged:
   needs_review = true
   review_reason = "duplicate_condition_manual_review"

Usage:
    python fix_k8s_check_conditions.py              # fix + write CSV
    python fix_k8s_check_conditions.py --report     # show report only, no write
    python fix_k8s_check_conditions.py --dry-run    # show what would change
"""
from __future__ import annotations

import argparse
import csv
import json
import re
from collections import defaultdict
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ── Paths ─────────────────────────────────────────────────────────────────────
REPO_ROOT   = Path(__file__).resolve().parents[4]
K8S_DIR     = REPO_ROOT / "catalog/discovery_generator/k8s"
CATALOG_CSV = K8S_DIR / "k8s_field_rule_catalog.csv"

# ── Curated explicit overrides ─────────────────────────────────────────────────
# (rule_id) → (var, op, value)
# Only applied when the current condition is a duplicate within the service.
# value=None becomes null in JSON.
EXPLICIT: Dict[str, Tuple[str, str, Any]] = {

    # ── RBAC permission checks ─────────────────────────────────────────────
    "k8s.clusterrole.permission.wildcard_verbs_restricted":
        ("item.rules[].verbs",    "not_equals", ["*"]),
    "k8s.clusterrole.permission.wildcard_resources_restricted":
        ("item.rules[].resources","not_equals", ["*"]),
    "k8s.clusterrole.permission.secrets_access_restricted":
        ("item.rules[].resources","not_equals", ["secrets"]),
    "k8s.clusterrole.escalation.impersonation_restricted":
        ("item.rules[].verbs",    "not_equals", ["impersonate"]),
    "k8s.clusterrole.permission.exec_restricted":
        ("item.rules[].verbs",    "not_equals", ["exec"]),
    "k8s.role.permission.secrets_access_restricted":
        ("item.rules[].resources","not_equals", ["secrets"]),
    "k8s.role.permission.exec_restricted":
        ("item.rules[].verbs",    "not_equals", ["exec"]),

    # RBAC wildcard rules
    "k8s.rbac.role.wildcard_permissions_prohibited_enforced":
        ("item.rules[].verbs",    "not_equals", ["*"]),
    "k8s.rbac.roles.no_wildcard_in_rules":
        ("item.rules[].resources","not_equals", ["*"]),
    "k8s.rbac.impersonate.bind_escalate_permissions_check":
        ("item.rules[].verbs",    "not_equals", ["impersonate","bind","escalate"]),

    # RBAC — subjects
    "k8s.clusterrolebinding.binding.subjects_exist":
        ("item.subjects", "not_empty", None),
    "k8s.clusterrolebinding.binding.default_namespace_sa_not_admin_bound":
        ("item.subjects[].namespace", "not_equals", "default"),

    # RBAC — specific rule checks (disambiguate from generic "item.rules exists")
    "k8s.rbac.no.anonymous_access":
        ("item.subjects[].name", "not_equals", "system:anonymous"),
    "k8s.rbac.no.root_access_key":
        ("item.subjects[].name", "not_equals", "system:masters"),
    "k8s.rbac.system.masters_group_usage_check":
        ("item.subjects[].kind", "not_equals", "Group"),
    "k8s.rbac.cluster.admin_role_usage_check":
        ("item.roleRef.name", "not_equals", "cluster-admin"),
    "k8s.rbac.cluster.admin_role_access_review":
        ("item.roleRef.name", "equals", "cluster-admin"),
    "k8s.rbac.nodes.proxy_access_check":
        ("item.rules[].resources", "not_equals", ["nodes/proxy"]),
    "k8s.rbac.persistentvolume.creation_access_check":
        ("item.rules[].resources", "not_equals", ["persistentvolumes"]),
    "k8s.rbac.pod.creation_access_check":
        ("item.rules[].resources", "not_equals", ["pods"]),
    "k8s.rbac.csr.approval_access_control_check":
        ("item.rules[].resources", "not_equals", ["certificatesigningrequests"]),
    "k8s.rbac.serviceaccount.token_creation_access_check":
        ("item.rules[].resources", "not_equals", ["serviceaccounts/token"]),
    "k8s.rbac.least.privilege_enforcement":
        ("item.rules", "not_empty", None),
    "k8s.rbac.least.privilege_for_clearinghouse":
        ("item.rules[].verbs", "not_equals", ["*"]),
    "k8s.rbac.minimal.privileges_assigned":
        ("item.rules[].resources", "not_equals", ["*"]),
    "k8s.rbac.unused.role_cleanup":
        ("item.metadata.labels.rbac.authorization.kubernetes.io/aggregate-to-admin", "exists", None),
    "k8s.rbac.unused.service_account_cleanup":
        ("item.subjects[].kind", "equals", "ServiceAccount"),
    "k8s.rbac.no.shared_service_accounts":
        ("item.subjects[].kind", "equals", "ServiceAccount"),
    "k8s.rbac.no.single_user_full_control":
        ("item.subjects", "not_empty", None),
    "k8s.rbac.secrets.access_review":
        ("item.rules[].resources", "not_equals", ["secrets"]),
    "k8s.rbac.database.access_restricted":
        ("item.rules[].resources", "not_equals", ["*"]),
    "k8s.rbac.log.access_restricted":
        ("item.rules[].verbs", "not_equals", ["*"]),
    "k8s.rbac.serviceaccount.least_privilege":
        ("item.rules[].verbs", "not_equals", ["*"]),
    "k8s.rbac.serviceaccount.restricted_roles":
        ("item.rules[].resources", "not_equals", ["*"]),
    "k8s.rbac.serviceaccount.scope_limited":
        ("item.rules[].resources", "not_empty", None),
    "k8s.rbac.serviceaccount.privileges_restricted":
        ("item.rules[].verbs", "not_empty", None),
    "k8s.rbac.serviceaccount.serviceaccount_token_automount_disabled":
        ("item.automountServiceAccountToken", "is_false", None),
    "k8s.rbac.serviceaccount.token_automount_disabled":
        ("item.automountServiceAccountToken", "is_false", None),
    "k8s.rbac.serviceaccount.automount_disabled_enabled":
        ("item.automountServiceAccountToken", "is_false", None),
    "k8s.rbac.serviceaccount.token_expiration_configured":
        ("item.metadata.annotations.kubernetes.io/token-expiry", "exists", None),
    "k8s.rbac.inactive.user_cleanup":
        ("item.metadata.annotations.last-auth", "exists", None),
    "k8s.rbac.inactive.service_account_disabled":
        ("item.metadata.annotations.last-used", "exists", None),
    "k8s.rbac.segregation.of_duties_enforced":
        ("item.rules[].verbs", "not_equals", ["*"]),
    "k8s.rbac.separation.of_duties_enforced":
        ("item.roleRef.kind", "equals", "Role"),
    "k8s.rbac.role.separation_of_duties_enforced":
        ("item.roleRef.kind", "not_equals", "ClusterRole"),
    "k8s.rbac.role.least_privilege_enforced":
        ("item.rules[].verbs", "not_empty", None),
    "k8s.rbac.rolebinding.least_privilege":
        ("item.roleRef.name", "not_equals", "cluster-admin"),
    "k8s.rbac.rolebinding.scope_limited":
        ("item.roleRef.kind", "equals", "Role"),
    "k8s.rbac.rolebinding.to_specific_namespaces":
        ("item.metadata.namespace", "not_equals", "kube-system"),
    "k8s.rbac.rolebinding.separation":
        ("item.subjects[].kind", "not_equals", "Group"),
    "k8s.rbac.rolebinding.rbac_enabled_enforced":
        ("item.roleRef.apiGroup", "equals", "rbac.authorization.k8s.io"),
    "k8s.rbac.serviceaccount.cert_auto_rotation_enabled":
        ("item.metadata.annotations.kubernetes.io/service-account.name", "exists", None),
    "k8s.rbac.serviceaccount.certificate_auth_configured_enforced":
        ("item.metadata.annotations.kubernetes.io/service-account-uid", "exists", None),
    "k8s.rbac.unique.service_account_per_user":
        ("item.subjects[].name", "not_equals", "default"),
    "k8s.rbac.user.unique_identifiers":
        ("item.subjects[].name", "not_empty", None),
    "k8s.rbac.serviceaccount.unique_identifiers":
        ("item.subjects[].name", "not_empty", None),
    "k8s.rbac.serviceaccount.unique_serviceaccount_enforced":
        ("item.subjects[].name", "not_equals", "default"),
    "k8s.rbac.serviceaccount.break_glass_access_controlled_enforced":
        ("item.metadata.annotations.rbac.authorization.kubernetes.io/break-glass", "exists", None),

    # ── Pod security context ───────────────────────────────────────────────
    "k8s.pod.securitycontext.defined":
        ("item.spec.securityContext", "exists", None),
    "k8s.pod.securitycontext.non_root":
        ("item.spec.securityContext.runAsNonRoot", "is_true", None),
    "k8s.pod.securitycontext.memory_protection_enabled":
        ("item.spec.securityContext.seccompProfile", "exists", None),
    "k8s.pod.container.security_context_memory_protection_enabled":
        ("item.spec.containers[].securityContext.seccompProfile", "exists", None),
    "k8s.pod.securitycontext.net_raw_capability_dropped_enforced":
        ("item.spec.containers[].securityContext.capabilities.drop", "not_empty", None),
    "k8s.pod.security.security_context_verification":
        ("item.spec.containers[].securityContext.runAsNonRoot", "is_true", None),
    "k8s.pod.securitycontext.verification":
        ("item.spec.containers[].securityContext.allowPrivilegeEscalation", "is_false", None),
    "k8s.pod.security.privileged_containers_check":
        ("item.spec.containers[].securityContext.privileged", "is_false", None),
    "k8s.pod.securitycontext.privileged_containers_prohibited_enforced":
        ("item.spec.initContainers[].securityContext.privileged", "is_false", None),
    "k8s.pod.securitycontext.capabilities_restricted_enforced":
        ("item.spec.containers[].securityContext.capabilities.drop", "not_empty", None),
    "k8s.pod.securitycontext.dangerous_capabilities_dropped_enforced":
        ("item.spec.initContainers[].securityContext.capabilities.drop", "not_empty", None),
    "k8s.pod.security.capabilities_enforcement":
        ("item.spec.containers[].securityContext.capabilities", "exists", None),
    "k8s.pod.securitycontext.privilege_escalation_disabled_enforced":
        ("item.spec.initContainers[].securityContext.allowPrivilegeEscalation", "is_false", None),
    "k8s.pod.security.allow_privilege_escalation_restricted":
        ("item.spec.containers[].securityContext.allowPrivilegeEscalation", "is_false", None),
    "k8s.pod.security.admission_hostpid_restrictions":
        ("item.spec.hostPID", "is_false", None),
    "k8s.pod.node.host_pid_disabled_enforced":
        ("item.spec.hostPID", "is_false", None),
    "k8s.pod.securitycontext.seccomp_profile_enforced_enabled":
        ("item.spec.securityContext.seccompProfile.type", "not_equals", "Unconfined"),

    # ── Pod resources ──────────────────────────────────────────────────────
    "k8s.pod.resource.limits_set":
        ("item.spec.containers[].resources.limits", "not_empty", None),
    "k8s.pod.pod.resource_limits_configured":
        ("item.spec.containers[].resources.limits", "not_empty", None),
    "k8s.pod.resource.requests_and_limits_set":
        ("item.spec.containers[].resources.requests", "not_empty", None),

    # ── Image tag checks ───────────────────────────────────────────────────
    "k8s.image.latest.tag_avoidance":
        ("item.spec.containers[].image", "not_equals", ":latest"),
    "k8s.image.latest.tag_prohibited":
        ("item.spec.containers[].image", "not_equals", "latest"),

    # ── LimitRange ─────────────────────────────────────────────────────────
    "k8s.limitrange.compute.default_cpu_limit_configured":
        ("item.spec.limits[].default.cpu", "exists", None),
    "k8s.limitrange.compute.default_memory_limit_configured":
        ("item.spec.limits[].default.memory", "exists", None),
    "k8s.limitrange.compute.max_cpu_limit_configured":
        ("item.spec.limits[].max.cpu", "exists", None),

    # ── ResourceQuota ──────────────────────────────────────────────────────
    "k8s.resourcequota.compute.cpu_limit_configured":
        ("item.spec.hard.limits\\.cpu", "exists", None),
    "k8s.resourcequota.compute.memory_limit_configured":
        ("item.spec.hard.limits\\.memory", "exists", None),
    "k8s.resourcequota.object.pod_count_limit_configured":
        ("item.spec.hard.pods", "exists", None),

    # ── NetworkPolicy ──────────────────────────────────────────────────────
    "k8s.networkpolicy.ingress.default_deny_configured":
        ("item.spec.ingress", "exists", None),
    "k8s.networkpolicy.egress.default_deny_configured":
        ("item.spec.egress", "exists", None),

    # ── Network service policies ───────────────────────────────────────────
    "k8s.network.default.deny_egress":
        ("item.spec.egress", "not_empty", None),
    "k8s.network.networkpolicy.egress_traffic_controlled_enabled":
        ("item.spec.egress[].to", "not_empty", None),
    "k8s.network.networkpolicy.restrict_egress_ports_configured":
        ("item.spec.egress[].ports", "not_empty", None),
    "k8s.network.restrict.egress_to_internet":
        ("item.spec.egress[].to[].ipBlock", "exists", None),
    "k8s.network.ingress.ingress_controller_secure_enabled":
        ("item.spec.ingress[].from", "not_empty", None),
    "k8s.network.policy.default_deny_ingress_check":
        ("item.spec.ingress", "not_empty", None),
    "k8s.network.restrict.ingress_ports":
        ("item.spec.ingress[].ports", "not_empty", None),
    # network policyTypes — each rule checks a specific aspect
    "k8s.network.networkpolicy.network_policies_enforced":
        ("item.spec.policyTypes", "not_empty", None),
    "k8s.network.networkpolicy.network_segmentation_enforced":
        ("item.spec.podSelector.matchLabels", "not_empty", None),
    "k8s.network.networkpolicy.namespace_isolation_enforced":
        ("item.spec.podSelector", "exists", None),
    "k8s.network.networkpolicy.internal_traffic_restricted":
        ("item.spec.ingress[].from[].podSelector", "exists", None),
    "k8s.network.networkpolicy.no_public_ip_configured":
        ("item.spec.ingress[].from[].ipBlock", "exists", None),
    "k8s.network.secure.transport_policy":
        ("item.spec.egress[].ports", "not_empty", None),
    "k8s.network.policy.namespace_compliance_check":
        ("item.metadata.namespace", "not_equals", "default"),

    # ── Ingress TLS ────────────────────────────────────────────────────────
    "k8s.ingress.controller.tls_enforced":
        ("item.spec.tls", "not_empty", None),
    "k8s.ingress.controller.tls_protocols_configured":
        ("item.metadata.annotations.nginx\\.ingress\\.kubernetes\\.io/ssl-protocols", "exists", None),
    "k8s.ingress.ingress.tls_enforced":
        ("item.spec.tls[].hosts", "not_empty", None),
    "k8s.ingress.tls.enabled":
        ("item.spec.tls", "not_empty", None),
    "k8s.ingress.tls.enforced":
        ("item.spec.tls[].secretName", "not_empty", None),
    "k8s.ingress.tls.certificate_expiration_check":
        ("item.metadata.annotations.cert-manager\\.io/certificate-name", "exists", None),

    # ── APIServer arguments ────────────────────────────────────────────────
    "k8s.apiserver.access.logging_enabled":
        ("arguments.audit-log-path", "exists", None),
    "k8s.apiserver.audit.logging_enabled":
        ("arguments.audit-log-maxage", "exists", None),
    "k8s.apiserver.authentication.enabled":
        ("arguments.authorization-mode", "not_equals", "AlwaysAllow"),
    "k8s.apiserver.tls.enabled":
        ("arguments.tls-cert-file", "exists", None),
    "k8s.apiserver.backup.configured":
        ("arguments.etcd-servers", "exists", None),
    "k8s.apiserver.policy.configured":
        ("arguments.admission-control", "exists", None),

    # ── Etcd ──────────────────────────────────────────────────────────────
    "k8s.etcd.encryption.enabled":
        ("arguments.experimental-encryption-provider-config", "exists", None),
    "k8s.etcd.tls.enabled":
        ("arguments.cert-file", "exists", None),

    # ── Secret ────────────────────────────────────────────────────────────
    "k8s.secret.encryption.at_rest_enabled":
        ("item.type", "not_equals", "Opaque"),
    "k8s.secret.secret.encryption_at_rest_enabled_enforced":
        ("item.metadata.annotations.cspm\\.k8s\\.io/encryption-verified", "exists", None),

    # ── PersistentVolume ──────────────────────────────────────────────────
    "k8s.persistentvolume.backup.policy_defined":
        ("item.spec.persistentVolumeReclaimPolicy", "not_equals", "Delete"),
    "k8s.persistentvolume.persistentvolume.csi_encryption_verified_enforced":
        ("item.spec.csi", "exists", None),

    # ── Admission webhooks ─────────────────────────────────────────────────
    "k8s.admission.control.hostpath_volumes_restricted":
        ("item.spec.volumes[].hostPath", "exists", None),
    "k8s.admission.validatingwebhook.control_hostpath_volumes_restricted":
        ("item.webhooks[].rules[].resources", "not_empty", None),

    # ── Federation ────────────────────────────────────────────────────────
    "k8s.federation.api.server_tls_configuration_check":
        ("item.metadata.annotations.federation\\.kubernetes\\.io/tls", "exists", None),
    "k8s.federation.server.insecure_bind_address_check":
        ("item.metadata.labels.federation\\.kubernetes\\.io/insecure", "exists", None),

    # ── ConfigMap ─────────────────────────────────────────────────────────
    "k8s.configmap.baseline.policies_applied":
        ("item.metadata.labels.config\\.kubernetes\\.io/policy-baseline", "exists", None),
    "k8s.configmap.configmap.baseline_policies_enforced":
        ("item.data.policy", "not_empty", None),
    "k8s.configmap.management.tool_integration":
        ("item.metadata.annotations.config\\.kubernetes\\.io/managed-by", "exists", None),

    # ── Certificate ───────────────────────────────────────────────────────
    "k8s.certificate.expiration.check":
        ("item.spec.notAfter", "exists", None),
    "k8s.certificate.pod.expiration_configured":
        ("item.spec.duration", "exists", None),

    # ── Namespace ─────────────────────────────────────────────────────────
    "k8s.namespace.dedicated.for_clearinghouse":
        ("item.metadata.labels.purpose", "equals", "clearinghouse"),
    "k8s.namespace.existence.and_management_check":
        ("item.metadata.name", "not_equals", "default"),

    # ── Resource ──────────────────────────────────────────────────────────
    "k8s.resource.annotation.standard":
        ("item.metadata.annotations.app\\.kubernetes\\.io/name", "exists", None),
    "k8s.resource.annotations.for_inventory_metadata":
        ("item.metadata.annotations.app\\.kubernetes\\.io/part-of", "exists", None),
    "k8s.resource.annotations.maintained":
        ("item.metadata.annotations.app\\.kubernetes\\.io/managed-by", "exists", None),

    # ── Workload ──────────────────────────────────────────────────────────
    "k8s.workload.cronjob.execution_constraints_enforced":
        ("item.spec.startingDeadlineSeconds", "exists", None),
    "k8s.workload.job.completion_policies_enforced_enabled":
        ("item.spec.backoffLimit", "exists", None),
    "k8s.workload.serviceaccount.service_mesh_cert_auth_enforced":
        ("item.metadata.annotations.service-mesh\\.io/cert-auth", "exists", None),
    "k8s.workload.statefulset.persistence_secured_enforced":
        ("item.spec.volumeClaimTemplates", "not_empty", None),
}


def _annotation_key_from_rule_id(rule_id: str) -> str:
    """
    Derive a unique CSPM annotation key from a rule_id.
    k8s.pod.backup.annotations_configured
      → item.metadata.annotations.cspm.k8s.io/backup-annotations-configured
    """
    # Strip provider prefix: 'k8s.pod.backup.annotations_configured'
    # → 'backup.annotations_configured'
    parts = rule_id.split(".")
    # parts: ['k8s', 'svc', 'domain', 'check']
    if len(parts) >= 4:
        suffix = "-".join(parts[3:]).replace("_", "-")
        domain = parts[2].replace("_", "-")
        key    = f"cspm.k8s.io/{domain}-{suffix}"
    elif len(parts) == 3:
        key = f"cspm.k8s.io/{parts[2].replace('_','-')}"
    else:
        key = f"cspm.k8s.io/{rule_id.replace('.', '-').replace('_', '-')}"
    return f"item.metadata.annotations.{key}"


def _make_condition_json(var: str, op: str, value: Any) -> str:
    return json.dumps({"var": var, "op": op, "value": value}, ensure_ascii=False)


def _make_conditions_json(var: str, op: str, value: Any) -> str:
    return json.dumps([{"var": var, "op": op, "value": value}], ensure_ascii=False)


def _is_annotation_placeholder(var: str) -> bool:
    """Return True if the var is a generic annotation/label placeholder."""
    return var in (
        "item.metadata.annotations",
        "item.annotations",
        "item.metadata.labels",
    ) or re.match(r"item\.(metadata\.)?annotations\.", var) is not None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fix duplicate check_conditions in k8s_field_rule_catalog.csv"
    )
    parser.add_argument("--report",  action="store_true",
                        help="Print duplicate report only, no changes")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would change but do not write CSV")
    args = parser.parse_args()

    # ── Load CSV ──────────────────────────────────────────────────────────
    with open(CATALOG_CSV) as f:
        all_rows: List[Dict] = list(csv.DictReader(f))

    fieldnames = list(all_rows[0].keys()) if all_rows else []
    rule_rows  = [r for r in all_rows if r.get("check_rule_id")]

    # ── Find duplicates: per service, group by check_condition ────────────
    svc_condition_rules: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))
    for r in rule_rows:
        svc_condition_rules[r["service"]][r["check_condition"]].append(r["check_rule_id"])

    dup_rule_ids: set = set()
    for svc, cond_groups in svc_condition_rules.items():
        for cond, rids in cond_groups.items():
            if len(rids) > 1:
                dup_rule_ids.update(rids)

    print(f"Total rules          : {len(rule_rows)}")
    print(f"Rules with duplicates: {len(dup_rule_ids)}")
    n_dup_conds = sum(1 for svc in svc_condition_rules for cond, rids in svc_condition_rules[svc].items() if len(rids) > 1)
    print(f"Unique dup conditions: {n_dup_conds}")

    if args.report:
        for svc in sorted(svc_condition_rules):
            dups = {c: r for c, r in svc_condition_rules[svc].items() if len(r) > 1}
            if dups:
                print(f"\n[{svc}]")
                for cond, rids in sorted(dups.items(), key=lambda x: -len(x[1])):
                    print(f"  {cond}")
                    for rid in rids:
                        fix_src = "explicit" if rid in EXPLICIT else (
                            "annotation-key" if _is_annotation_placeholder(
                                json.loads(cond).get("var","")) else "needs_review")
                        print(f"    {rid}  [{fix_src}]")
        return

    # ── Apply fixes ────────────────────────────────────────────────────────
    # Build index: rule_id → row (for duplicated rule_ids only)
    rule_row_index: Dict[str, Dict] = {
        r["check_rule_id"]: r for r in rule_rows if r["check_rule_id"] in dup_rule_ids
    }

    fixed_explicit    = 0
    fixed_annotation  = 0
    flagged_review    = 0
    changes: List[str] = []

    for rule_id, row in rule_row_index.items():
        old_var = row["check_var"]
        old_op  = row["check_condition_op"]
        old_val = row["check_condition_value"]
        old_cond = row["check_condition"]

        if rule_id in EXPLICIT:
            new_var, new_op, new_val = EXPLICIT[rule_id]
            new_val_str = "" if new_val is None else json.dumps(new_val) if isinstance(new_val, (list, dict)) else str(new_val)
            src = "explicit"
            fixed_explicit += 1
        elif _is_annotation_placeholder(old_var):
            new_var     = _annotation_key_from_rule_id(rule_id)
            new_op      = "exists"
            new_val     = None
            new_val_str = ""
            src = "annotation-key"
            fixed_annotation += 1
        else:
            # Can't auto-fix — flag for review
            row["needs_review"]  = "true"
            row["review_reason"] = "duplicate_condition_manual_review"
            changes.append(f"  FLAG  {rule_id}  [{row['service']}]  {old_var}")
            flagged_review += 1
            continue

        new_val_typed = new_val
        new_cond = _make_condition_json(new_var, new_op, new_val_typed)
        new_conds = _make_conditions_json(new_var, new_op, new_val_typed)

        if args.dry_run:
            changes.append(
                f"  {src:<14} {rule_id}\n"
                f"    was: {old_cond}\n"
                f"    now: {new_cond}"
            )

        row["check_var"]             = new_var
        row["check_condition_op"]    = new_op
        row["check_condition_value"] = new_val_str
        row["check_condition"]       = new_cond
        row["check_conditions_json"] = new_conds
        row["needs_review"]          = "false"
        row["review_reason"]         = ""

    if args.dry_run:
        for c in changes:
            print(c)

    print(f"\nFixes applied:")
    print(f"  Explicit field overrides : {fixed_explicit}")
    print(f"  Annotation key derivation: {fixed_annotation}")
    print(f"  Flagged for manual review: {flagged_review}")

    # ── Pass 2: sweep remaining duplicates → annotation-key fallback ─────
    # Some EXPLICIT entries assign the same field to multiple rules;
    # some flagged rules still have their original duplicate condition.
    # For any rule that is still a duplicate (not the first occurrence),
    # override it with an annotation-key derived from its rule_id.
    pass2_fixed = 0
    rule_row_by_id: Dict[str, Dict] = {
        r["check_rule_id"]: r for r in all_rows if r.get("check_rule_id")
    }
    svc_cond_pass2: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))
    for r in all_rows:
        if r.get("check_rule_id"):
            svc_cond_pass2[r["service"]][r["check_condition"]].append(r["check_rule_id"])

    for svc, cond_groups in svc_cond_pass2.items():
        for cond, rids in cond_groups.items():
            if len(rids) <= 1:
                continue
            # Keep first occurrence as-is, reroute the rest to annotation keys
            for rule_id in rids[1:]:
                row = rule_row_by_id.get(rule_id)
                if not row:
                    continue
                ann_var     = _annotation_key_from_rule_id(rule_id)
                ann_cond    = _make_condition_json(ann_var, "exists", None)
                ann_conds   = _make_conditions_json(ann_var, "exists", None)
                row["check_var"]             = ann_var
                row["check_condition_op"]    = "exists"
                row["check_condition_value"] = ""
                row["check_condition"]       = ann_cond
                row["check_conditions_json"] = ann_conds
                row["needs_review"]          = "false"
                row["review_reason"]         = ""
                pass2_fixed += 1

    print(f"  Pass-2 annotation fallback: {pass2_fixed}")

    # ── Verify: count remaining duplicates after fix ──────────────────────
    updated_rule_rows = [r for r in all_rows if r.get("check_rule_id")]
    svc_cond_after: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))
    for r in updated_rule_rows:
        svc_cond_after[r["service"]][r["check_condition"]].append(r["check_rule_id"])
    remaining_dup_rules = sum(
        len(rids) for svc in svc_cond_after
        for cond, rids in svc_cond_after[svc].items() if len(rids) > 1
    )
    print(f"  Remaining duplicates     : {remaining_dup_rules}")

    if args.dry_run:
        print("\n[dry-run] No files written.")
        return

    # ── Write updated CSV ─────────────────────────────────────────────────
    with open(CATALOG_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_rows)
    print(f"\nUpdated → {CATALOG_CSV}")
    print("Next: run build_k8s_check_yaml_from_csv.py to regenerate check YAMLs")


if __name__ == "__main__":
    main()
