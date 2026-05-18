"""
Kubernetes (native) Container Security provider — Pattern A analyze() for
Pod securityContext, RBAC over-permission, network policy gaps, and namespace
isolation checks from discovery_findings.emitted_fields.
"""
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .base import BaseContainerSecurityProvider

logger = logging.getLogger(__name__)


def _fid(rule_id: str, resource_uid: str, scan_run_id: str) -> str:
    raw = f"{rule_id}|{resource_uid}|{scan_run_id}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _finding(rule_id: str, domain: str, resource_uid: str, resource_type: str,
             account_id: str, region: str, severity: str, title: str,
             remediation: str, scan_run_id: str, tenant_id: str) -> Dict[str, Any]:
    return {
        "finding_id": _fid(rule_id, resource_uid, scan_run_id),
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        "account_id": account_id,
        "provider": "k8s",
        "region": region,
        "resource_uid": resource_uid,
        "resource_type": resource_type,
        "severity": severity.upper(),
        "status": "FAIL",
        "security_domain": domain,
        "container_service": "k8s",
        "cluster_name": "",
        "rule_id": rule_id,
        "title": title,
        "description": title,
        "remediation": remediation,
        "finding_data": {},
        "first_seen_at": datetime.now(timezone.utc),
        "last_seen_at": datetime.now(timezone.utc),
    }


class K8sContainerSecurityProvider(BaseContainerSecurityProvider):
    """Kubernetes native container security provider with Pattern A analysis."""

    @property
    def discovery_services(self) -> List[str]:
        return [
            "pods", "deployments", "daemonsets", "statefulsets",
            "replicasets", "jobs", "cronjobs", "namespaces",
            "serviceaccounts", "roles", "rolebindings",
            "clusterroles", "clusterrolebindings",
            "networkpolicies", "podsecuritypolicies",
            "services", "ingresses",
        ]

    @property
    def inventory_resource_prefixes(self) -> List[str]:
        return ["pod.", "deployment.", "daemonset.", "statefulset.", "namespace.", "serviceaccount."]

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        discoveries_conn: Any,
        check_conn: Optional[Any] = None,
    ) -> Optional[List[Dict[str, Any]]]:
        findings: List[Dict[str, Any]] = []

        try:
            from psycopg2.extras import RealDictCursor
            with discoveries_conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT resource_uid, resource_type, emitted_fields, account_id, region
                    FROM discovery_findings
                    WHERE scan_run_id = %s
                      AND tenant_id = %s
                      AND provider = 'k8s'
                      AND service IN ('pods', 'deployments', 'daemonsets', 'statefulsets',
                                      'namespaces', 'serviceaccounts', 'clusterroles',
                                      'clusterrolebindings', 'networkpolicies')
                    ORDER BY resource_uid
                    """,
                    (scan_run_id, tenant_id),
                )
                rows = cur.fetchall()
        except Exception as exc:
            logger.error("K8s container analyze(): discovery query failed: %s", exc)
            return None

        namespaces_with_netpol: set = set()

        # First pass: collect namespaces that have NetworkPolicies
        for row in rows:
            if "networkpolic" in (row.get("resource_type") or "").lower():
                ns = (row.get("emitted_fields") or {}).get("namespace") or ""
                if ns:
                    namespaces_with_netpol.add(ns)

        for row in rows:
            fields = row.get("emitted_fields") or {}
            uid = row.get("resource_uid", "")
            rtype = (row.get("resource_type") or "").lower()
            region = row.get("region") or "global"
            acct = row.get("account_id") or account_id or ""

            # ── Module 1: Pod securityContext ──
            if "pod" in rtype or "deployment" in rtype or "daemonset" in rtype or "statefulset" in rtype:
                spec = fields.get("spec") or {}
                containers = spec.get("containers") or []
                if not containers:
                    # Try nested template spec (Deployment/DaemonSet/StatefulSet)
                    containers = (spec.get("template") or {}).get("spec", {}).get("containers") or []

                for container in containers:
                    if not isinstance(container, dict):
                        continue
                    sc = container.get("securityContext") or {}
                    c_uid = f"{uid}/{container.get('name', 'unknown')}"

                    # privileged container
                    if sc.get("privileged") is True:
                        findings.append(_finding(
                            "k8s.pod.container.not_privileged", "pod_security",
                            c_uid, "k8s.pod.container", acct, region, "CRITICAL",
                            f"Container '{container.get('name')}' runs as privileged",
                            "Set securityContext.privileged=false on all containers.",
                            scan_run_id, tenant_id,
                        ))

                    # allowPrivilegeEscalation
                    if sc.get("allowPrivilegeEscalation") is True or "allowPrivilegeEscalation" not in sc:
                        findings.append(_finding(
                            "k8s.pod.container.no_allow_privilege_escalation", "pod_security",
                            c_uid, "k8s.pod.container", acct, region, "HIGH",
                            f"Container '{container.get('name')}' allows privilege escalation",
                            "Set securityContext.allowPrivilegeEscalation=false.",
                            scan_run_id, tenant_id,
                        ))

                    # readOnlyRootFilesystem
                    if not sc.get("readOnlyRootFilesystem"):
                        findings.append(_finding(
                            "k8s.pod.container.read_only_root_filesystem", "pod_security",
                            c_uid, "k8s.pod.container", acct, region, "HIGH",
                            f"Container '{container.get('name')}' does not use read-only root filesystem",
                            "Set securityContext.readOnlyRootFilesystem=true.",
                            scan_run_id, tenant_id,
                        ))

                    # runAsNonRoot
                    run_as_user = sc.get("runAsUser")
                    run_as_non_root = sc.get("runAsNonRoot")
                    if not run_as_non_root and (run_as_user is None or run_as_user == 0):
                        findings.append(_finding(
                            "k8s.pod.container.run_as_non_root", "pod_security",
                            c_uid, "k8s.pod.container", acct, region, "HIGH",
                            f"Container '{container.get('name')}' may run as root",
                            "Set securityContext.runAsNonRoot=true or runAsUser > 0.",
                            scan_run_id, tenant_id,
                        ))

            # ── Module 2: RBAC wildcard ClusterRole ──
            elif "clusterrole" in rtype and "binding" not in rtype:
                rules = fields.get("rules") or []
                for rule in rules:
                    if not isinstance(rule, dict):
                        continue
                    verbs = rule.get("verbs") or []
                    resources = rule.get("resources") or []
                    if "*" in verbs and "*" in resources:
                        findings.append(_finding(
                            "k8s.rbac.clusterrole.wildcard_verb_resource", "rbac_security",
                            uid, "k8s.ClusterRole", acct, region, "CRITICAL",
                            "K8s ClusterRole grants wildcard verbs on wildcard resources",
                            "Remove wildcard (*) verb+resource grants from ClusterRole.",
                            scan_run_id, tenant_id,
                        ))
                        break

            # ── Module 3: ServiceAccount with automountServiceAccountToken ──
            elif "serviceaccount" in rtype:
                auto_mount = fields.get("automountServiceAccountToken")
                if auto_mount is True or auto_mount is None:
                    findings.append(_finding(
                        "k8s.serviceaccount.automount_token_disabled", "rbac_security",
                        uid, "k8s.ServiceAccount", acct, region, "MEDIUM",
                        "K8s ServiceAccount has automountServiceAccountToken enabled or unset",
                        "Set automountServiceAccountToken=false on ServiceAccounts not needing API access.",
                        scan_run_id, tenant_id,
                    ))

            # ── Module 4: Namespace without NetworkPolicy ──
            elif "namespace" in rtype:
                ns_name = fields.get("name") or (uid.split("/")[-1] if "/" in uid else uid)
                if ns_name not in namespaces_with_netpol and ns_name not in ("kube-system", "kube-public"):
                    findings.append(_finding(
                        "k8s.namespace.network_policy_missing", "network_security",
                        uid, "k8s.Namespace", acct, region, "HIGH",
                        f"K8s namespace '{ns_name}' has no NetworkPolicy — all pod-to-pod traffic allowed",
                        "Create a default-deny NetworkPolicy in every application namespace.",
                        scan_run_id, tenant_id,
                    ))

        logger.info(
            "K8s container analyze(): %d findings for scan=%s account=%s",
            len(findings), scan_run_id, account_id,
        )
        return findings if findings else None
