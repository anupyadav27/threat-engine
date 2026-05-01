"""
Kubernetes IAM Provider

Reads K8s RBAC data from discovery_findings to surface:
  - ClusterRoleBindings that grant cluster-admin
  - Wildcard permissions in ClusterRoles/Roles (verbs/resources = *)
  - Default service account usage with non-trivial permissions
  - Broad role bindings at cluster scope

Queries discovery_findings for service='rbac' and provider in ('k8s', 'kubernetes').
"""

import logging
from typing import Any, Dict, List

from .base import BaseIAMProvider, empty_result

logger = logging.getLogger(__name__)

_CLUSTER_ADMIN_ROLE = "cluster-admin"


class K8sIAMProvider(BaseIAMProvider):
    """Kubernetes RBAC analysis provider."""

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
    ) -> Dict[str, Any]:
        """Analyze Kubernetes RBAC posture from discovery findings.

        Queries:
          - discovery_findings WHERE provider IN ('k8s', 'kubernetes')
            AND service = 'rbac'

        Args:
            scan_run_id: Pipeline scan run ID
            tenant_id: Tenant identifier
            account_id: K8s cluster identifier

        Returns:
            Standardized result dict with K8s RBAC findings.
        """
        result = empty_result()

        try:
            from psycopg2.extras import RealDictCursor
            from engine_common.db_connections import get_discovery_conn
        except ImportError as e:
            logger.warning(f"K8s IAM provider: missing dependency ({e}) — returning empty results")
            return result

        policy_findings: List[Dict[str, Any]] = []

        try:
            disc_conn = get_discovery_conn()
            with disc_conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT resource_uid, resource_type, emitted_fields, account_id, region
                    FROM discovery_findings
                    WHERE scan_run_id = %s
                      AND tenant_id = %s
                      AND provider IN ('k8s', 'kubernetes')
                      AND service = 'rbac'
                    ORDER BY resource_type, resource_uid
                    """,
                    (scan_run_id, tenant_id),
                )
                rbac_rows = cur.fetchall()
            disc_conn.close()

            for row in rbac_rows:
                fields = row.get("emitted_fields") or {}
                resource_uid = row.get("resource_uid", "")
                resource_type = row.get("resource_type", "")

                # ClusterRoleBinding → cluster-admin
                if "clusterrolebinding" in resource_type.lower():
                    role_ref = fields.get("roleRef") or {}
                    role_name = role_ref.get("name", "")
                    subjects = fields.get("subjects") or []

                    if role_name == _CLUSTER_ADMIN_ROLE:
                        for subject in subjects:
                            if not isinstance(subject, dict):
                                continue
                            subject_name = subject.get("name", "")
                            subject_kind = subject.get("kind", "")
                            policy_findings.append({
                                "finding_id": f"k8s_cadmin_{resource_uid[-12:] if resource_uid else 'unknown'}_{subject_name[:8]}",
                                "rule_id": "k8s.rbac.cluster_admin_binding",
                                "severity": "critical",
                                "status": "FAIL",
                                "title": f"K8s cluster-admin bound to {subject_kind}/{subject_name}",
                                "resource_uid": resource_uid,
                                "resource_type": resource_type,
                                "account_id": row.get("account_id", account_id),
                                "region": row.get("region", "global"),
                                "provider": "k8s",
                                "finding_data": {
                                    "module": "k8s_rbac_analysis",
                                    "role_name": role_name,
                                    "subject_kind": subject_kind,
                                    "subject_name": subject_name,
                                    "subject_namespace": subject.get("namespace", ""),
                                    "remediation": (
                                        "Remove cluster-admin ClusterRoleBinding and replace "
                                        "with least-privilege ClusterRole or namespace-scoped Role."
                                    ),
                                },
                            })

                    # Default service account bindings
                    for subject in subjects:
                        if isinstance(subject, dict) and subject.get("name") == "default" and subject.get("kind") == "ServiceAccount":
                            policy_findings.append({
                                "finding_id": f"k8s_defsa_{resource_uid[-12:] if resource_uid else 'unknown'}",
                                "rule_id": "k8s.rbac.default_service_account_binding",
                                "severity": "high",
                                "status": "FAIL",
                                "title": f"K8s default service account has ClusterRole '{role_name}'",
                                "resource_uid": resource_uid,
                                "resource_type": resource_type,
                                "account_id": row.get("account_id", account_id),
                                "region": row.get("region", "global"),
                                "provider": "k8s",
                                "finding_data": {
                                    "module": "k8s_rbac_analysis",
                                    "role_name": role_name,
                                    "namespace": subject.get("namespace", "default"),
                                    "remediation": (
                                        "Avoid binding roles to the default service account. "
                                        "Create dedicated service accounts with minimal permissions."
                                    ),
                                },
                            })

                # ClusterRole / Role — wildcard rules
                if "clusterrole" in resource_type.lower() or resource_type.lower() == "k8s.rbac.role":
                    rules = fields.get("rules") or []
                    has_wildcard = False
                    for rule in rules:
                        if not isinstance(rule, dict):
                            continue
                        verbs = rule.get("verbs") or []
                        resources = rule.get("resources") or []
                        if "*" in verbs and "*" in resources:
                            has_wildcard = True
                            break

                    if has_wildcard:
                        role_name = fields.get("metadata", {}).get("name", resource_uid)
                        policy_findings.append({
                            "finding_id": f"k8s_wildcard_{resource_uid[-12:] if resource_uid else 'unknown'}",
                            "rule_id": "k8s.rbac.wildcard_permissions",
                            "severity": "high",
                            "status": "FAIL",
                            "title": f"K8s role '{role_name}' has wildcard verbs and resources",
                            "resource_uid": resource_uid,
                            "resource_type": resource_type,
                            "account_id": row.get("account_id", account_id),
                            "region": row.get("region", "global"),
                            "provider": "k8s",
                            "finding_data": {
                                "module": "k8s_rbac_analysis",
                                "role_name": role_name,
                                "remediation": (
                                    "Replace wildcard verbs (*) and resources (*) with "
                                    "specific permissions following least-privilege."
                                ),
                            },
                        })

            logger.info(
                f"K8s IAM provider: {len(rbac_rows)} RBAC resources, "
                f"{len(policy_findings)} findings"
            )

        except Exception as e:
            logger.warning(f"K8s IAM discovery query failed (non-fatal): {e}")

        result["policy_findings"] = policy_findings
        return result
