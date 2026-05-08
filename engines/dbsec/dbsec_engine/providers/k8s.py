"""K8s DBSec provider — DB workload analysis via Pods, Services, Deployments, StatefulSets.

Current K8s discovery catalog includes:
  - k8s.core/Pod               (running containers — includes DB sidecars)
  - k8s.core/Service           (network endpoints — LoadBalancer = public exposure)
  - k8s.apps/Deployment        (stateless workloads that may include DB containers)
  - k8s.apps/StatefulSet       (stateful workloads — primary DB pattern)
  - k8s.core/Secret            (credential storage)
  - k8s.rbac/ClusterRole       (privilege — authentication posture)

All resource types are filtered to DB workloads via label/name detection.
"""

import logging
from typing import Any, Dict, List

from dbsec_engine.providers.base import BaseDBSecProvider

logger = logging.getLogger(__name__)

K8S_DB_RESOURCE_TYPES = [
    # Namespaced resource types (actual discovery format)
    "k8s.apps/StatefulSet",
    "k8s.apps/Deployment",
    "k8s.core/Pod",
    "k8s.core/Service",
    "k8s.core/Secret",
    "k8s.rbac/ClusterRole",
    # Legacy/alternate formats
    "StatefulSet",
    "stateful_set",
    "apps_statefulset",
    "Pod",
    "pod",
    "Deployment",
    "deployment",
    "Service",
    "service",
]

# Labels and name fragments that identify DB workloads
DB_APP_LABELS = {
    "mysql", "postgres", "postgresql", "redis", "mongodb", "mongo",
    "elasticsearch", "elastic", "cassandra", "mariadb", "memcached",
    "minio", "kafka", "zookeeper", "etcd", "influxdb", "clickhouse",
}

# Secret name patterns that suggest DB credentials
DB_SECRET_PATTERNS = {
    "mysql", "postgres", "redis", "mongodb", "elastic", "db-password",
    "database", "db-secret", "db-credentials",
}

PILLAR_NETWORK = "network_exposure"
PILLAR_ENCRYPT = "encryption"
PILLAR_AUTH = "authentication"
PILLAR_AUDIT = "audit_activity"
PILLAR_COMPLIANCE = "compliance_posture"


def _is_db_workload(ef: Dict[str, Any], resource_uid: str = "") -> bool:
    """Return True if the resource is a DB workload (by labels or name)."""
    metadata = ef.get("metadata", {}) or {}
    labels = metadata.get("labels", {}) or {}
    name = metadata.get("name", resource_uid or "").lower()

    app_name = labels.get("app", labels.get("app.kubernetes.io/name", "")).lower()
    component = labels.get("component", "").lower()

    # Match against known DB label values or resource name fragments
    return (
        any(db in app_name for db in DB_APP_LABELS)
        or any(db in component for db in DB_APP_LABELS)
        or any(db in name for db in DB_APP_LABELS)
    )


def _is_db_secret(ef: Dict[str, Any], resource_uid: str = "") -> bool:
    """Return True if this Secret appears to store DB credentials."""
    metadata = ef.get("metadata", {}) or {}
    name = metadata.get("name", resource_uid or "").lower()
    return any(pattern in name for pattern in DB_SECRET_PATTERNS)


class K8sDBSecProvider(BaseDBSecProvider):
    """Kubernetes database workload security checks.

    Scans Pods, Services, Deployments, StatefulSets with DB-related labels,
    and Secrets with DB credential naming patterns.
    """

    @property
    def db_resource_types(self) -> List[str]:
        return K8S_DB_RESOURCE_TYPES

    @property
    def provider_name(self) -> str:
        return "k8s"

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        discoveries_conn: Any,
        check_conn: Any,  # noqa: ARG002 — unused by K8s provider; kept for ABC contract
    ) -> List[Dict[str, Any]]:
        """Override analyze to filter K8s resources to DB workloads and credential secrets."""
        _ = check_conn  # not used by K8s provider; present for interface contract
        resources = self._load_db_resources(scan_run_id, tenant_id, discoveries_conn)

        db_resources: List[Dict[str, Any]] = []
        for r in resources:
            rtype = r["resource_type"]
            ef = r["emitted_fields"]
            uid = r["resource_uid"]

            if rtype in ("k8s.core/Secret", "Secret", "secret"):
                if _is_db_secret(ef, uid):
                    db_resources.append(r)
            elif _is_db_workload(ef, uid):
                db_resources.append(r)

        # Fallback: if no label-matched results, include all StatefulSets
        if not db_resources:
            statefulset_types = {
                "k8s.apps/StatefulSet", "StatefulSet", "stateful_set", "apps_statefulset"
            }
            db_resources = [r for r in resources if r["resource_type"] in statefulset_types]

        # Second fallback: if still empty, include all Services and Pods
        if not db_resources:
            fallback_types = {"k8s.core/Service", "k8s.core/Pod", "Service", "Pod"}
            db_resources = [r for r in resources if r["resource_type"] in fallback_types][:20]

        logger.info(
            "DBSec[k8s] scan_run_id=%s: %d total resources, %d DB workloads selected",
            scan_run_id, len(resources), len(db_resources),
        )

        findings: List[Dict[str, Any]] = []
        for resource in db_resources:
            for pillar_fn, name in [
                (self._check_pillar_1_exposure, "Pillar1"),
                (self._check_pillar_2_encryption, "Pillar2"),
                (self._check_pillar_3_authentication, "Pillar3"),
                (self._check_pillar_4_audit, "Pillar4"),
                (self._check_pillar_5_compliance, "Pillar5"),
            ]:
                try:
                    findings.extend(pillar_fn(resource, tenant_id, account_id, scan_run_id))
                except Exception as exc:
                    logger.warning("K8s %s error resource=%s: %s", name, resource.get("resource_uid"), exc)

        return findings

    def _check_pillar_1_exposure(
        self, resource: Dict[str, Any], tenant_id: str, account_id: str, scan_run_id: str
    ) -> List[Dict[str, Any]]:
        ef = resource["emitted_fields"]
        rtype = resource["resource_type"]
        slug = self._slug(rtype)
        rule_id = f"k8s.dbsec.{PILLAR_NETWORK}.{slug}"

        metadata = ef.get("metadata", {}) or {}
        namespace = metadata.get("namespace", "")

        if rtype in ("k8s.core/Service", "Service", "service"):
            spec = ef.get("spec", {}) or {}
            svc_type = spec.get("type", "ClusterIP")
            is_lb = str(svc_type) == "LoadBalancer"
            # Check ports for DB port exposure
            ports = spec.get("ports", []) or []
            db_ports = {3306, 5432, 1433, 27017, 6379, 9200, 9042}
            exposed_db_ports = [p.get("port") for p in ports if isinstance(p, dict) and p.get("port") in db_ports]

            status = "FAIL" if is_lb else "PASS"
            severity = "HIGH" if is_lb else "INFO"
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_NETWORK, severity, status,
                    {
                        "check": "service_exposure",
                        "service_type": svc_type,
                        "internet_exposed": is_lb,
                        "exposed_db_ports": exposed_db_ports,
                        "namespace": namespace,
                    },
                )
            ]

        if rtype in ("k8s.core/Secret", "Secret", "secret"):
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_NETWORK, "INFO", "PASS",
                    {"check": "secret_not_exposed", "note": "K8s Secrets are not network-exposed resources",
                     "namespace": namespace},
                )
            ]

        # Pod/Deployment/StatefulSet: check for hostNetwork
        spec_raw = ef.get("spec", {}) or {}
        template_spec = spec_raw.get("template", {}).get("spec", {}) if isinstance(spec_raw, dict) else {}
        pod_spec = template_spec if template_spec else spec_raw
        host_network = pod_spec.get("hostNetwork", False)
        host_port_exposed = any(
            p.get("hostPort") and p.get("containerPort") in {3306, 5432, 1433, 27017, 6379}
            for c in (pod_spec.get("containers", []) or [])
            for p in (c.get("ports", []) or [])
            if isinstance(p, dict)
        )

        is_exposed = bool(host_network) or host_port_exposed
        status = "FAIL" if is_exposed else "PASS"
        severity = "HIGH" if is_exposed else "INFO"

        return [
            self._make_finding(
                scan_run_id, tenant_id, account_id, resource, rule_id,
                PILLAR_NETWORK, severity, status,
                {
                    "check": "host_network_exposure",
                    "host_network": bool(host_network),
                    "host_port_exposed": host_port_exposed,
                    "namespace": namespace,
                },
            )
        ]

    def _check_pillar_2_encryption(
        self, resource: Dict[str, Any], tenant_id: str, account_id: str, scan_run_id: str
    ) -> List[Dict[str, Any]]:
        ef = resource["emitted_fields"]
        rtype = resource["resource_type"]
        slug = self._slug(rtype)
        rule_id = f"k8s.dbsec.{PILLAR_ENCRYPT}.{slug}"

        metadata = ef.get("metadata", {}) or {}

        if rtype in ("k8s.core/Secret", "Secret", "secret"):
            # Check if secret type is Opaque (custom) vs kubernetes.io/tls
            secret_type = ef.get("type", "Opaque")
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_ENCRYPT, "INFO", "PASS",
                    {
                        "check": "secret_type",
                        "secret_type": secret_type,
                        "note": "K8s Secrets are base64-encoded but stored encrypted at rest if etcd encryption is enabled",
                    },
                )
            ]

        spec_raw = ef.get("spec", {}) or {}
        template_spec = spec_raw.get("template", {}).get("spec", {}) if isinstance(spec_raw, dict) else {}
        pod_spec = template_spec if template_spec else spec_raw
        containers = pod_spec.get("containers", []) or []

        # Check volumeClaimTemplates (StatefulSet) for persistent storage
        volume_claims = spec_raw.get("volumeClaimTemplates", []) or []
        has_pvc = bool(volume_claims)

        # Check for TLS env vars
        env_vars = []
        for c in containers:
            env_vars.extend(c.get("env", []) or [])
        has_tls_config = any(
            "tls" in (e.get("name", "") or "").lower() or "ssl" in (e.get("name", "") or "").lower()
            for e in env_vars
        )

        return [
            self._make_finding(
                scan_run_id, tenant_id, account_id, resource, rule_id,
                PILLAR_ENCRYPT, "MEDIUM" if not has_pvc else "INFO",
                "FAIL" if not has_pvc else "PASS",
                {
                    "check": "persistent_storage",
                    "has_persistent_volume_claims": has_pvc,
                    "tls_env_configured": has_tls_config,
                    "pvc_count": len(volume_claims),
                    "namespace": metadata.get("namespace", ""),
                },
            )
        ]

    def _check_pillar_3_authentication(
        self, resource: Dict[str, Any], tenant_id: str, account_id: str, scan_run_id: str
    ) -> List[Dict[str, Any]]:
        ef = resource["emitted_fields"]
        rtype = resource["resource_type"]
        slug = self._slug(rtype)
        rule_id = f"k8s.dbsec.{PILLAR_AUTH}.{slug}"

        metadata = ef.get("metadata", {}) or {}

        if rtype in ("k8s.core/Secret", "Secret", "secret"):
            # Check if secret has any data (non-empty credential)
            data = ef.get("data", {}) or {}
            has_password_key = any(
                "password" in k.lower() or "pass" in k.lower() or "secret" in k.lower()
                for k in data
            )
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_AUTH, "INFO", "PASS",
                    {
                        "check": "secret_credential_storage",
                        "has_password_key": has_password_key,
                        "note": "DB credentials stored in K8s Secret (recommended over plaintext env vars)",
                    },
                )
            ]

        spec_raw = ef.get("spec", {}) or {}
        template_spec = spec_raw.get("template", {}).get("spec", {}) if isinstance(spec_raw, dict) else {}
        pod_spec = template_spec if template_spec else spec_raw
        containers = pod_spec.get("containers", []) or []

        # Check for plain-text passwords in env vars (should use secretKeyRef instead)
        plain_password = False
        has_secret_ref = False
        for c in containers:
            for env in c.get("env", []) or []:
                env_name = (env.get("name", "") or "").upper()
                if any(p in env_name for p in ("PASSWORD", "PASSWD", "SECRET", "AUTH", "TOKEN")):
                    if env.get("value"):  # plain text value — HIGH risk
                        plain_password = True
                    elif (env.get("valueFrom") or {}).get("secretKeyRef"):
                        has_secret_ref = True

        status = "FAIL" if plain_password else "PASS"
        severity = "HIGH" if plain_password else "INFO"

        return [
            self._make_finding(
                scan_run_id, tenant_id, account_id, resource, rule_id,
                PILLAR_AUTH, severity, status,
                {
                    "check": "credential_management",
                    "plain_text_password": plain_password,
                    "uses_secret_ref": has_secret_ref,
                    "namespace": metadata.get("namespace", ""),
                },
            )
        ]

    def _check_pillar_4_audit(
        self, resource: Dict[str, Any], tenant_id: str, account_id: str, scan_run_id: str
    ) -> List[Dict[str, Any]]:
        ef = resource["emitted_fields"]
        rtype = resource["resource_type"]
        slug = self._slug(rtype)
        rule_id = f"k8s.dbsec.{PILLAR_AUDIT}.{slug}"

        metadata = ef.get("metadata", {}) or {}
        annotations = metadata.get("annotations", {}) or {}
        labels = metadata.get("labels", {}) or {}

        if rtype in ("k8s.core/Secret", "Secret", "secret"):
            return [
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource, rule_id,
                    PILLAR_AUDIT, "INFO", "PASS",
                    {
                        "check": "secret_audit",
                        "note": "Secret access audited via Kubernetes Audit Logs",
                        "namespace": metadata.get("namespace", ""),
                    },
                )
            ]

        # Check for monitoring/logging sidecar annotations
        monitoring_annotations = {
            "prometheus.io/scrape", "datadog/enabled",
            "fluentd.io/parser", "co.elastic.logs/enabled",
        }
        has_monitoring = (
            any(k in monitoring_annotations for k in annotations)
            or any("monitor" in k.lower() or "log" in k.lower() for k in labels)
        )

        return [
            self._make_finding(
                scan_run_id, tenant_id, account_id, resource, rule_id,
                PILLAR_AUDIT, "MEDIUM" if not has_monitoring else "INFO",
                "FAIL" if not has_monitoring else "PASS",
                {
                    "check": "monitoring_configured",
                    "monitoring_annotations": has_monitoring,
                    "namespace": metadata.get("namespace", ""),
                },
            )
        ]

    def _check_pillar_5_compliance(
        self, resource: Dict[str, Any], tenant_id: str, account_id: str, scan_run_id: str
    ) -> List[Dict[str, Any]]:
        ef = resource["emitted_fields"]
        rtype = resource["resource_type"]
        slug = self._slug(rtype)
        base_rule = f"k8s.dbsec.{PILLAR_COMPLIANCE}.{slug}"
        findings = []

        metadata = ef.get("metadata", {}) or {}

        if rtype in ("k8s.core/Secret", "Secret", "secret"):
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource,
                    f"{base_rule}.secret_rotation", PILLAR_COMPLIANCE,
                    "MEDIUM", "FAIL",
                    {
                        "check": "secret_rotation",
                        "note": "K8s Secret rotation policy not determinable from discovery metadata",
                        "namespace": metadata.get("namespace", ""),
                    },
                )
            )
            return findings

        if rtype in ("k8s.core/Service", "Service", "service"):
            findings.append(
                self._make_finding(
                    scan_run_id, tenant_id, account_id, resource,
                    f"{base_rule}.service_compliance", PILLAR_COMPLIANCE,
                    "INFO", "PASS",
                    {"check": "not_applicable", "note": "Service compliance managed at workload level"},
                )
            )
            return findings

        spec_raw = ef.get("spec", {}) or {}
        template_spec = spec_raw.get("template", {}).get("spec", {}) if isinstance(spec_raw, dict) else {}
        pod_spec = template_spec if template_spec else spec_raw
        containers = pod_spec.get("containers", []) or []

        # Replica count for HA
        replicas = spec_raw.get("replicas", 1)
        try:
            replicas = int(replicas) if replicas is not None else 1
        except (ValueError, TypeError):
            replicas = 1
        is_ha = replicas >= 2

        findings.append(
            self._make_finding(
                scan_run_id, tenant_id, account_id, resource,
                f"{base_rule}.ha", PILLAR_COMPLIANCE,
                "MEDIUM" if not is_ha else "INFO",
                "FAIL" if not is_ha else "PASS",
                {
                    "check": "replica_count",
                    "replicas": replicas,
                    "ha_compliant": is_ha,
                    "compliant_minimum": 2,
                    "namespace": metadata.get("namespace", ""),
                },
            )
        )

        # Resource limits (production readiness)
        all_have_limits = (
            all(c.get("resources", {}).get("limits") for c in containers)
            if containers else False
        )
        findings.append(
            self._make_finding(
                scan_run_id, tenant_id, account_id, resource,
                f"{base_rule}.resource_limits", PILLAR_COMPLIANCE,
                "LOW" if not all_have_limits else "INFO",
                "FAIL" if not all_have_limits else "PASS",
                {
                    "check": "resource_limits",
                    "all_containers_have_limits": all_have_limits,
                    "container_count": len(containers),
                },
            )
        )

        return findings
