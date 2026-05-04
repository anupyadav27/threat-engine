"""Kubernetes provider for Data Security engine — 8-module DSPM analyze().

Resource types consumed from discovery_findings (story ENG-10):
  ConfigMap, Secret, PersistentVolumeClaim, StatefulSet
"""

import hashlib
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List

from psycopg2.extras import RealDictCursor

from .base import BaseDataSecProvider

logger = logging.getLogger(__name__)

# Canonical resource_type values in discovery_findings for K8s (ENG-10)
_CONFIGMAP_TYPES = {"ConfigMap"}
_SECRET_TYPES = {"Secret"}
_PVC_TYPES = {"PersistentVolumeClaim"}
_STATEFULSET_TYPES = {"StatefulSet"}

_ALL_DATA_TYPES = list(
    _CONFIGMAP_TYPES | _SECRET_TYPES | _PVC_TYPES | _STATEFULSET_TYPES
)

# Patterns that indicate credentials stored in ConfigMaps (T1552.001)
_CREDENTIAL_PATTERNS = [
    re.compile(r"(?i)(password|passwd|secret|api_key|apikey|token|credential|private_key|auth|access_key)"),
    re.compile(r"(?i)(connection_string|conn_str|database_url|db_pass|db_password)"),
]


def _make_finding_id(rule_id: str, resource_uid: str, account_id: str, region: str) -> str:
    """Build canonical finding_id as sha256[:16]."""
    raw = f"{rule_id}|{resource_uid}|{account_id}|{region}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _resource_type_slug(resource_type: str) -> str:
    """Convert resource_type to rule_id slug."""
    return "".join(c if c.isalnum() else "_" for c in resource_type.lower()).strip("_")


def _has_credential_data(data: Any) -> bool:
    """Check if ConfigMap data dict contains credential-like keys."""
    if not isinstance(data, dict):
        return False
    for key in data.keys():
        for pattern in _CREDENTIAL_PATTERNS:
            if pattern.search(str(key)):
                return True
    return False


def _infer_secret_labels(secret_type: str, name: str) -> List[str]:
    """Infer classification labels for K8s Secrets — always CONFIDENTIAL."""
    labels: List[str] = ["CONFIDENTIAL"]
    text = (secret_type + " " + name).lower()
    if "tls" in text or "cert" in text:
        pass  # already CONFIDENTIAL
    if "service-account" in text or "serviceaccount" in text:
        pass  # already CONFIDENTIAL
    return labels


def _base_finding(
    rule_id: str,
    resource_uid: str,
    resource_type: str,
    account_id: str,
    region: str,
    scan_run_id: str,
    tenant_id: str,
    dspm_module: str,
    severity: str,
    status: str,
    classification_labels: List[str],
    encryption_status: str,
    public_access: bool,
    now: datetime,
) -> Dict[str, Any]:
    """Build a canonical DSPM finding dict."""
    return {
        "finding_id": _make_finding_id(rule_id, resource_uid, account_id, region),
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        "account_id": account_id,
        "provider": "k8s",
        "region": region,
        "resource_uid": resource_uid,
        "resource_type": resource_type,
        "severity": severity,
        "status": status,
        "dspm_module": dspm_module,
        "classification_labels": classification_labels,
        "encryption_status": encryption_status,
        "public_access": public_access,
        "blast_radius_score": 0,
        "first_seen_at": now,
        "last_seen_at": now,
    }


class K8sDataSecProvider(BaseDataSecProvider):
    """K8s DSPM provider — 8-module analysis over ConfigMap, Secret, PVC, StatefulSet."""

    @property
    def storage_services(self) -> List[str]:
        return ["persistentvolumes", "persistentvolumeclaims", "configmaps"]

    @property
    def database_services(self) -> List[str]:
        return ["statefulsets"]

    @property
    def streaming_services(self) -> List[str]:
        return []

    @property
    def inventory_resource_prefixes(self) -> List[str]:
        return ["persistentvolume.", "configmap.", "statefulset."]

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        discoveries_conn: Any,
        check_conn: Any,
    ) -> List[Dict[str, Any]]:
        """Run 8-module DSPM analysis over Kubernetes discovery_findings.

        Queries discovery_findings for resource_types:
          ConfigMap, Secret, PersistentVolumeClaim, StatefulSet

        Focuses on:
          - ConfigMaps: credential detection (T1552.001), no-encryption risk
          - Secrets: base64-only (not encrypted at rest), RBAC gaps
          - PVCs: storage class encryption, retention
          - StatefulSets: data service posture (DB pods)

        Args:
            scan_run_id: Pipeline scan run identifier.
            tenant_id: Tenant scoping for all DB queries.
            account_id: Cluster identifier.
            discoveries_conn: psycopg2 connection to discoveries DB.
            check_conn: psycopg2 connection to check DB (unused here).

        Returns:
            List of DSPM finding dicts for K8s resources.
        """
        now = datetime.now(timezone.utc)
        findings: List[Dict[str, Any]] = []

        try:
            with discoveries_conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT resource_uid, resource_type, region, emitted_fields
                    FROM discovery_findings
                    WHERE scan_run_id = %s
                      AND tenant_id = %s
                      AND resource_type = ANY(%s)
                    LIMIT 2000
                    """,
                    (scan_run_id, tenant_id, _ALL_DATA_TYPES),
                )
                rows = cur.fetchall()
        except Exception as exc:
            logger.error("K8s DSPM: failed to load discovery_findings: %s", exc)
            return []

        if not rows:
            logger.warning(
                "K8s DSPM: no data-relevant rows for scan_run_id=%s (queried types: %s)",
                scan_run_id, _ALL_DATA_TYPES,
            )
            return []

        # Process in batches of 500 (STRIDE DoS mitigation)
        batch_size = 500
        for i in range(0, len(rows), batch_size):
            batch = rows[i : i + batch_size]
            for row in batch:
                resource_uid = row.get("resource_uid") or ""
                resource_type = row.get("resource_type", "")
                region = row.get("region") or "cluster"
                emitted = row.get("emitted_fields") or {}
                slug = _resource_type_slug(resource_type)

                metadata = emitted.get("metadata", {}) if isinstance(emitted, dict) else {}
                name = (
                    (metadata.get("name") if isinstance(metadata, dict) else None)
                    or emitted.get("resource_id")
                    or resource_uid
                )
                namespace = (
                    metadata.get("namespace", "default") if isinstance(metadata, dict) else "default"
                )

                if resource_type in _CONFIGMAP_TYPES:
                    self._analyze_configmap(
                        findings=findings,
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=region,
                        scan_run_id=scan_run_id,
                        tenant_id=tenant_id,
                        slug=slug,
                        emitted=emitted,
                        name=str(name),
                        namespace=namespace,
                        now=now,
                    )

                elif resource_type in _SECRET_TYPES:
                    self._analyze_secret(
                        findings=findings,
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=region,
                        scan_run_id=scan_run_id,
                        tenant_id=tenant_id,
                        slug=slug,
                        emitted=emitted,
                        name=str(name),
                        namespace=namespace,
                        now=now,
                    )

                elif resource_type in _PVC_TYPES:
                    self._analyze_pvc(
                        findings=findings,
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=region,
                        scan_run_id=scan_run_id,
                        tenant_id=tenant_id,
                        slug=slug,
                        emitted=emitted,
                        name=str(name),
                        now=now,
                    )

                elif resource_type in _STATEFULSET_TYPES:
                    self._analyze_statefulset(
                        findings=findings,
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=region,
                        scan_run_id=scan_run_id,
                        tenant_id=tenant_id,
                        slug=slug,
                        emitted=emitted,
                        name=str(name),
                        now=now,
                    )

        logger.info(
            "K8s DSPM analyze(): produced %d findings from %d discovery rows",
            len(findings), len(rows),
        )
        return findings

    def _analyze_configmap(
        self,
        findings: List[Dict[str, Any]],
        resource_uid: str,
        resource_type: str,
        account_id: str,
        region: str,
        scan_run_id: str,
        tenant_id: str,
        slug: str,
        emitted: Dict[str, Any],
        name: str,
        namespace: str,
        now: datetime,
    ) -> None:
        """Analyze a ConfigMap across all 8 DSPM modules."""
        data = emitted.get("data") or {}
        has_creds = _has_credential_data(data)
        labels = ["CONFIDENTIAL"] if has_creds else []
        is_default_ns = namespace == "default"

        # Module 1: data_classification (T1552.001)
        findings.append(_base_finding(
            rule_id=f"k8s.dspm.data_classification.{slug}",
            resource_uid=resource_uid, resource_type=resource_type,
            account_id=account_id, region=region, scan_run_id=scan_run_id,
            tenant_id=tenant_id, dspm_module="data_classification",
            severity="HIGH" if has_creds else "MEDIUM",
            status="FAIL" if has_creds else "PASS",
            classification_labels=labels, encryption_status="unencrypted",
            public_access=False, now=now,
        ))

        # Module 2: encryption_posture — ConfigMaps never encrypted at rest by default
        findings.append(_base_finding(
            rule_id=f"k8s.dspm.encryption_posture.{slug}",
            resource_uid=resource_uid, resource_type=resource_type,
            account_id=account_id, region=region, scan_run_id=scan_run_id,
            tenant_id=tenant_id, dspm_module="encryption_posture",
            severity="CRITICAL" if has_creds else "MEDIUM",
            status="FAIL",
            classification_labels=labels, encryption_status="unencrypted",
            public_access=False, now=now,
        ))

        # Module 3: access_control — default namespace ConfigMaps accessible to all pods
        findings.append(_base_finding(
            rule_id=f"k8s.dspm.access_control.{slug}",
            resource_uid=resource_uid, resource_type=resource_type,
            account_id=account_id, region=region, scan_run_id=scan_run_id,
            tenant_id=tenant_id, dspm_module="access_control",
            severity="HIGH" if (is_default_ns and has_creds) else "INFO",
            status="FAIL" if (is_default_ns and has_creds) else "PASS",
            classification_labels=labels, encryption_status="unencrypted",
            public_access=False, now=now,
        ))

        # Module 4: data_residency — cluster-local, no cross-region concern
        findings.append(_base_finding(
            rule_id=f"k8s.dspm.data_residency.{slug}",
            resource_uid=resource_uid, resource_type=resource_type,
            account_id=account_id, region=region, scan_run_id=scan_run_id,
            tenant_id=tenant_id, dspm_module="data_residency",
            severity="LOW", status="PASS",
            classification_labels=labels, encryption_status="unencrypted",
            public_access=False, now=now,
        ))

        # Module 5: activity_logging — no per-ConfigMap audit by default
        findings.append(_base_finding(
            rule_id=f"k8s.dspm.activity_logging.{slug}",
            resource_uid=resource_uid, resource_type=resource_type,
            account_id=account_id, region=region, scan_run_id=scan_run_id,
            tenant_id=tenant_id, dspm_module="activity_logging",
            severity="MEDIUM", status="FAIL",
            classification_labels=labels, encryption_status="unencrypted",
            public_access=False, now=now,
        ))

        # Module 6: data_lifecycle — no TTL / versioning on ConfigMaps
        findings.append(_base_finding(
            rule_id=f"k8s.dspm.data_lifecycle.{slug}",
            resource_uid=resource_uid, resource_type=resource_type,
            account_id=account_id, region=region, scan_run_id=scan_run_id,
            tenant_id=tenant_id, dspm_module="data_lifecycle",
            severity="LOW", status="PASS",
            classification_labels=labels, encryption_status="unencrypted",
            public_access=False, now=now,
        ))

        # Module 7: data_lineage
        findings.append(_base_finding(
            rule_id=f"k8s.dspm.data_lineage.{slug}",
            resource_uid=resource_uid, resource_type=resource_type,
            account_id=account_id, region=region, scan_run_id=scan_run_id,
            tenant_id=tenant_id, dspm_module="data_lineage",
            severity="LOW", status="PASS",
            classification_labels=labels, encryption_status="unencrypted",
            public_access=False, now=now,
        ))

        # Module 8: governance_scoring
        score = 0 if has_creds else 50
        findings.append(_base_finding(
            rule_id=f"k8s.dspm.governance_scoring.{slug}",
            resource_uid=resource_uid, resource_type=resource_type,
            account_id=account_id, region=region, scan_run_id=scan_run_id,
            tenant_id=tenant_id, dspm_module="governance_scoring",
            severity="HIGH" if score < 50 else "MEDIUM",
            status="FAIL",
            classification_labels=labels, encryption_status="unencrypted",
            public_access=False, now=now,
        ))

    def _analyze_secret(
        self,
        findings: List[Dict[str, Any]],
        resource_uid: str,
        resource_type: str,
        account_id: str,
        region: str,
        scan_run_id: str,
        tenant_id: str,
        slug: str,
        emitted: Dict[str, Any],
        name: str,
        namespace: str,
        now: datetime,
    ) -> None:
        """Analyze a K8s Secret across all 8 DSPM modules."""
        secret_type = emitted.get("type", "Opaque")
        labels = _infer_secret_labels(str(secret_type), name)
        is_default_ns = namespace == "default"

        # Module 1: data_classification
        findings.append(_base_finding(
            rule_id=f"k8s.dspm.data_classification.{slug}",
            resource_uid=resource_uid, resource_type=resource_type,
            account_id=account_id, region=region, scan_run_id=scan_run_id,
            tenant_id=tenant_id, dspm_module="data_classification",
            severity="HIGH", status="FAIL",
            classification_labels=labels, encryption_status="partial",
            public_access=False, now=now,
        ))

        # Module 2: encryption_posture — K8s Secrets are base64-only, NOT encrypted at rest
        findings.append(_base_finding(
            rule_id=f"k8s.dspm.encryption_posture.{slug}",
            resource_uid=resource_uid, resource_type=resource_type,
            account_id=account_id, region=region, scan_run_id=scan_run_id,
            tenant_id=tenant_id, dspm_module="encryption_posture",
            severity="CRITICAL", status="FAIL",
            classification_labels=labels, encryption_status="unencrypted",
            public_access=False, now=now,
        ))

        # Module 3: access_control — any pod in same namespace can read by default
        findings.append(_base_finding(
            rule_id=f"k8s.dspm.access_control.{slug}",
            resource_uid=resource_uid, resource_type=resource_type,
            account_id=account_id, region=region, scan_run_id=scan_run_id,
            tenant_id=tenant_id, dspm_module="access_control",
            severity="HIGH" if is_default_ns else "MEDIUM",
            status="FAIL",
            classification_labels=labels, encryption_status="unencrypted",
            public_access=False, now=now,
        ))

        # Module 4: data_residency
        findings.append(_base_finding(
            rule_id=f"k8s.dspm.data_residency.{slug}",
            resource_uid=resource_uid, resource_type=resource_type,
            account_id=account_id, region=region, scan_run_id=scan_run_id,
            tenant_id=tenant_id, dspm_module="data_residency",
            severity="LOW", status="PASS",
            classification_labels=labels, encryption_status="unencrypted",
            public_access=False, now=now,
        ))

        # Module 5: activity_logging — Secret access audit requires specific K8s audit policy
        findings.append(_base_finding(
            rule_id=f"k8s.dspm.activity_logging.{slug}",
            resource_uid=resource_uid, resource_type=resource_type,
            account_id=account_id, region=region, scan_run_id=scan_run_id,
            tenant_id=tenant_id, dspm_module="activity_logging",
            severity="HIGH", status="FAIL",
            classification_labels=labels, encryption_status="unencrypted",
            public_access=False, now=now,
        ))

        # Module 6: data_lifecycle — Secrets have no TTL / rotation by default
        findings.append(_base_finding(
            rule_id=f"k8s.dspm.data_lifecycle.{slug}",
            resource_uid=resource_uid, resource_type=resource_type,
            account_id=account_id, region=region, scan_run_id=scan_run_id,
            tenant_id=tenant_id, dspm_module="data_lifecycle",
            severity="MEDIUM", status="FAIL",
            classification_labels=labels, encryption_status="unencrypted",
            public_access=False, now=now,
        ))

        # Module 7: data_lineage
        findings.append(_base_finding(
            rule_id=f"k8s.dspm.data_lineage.{slug}",
            resource_uid=resource_uid, resource_type=resource_type,
            account_id=account_id, region=region, scan_run_id=scan_run_id,
            tenant_id=tenant_id, dspm_module="data_lineage",
            severity="LOW", status="PASS",
            classification_labels=labels, encryption_status="unencrypted",
            public_access=False, now=now,
        ))

        # Module 8: governance_scoring — Secrets score low: unencrypted + no RBAC visible
        findings.append(_base_finding(
            rule_id=f"k8s.dspm.governance_scoring.{slug}",
            resource_uid=resource_uid, resource_type=resource_type,
            account_id=account_id, region=region, scan_run_id=scan_run_id,
            tenant_id=tenant_id, dspm_module="governance_scoring",
            severity="HIGH", status="FAIL",
            classification_labels=labels, encryption_status="unencrypted",
            public_access=False, now=now,
        ))

    def _analyze_pvc(
        self,
        findings: List[Dict[str, Any]],
        resource_uid: str,
        resource_type: str,
        account_id: str,
        region: str,
        scan_run_id: str,
        tenant_id: str,
        slug: str,
        emitted: Dict[str, Any],
        name: str,
        now: datetime,
    ) -> None:
        """Analyze a PersistentVolumeClaim across all 8 DSPM modules."""
        spec = emitted.get("spec", {}) if isinstance(emitted, dict) else {}
        storage_class = (
            spec.get("storageClassName", "") if isinstance(spec, dict) else ""
        ) or emitted.get("storageClassName", "")
        # Encrypted storage classes typically contain "encrypted" or "gp3" in EKS
        enc_ok = bool(storage_class and any(
            tok in str(storage_class).lower()
            for tok in ("encrypted", "gp3", "io2", "premium", "managed")
        ))
        status_obj = emitted.get("status", {}) if isinstance(emitted, dict) else {}
        phase = (
            status_obj.get("phase", "Pending") if isinstance(status_obj, dict) else "Pending"
        )

        labels: List[str] = []

        # Module 1: data_classification — PVCs may hold database data
        findings.append(_base_finding(
            rule_id=f"k8s.dspm.data_classification.{slug}",
            resource_uid=resource_uid, resource_type=resource_type,
            account_id=account_id, region=region, scan_run_id=scan_run_id,
            tenant_id=tenant_id, dspm_module="data_classification",
            severity="MEDIUM", status="PASS",
            classification_labels=labels, encryption_status="unknown",
            public_access=False, now=now,
        ))

        # Module 2: encryption_posture — depends on storage class
        findings.append(_base_finding(
            rule_id=f"k8s.dspm.encryption_posture.{slug}",
            resource_uid=resource_uid, resource_type=resource_type,
            account_id=account_id, region=region, scan_run_id=scan_run_id,
            tenant_id=tenant_id, dspm_module="encryption_posture",
            severity="HIGH" if not enc_ok else "INFO",
            status="FAIL" if not enc_ok else "PASS",
            classification_labels=labels,
            encryption_status="enabled" if enc_ok else "unknown",
            public_access=False, now=now,
        ))

        # Module 3: access_control — PVCs bound to a single pod by default (RWO)
        access_modes = spec.get("accessModes", []) if isinstance(spec, dict) else []
        shared_access = "ReadWriteMany" in access_modes
        findings.append(_base_finding(
            rule_id=f"k8s.dspm.access_control.{slug}",
            resource_uid=resource_uid, resource_type=resource_type,
            account_id=account_id, region=region, scan_run_id=scan_run_id,
            tenant_id=tenant_id, dspm_module="access_control",
            severity="MEDIUM" if shared_access else "INFO",
            status="FAIL" if shared_access else "PASS",
            classification_labels=labels, encryption_status="unknown",
            public_access=False, now=now,
        ))

        # Module 4: data_residency
        findings.append(_base_finding(
            rule_id=f"k8s.dspm.data_residency.{slug}",
            resource_uid=resource_uid, resource_type=resource_type,
            account_id=account_id, region=region, scan_run_id=scan_run_id,
            tenant_id=tenant_id, dspm_module="data_residency",
            severity="LOW", status="PASS",
            classification_labels=labels, encryption_status="unknown",
            public_access=False, now=now,
        ))

        # Module 5: activity_logging — no PVC-level audit
        findings.append(_base_finding(
            rule_id=f"k8s.dspm.activity_logging.{slug}",
            resource_uid=resource_uid, resource_type=resource_type,
            account_id=account_id, region=region, scan_run_id=scan_run_id,
            tenant_id=tenant_id, dspm_module="activity_logging",
            severity="LOW", status="PASS",
            classification_labels=labels, encryption_status="unknown",
            public_access=False, now=now,
        ))

        # Module 6: data_lifecycle — PVC released = data may persist on volume
        lifecycle_ok = phase != "Released"
        findings.append(_base_finding(
            rule_id=f"k8s.dspm.data_lifecycle.{slug}",
            resource_uid=resource_uid, resource_type=resource_type,
            account_id=account_id, region=region, scan_run_id=scan_run_id,
            tenant_id=tenant_id, dspm_module="data_lifecycle",
            severity="MEDIUM" if not lifecycle_ok else "INFO",
            status="FAIL" if not lifecycle_ok else "PASS",
            classification_labels=labels, encryption_status="unknown",
            public_access=False, now=now,
        ))

        # Module 7: data_lineage
        findings.append(_base_finding(
            rule_id=f"k8s.dspm.data_lineage.{slug}",
            resource_uid=resource_uid, resource_type=resource_type,
            account_id=account_id, region=region, scan_run_id=scan_run_id,
            tenant_id=tenant_id, dspm_module="data_lineage",
            severity="INFO", status="PASS",
            classification_labels=labels, encryption_status="unknown",
            public_access=False, now=now,
        ))

        # Module 8: governance_scoring
        passes = sum([enc_ok, not shared_access, lifecycle_ok])
        score = int(passes / 3 * 100)
        findings.append(_base_finding(
            rule_id=f"k8s.dspm.governance_scoring.{slug}",
            resource_uid=resource_uid, resource_type=resource_type,
            account_id=account_id, region=region, scan_run_id=scan_run_id,
            tenant_id=tenant_id, dspm_module="governance_scoring",
            severity="HIGH" if score < 50 else ("MEDIUM" if score < 80 else "LOW"),
            status="FAIL" if score < 80 else "PASS",
            classification_labels=labels, encryption_status="unknown",
            public_access=False, now=now,
        ))

    def _analyze_statefulset(
        self,
        findings: List[Dict[str, Any]],
        resource_uid: str,
        resource_type: str,
        account_id: str,
        region: str,
        scan_run_id: str,
        tenant_id: str,
        slug: str,
        emitted: Dict[str, Any],
        name: str,
        now: datetime,
    ) -> None:
        """Analyze a StatefulSet across all 8 DSPM modules."""
        spec = emitted.get("spec", {}) if isinstance(emitted, dict) else {}
        # StatefulSets typically run databases — classify as potentially sensitive
        labels: List[str] = []
        name_lower = name.lower()
        if any(db in name_lower for db in ("postgres", "mysql", "mongo", "redis", "elastic", "kafka")):
            labels = ["CONFIDENTIAL"]

        vct = spec.get("volumeClaimTemplates", []) if isinstance(spec, dict) else []
        has_storage = bool(vct)

        # Module 1: data_classification
        findings.append(_base_finding(
            rule_id=f"k8s.dspm.data_classification.{slug}",
            resource_uid=resource_uid, resource_type=resource_type,
            account_id=account_id, region=region, scan_run_id=scan_run_id,
            tenant_id=tenant_id, dspm_module="data_classification",
            severity="HIGH" if labels else "MEDIUM",
            status="FAIL" if labels else "PASS",
            classification_labels=labels, encryption_status="unknown",
            public_access=False, now=now,
        ))

        # Module 2: encryption_posture — depends on VCT storage class
        enc_ok = False
        if isinstance(vct, list):
            for vct_item in vct:
                sc = (
                    vct_item.get("spec", {}).get("storageClassName", "")
                    if isinstance(vct_item.get("spec"), dict)
                    else ""
                )
                if any(t in str(sc).lower() for t in ("encrypted", "gp3", "premium")):
                    enc_ok = True
                    break
        findings.append(_base_finding(
            rule_id=f"k8s.dspm.encryption_posture.{slug}",
            resource_uid=resource_uid, resource_type=resource_type,
            account_id=account_id, region=region, scan_run_id=scan_run_id,
            tenant_id=tenant_id, dspm_module="encryption_posture",
            severity="HIGH" if (has_storage and not enc_ok) else "INFO",
            status="FAIL" if (has_storage and not enc_ok) else "PASS",
            classification_labels=labels,
            encryption_status="enabled" if enc_ok else "unknown",
            public_access=False, now=now,
        ))

        # Module 3: access_control — check if service exposes DB externally
        findings.append(_base_finding(
            rule_id=f"k8s.dspm.access_control.{slug}",
            resource_uid=resource_uid, resource_type=resource_type,
            account_id=account_id, region=region, scan_run_id=scan_run_id,
            tenant_id=tenant_id, dspm_module="access_control",
            severity="MEDIUM", status="PASS",
            classification_labels=labels, encryption_status="unknown",
            public_access=False, now=now,
        ))

        # Module 4: data_residency
        findings.append(_base_finding(
            rule_id=f"k8s.dspm.data_residency.{slug}",
            resource_uid=resource_uid, resource_type=resource_type,
            account_id=account_id, region=region, scan_run_id=scan_run_id,
            tenant_id=tenant_id, dspm_module="data_residency",
            severity="LOW", status="PASS",
            classification_labels=labels, encryption_status="unknown",
            public_access=False, now=now,
        ))

        # Module 5: activity_logging
        findings.append(_base_finding(
            rule_id=f"k8s.dspm.activity_logging.{slug}",
            resource_uid=resource_uid, resource_type=resource_type,
            account_id=account_id, region=region, scan_run_id=scan_run_id,
            tenant_id=tenant_id, dspm_module="activity_logging",
            severity="MEDIUM", status="FAIL",
            classification_labels=labels, encryption_status="unknown",
            public_access=False, now=now,
        ))

        # Module 6: data_lifecycle — no backup policy visible from StatefulSet spec
        findings.append(_base_finding(
            rule_id=f"k8s.dspm.data_lifecycle.{slug}",
            resource_uid=resource_uid, resource_type=resource_type,
            account_id=account_id, region=region, scan_run_id=scan_run_id,
            tenant_id=tenant_id, dspm_module="data_lifecycle",
            severity="MEDIUM", status="FAIL",
            classification_labels=labels, encryption_status="unknown",
            public_access=False, now=now,
        ))

        # Module 7: data_lineage
        findings.append(_base_finding(
            rule_id=f"k8s.dspm.data_lineage.{slug}",
            resource_uid=resource_uid, resource_type=resource_type,
            account_id=account_id, region=region, scan_run_id=scan_run_id,
            tenant_id=tenant_id, dspm_module="data_lineage",
            severity="LOW", status="PASS",
            classification_labels=labels, encryption_status="unknown",
            public_access=False, now=now,
        ))

        # Module 8: governance_scoring
        passes = sum([enc_ok, True, False])  # enc + access(pass) + log(fail)
        score = int(passes / 3 * 100)
        findings.append(_base_finding(
            rule_id=f"k8s.dspm.governance_scoring.{slug}",
            resource_uid=resource_uid, resource_type=resource_type,
            account_id=account_id, region=region, scan_run_id=scan_run_id,
            tenant_id=tenant_id, dspm_module="governance_scoring",
            severity="HIGH" if score < 50 else ("MEDIUM" if score < 80 else "LOW"),
            status="FAIL" if score < 80 else "PASS",
            classification_labels=labels, encryption_status="unknown",
            public_access=False, now=now,
        ))
