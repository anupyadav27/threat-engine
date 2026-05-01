"""Kubernetes provider for Data Security engine — 8-module DSPM analyze()."""

import hashlib
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List

from psycopg2.extras import RealDictCursor

from .base import BaseDataSecProvider

logger = logging.getLogger(__name__)

# Actual resource_type values in discovery_findings for K8s
_CONFIGMAP_TYPES = {"k8s.core/ConfigMap"}
_SECRET_TYPES = {"k8s.core/Secret"}
_ALL_DATA_TYPES = _CONFIGMAP_TYPES | _SECRET_TYPES

# Patterns that indicate credentials stored in ConfigMaps (T1552.001)
_CREDENTIAL_PATTERNS = [
    re.compile(r"(?i)(password|passwd|secret|api_key|apikey|token|credential|private_key|auth|access_key)", re.IGNORECASE),
    re.compile(r"(?i)(connection_string|conn_str|database_url|db_pass)", re.IGNORECASE),
]


def _make_finding_id(rule_id: str, resource_uid: str, account_id: str, region: str) -> str:
    raw = f"{rule_id}|{resource_uid}|{account_id}|{region}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _resource_type_slug(resource_type: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in resource_type.lower()).strip("_")


def _has_credential_data(data: Any) -> bool:
    """Check if ConfigMap data dict contains credential-like keys or values."""
    if not isinstance(data, dict):
        return False
    for key in data.keys():
        for pattern in _CREDENTIAL_PATTERNS:
            if pattern.search(str(key)):
                return True
    return False


def _infer_secret_labels(secret_type: str, name: str) -> List[str]:
    """Infer classification labels for K8s Secrets."""
    labels: List[str] = ["CONFIDENTIAL"]  # All K8s Secrets are CONFIDENTIAL
    text = (secret_type + " " + name).lower()
    if "tls" in text or "cert" in text:
        labels.append("CONFIDENTIAL")
    if "service-account" in text:
        labels.append("CONFIDENTIAL")
    return list(set(labels))


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

        Focuses on ConfigMaps (T1552.001 — credentials in files) and Secrets
        (classification, encryption-at-rest, access control).

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
                    (scan_run_id, tenant_id, list(_ALL_DATA_TYPES)),
                )
                rows = cur.fetchall()
        except Exception as exc:
            logger.error("K8s DSPM: failed to load discovery_findings: %s", exc)
            return []

        if not rows:
            logger.warning("K8s DSPM: no data-relevant rows for scan_run_id=%s", scan_run_id)
            return []

        for row in rows:
            resource_uid = row.get("resource_uid") or ""
            resource_type = row.get("resource_type", "")
            region = row.get("region") or "cluster"
            emitted = row.get("emitted_fields") or {}
            slug = _resource_type_slug(resource_type)

            metadata = emitted.get("metadata", {}) if isinstance(emitted, dict) else {}
            name = (
                metadata.get("name")
                or emitted.get("resource_id")
                or resource_uid
            )
            namespace = metadata.get("namespace", "default") if isinstance(metadata, dict) else "default"

            if resource_type in _CONFIGMAP_TYPES:
                data = emitted.get("data") or {}
                has_creds = _has_credential_data(data)
                labels = ["CONFIDENTIAL"] if has_creds else []

                # ── Module 1: classification (T1552.001) ────────────────
                rule_id = f"k8s.dspm.classification.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="classification",
                    severity="HIGH" if has_creds else "MEDIUM",
                    status="FAIL" if has_creds else "PASS",
                    classification_labels=labels, encryption_status="unencrypted",
                    public_access=False, now=now,
                ))

                # ── Module 2: encryption ────────────────────────────────
                # ConfigMaps are NEVER encrypted at rest by default
                rule_id = f"k8s.dspm.encryption.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="encryption",
                    severity="CRITICAL" if has_creds else "MEDIUM",
                    status="FAIL",
                    classification_labels=labels, encryption_status="unencrypted",
                    public_access=False, now=now,
                ))

                # ── Module 3: access_control ────────────────────────────
                # ConfigMaps in default namespace are potentially accessible to all pods
                is_default_ns = namespace == "default"
                rule_id = f"k8s.dspm.access_control.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="access_control",
                    severity="HIGH" if (is_default_ns and has_creds) else "INFO",
                    status="FAIL" if (is_default_ns and has_creds) else "PASS",
                    classification_labels=labels, encryption_status="unencrypted",
                    public_access=False, now=now,
                ))

                # ── Module 4: data_residency ────────────────────────────
                rule_id = f"k8s.dspm.data_residency.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="data_residency",
                    severity="LOW", status="PASS",
                    classification_labels=labels, encryption_status="unencrypted",
                    public_access=False, now=now,
                ))

                # ── Module 5: activity_logging ──────────────────────────
                # No per-object audit by default for ConfigMaps
                rule_id = f"k8s.dspm.activity_logging.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="activity_logging",
                    severity="MEDIUM", status="FAIL",
                    classification_labels=labels, encryption_status="unencrypted",
                    public_access=False, now=now,
                ))

                # ── Module 6: lifecycle ─────────────────────────────────
                rule_id = f"k8s.dspm.lifecycle.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="lifecycle",
                    severity="LOW", status="PASS",
                    classification_labels=labels, encryption_status="unencrypted",
                    public_access=False, now=now,
                ))

                # ── Module 7: data_lineage ──────────────────────────────
                rule_id = f"k8s.dspm.data_lineage.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="data_lineage",
                    severity="LOW", status="PASS",
                    classification_labels=labels, encryption_status="unencrypted",
                    public_access=False, now=now,
                ))

                # ── Module 8: governance_score ──────────────────────────
                # ConfigMaps: unencrypted + possibly public = low score
                score = 0 if has_creds else 50
                gov_sev = "HIGH" if score < 50 else "MEDIUM"
                rule_id = f"k8s.dspm.governance_score.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="governance_score",
                    severity=gov_sev, status="FAIL",
                    classification_labels=labels, encryption_status="unencrypted",
                    public_access=False, now=now,
                ))

            elif resource_type in _SECRET_TYPES:
                secret_type = emitted.get("type", "Opaque")
                labels = _infer_secret_labels(str(secret_type), str(name))

                # ── Module 1: classification ────────────────────────────
                rule_id = f"k8s.dspm.classification.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="classification",
                    severity="HIGH", status="FAIL",
                    classification_labels=labels, encryption_status="partial",
                    public_access=False, now=now,
                ))

                # ── Module 2: encryption ────────────────────────────────
                # K8s Secrets: base64-encoded only, NOT encrypted at rest by default
                # (unless etcd encryption at rest configured — cannot detect from emitted_fields)
                rule_id = f"k8s.dspm.encryption.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="encryption",
                    severity="CRITICAL", status="FAIL",
                    classification_labels=labels, encryption_status="unencrypted",
                    public_access=False, now=now,
                ))

                # ── Module 3: access_control ────────────────────────────
                # Secrets accessible to any pod in same namespace by default
                is_default_ns = namespace == "default"
                rule_id = f"k8s.dspm.access_control.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="access_control",
                    severity="HIGH" if is_default_ns else "MEDIUM",
                    status="FAIL",
                    classification_labels=labels, encryption_status="unencrypted",
                    public_access=False, now=now,
                ))

                # ── Module 4: data_residency ────────────────────────────
                rule_id = f"k8s.dspm.data_residency.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="data_residency",
                    severity="LOW", status="PASS",
                    classification_labels=labels, encryption_status="unencrypted",
                    public_access=False, now=now,
                ))

                # ── Module 5: activity_logging ──────────────────────────
                rule_id = f"k8s.dspm.activity_logging.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="activity_logging",
                    severity="HIGH", status="FAIL",
                    classification_labels=labels, encryption_status="unencrypted",
                    public_access=False, now=now,
                ))

                # ── Module 6: lifecycle ─────────────────────────────────
                # Secrets should have TTL / rotation — K8s doesn't enforce this by default
                rule_id = f"k8s.dspm.lifecycle.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="lifecycle",
                    severity="MEDIUM", status="FAIL",
                    classification_labels=labels, encryption_status="unencrypted",
                    public_access=False, now=now,
                ))

                # ── Module 7: data_lineage ──────────────────────────────
                rule_id = f"k8s.dspm.data_lineage.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="data_lineage",
                    severity="LOW", status="PASS",
                    classification_labels=labels, encryption_status="unencrypted",
                    public_access=False, now=now,
                ))

                # ── Module 8: governance_score ──────────────────────────
                # Secrets score low: no encryption, no RBAC enforcement visible
                rule_id = f"k8s.dspm.governance_score.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="governance_score",
                    severity="HIGH", status="FAIL",
                    classification_labels=labels, encryption_status="unencrypted",
                    public_access=False, now=now,
                ))

        logger.info("K8s DSPM analyze(): produced %d findings from %d discovery rows", len(findings), len(rows))
        return findings
