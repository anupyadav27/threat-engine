"""GCP provider for Data Security engine — 8-module DSPM analyze()."""

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from psycopg2.extras import RealDictCursor

from .base import BaseDataSecProvider

logger = logging.getLogger(__name__)

# GCP EU regions for GDPR residency
_EU_REGIONS = {
    "europe-west1", "europe-west2", "europe-west3", "europe-west4",
    "europe-west6", "europe-west8", "europe-west9", "europe-west10",
    "europe-west12", "europe-north1", "europe-central2", "europe-southwest1",
    "EU",  # multi-region
}
# GCP US regions
_US_REGIONS = {"us-central1", "us-east1", "us-east4", "us-west1", "us-west2", "us-west3", "us-west4", "US"}

# Actual resource_type values in discovery_findings for GCP
_BUCKET_TYPES = {"storage.googleapis.com/Bucket"}
_BIGQUERY_TYPES = {"bigquery.googleapis.com/Dataset"}
_SECRET_TYPES = {"secretmanager.googleapis.com/Secret"}
_ALL_DATA_TYPES = _BUCKET_TYPES | _BIGQUERY_TYPES | _SECRET_TYPES

_PII_TOKENS = {"pii", "personal", "customer", "user", "patient", "member", "employee"}
_PHI_TOKENS = {"phi", "health", "medical", "hipaa", "clinical"}
_FINANCIAL_TOKENS = {"financial", "finance", "payment", "billing", "pci", "card", "bank"}
_CONFIDENTIAL_TOKENS = {"secret", "credential", "password", "token", "key", "private", "sensitive"}


def _make_finding_id(rule_id: str, resource_uid: str, account_id: str, region: str) -> str:
    raw = f"{rule_id}|{resource_uid}|{account_id}|{region}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _resource_type_slug(resource_type: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in resource_type.lower()).strip("_")


def _infer_labels(name: str, description: str = "") -> List[str]:
    text = (name + " " + description).lower()
    tokens = set(text.replace("-", " ").replace("_", " ").replace(".", " ").split())
    labels: List[str] = []
    if tokens & _PII_TOKENS:
        labels.append("PII")
    if tokens & _PHI_TOKENS:
        labels.append("PHI")
    if tokens & _FINANCIAL_TOKENS:
        labels.append("FINANCIAL")
    if tokens & _CONFIDENTIAL_TOKENS:
        labels.append("CONFIDENTIAL")
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
    return {
        "finding_id": _make_finding_id(rule_id, resource_uid, account_id, region),
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        "account_id": account_id,
        "provider": "gcp",
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


class GCPDataSecProvider(BaseDataSecProvider):

    @property
    def storage_services(self) -> List[str]:
        return ["storage", "bigtable"]

    @property
    def database_services(self) -> List[str]:
        return ["cloudsql", "firestore", "spanner", "bigquery", "datastore"]

    @property
    def streaming_services(self) -> List[str]:
        return ["pubsub", "dataflow"]

    @property
    def inventory_resource_prefixes(self) -> List[str]:
        return ["storage.", "cloudsql.", "bigquery.", "pubsub.", "firestore.", "spanner."]

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        discoveries_conn: Any,
        check_conn: Any,
    ) -> List[Dict[str, Any]]:
        """Run 8-module DSPM analysis over GCP discovery_findings.

        Args:
            scan_run_id: Pipeline scan run identifier.
            tenant_id: Tenant scoping for all DB queries.
            account_id: Cloud account identifier.
            discoveries_conn: psycopg2 connection to discoveries DB.
            check_conn: psycopg2 connection to check DB (unused here).

        Returns:
            List of DSPM finding dicts for GCP resources.
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
            logger.error("GCP DSPM: failed to load discovery_findings: %s", exc)
            return []

        if not rows:
            logger.warning("GCP DSPM: no data-relevant rows for scan_run_id=%s", scan_run_id)
            return []

        for row in rows:
            resource_uid = row.get("resource_uid") or ""
            resource_type = row.get("resource_type", "")
            region = row.get("region") or "us-central1"
            emitted = row.get("emitted_fields") or {}
            slug = _resource_type_slug(resource_type)

            name = (
                emitted.get("name")
                or emitted.get("id")
                or emitted.get("resource_id")
                or resource_uid
            )
            labels = _infer_labels(str(name))

            # ── Module 1: classification ────────────────────────────────────
            rule_id = f"gcp.dspm.classification.{slug}"
            findings.append(_base_finding(
                rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                account_id=account_id, region=region, scan_run_id=scan_run_id,
                tenant_id=tenant_id, dspm_module="classification",
                severity="HIGH" if labels else "MEDIUM",
                status="FAIL" if labels else "PASS",
                classification_labels=labels, encryption_status="unknown",
                public_access=False, now=now,
            ))

            # ── Module 2: encryption ────────────────────────────────────────
            if resource_type in _BUCKET_TYPES:
                # GCS: encryption field — default Google-managed is always present
                enc_config = emitted.get("encryption") or emitted.get("encryptionConfiguration")
                cmek = bool(enc_config and enc_config.get("defaultKmsKeyName")) if isinstance(enc_config, dict) else False
                enc_status = "encrypted" if True else "unencrypted"  # GCS always encrypted
                # Flag if not using CMEK (customer-managed)
                sev = "MEDIUM" if not cmek else "INFO"
                rule_id = f"gcp.dspm.encryption.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="encryption",
                    severity=sev, status="FAIL" if not cmek else "PASS",
                    classification_labels=labels, encryption_status=enc_status,
                    public_access=False, now=now,
                ))
            elif resource_type in _BIGQUERY_TYPES:
                # BigQuery default encryption = Google-managed
                rule_id = f"gcp.dspm.encryption.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="encryption",
                    severity="MEDIUM", status="FAIL",
                    classification_labels=labels, encryption_status="encrypted",
                    public_access=False, now=now,
                ))
            elif resource_type in _SECRET_TYPES:
                rule_id = f"gcp.dspm.encryption.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="encryption",
                    severity="INFO", status="PASS",
                    classification_labels=labels, encryption_status="encrypted",
                    public_access=False, now=now,
                ))

            # ── Module 3: access_control ────────────────────────────────────
            if resource_type in _BUCKET_TYPES:
                # iamConfiguration.uniformBucketLevelAccess.enabled = True is safer
                iam_config = emitted.get("iamConfiguration", {})
                uniform = (
                    iam_config.get("uniformBucketLevelAccess", {}).get("enabled", False)
                    if isinstance(iam_config, dict) else False
                )
                # publicAccessPrevention
                pub_prevention = (
                    iam_config.get("publicAccessPrevention", "unspecified")
                    if isinstance(iam_config, dict) else "unspecified"
                )
                is_public = not uniform and pub_prevention != "enforced"
                sev = "HIGH" if is_public else "INFO"
                rule_id = f"gcp.dspm.access_control.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="access_control",
                    severity=sev, status="FAIL" if is_public else "PASS",
                    classification_labels=labels, encryption_status="unknown",
                    public_access=is_public, now=now,
                ))

            # ── Module 4: data_residency ────────────────────────────────────
            location = emitted.get("location") or emitted.get("storageClass", "") or region
            in_eu = location in _EU_REGIONS or location.startswith("europe")
            in_us = location in _US_REGIONS or location.startswith("us")
            residency_ok = in_eu or in_us
            sev = "MEDIUM" if not residency_ok else "INFO"
            rule_id = f"gcp.dspm.data_residency.{slug}"
            findings.append(_base_finding(
                rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                account_id=account_id, region=region, scan_run_id=scan_run_id,
                tenant_id=tenant_id, dspm_module="data_residency",
                severity=sev, status="FAIL" if not residency_ok else "PASS",
                classification_labels=labels, encryption_status="unknown",
                public_access=False, now=now,
            ))

            # ── Module 5: activity_logging ──────────────────────────────────
            if resource_type in _BUCKET_TYPES:
                # GCS: logging.logBucket present means logging configured
                logging_config = emitted.get("logging", {})
                has_logging = bool(
                    logging_config.get("logBucket") if isinstance(logging_config, dict) else logging_config
                )
                sev = "HIGH" if not has_logging else "INFO"
                rule_id = f"gcp.dspm.activity_logging.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="activity_logging",
                    severity=sev, status="FAIL" if not has_logging else "PASS",
                    classification_labels=labels, encryption_status="unknown",
                    public_access=False, now=now,
                ))

            # ── Module 6: lifecycle ─────────────────────────────────────────
            if resource_type in _BUCKET_TYPES:
                versioning = emitted.get("versioning", {})
                versioning_on = (
                    versioning.get("enabled", False) if isinstance(versioning, dict) else bool(versioning)
                )
                lifecycle_rule = emitted.get("lifecycle", {})
                has_lifecycle = bool(
                    lifecycle_rule.get("rule") if isinstance(lifecycle_rule, dict) else lifecycle_rule
                )
                lifecycle_ok = versioning_on or has_lifecycle
                sev = "MEDIUM" if not lifecycle_ok else "INFO"
                rule_id = f"gcp.dspm.lifecycle.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="lifecycle",
                    severity=sev, status="FAIL" if not lifecycle_ok else "PASS",
                    classification_labels=labels, encryption_status="unknown",
                    public_access=False, now=now,
                ))

            # ── Module 7: data_lineage ──────────────────────────────────────
            rule_id = f"gcp.dspm.data_lineage.{slug}"
            findings.append(_base_finding(
                rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                account_id=account_id, region=region, scan_run_id=scan_run_id,
                tenant_id=tenant_id, dspm_module="data_lineage",
                severity="LOW", status="PASS",
                classification_labels=labels, encryption_status="unknown",
                public_access=False, now=now,
            ))

            # ── Module 8: governance_score ──────────────────────────────────
            enc_ok = resource_type in _SECRET_TYPES  # secrets always encrypted
            pub_ok = True
            if resource_type in _BUCKET_TYPES:
                iam_conf = emitted.get("iamConfiguration", {})
                enc_ok = True  # GCS always encrypted
                uniform2 = (
                    iam_conf.get("uniformBucketLevelAccess", {}).get("enabled", False)
                    if isinstance(iam_conf, dict) else False
                )
                pub_ok = bool(uniform2)
            score = int(sum([enc_ok, pub_ok]) / 2 * 100)
            gov_sev = "HIGH" if score < 50 else ("MEDIUM" if score < 80 else "LOW")
            rule_id = f"gcp.dspm.governance_score.{slug}"
            findings.append(_base_finding(
                rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                account_id=account_id, region=region, scan_run_id=scan_run_id,
                tenant_id=tenant_id, dspm_module="governance_score",
                severity=gov_sev, status="FAIL" if score < 80 else "PASS",
                classification_labels=labels, encryption_status="unknown",
                public_access=False, now=now,
            ))

        logger.info("GCP DSPM analyze(): produced %d findings from %d discovery rows", len(findings), len(rows))
        return findings
