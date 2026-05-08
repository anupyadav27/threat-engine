"""GCP provider for Data Security engine — 8-module DSPM analyze().

Resource types consumed from discovery_findings (story ENG-10):
  Storage::Bucket, CloudSQL::Instance, BigQuery::Dataset,
  Spanner::Instance, Firestore::Database, SecretManager::Secret
"""

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
_US_REGIONS = {
    "us-central1", "us-east1", "us-east4", "us-west1",
    "us-west2", "us-west3", "us-west4", "US",
}

# Canonical resource_type values in discovery_findings for GCP (ENG-10)
_BUCKET_TYPES = {"Storage::Bucket"}
_CLOUDSQL_TYPES = {"CloudSQL::Instance"}
_BIGQUERY_TYPES = {"BigQuery::Dataset"}
_SPANNER_TYPES = {"Spanner::Instance"}
_FIRESTORE_TYPES = {"Firestore::Database"}
_SECRET_TYPES = {"SecretManager::Secret"}

_ALL_DATA_TYPES = list(
    _BUCKET_TYPES | _CLOUDSQL_TYPES | _BIGQUERY_TYPES
    | _SPANNER_TYPES | _FIRESTORE_TYPES | _SECRET_TYPES
)

_PII_TOKENS = {"pii", "personal", "customer", "user", "patient", "member", "employee"}
_PHI_TOKENS = {"phi", "health", "medical", "hipaa", "clinical"}
_FINANCIAL_TOKENS = {"financial", "finance", "payment", "billing", "pci", "card", "bank"}
_CONFIDENTIAL_TOKENS = {"secret", "credential", "password", "token", "key", "private", "sensitive"}


def _make_finding_id(rule_id: str, resource_uid: str, account_id: str, region: str) -> str:
    """Build canonical finding_id as sha256[:16]."""
    raw = f"{rule_id}|{resource_uid}|{account_id}|{region}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _resource_type_slug(resource_type: str) -> str:
    """Convert resource_type to rule_id slug."""
    return "".join(c if c.isalnum() else "_" for c in resource_type.lower()).strip("_")


def _infer_labels(name: str, description: str = "") -> List[str]:
    """Infer classification labels from resource name and description tokens."""
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
    """Build a canonical DSPM finding dict."""
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
    """GCP DSPM provider — 8-module analysis over GCS, CloudSQL, BigQuery, Spanner, Firestore, SecretManager."""

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

        Queries discovery_findings for resource_types:
          Storage::Bucket, CloudSQL::Instance, BigQuery::Dataset,
          Spanner::Instance, Firestore::Database, SecretManager::Secret

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
                    (scan_run_id, tenant_id, _ALL_DATA_TYPES),
                )
                rows = cur.fetchall()
        except Exception as exc:
            logger.error("GCP DSPM: failed to load discovery_findings: %s", exc)
            return []

        if not rows:
            logger.warning(
                "GCP DSPM: no data-relevant rows for scan_run_id=%s (queried types: %s)",
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
                region = row.get("region") or "us-central1"
                emitted = row.get("emitted_fields") or {}
                slug = _resource_type_slug(resource_type)

                name = (
                    emitted.get("name")
                    or emitted.get("id")
                    or emitted.get("friendlyName")
                    or emitted.get("resource_id")
                    or resource_uid
                )
                description = str(emitted.get("description", "")) or str(emitted.get("labels", ""))
                labels = _infer_labels(str(name), description)

                # ── Module 1: data_classification ──────────────────────────────
                rule_id = f"gcp.dspm.data_classification.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="data_classification",
                    severity="HIGH" if labels else "MEDIUM",
                    status="FAIL" if labels else "PASS",
                    classification_labels=labels, encryption_status="unknown",
                    public_access=False, now=now,
                ))

                # ── Module 2: encryption_posture ───────────────────────────────
                if resource_type in _BUCKET_TYPES:
                    # GCS: always encrypted; CMEK = customer-managed key
                    enc_config = emitted.get("encryption") or emitted.get("encryptionConfiguration")
                    cmek = bool(
                        isinstance(enc_config, dict) and enc_config.get("defaultKmsKeyName")
                    )
                    enc_status = "enabled"  # GCS always encrypted at rest
                    # Flag MEDIUM if not CMEK (customer-managed)
                    rule_id = f"gcp.dspm.encryption_posture.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="encryption_posture",
                        severity="MEDIUM" if not cmek else "INFO",
                        status="FAIL" if not cmek else "PASS",
                        classification_labels=labels, encryption_status=enc_status,
                        public_access=False, now=now,
                    ))
                elif resource_type in _CLOUDSQL_TYPES:
                    # CloudSQL: diskEncryptionConfiguration
                    disk_enc = emitted.get("diskEncryptionConfiguration") or emitted.get("databaseFlags")
                    cmek = bool(
                        isinstance(disk_enc, dict) and disk_enc.get("kmsKeyName")
                    )
                    enc_status = "enabled"  # CloudSQL always encrypted at rest
                    rule_id = f"gcp.dspm.encryption_posture.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="encryption_posture",
                        severity="MEDIUM" if not cmek else "INFO",
                        status="FAIL" if not cmek else "PASS",
                        classification_labels=labels, encryption_status=enc_status,
                        public_access=False, now=now,
                    ))
                elif resource_type in _BIGQUERY_TYPES:
                    # BigQuery: defaultEncryptionConfiguration
                    bq_enc = emitted.get("defaultEncryptionConfiguration", {})
                    cmek = bool(
                        isinstance(bq_enc, dict) and bq_enc.get("kmsKeyName")
                    )
                    enc_status = "enabled"  # BigQuery always encrypted
                    rule_id = f"gcp.dspm.encryption_posture.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="encryption_posture",
                        severity="MEDIUM" if not cmek else "INFO",
                        status="FAIL" if not cmek else "PASS",
                        classification_labels=labels, encryption_status=enc_status,
                        public_access=False, now=now,
                    ))
                elif resource_type in (_SPANNER_TYPES | _FIRESTORE_TYPES):
                    # Spanner/Firestore: always encrypted; flag CMEK absence as MEDIUM
                    cmek = bool(emitted.get("encryptionConfig", {}).get("kmsKeyName"))
                    enc_status = "enabled"
                    rule_id = f"gcp.dspm.encryption_posture.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="encryption_posture",
                        severity="MEDIUM" if not cmek else "INFO",
                        status="FAIL" if not cmek else "PASS",
                        classification_labels=labels, encryption_status=enc_status,
                        public_access=False, now=now,
                    ))
                elif resource_type in _SECRET_TYPES:
                    # Secret Manager: always encrypted — PASS
                    rule_id = f"gcp.dspm.encryption_posture.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="encryption_posture",
                        severity="INFO", status="PASS",
                        classification_labels=labels, encryption_status="enabled",
                        public_access=False, now=now,
                    ))

                # ── Module 3: access_control ───────────────────────────────────
                if resource_type in _BUCKET_TYPES:
                    iam_config = emitted.get("iamConfiguration", {})
                    uniform = (
                        iam_config.get("uniformBucketLevelAccess", {}).get("enabled", False)
                        if isinstance(iam_config, dict) else False
                    )
                    pub_prevention = (
                        iam_config.get("publicAccessPrevention", "unspecified")
                        if isinstance(iam_config, dict) else "unspecified"
                    )
                    is_public = not uniform and pub_prevention != "enforced"
                    rule_id = f"gcp.dspm.access_control.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="access_control",
                        severity="HIGH" if is_public else "INFO",
                        status="FAIL" if is_public else "PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=is_public, now=now,
                    ))
                elif resource_type in _CLOUDSQL_TYPES:
                    # CloudSQL: ipConfiguration.requireSsl + authorizedNetworks
                    ip_cfg = emitted.get("settings", {}).get("ipConfiguration", {}) if isinstance(emitted.get("settings"), dict) else {}
                    ssl_required = bool(ip_cfg.get("requireSsl", False)) if isinstance(ip_cfg, dict) else False
                    auth_nets = ip_cfg.get("authorizedNetworks", []) if isinstance(ip_cfg, dict) else []
                    overly_open = any(
                        n.get("value") in ("0.0.0.0/0", "::/0")
                        for n in (auth_nets if isinstance(auth_nets, list) else [])
                    )
                    is_public = overly_open or not ssl_required
                    rule_id = f"gcp.dspm.access_control.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="access_control",
                        severity="CRITICAL" if overly_open else ("MEDIUM" if is_public else "INFO"),
                        status="FAIL" if is_public else "PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=is_public, now=now,
                    ))
                elif resource_type in (_BIGQUERY_TYPES | _SPANNER_TYPES | _FIRESTORE_TYPES | _SECRET_TYPES):
                    # BigQuery/Spanner/Firestore/SecretManager: check IAM bindings for allUsers
                    iam = emitted.get("iamPolicy", {}) or emitted.get("policy", {})
                    bindings = iam.get("bindings", []) if isinstance(iam, dict) else []
                    is_public = any(
                        "allUsers" in b.get("members", []) or "allAuthenticatedUsers" in b.get("members", [])
                        for b in (bindings if isinstance(bindings, list) else [])
                    )
                    rule_id = f"gcp.dspm.access_control.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="access_control",
                        severity="CRITICAL" if is_public else "INFO",
                        status="FAIL" if is_public else "PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=is_public, now=now,
                    ))

                # ── Module 4: data_residency ───────────────────────────────────
                location = emitted.get("location") or emitted.get("storageClass", "") or region
                in_eu = str(location).startswith("europe") or location in _EU_REGIONS
                in_us = str(location).startswith("us") or location in _US_REGIONS
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

                # ── Module 5: activity_logging ─────────────────────────────────
                if resource_type in _BUCKET_TYPES:
                    logging_cfg = emitted.get("logging", {})
                    has_logging = bool(
                        isinstance(logging_cfg, dict) and logging_cfg.get("logBucket")
                    )
                    rule_id = f"gcp.dspm.activity_logging.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="activity_logging",
                        severity="HIGH" if not has_logging else "INFO",
                        status="FAIL" if not has_logging else "PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=False, now=now,
                    ))
                elif resource_type in _CLOUDSQL_TYPES:
                    # CloudSQL: database flags for logging
                    flags = emitted.get("settings", {}).get("databaseFlags", []) if isinstance(emitted.get("settings"), dict) else []
                    log_flag = any(
                        f.get("name") in ("log_connections", "log_disconnections", "log_min_messages")
                        for f in (flags if isinstance(flags, list) else [])
                    )
                    has_logging = log_flag
                    rule_id = f"gcp.dspm.activity_logging.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="activity_logging",
                        severity="HIGH" if not has_logging else "INFO",
                        status="FAIL" if not has_logging else "PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=False, now=now,
                    ))
                elif resource_type in (_BIGQUERY_TYPES | _SPANNER_TYPES | _FIRESTORE_TYPES | _SECRET_TYPES):
                    # BigQuery/Spanner: audit logs via Cloud Audit Logs (always on in most configs)
                    # approximated by presence of auditConfigs or IAM audit settings
                    audit_cfg = (
                        emitted.get("iamPolicy", {}).get("auditConfigs", [])
                        if isinstance(emitted.get("iamPolicy"), dict) else []
                    )
                    has_logging = bool(audit_cfg)
                    rule_id = f"gcp.dspm.activity_logging.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="activity_logging",
                        severity="MEDIUM" if not has_logging else "INFO",
                        status="FAIL" if not has_logging else "PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=False, now=now,
                    ))

                # ── Module 6: data_lifecycle ───────────────────────────────────
                if resource_type in _BUCKET_TYPES:
                    versioning = emitted.get("versioning", {})
                    versioning_on = (
                        isinstance(versioning, dict) and versioning.get("enabled", False)
                    )
                    lifecycle_rule = emitted.get("lifecycle", {})
                    has_lifecycle = bool(
                        isinstance(lifecycle_rule, dict) and lifecycle_rule.get("rule")
                    )
                    lifecycle_ok = versioning_on or has_lifecycle
                    rule_id = f"gcp.dspm.data_lifecycle.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="data_lifecycle",
                        severity="MEDIUM" if not lifecycle_ok else "INFO",
                        status="FAIL" if not lifecycle_ok else "PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=False, now=now,
                    ))
                elif resource_type in _CLOUDSQL_TYPES:
                    # CloudSQL: backupConfiguration enabled
                    backup_cfg = emitted.get("settings", {}).get("backupConfiguration", {}) if isinstance(emitted.get("settings"), dict) else {}
                    backup_on = isinstance(backup_cfg, dict) and bool(backup_cfg.get("enabled", False))
                    rule_id = f"gcp.dspm.data_lifecycle.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="data_lifecycle",
                        severity="HIGH" if not backup_on else "INFO",
                        status="FAIL" if not backup_on else "PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=False, now=now,
                    ))
                elif resource_type in (_BIGQUERY_TYPES | _SPANNER_TYPES | _FIRESTORE_TYPES | _SECRET_TYPES):
                    # BigQuery: defaultTableExpirationMs; Spanner: no native TTL
                    ttl = emitted.get("defaultTableExpirationMs") or emitted.get("retentionPeriod")
                    lifecycle_ok = bool(ttl)
                    rule_id = f"gcp.dspm.data_lifecycle.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="data_lifecycle",
                        severity="LOW" if not lifecycle_ok else "INFO",
                        status="FAIL" if not lifecycle_ok else "PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=False, now=now,
                    ))

                # ── Module 7: data_lineage ─────────────────────────────────────
                # BigQuery: linked datasets / transfer config = downstream data flows
                if resource_type in _BIGQUERY_TYPES:
                    transfers = emitted.get("transferConfigs") or emitted.get("linkedDataset")
                    has_flow = bool(transfers)
                    rule_id = f"gcp.dspm.data_lineage.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="data_lineage",
                        severity="LOW" if has_flow else "INFO",
                        status="PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=False, now=now,
                    ))
                else:
                    rule_id = f"gcp.dspm.data_lineage.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="data_lineage",
                        severity="INFO", status="PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=False, now=now,
                    ))

                # ── Module 8: governance_scoring ───────────────────────────────
                enc_ok = False
                pub_ok = True
                log_ok = False

                if resource_type in _BUCKET_TYPES:
                    enc_ok = True  # GCS always encrypted
                    iam_c = emitted.get("iamConfiguration", {})
                    pub_ok = bool(
                        isinstance(iam_c, dict)
                        and iam_c.get("uniformBucketLevelAccess", {}).get("enabled", False)
                    )
                    log_ok = bool(
                        isinstance(emitted.get("logging"), dict)
                        and emitted.get("logging", {}).get("logBucket")
                    )
                elif resource_type in _CLOUDSQL_TYPES:
                    enc_ok = True  # CloudSQL always encrypted
                    settings = emitted.get("settings", {})
                    ip_c = settings.get("ipConfiguration", {}) if isinstance(settings, dict) else {}
                    pub_ok = not any(
                        n.get("value") in ("0.0.0.0/0", "::/0")
                        for n in (ip_c.get("authorizedNetworks", []) if isinstance(ip_c, dict) else [])
                    )
                    flags2 = settings.get("databaseFlags", []) if isinstance(settings, dict) else []
                    log_ok = any(
                        f.get("name") in ("log_connections",)
                        for f in (flags2 if isinstance(flags2, list) else [])
                    )
                elif resource_type in _BIGQUERY_TYPES:
                    enc_ok = True  # BigQuery always encrypted
                    iam2 = emitted.get("iamPolicy", {})
                    bindings2 = iam2.get("bindings", []) if isinstance(iam2, dict) else []
                    pub_ok = not any(
                        "allUsers" in b.get("members", [])
                        for b in (bindings2 if isinstance(bindings2, list) else [])
                    )
                    log_ok = bool(iam2.get("auditConfigs") if isinstance(iam2, dict) else False)
                elif resource_type in (_SPANNER_TYPES | _FIRESTORE_TYPES | _SECRET_TYPES):
                    enc_ok = True  # always encrypted
                    iam3 = emitted.get("iamPolicy", {})
                    bindings3 = iam3.get("bindings", []) if isinstance(iam3, dict) else []
                    pub_ok = not any(
                        "allUsers" in b.get("members", [])
                        for b in (bindings3 if isinstance(bindings3, list) else [])
                    )
                    log_ok = bool(iam3.get("auditConfigs") if isinstance(iam3, dict) else False)

                passes = sum([enc_ok, pub_ok, log_ok])
                score = int(passes / 3 * 100)
                gov_sev = "HIGH" if score < 50 else ("MEDIUM" if score < 80 else "LOW")
                rule_id = f"gcp.dspm.governance_scoring.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="governance_scoring",
                    severity=gov_sev, status="FAIL" if score < 80 else "PASS",
                    classification_labels=labels, encryption_status="unknown",
                    public_access=False, now=now,
                ))

        logger.info(
            "GCP DSPM analyze(): produced %d findings from %d discovery rows",
            len(findings), len(rows),
        )
        return findings
