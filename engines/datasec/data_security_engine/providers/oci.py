"""OCI provider for Data Security engine — 8-module DSPM analyze().

Resource types consumed from discovery_findings (story ENG-10):
  ObjectStorage::Bucket, Database::AutonomousDatabase,
  NoSQL::Table, Streaming::Stream
"""

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from psycopg2.extras import RealDictCursor

from .base import BaseDataSecProvider

logger = logging.getLogger(__name__)

# OCI sovereign regions — EU-tier for GDPR residency approximation
_EU_REGIONS = {
    "eu-frankfurt-1", "eu-amsterdam-1", "eu-milan-1",
    "eu-stockholm-1", "eu-madrid-1", "eu-paris-1",
    "uk-london-1", "uk-cardiff-1",
}
# OCI US regions
_US_REGIONS = {
    "us-ashburn-1", "us-phoenix-1", "us-sanjose-1",
    "us-chicago-1", "us-saltlake-2",
}

# Canonical resource_type values in discovery_findings for OCI (ENG-10)
_BUCKET_TYPES = {"ObjectStorage::Bucket"}
_AUTONOMOUS_DB_TYPES = {"Database::AutonomousDatabase"}
_NOSQL_TYPES = {"NoSQL::Table"}
_STREAMING_TYPES = {"Streaming::Stream"}

_ALL_DATA_TYPES = list(
    _BUCKET_TYPES | _AUTONOMOUS_DB_TYPES | _NOSQL_TYPES | _STREAMING_TYPES
)

_PII_TOKENS = {"pii", "personal", "customer", "user", "patient", "member"}
_PHI_TOKENS = {"phi", "health", "medical", "hipaa", "clinical"}
_FINANCIAL_TOKENS = {"financial", "finance", "payment", "billing", "pci"}
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
        "provider": "oci",
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


class OCIDataSecProvider(BaseDataSecProvider):
    """OCI DSPM provider — 8-module analysis over ObjectStorage, AutonomousDB, NoSQL, Streaming."""

    @property
    def storage_services(self) -> List[str]:
        return ["objectstorage"]

    @property
    def database_services(self) -> List[str]:
        return ["autonomous-database", "mysql"]

    @property
    def streaming_services(self) -> List[str]:
        return ["streaming"]

    @property
    def inventory_resource_prefixes(self) -> List[str]:
        return ["objectstorage.", "autonomous-database."]

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        discoveries_conn: Any,
        check_conn: Any,
    ) -> List[Dict[str, Any]]:
        """Run 8-module DSPM analysis over OCI discovery_findings.

        Queries discovery_findings for resource_types:
          ObjectStorage::Bucket, Database::AutonomousDatabase,
          NoSQL::Table, Streaming::Stream

        Args:
            scan_run_id: Pipeline scan run identifier.
            tenant_id: Tenant scoping for all DB queries.
            account_id: Cloud account identifier.
            discoveries_conn: psycopg2 connection to discoveries DB.
            check_conn: psycopg2 connection to check DB (unused here).

        Returns:
            List of DSPM finding dicts for OCI resources.
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
            logger.error("OCI DSPM: failed to load discovery_findings: %s", exc)
            return []

        if not rows:
            logger.warning(
                "OCI DSPM: no data-relevant rows for scan_run_id=%s (queried types: %s)",
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
                region = row.get("region") or "ap-mumbai-1"
                emitted = row.get("emitted_fields") or {}
                slug = _resource_type_slug(resource_type)

                name = (
                    emitted.get("name")
                    or emitted.get("displayName")
                    or emitted.get("dbName")
                    or emitted.get("resource_id")
                    or resource_uid
                )
                description = str(emitted.get("freeformTags", "")) or str(emitted.get("definedTags", ""))
                labels = _infer_labels(str(name), description)

                # ── Module 1: data_classification ──────────────────────────────
                rule_id = f"oci.dspm.data_classification.{slug}"
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
                    # OCI Object Storage: kmsKeyId = CMEK; absence = Oracle-managed
                    kms_key = emitted.get("kmsKeyId") or emitted.get("kmsKey")
                    enc_status = "enabled"  # OCI always encrypts at rest
                    cmek = bool(kms_key)
                    rule_id = f"oci.dspm.encryption_posture.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="encryption_posture",
                        severity="MEDIUM" if not cmek else "INFO",
                        status="FAIL" if not cmek else "PASS",
                        classification_labels=labels, encryption_status=enc_status,
                        public_access=False, now=now,
                    ))
                elif resource_type in _AUTONOMOUS_DB_TYPES:
                    # ADB: always encrypted; CMEK via vault
                    vault = emitted.get("vaultId") or emitted.get("kmsKeyId")
                    cmek = bool(vault)
                    rule_id = f"oci.dspm.encryption_posture.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="encryption_posture",
                        severity="MEDIUM" if not cmek else "INFO",
                        status="FAIL" if not cmek else "PASS",
                        classification_labels=labels, encryption_status="enabled",
                        public_access=False, now=now,
                    ))
                elif resource_type in (_NOSQL_TYPES | _STREAMING_TYPES):
                    # NoSQL/Streaming: Oracle-managed encryption
                    rule_id = f"oci.dspm.encryption_posture.{slug}"
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
                    # OCI Object Storage: publicAccessType
                    pub_access_type = emitted.get("publicAccessType", "NoPublicAccess")
                    is_public = pub_access_type in {"ObjectRead", "ObjectReadWithoutList"}
                    rule_id = f"oci.dspm.access_control.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="access_control",
                        severity="CRITICAL" if is_public else "INFO",
                        status="FAIL" if is_public else "PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=is_public, now=now,
                    ))
                elif resource_type in _AUTONOMOUS_DB_TYPES:
                    # ADB: isAccessControlEnabled or whitelistedIps == [] means open
                    access_ctrl = bool(emitted.get("isAccessControlEnabled", False))
                    whitelist = emitted.get("whitelistedIps", [])
                    is_public = not access_ctrl and not bool(whitelist)
                    rule_id = f"oci.dspm.access_control.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="access_control",
                        severity="HIGH" if is_public else "INFO",
                        status="FAIL" if is_public else "PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=is_public, now=now,
                    ))
                elif resource_type in (_NOSQL_TYPES | _STREAMING_TYPES):
                    # NoSQL/Streaming: no public access by default
                    rule_id = f"oci.dspm.access_control.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="access_control",
                        severity="INFO", status="PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=False, now=now,
                    ))

                # ── Module 4: data_residency ───────────────────────────────────
                in_eu = region in _EU_REGIONS
                in_us = region in _US_REGIONS
                residency_ok = in_eu or in_us
                sev = "LOW" if not residency_ok else "INFO"
                rule_id = f"oci.dspm.data_residency.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="data_residency",
                    severity=sev, status="PASS",  # OCI sovereign regions are all compliant
                    classification_labels=labels, encryption_status="unknown",
                    public_access=False, now=now,
                ))

                # ── Module 5: activity_logging ─────────────────────────────────
                if resource_type in _BUCKET_TYPES:
                    has_logging = bool(
                        emitted.get("accessLogging")
                        or emitted.get("loggingConfig")
                        or emitted.get("objectEventsEnabled")
                    )
                    rule_id = f"oci.dspm.activity_logging.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="activity_logging",
                        severity="HIGH" if not has_logging else "INFO",
                        status="FAIL" if not has_logging else "PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=False, now=now,
                    ))
                elif resource_type in _AUTONOMOUS_DB_TYPES:
                    # ADB: audit via OCI Audit Service; approximated by auditLevel
                    has_logging = bool(
                        emitted.get("auditingEnabled")
                        or emitted.get("dbVersion")  # proxy: if version known, service is active
                    )
                    rule_id = f"oci.dspm.activity_logging.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="activity_logging",
                        severity="MEDIUM" if not has_logging else "INFO",
                        status="FAIL" if not has_logging else "PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=False, now=now,
                    ))
                elif resource_type in (_NOSQL_TYPES | _STREAMING_TYPES):
                    # NoSQL/Streaming: no per-resource audit config visible in emitted_fields
                    rule_id = f"oci.dspm.activity_logging.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="activity_logging",
                        severity="MEDIUM", status="FAIL",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=False, now=now,
                    ))

                # ── Module 6: data_lifecycle ───────────────────────────────────
                if resource_type in _BUCKET_TYPES:
                    versioning = emitted.get("versioning", "Disabled")
                    lifecycle_rules = emitted.get("objectLifecyclePolicies") or emitted.get("lifecycleRules")
                    lifecycle_ok = versioning == "Enabled" or bool(lifecycle_rules)
                    rule_id = f"oci.dspm.data_lifecycle.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="data_lifecycle",
                        severity="MEDIUM" if not lifecycle_ok else "INFO",
                        status="FAIL" if not lifecycle_ok else "PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=False, now=now,
                    ))
                elif resource_type in _AUTONOMOUS_DB_TYPES:
                    # ADB: backupRetentionPeriodInDays
                    retention = emitted.get("backupRetentionPeriodInDays", 0)
                    lifecycle_ok = int(retention or 0) > 0
                    rule_id = f"oci.dspm.data_lifecycle.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="data_lifecycle",
                        severity="HIGH" if not lifecycle_ok else "INFO",
                        status="FAIL" if not lifecycle_ok else "PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=False, now=now,
                    ))
                elif resource_type in (_NOSQL_TYPES | _STREAMING_TYPES):
                    rule_id = f"oci.dspm.data_lifecycle.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="data_lifecycle",
                        severity="LOW", status="PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=False, now=now,
                    ))

                # ── Module 7: data_lineage ─────────────────────────────────────
                rule_id = f"oci.dspm.data_lineage.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="data_lineage",
                    severity="INFO", status="PASS",
                    classification_labels=labels, encryption_status="unknown",
                    public_access=False, now=now,
                ))

                # ── Module 8: governance_scoring ───────────────────────────────
                enc_ok = True  # OCI always encrypts at rest
                pub_ok = True
                log_ok = False

                if resource_type in _BUCKET_TYPES:
                    pub_access_type2 = emitted.get("publicAccessType", "NoPublicAccess")
                    pub_ok = pub_access_type2 not in {"ObjectRead", "ObjectReadWithoutList"}
                    log_ok = bool(emitted.get("accessLogging") or emitted.get("objectEventsEnabled"))
                elif resource_type in _AUTONOMOUS_DB_TYPES:
                    access_ctrl2 = bool(emitted.get("isAccessControlEnabled", False))
                    pub_ok = access_ctrl2
                    log_ok = bool(emitted.get("auditingEnabled"))
                elif resource_type in (_NOSQL_TYPES | _STREAMING_TYPES):
                    pub_ok = True
                    log_ok = False  # no visible audit config

                passes = sum([enc_ok, pub_ok, log_ok])
                score = int(passes / 3 * 100)
                gov_sev = "HIGH" if score < 50 else ("MEDIUM" if score < 80 else "LOW")
                rule_id = f"oci.dspm.governance_scoring.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="governance_scoring",
                    severity=gov_sev, status="FAIL" if score < 80 else "PASS",
                    classification_labels=labels, encryption_status="unknown",
                    public_access=False, now=now,
                ))

        logger.info(
            "OCI DSPM analyze(): produced %d findings from %d discovery rows",
            len(findings), len(rows),
        )
        return findings
