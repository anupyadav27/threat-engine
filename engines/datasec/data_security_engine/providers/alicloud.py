"""AliCloud provider for Data Security engine — 8-module DSPM analyze().

Resource types consumed from discovery_findings (story ENG-10):
  OSS::Bucket, RDS::DBInstance, PolarDB::Cluster,
  TableStore::Instance, MaxCompute::Project
"""

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from psycopg2.extras import RealDictCursor

from .base import BaseDataSecProvider

logger = logging.getLogger(__name__)

# Canonical resource_type values in discovery_findings for AliCloud (ENG-10)
_OSS_TYPES = {"OSS::Bucket"}
_RDS_TYPES = {"RDS::DBInstance"}
_POLARDB_TYPES = {"PolarDB::Cluster"}
_TABLESTORE_TYPES = {"TableStore::Instance"}
_MAXCOMPUTE_TYPES = {"MaxCompute::Project"}

_ALL_DATA_TYPES = list(
    _OSS_TYPES | _RDS_TYPES | _POLARDB_TYPES | _TABLESTORE_TYPES | _MAXCOMPUTE_TYPES
)

_PII_TOKENS = {"pii", "personal", "customer", "user", "patient", "member", "employee"}
_PHI_TOKENS = {"phi", "health", "medical", "hipaa", "clinical"}
_FINANCIAL_TOKENS = {"financial", "finance", "payment", "billing", "pci", "card", "bank"}
_CONFIDENTIAL_TOKENS = {"secret", "credential", "password", "token", "key", "private", "sensitive", "confidential"}


def _make_finding_id(rule_id: str, resource_uid: str, account_id: str, region: str) -> str:
    """Build canonical finding_id as sha256[:16]."""
    raw = f"{rule_id}|{resource_uid}|{account_id}|{region}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _resource_type_slug(resource_type: str) -> str:
    """Convert resource_type to rule_id slug."""
    return "".join(c if c.isalnum() else "_" for c in resource_type.lower()).strip("_")


def _infer_labels(name: str, resource_type: str = "", description: str = "") -> List[str]:
    """Infer classification labels from resource name, type, and description tokens."""
    text = (name + " " + resource_type + " " + description).lower()
    tokens = set(
        text.replace("-", " ").replace("_", " ").replace(".", " ").replace("/", " ").split()
    )
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
        "provider": "alicloud",
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


class AliCloudDataSecProvider(BaseDataSecProvider):
    """AliCloud DSPM provider — 8-module analysis over OSS, RDS, PolarDB, TableStore, MaxCompute."""

    @property
    def storage_services(self) -> List[str]:
        return ["oss"]

    @property
    def database_services(self) -> List[str]:
        return ["rds", "polardb", "mongodb", "tablestore"]

    @property
    def streaming_services(self) -> List[str]:
        return ["mns", "eventbridge", "datahub"]

    @property
    def inventory_resource_prefixes(self) -> List[str]:
        return ["oss.", "rds.", "polardb.", "mns."]

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        discoveries_conn: Any,
        check_conn: Any,
    ) -> List[Dict[str, Any]]:
        """Run 8-module DSPM analysis over AliCloud discovery_findings.

        Queries discovery_findings for resource_types:
          OSS::Bucket, RDS::DBInstance, PolarDB::Cluster,
          TableStore::Instance, MaxCompute::Project

        Args:
            scan_run_id: Pipeline scan run identifier.
            tenant_id: Tenant scoping for all DB queries.
            account_id: Cloud account identifier.
            discoveries_conn: psycopg2 connection to discoveries DB.
            check_conn: psycopg2 connection to check DB (unused here).

        Returns:
            List of DSPM finding dicts for AliCloud resources.
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
            logger.error("AliCloud DSPM: failed to load discovery_findings: %s", exc)
            return []

        if not rows:
            logger.warning(
                "AliCloud DSPM: no data-relevant rows for scan_run_id=%s (queried types: %s)",
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
                region = row.get("region") or "cn-hangzhou"
                emitted = row.get("emitted_fields") or {}
                slug = _resource_type_slug(resource_type)

                name = (
                    emitted.get("BucketName")
                    or emitted.get("DBInstanceId")
                    or emitted.get("DBClusterId")
                    or emitted.get("InstanceName")
                    or emitted.get("ProjectName")
                    or emitted.get("Name")
                    or emitted.get("resource_id")
                    or resource_uid
                )
                description = str(emitted.get("Tags", "")) or str(emitted.get("Comment", ""))
                labels = _infer_labels(str(name), resource_type, description)

                # ── Module 1: data_classification ──────────────────────────────
                rule_id = f"alicloud.dspm.data_classification.{slug}"
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
                if resource_type in _OSS_TYPES:
                    # OSS: ServerSideEncryption rule
                    sse_rule = emitted.get("ServerSideEncryptionRule", {})
                    sse_alg = (
                        sse_rule.get("SSEAlgorithm", "None")
                        if isinstance(sse_rule, dict) else ""
                    )
                    enc_ok = sse_alg not in ("None", "", "null")
                    enc_status = "enabled" if enc_ok else "disabled"
                    rule_id = f"alicloud.dspm.encryption_posture.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="encryption_posture",
                        severity="CRITICAL" if not enc_ok else "INFO",
                        status="FAIL" if not enc_ok else "PASS",
                        classification_labels=labels, encryption_status=enc_status,
                        public_access=False, now=now,
                    ))
                elif resource_type in _RDS_TYPES:
                    # RDS: TDE encryption status
                    tde = emitted.get("TDEStatus", "") or emitted.get("StorageType", "")
                    enc_ok = str(tde).lower() in ("enabled", "local_ssd", "cloud_essd")
                    enc_status = "enabled" if enc_ok else "disabled"
                    rule_id = f"alicloud.dspm.encryption_posture.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="encryption_posture",
                        severity="HIGH" if not enc_ok else "INFO",
                        status="FAIL" if not enc_ok else "PASS",
                        classification_labels=labels, encryption_status=enc_status,
                        public_access=False, now=now,
                    ))
                elif resource_type in _POLARDB_TYPES:
                    # PolarDB: TDE encryption
                    tde_status = emitted.get("TDEStatus", "Disabled")
                    enc_ok = str(tde_status).lower() == "enabled"
                    enc_status = "enabled" if enc_ok else "disabled"
                    rule_id = f"alicloud.dspm.encryption_posture.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="encryption_posture",
                        severity="HIGH" if not enc_ok else "INFO",
                        status="FAIL" if not enc_ok else "PASS",
                        classification_labels=labels, encryption_status=enc_status,
                        public_access=False, now=now,
                    ))
                elif resource_type in (_TABLESTORE_TYPES | _MAXCOMPUTE_TYPES):
                    # TableStore/MaxCompute: encryption always on (AliCloud managed)
                    rule_id = f"alicloud.dspm.encryption_posture.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="encryption_posture",
                        severity="INFO", status="PASS",
                        classification_labels=labels, encryption_status="enabled",
                        public_access=False, now=now,
                    ))

                # ── Module 3: access_control ───────────────────────────────────
                if resource_type in _OSS_TYPES:
                    # OSS: ACL public-read or public-read-write = public
                    acl = emitted.get("AccessControlList", {}) or emitted.get("Grant", "private")
                    acl_str = (
                        acl.get("Grant", "private") if isinstance(acl, dict) else str(acl)
                    )
                    is_public = acl_str in ("public-read", "public-read-write")
                    rule_id = f"alicloud.dspm.access_control.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="access_control",
                        severity="CRITICAL" if is_public else "INFO",
                        status="FAIL" if is_public else "PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=is_public, now=now,
                    ))
                elif resource_type in _RDS_TYPES:
                    # RDS: DBInstanceNetType = Internet = public
                    net_type = emitted.get("DBInstanceNetType", "Intranet")
                    is_public = str(net_type).lower() == "internet"
                    rule_id = f"alicloud.dspm.access_control.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="access_control",
                        severity="CRITICAL" if is_public else "INFO",
                        status="FAIL" if is_public else "PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=is_public, now=now,
                    ))
                elif resource_type in (_POLARDB_TYPES | _TABLESTORE_TYPES | _MAXCOMPUTE_TYPES):
                    # PolarDB/TableStore/MaxCompute: internal-only by default
                    rule_id = f"alicloud.dspm.access_control.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="access_control",
                        severity="INFO", status="PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=False, now=now,
                    ))

                # ── Module 4: data_residency ───────────────────────────────────
                # AliCloud China regions for data sovereignty compliance
                in_cn = region.startswith("cn-")
                # Non-China regions are flagged as potential residency concern
                sev = "MEDIUM" if not in_cn else "INFO"
                rule_id = f"alicloud.dspm.data_residency.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="data_residency",
                    severity=sev, status="FAIL" if not in_cn else "PASS",
                    classification_labels=labels, encryption_status="unknown",
                    public_access=False, now=now,
                ))

                # ── Module 5: activity_logging ─────────────────────────────────
                if resource_type in _OSS_TYPES:
                    # OSS: logging enabled via LoggingConfiguration
                    log_cfg = emitted.get("LoggingConfiguration") or emitted.get("logging")
                    has_logging = bool(log_cfg)
                    rule_id = f"alicloud.dspm.activity_logging.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="activity_logging",
                        severity="HIGH" if not has_logging else "INFO",
                        status="FAIL" if not has_logging else "PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=False, now=now,
                    ))
                elif resource_type in _RDS_TYPES:
                    # RDS: SQLAuditStatus = Enable
                    audit = emitted.get("SQLAuditStatus", "") or emitted.get("SecurityAuditStatus", "")
                    has_logging = str(audit).lower() in ("enable", "enabled", "on")
                    rule_id = f"alicloud.dspm.activity_logging.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="activity_logging",
                        severity="HIGH" if not has_logging else "INFO",
                        status="FAIL" if not has_logging else "PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=False, now=now,
                    ))
                elif resource_type in (_POLARDB_TYPES | _TABLESTORE_TYPES | _MAXCOMPUTE_TYPES):
                    # PolarDB/TableStore/MaxCompute: audit logging not visible in emitted_fields
                    rule_id = f"alicloud.dspm.activity_logging.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="activity_logging",
                        severity="MEDIUM", status="FAIL",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=False, now=now,
                    ))

                # ── Module 6: data_lifecycle ───────────────────────────────────
                if resource_type in _OSS_TYPES:
                    # OSS: LifecycleConfiguration rules
                    lifecycle_cfg = emitted.get("LifecycleConfiguration") or emitted.get("lifecycle")
                    lifecycle_ok = bool(lifecycle_cfg)
                    rule_id = f"alicloud.dspm.data_lifecycle.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="data_lifecycle",
                        severity="MEDIUM" if not lifecycle_ok else "INFO",
                        status="FAIL" if not lifecycle_ok else "PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=False, now=now,
                    ))
                elif resource_type in _RDS_TYPES:
                    # RDS: BackupRetentionPeriod
                    retention = emitted.get("BackupRetentionPeriod", 0)
                    lifecycle_ok = int(retention or 0) > 0
                    rule_id = f"alicloud.dspm.data_lifecycle.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="data_lifecycle",
                        severity="HIGH" if not lifecycle_ok else "INFO",
                        status="FAIL" if not lifecycle_ok else "PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=False, now=now,
                    ))
                elif resource_type in (_POLARDB_TYPES | _TABLESTORE_TYPES | _MAXCOMPUTE_TYPES):
                    backup = emitted.get("BackupRetentionPolicyOnClusterDeletion") or emitted.get("BackupRetentionPeriod")
                    lifecycle_ok = bool(backup)
                    rule_id = f"alicloud.dspm.data_lifecycle.{slug}"
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
                # MaxCompute: data processing jobs indicate upstream/downstream flows
                if resource_type in _MAXCOMPUTE_TYPES:
                    jobs = emitted.get("Jobs") or emitted.get("tables")
                    has_flow = bool(jobs)
                    rule_id = f"alicloud.dspm.data_lineage.{slug}"
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
                    rule_id = f"alicloud.dspm.data_lineage.{slug}"
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

                if resource_type in _OSS_TYPES:
                    sse_r = emitted.get("ServerSideEncryptionRule", {})
                    sse_a = sse_r.get("SSEAlgorithm", "None") if isinstance(sse_r, dict) else ""
                    enc_ok = sse_a not in ("None", "", "null")
                    acl2 = emitted.get("AccessControlList", {}) or {}
                    acl_str2 = acl2.get("Grant", "private") if isinstance(acl2, dict) else str(acl2)
                    pub_ok = acl_str2 not in ("public-read", "public-read-write")
                    log_ok = bool(emitted.get("LoggingConfiguration") or emitted.get("logging"))
                elif resource_type in _RDS_TYPES:
                    tde2 = emitted.get("TDEStatus", "")
                    enc_ok = str(tde2).lower() == "enabled"
                    net_type2 = emitted.get("DBInstanceNetType", "Intranet")
                    pub_ok = str(net_type2).lower() != "internet"
                    audit2 = emitted.get("SQLAuditStatus", "")
                    log_ok = str(audit2).lower() in ("enable", "enabled", "on")
                elif resource_type in _POLARDB_TYPES:
                    tde3 = emitted.get("TDEStatus", "Disabled")
                    enc_ok = str(tde3).lower() == "enabled"
                    pub_ok = True
                    log_ok = False
                elif resource_type in (_TABLESTORE_TYPES | _MAXCOMPUTE_TYPES):
                    enc_ok = True  # always encrypted
                    pub_ok = True
                    log_ok = False

                passes = sum([enc_ok, pub_ok, log_ok])
                score = int(passes / 3 * 100)
                gov_sev = "HIGH" if score < 50 else ("MEDIUM" if score < 80 else "LOW")
                rule_id = f"alicloud.dspm.governance_scoring.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="governance_scoring",
                    severity=gov_sev, status="FAIL" if score < 80 else "PASS",
                    classification_labels=labels, encryption_status="unknown",
                    public_access=False, now=now,
                ))

        logger.info(
            "AliCloud DSPM analyze(): produced %d findings from %d discovery rows",
            len(findings), len(rows),
        )
        return findings
