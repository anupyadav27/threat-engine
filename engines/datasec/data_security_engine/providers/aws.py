"""AWS provider for Data Security engine — 8-module DSPM analyze().

Resource types consumed from discovery_findings (story ENG-10):
  S3::Bucket, RDS::DBInstance, DynamoDB::Table, Redshift::Cluster,
  Glue::Database, ElasticSearch::Domain, Kinesis::Stream
"""

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from psycopg2.extras import RealDictCursor

from .base import BaseDataSecProvider

logger = logging.getLogger(__name__)

# EU regions for GDPR residency check
_EU_REGIONS = {
    "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-central-2",
    "eu-north-1", "eu-south-1", "eu-south-2",
}
# US regions for HIPAA residency check
_US_REGIONS = {
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "us-gov-east-1", "us-gov-west-1",
}

# Canonical resource_type values in discovery_findings for AWS data resources (ENG-10)
_S3_TYPES = {"S3::Bucket"}
_RDS_TYPES = {"RDS::DBInstance"}
_DYNAMO_TYPES = {"DynamoDB::Table"}
_REDSHIFT_TYPES = {"Redshift::Cluster"}
_GLUE_TYPES = {"Glue::Database"}
_ES_TYPES = {"ElasticSearch::Domain"}
_KINESIS_TYPES = {"Kinesis::Stream"}

# Storage types: full classification + encryption + access + lifecycle analysis
_STORAGE_TYPES = _S3_TYPES
# Database types: encryption + residency + logging analysis
_DATABASE_TYPES = _RDS_TYPES | _DYNAMO_TYPES | _REDSHIFT_TYPES | _GLUE_TYPES | _ES_TYPES
# Streaming types: access + logging analysis
_STREAMING_TYPES = _KINESIS_TYPES

_ALL_DATA_TYPES = list(
    _STORAGE_TYPES | _DATABASE_TYPES | _STREAMING_TYPES
)

# Classification label hints by resource name / description tokens
_PII_TOKENS = {"pii", "personal", "customer", "user", "patient", "member", "employee", "contact", "profile"}
_PHI_TOKENS = {"phi", "health", "medical", "hipaa", "patient", "clinical", "ehr", "emr"}
_FINANCIAL_TOKENS = {"financial", "finance", "payment", "billing", "pci", "card", "bank", "transaction", "revenue"}
_CONFIDENTIAL_TOKENS = {"secret", "credential", "password", "token", "key", "private", "sensitive", "confidential"}


def _make_finding_id(rule_id: str, resource_uid: str, account_id: str, region: str) -> str:
    """Build canonical finding_id as sha256[:16]."""
    raw = f"{rule_id}|{resource_uid}|{account_id}|{region}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _resource_type_slug(resource_type: str) -> str:
    """Convert resource_type to rule_id slug (lowercase, replace non-alnum with _)."""
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
        "provider": "aws",
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


class AWSDataSecProvider(BaseDataSecProvider):
    """AWS DSPM provider — 8-module analysis over S3, RDS, DynamoDB, Redshift, Glue, ES, Kinesis."""

    @property
    def storage_services(self) -> List[str]:
        return ["s3", "glacier", "s3control", "s3outposts"]

    @property
    def database_services(self) -> List[str]:
        return [
            "rds", "dynamodb", "redshift", "documentdb",
            "neptune", "opensearch", "glue", "lakeformation",
            "athena", "dax", "timestream", "keyspaces",
        ]

    @property
    def streaming_services(self) -> List[str]:
        return ["sns", "sqs", "kinesis", "firehose", "kafka", "msk"]

    @property
    def inventory_resource_prefixes(self) -> List[str]:
        return [
            "s3.", "rds.", "dynamodb.", "redshift.",
            "kinesis.", "sqs.", "sns.", "glue.", "athena.",
        ]

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        discoveries_conn: Any,
        check_conn: Any,
    ) -> List[Dict[str, Any]]:
        """Run 8-module DSPM analysis over AWS discovery_findings.

        Queries discovery_findings for resource_types:
          S3::Bucket, RDS::DBInstance, DynamoDB::Table, Redshift::Cluster,
          Glue::Database, ElasticSearch::Domain, Kinesis::Stream

        Args:
            scan_run_id: Pipeline scan run identifier.
            tenant_id: Tenant scoping for all DB queries.
            account_id: Cloud account identifier.
            discoveries_conn: psycopg2 connection to discoveries DB.
            check_conn: psycopg2 connection to check DB (unused here).

        Returns:
            List of DSPM finding dicts for AWS resources.
        """
        now = datetime.now(timezone.utc)
        findings: List[Dict[str, Any]] = []

        try:
            with discoveries_conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Primary data resource types (canonical ENG-10 list)
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
            logger.error("AWS DSPM: failed to load discovery_findings: %s", exc)
            return []

        if not rows:
            logger.warning(
                "AWS DSPM: no data-relevant discovery rows for scan_run_id=%s "
                "(queried types: %s)",
                scan_run_id,
                _ALL_DATA_TYPES,
            )
            return []

        # Process in batches of 500 (STRIDE DoS mitigation)
        batch_size = 500
        for i in range(0, len(rows), batch_size):
            batch = rows[i : i + batch_size]
            for row in batch:
                resource_uid = row.get("resource_uid") or ""
                resource_type = row.get("resource_type", "")
                region = row.get("region") or "us-east-1"
                emitted = row.get("emitted_fields") or {}
                slug = _resource_type_slug(resource_type)

                name = (
                    emitted.get("Name")
                    or emitted.get("DBInstanceIdentifier")
                    or emitted.get("TableName")
                    or emitted.get("ClusterIdentifier")
                    or emitted.get("DatabaseName")
                    or emitted.get("DomainName")
                    or emitted.get("StreamName")
                    or emitted.get("resource_id")
                    or emitted.get("resource_name")
                    or resource_uid
                )
                description = emitted.get("Description", "") or emitted.get("Tags", "")
                labels = _infer_labels(str(name), str(description))

                # ── Module 1: data_classification ──────────────────────────────
                class_sev = "HIGH" if labels else "MEDIUM"
                rule_id = f"aws.dspm.data_classification.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id,
                    resource_uid=resource_uid,
                    resource_type=resource_type,
                    account_id=account_id,
                    region=region,
                    scan_run_id=scan_run_id,
                    tenant_id=tenant_id,
                    dspm_module="data_classification",
                    severity=class_sev,
                    status="FAIL" if labels else "PASS",
                    classification_labels=labels,
                    encryption_status="unknown",
                    public_access=False,
                    now=now,
                ))

                # ── Module 2: encryption_posture ───────────────────────────────
                if resource_type in _S3_TYPES:
                    # S3: check ServerSideEncryptionConfiguration in emitted_fields
                    sse = emitted.get("ServerSideEncryptionConfiguration") or emitted.get("encryption", {})
                    is_encrypted = bool(sse)
                    enc_status = "enabled" if is_encrypted else "disabled"
                    sev = "INFO" if is_encrypted else "CRITICAL"
                    rule_id = f"aws.dspm.encryption_posture.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="encryption_posture",
                        severity=sev, status="PASS" if is_encrypted else "FAIL",
                        classification_labels=labels, encryption_status=enc_status,
                        public_access=False, now=now,
                    ))
                elif resource_type in _RDS_TYPES:
                    is_encrypted = bool(
                        emitted.get("StorageEncrypted")
                        or emitted.get("KmsKeyId")
                        or emitted.get("PerformanceInsightsKMSKeyId")
                    )
                    enc_status = "enabled" if is_encrypted else "disabled"
                    rule_id = f"aws.dspm.encryption_posture.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="encryption_posture",
                        severity="INFO" if is_encrypted else "CRITICAL",
                        status="PASS" if is_encrypted else "FAIL",
                        classification_labels=labels, encryption_status=enc_status,
                        public_access=False, now=now,
                    ))
                elif resource_type in _DYNAMO_TYPES:
                    sse_desc = emitted.get("SSEDescription", {})
                    is_encrypted = (
                        isinstance(sse_desc, dict) and sse_desc.get("Status") == "ENABLED"
                    )
                    enc_status = "enabled" if is_encrypted else "disabled"
                    rule_id = f"aws.dspm.encryption_posture.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="encryption_posture",
                        severity="HIGH" if not is_encrypted else "INFO",
                        status="PASS" if is_encrypted else "FAIL",
                        classification_labels=labels, encryption_status=enc_status,
                        public_access=False, now=now,
                    ))
                elif resource_type in (_REDSHIFT_TYPES | _ES_TYPES | _GLUE_TYPES | _KINESIS_TYPES):
                    # Redshift: Encrypted field; ES: EncryptionAtRestOptions; Kinesis: always encrypted
                    is_encrypted = bool(
                        emitted.get("Encrypted")
                        or emitted.get("EncryptionAtRestOptions", {})
                        or emitted.get("EncryptionConfig")
                        or resource_type in _KINESIS_TYPES  # Kinesis always SSE
                    )
                    enc_status = "enabled" if is_encrypted else "disabled"
                    rule_id = f"aws.dspm.encryption_posture.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="encryption_posture",
                        severity="INFO" if is_encrypted else "HIGH",
                        status="PASS" if is_encrypted else "FAIL",
                        classification_labels=labels, encryption_status=enc_status,
                        public_access=False, now=now,
                    ))

                # ── Module 3: access_control ───────────────────────────────────
                if resource_type in _S3_TYPES:
                    # Public access block configuration
                    pac = emitted.get("PublicAccessBlockConfiguration", {})
                    is_public = not (
                        isinstance(pac, dict)
                        and pac.get("BlockPublicAcls", False)
                        and pac.get("BlockPublicPolicy", False)
                        and pac.get("RestrictPublicBuckets", False)
                    )
                    # Also check policy status if present
                    pol = emitted.get("PolicyStatus", {})
                    if isinstance(pol, dict) and pol.get("IsPublic", False):
                        is_public = True
                    sev = "CRITICAL" if is_public else "INFO"
                    rule_id = f"aws.dspm.access_control.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="access_control",
                        severity=sev, status="FAIL" if is_public else "PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=is_public, now=now,
                    ))
                elif resource_type in _RDS_TYPES:
                    is_public = bool(emitted.get("PubliclyAccessible", False))
                    rule_id = f"aws.dspm.access_control.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="access_control",
                        severity="CRITICAL" if is_public else "INFO",
                        status="FAIL" if is_public else "PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=is_public, now=now,
                    ))
                elif resource_type in (_DYNAMO_TYPES | _REDSHIFT_TYPES | _GLUE_TYPES | _ES_TYPES | _KINESIS_TYPES):
                    # DynamoDB/Redshift: check if resource policies allow overly broad access
                    is_public = bool(
                        emitted.get("PubliclyAccessible", False)
                        or emitted.get("MasterUserPassword")  # password exposed in config = risky
                    )
                    rule_id = f"aws.dspm.access_control.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="access_control",
                        severity="HIGH" if is_public else "INFO",
                        status="FAIL" if is_public else "PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=is_public, now=now,
                    ))

                # ── Module 4: data_residency ───────────────────────────────────
                in_eu = region in _EU_REGIONS
                in_us = region in _US_REGIONS
                residency_ok = in_eu or in_us
                sev = "MEDIUM" if not residency_ok else "INFO"
                rule_id = f"aws.dspm.data_residency.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="data_residency",
                    severity=sev, status="FAIL" if not residency_ok else "PASS",
                    classification_labels=labels, encryption_status="unknown",
                    public_access=False, now=now,
                ))

                # ── Module 5: activity_logging ─────────────────────────────────
                if resource_type in _S3_TYPES:
                    # S3 server access logging — LoggingEnabled in emitted_fields
                    logging_cfg = emitted.get("LoggingEnabled") or emitted.get("logging", {})
                    has_logging = bool(logging_cfg)
                    rule_id = f"aws.dspm.activity_logging.{slug}"
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
                    # RDS: EnabledCloudwatchLogsExports or EnhancedMonitoringResourceArn
                    has_logging = bool(
                        emitted.get("EnabledCloudwatchLogsExports")
                        or emitted.get("EnhancedMonitoringResourceArn")
                        or emitted.get("PerformanceInsightsEnabled")
                    )
                    rule_id = f"aws.dspm.activity_logging.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="activity_logging",
                        severity="HIGH" if not has_logging else "INFO",
                        status="FAIL" if not has_logging else "PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=False, now=now,
                    ))
                elif resource_type in (_DYNAMO_TYPES | _KINESIS_TYPES):
                    # DynamoDB: Streams or CloudWatch contributor insights
                    has_logging = bool(
                        emitted.get("StreamSpecification", {})
                        or emitted.get("ContributorInsightsSummaries")
                        or emitted.get("StreamEnabled")
                    )
                    rule_id = f"aws.dspm.activity_logging.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="activity_logging",
                        severity="MEDIUM" if not has_logging else "INFO",
                        status="FAIL" if not has_logging else "PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=False, now=now,
                    ))
                elif resource_type in (_REDSHIFT_TYPES | _ES_TYPES | _GLUE_TYPES):
                    # Redshift: LoggingEnabled; ES: audit logs via CloudWatch
                    has_logging = bool(
                        emitted.get("LoggingProperties")
                        or emitted.get("LogPublishingOptions")
                        or emitted.get("CloudWatchLogsLogGroupArn")
                    )
                    rule_id = f"aws.dspm.activity_logging.{slug}"
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
                if resource_type in _S3_TYPES:
                    # S3: versioning + lifecycle rules
                    versioning = emitted.get("VersioningConfiguration", {}) or emitted.get("versioning", {})
                    versioning_on = (
                        isinstance(versioning, dict) and versioning.get("Status") == "Enabled"
                    )
                    lifecycle = emitted.get("LifecycleRules") or emitted.get("lifecycle_rules")
                    has_lifecycle = bool(lifecycle)
                    lifecycle_ok = versioning_on or has_lifecycle
                    rule_id = f"aws.dspm.data_lifecycle.{slug}"
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
                    # RDS: BackupRetentionPeriod > 0 and DeleteProtection
                    backup_days = emitted.get("BackupRetentionPeriod", 0)
                    delete_prot = bool(emitted.get("DeletionProtection", False))
                    lifecycle_ok = int(backup_days or 0) > 0 or delete_prot
                    rule_id = f"aws.dspm.data_lifecycle.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="data_lifecycle",
                        severity="HIGH" if not lifecycle_ok else "INFO",
                        status="FAIL" if not lifecycle_ok else "PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=False, now=now,
                    ))
                elif resource_type in _DYNAMO_TYPES:
                    # DynamoDB: PointInTimeRecoveryDescription
                    pitr = emitted.get("PointInTimeRecoveryDescription", {})
                    lifecycle_ok = (
                        isinstance(pitr, dict)
                        and pitr.get("PointInTimeRecoveryStatus") == "ENABLED"
                    )
                    rule_id = f"aws.dspm.data_lifecycle.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="data_lifecycle",
                        severity="MEDIUM" if not lifecycle_ok else "INFO",
                        status="FAIL" if not lifecycle_ok else "PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=False, now=now,
                    ))
                elif resource_type in (_REDSHIFT_TYPES | _ES_TYPES | _GLUE_TYPES | _KINESIS_TYPES):
                    # Redshift: AutomatedSnapshotRetentionPeriod; ES/Kinesis: no native backup config
                    retention = emitted.get("AutomatedSnapshotRetentionPeriod", 0)
                    lifecycle_ok = int(retention or 0) > 0
                    rule_id = f"aws.dspm.data_lifecycle.{slug}"
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
                # S3 event notifications → Lambda/SNS/SQS flows; RDS triggers; Kinesis consumers
                if resource_type in _S3_TYPES:
                    notif = emitted.get("NotificationConfiguration", {})
                    has_lambda_flow = bool(
                        isinstance(notif, dict) and (
                            notif.get("LambdaFunctionConfigurations")
                            or notif.get("QueueConfigurations")
                            or notif.get("TopicConfigurations")
                        )
                    )
                    rule_id = f"aws.dspm.data_lineage.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="data_lineage",
                        severity="LOW" if not has_lambda_flow else "INFO",
                        status="PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=False, now=now,
                    ))
                elif resource_type in _KINESIS_TYPES:
                    # Kinesis consumers = downstream data flow
                    consumer_count = len(emitted.get("ConsumerList", []) or [])
                    rule_id = f"aws.dspm.data_lineage.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="data_lineage",
                        severity="LOW" if consumer_count > 0 else "INFO",
                        status="PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=False, now=now,
                    ))
                else:
                    rule_id = f"aws.dspm.data_lineage.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                        account_id=account_id, region=region, scan_run_id=scan_run_id,
                        tenant_id=tenant_id, dspm_module="data_lineage",
                        severity="INFO", status="PASS",
                        classification_labels=labels, encryption_status="unknown",
                        public_access=False, now=now,
                    ))

                # ── Module 8: governance_scoring ───────────────────────────────
                # Aggregate posture: encryption + public-access-blocked + logging
                enc_ok = False
                pub_ok = True
                log_ok = False

                if resource_type in _S3_TYPES:
                    sse2 = emitted.get("ServerSideEncryptionConfiguration") or emitted.get("encryption", {})
                    enc_ok = bool(sse2)
                    pac2 = emitted.get("PublicAccessBlockConfiguration", {})
                    pub_ok = bool(
                        isinstance(pac2, dict)
                        and pac2.get("BlockPublicAcls", False)
                        and pac2.get("BlockPublicPolicy", False)
                    )
                    log_ok = bool(emitted.get("LoggingEnabled") or emitted.get("logging", {}))
                elif resource_type in _RDS_TYPES:
                    enc_ok = bool(emitted.get("StorageEncrypted") or emitted.get("KmsKeyId"))
                    pub_ok = not bool(emitted.get("PubliclyAccessible", False))
                    log_ok = bool(emitted.get("EnabledCloudwatchLogsExports"))
                elif resource_type in _DYNAMO_TYPES:
                    sse_d = emitted.get("SSEDescription", {})
                    enc_ok = isinstance(sse_d, dict) and sse_d.get("Status") == "ENABLED"
                    pub_ok = True  # DynamoDB not publicly accessible
                    log_ok = bool(emitted.get("StreamSpecification", {}))
                elif resource_type in (_REDSHIFT_TYPES | _ES_TYPES | _GLUE_TYPES | _KINESIS_TYPES):
                    enc_ok = bool(
                        emitted.get("Encrypted")
                        or emitted.get("EncryptionAtRestOptions", {})
                        or resource_type in _KINESIS_TYPES
                    )
                    pub_ok = not bool(emitted.get("PubliclyAccessible", False))
                    log_ok = bool(
                        emitted.get("LoggingProperties")
                        or emitted.get("LogPublishingOptions")
                    )

                passes = sum([enc_ok, pub_ok, log_ok])
                score = int(passes / 3 * 100)
                gov_sev = "HIGH" if score < 50 else ("MEDIUM" if score < 80 else "LOW")
                rule_id = f"aws.dspm.governance_scoring.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="governance_scoring",
                    severity=gov_sev, status="FAIL" if score < 80 else "PASS",
                    classification_labels=labels, encryption_status="unknown",
                    public_access=False, now=now,
                ))

        # ── Modules 9-11: cross_account_access, acl_ownership, lake_formation ─
        s3_rows = [r for r in rows if r.get("resource_type") in _S3_TYPES]
        cdr_conn: Optional[Any] = None
        try:
            from engine_common.db_connections import get_cdr_conn
            cdr_conn = get_cdr_conn()
        except Exception:
            pass
        try:
            findings.extend(self._analyze_cross_account_access(
                s3_rows=s3_rows, account_id=account_id,
                scan_run_id=scan_run_id, tenant_id=tenant_id,
                now=now, cdr_conn=cdr_conn,
            ))
            findings.extend(self._analyze_bucket_acl_ownership(
                s3_rows=s3_rows, account_id=account_id,
                scan_run_id=scan_run_id, tenant_id=tenant_id, now=now,
            ))
            findings.extend(self._analyze_lake_formation(
                discoveries_conn=discoveries_conn, account_id=account_id,
                scan_run_id=scan_run_id, tenant_id=tenant_id, now=now,
            ))
        except Exception as _xacct_exc:
            logger.warning("DataSec cross-account analysis failed (non-fatal): %s", _xacct_exc)
        finally:
            if cdr_conn:
                try:
                    cdr_conn.close()
                except Exception:
                    pass

        logger.info(
            "AWS DSPM analyze(): produced %d findings from %d discovery rows",
            len(findings), len(rows),
        )
        return findings

    def _analyze_cross_account_access(
        self,
        s3_rows: List[Dict],
        account_id: str,
        scan_run_id: str,
        tenant_id: str,
        now: datetime,
        cdr_conn: Optional[Any] = None,
    ) -> List[Dict[str, Any]]:
        """Check S3 bucket policies for cross-account Allow statements."""
        findings: List[Dict[str, Any]] = []
        seen: set = set()
        for row in s3_rows:
            resource_uid = row.get("resource_uid") or ""
            region = row.get("region") or "us-east-1"
            emitted = row.get("emitted_fields") or {}
            labels = _infer_labels(
                str(emitted.get("Name") or emitted.get("resource_id") or resource_uid)
            )
            policy_raw = emitted.get("Policy") or emitted.get("BucketPolicy") or ""
            if not policy_raw:
                continue
            try:
                policy = json.loads(policy_raw) if isinstance(policy_raw, str) else policy_raw
            except (ValueError, TypeError):
                continue
            for stmt in (policy.get("Statement") or []):
                if stmt.get("Effect") != "Allow":
                    continue
                principal = stmt.get("Principal")
                principals: List[str] = []
                if isinstance(principal, dict):
                    for v in principal.values():
                        principals.extend(v if isinstance(v, list) else [str(v)])
                elif isinstance(principal, str):
                    principals.append(principal)
                for p in principals:
                    if p == "*" or "amazonaws.com" in p or "arn:aws:iam" not in p:
                        continue
                    try:
                        other_acct = p.split(":")[4]
                    except IndexError:
                        continue
                    if not other_acct or other_acct == account_id:
                        continue
                    actions = stmt.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    has_write = any(
                        x in a.lower() for a in actions
                        for x in ("put", "delete", "write", "modify", "create")
                    )
                    has_policy = any("policy" in a.lower() for a in actions)
                    if has_write:
                        sev, rule = "CRITICAL", "aws.s3.bucket.no_cross_account_write_access"
                    elif has_policy:
                        sev, rule = "HIGH", "aws.s3.bucket.cross_account_replication_reviewed"
                    else:
                        sev, rule = "HIGH", "aws.s3.bucket.cross_account_read_access_reviewed"
                    # CDR enrichment: confirm active GetObject cross-account access
                    if cdr_conn and sev != "CRITICAL":
                        try:
                            with cdr_conn.cursor() as _cdr_cur:
                                _cdr_cur.execute(
                                    """
                                    SELECT COUNT(1) FROM cdr_findings
                                    WHERE resource_uid = %s AND tenant_id = %s
                                      AND operation ILIKE %s
                                      AND event_time >= NOW() - INTERVAL '24 hours'
                                    """,
                                    (resource_uid, tenant_id, "GetObject"),
                                )
                                if (_cdr_cur.fetchone() or [0])[0] > 0:
                                    sev = "CRITICAL"
                        except Exception:
                            pass
                    key = (resource_uid, rule)
                    if key not in seen:
                        seen.add(key)
                        findings.append(_base_finding(
                            rule_id=rule,
                            resource_uid=resource_uid,
                            resource_type="S3::Bucket",
                            account_id=account_id,
                            region=region,
                            scan_run_id=scan_run_id,
                            tenant_id=tenant_id,
                            dspm_module="cross_account_access",
                            severity=sev,
                            status="FAIL",
                            classification_labels=labels,
                            encryption_status="unknown",
                            public_access=False,
                            now=now,
                        ))
        return findings

    def _analyze_bucket_acl_ownership(
        self,
        s3_rows: List[Dict],
        account_id: str,
        scan_run_id: str,
        tenant_id: str,
        now: datetime,
    ) -> List[Dict[str, Any]]:
        """Check S3 bucket ObjectOwnership — should be BucketOwnerEnforced."""
        findings: List[Dict[str, Any]] = []
        for row in s3_rows:
            resource_uid = row.get("resource_uid") or ""
            region = row.get("region") or "us-east-1"
            emitted = row.get("emitted_fields") or {}
            labels = _infer_labels(
                str(emitted.get("Name") or emitted.get("resource_id") or resource_uid)
            )
            ownership = emitted.get("ObjectOwnership")
            if ownership is None:
                ownership_ctrl = emitted.get("BucketOwnershipControls")
                if isinstance(ownership_ctrl, dict):
                    rules = ownership_ctrl.get("Rules") or []
                    if rules:
                        ownership = (rules[0] or {}).get("ObjectOwnership")
            if ownership and ownership != "BucketOwnerEnforced":
                findings.append(_base_finding(
                    rule_id="aws.s3.bucket.bucket_owner_enforced",
                    resource_uid=resource_uid,
                    resource_type="S3::Bucket",
                    account_id=account_id,
                    region=region,
                    scan_run_id=scan_run_id,
                    tenant_id=tenant_id,
                    dspm_module="access_control",
                    severity="MEDIUM",
                    status="FAIL",
                    classification_labels=labels,
                    encryption_status="unknown",
                    public_access=False,
                    now=now,
                ))
        return findings

    def _analyze_lake_formation(
        self,
        discoveries_conn: Any,
        account_id: str,
        scan_run_id: str,
        tenant_id: str,
        now: datetime,
    ) -> List[Dict[str, Any]]:
        """Check LakeFormation for IAM_ALLOWED_PRINCIPALS and admin wildcard grants."""
        findings: List[Dict[str, Any]] = []
        try:
            with discoveries_conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT resource_uid, resource_type, region, emitted_fields
                    FROM discovery_findings
                    WHERE scan_run_id = %s AND tenant_id = %s
                      AND (resource_type ILIKE %s OR resource_type ILIKE %s)
                    LIMIT 500
                    """,
                    (scan_run_id, tenant_id, "%LakeFormation%", "%Glue::DataCatalog%"),
                )
                lf_rows = cur.fetchall()
        except Exception as exc:
            logger.warning("LakeFormation discovery query failed: %s", exc)
            return findings
        for row in lf_rows:
            resource_uid = row.get("resource_uid") or ""
            region = row.get("region") or "us-east-1"
            emitted = row.get("emitted_fields") or {}
            rtype = row.get("resource_type", "LakeFormation::Database")
            labels = _infer_labels(str(emitted.get("Name") or resource_uid))
            permissions = emitted.get("Permissions") or emitted.get("LakeFormationPermissions") or []
            for perm in (permissions if isinstance(permissions, list) else []):
                principal = perm.get("Principal") or {}
                if (isinstance(principal, dict)
                        and principal.get("DataLakePrincipalIdentifier") == "IAM_ALLOWED_PRINCIPALS"):
                    findings.append(_base_finding(
                        rule_id="aws.lakeformation.database.no_iam_allowed_principals",
                        resource_uid=resource_uid,
                        resource_type=rtype,
                        account_id=account_id,
                        region=region,
                        scan_run_id=scan_run_id,
                        tenant_id=tenant_id,
                        dspm_module="cross_account_access",
                        severity="HIGH",
                        status="FAIL",
                        classification_labels=labels,
                        encryption_status="unknown",
                        public_access=False,
                        now=now,
                    ))
                    break
            admin_perms = emitted.get("AdminPermissions") or emitted.get("CatalogPermissions") or []
            _admin_ops = {"CREATE_DATABASE", "CREATE_TABLE", "DATA_LOCATION_ACCESS", "SUPER"}
            for ap in (admin_perms if isinstance(admin_perms, list) else []):
                if _admin_ops & set(ap.get("Permissions") or []):
                    findings.append(_base_finding(
                        rule_id="aws.lakeformation.database.no_admin_wildcard_grant",
                        resource_uid=resource_uid,
                        resource_type=rtype,
                        account_id=account_id,
                        region=region,
                        scan_run_id=scan_run_id,
                        tenant_id=tenant_id,
                        dspm_module="cross_account_access",
                        severity="HIGH",
                        status="FAIL",
                        classification_labels=labels,
                        encryption_status="unknown",
                        public_access=False,
                        now=now,
                    ))
                    break
        return findings
