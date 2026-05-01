"""AWS provider for Data Security engine — 8-module DSPM analyze()."""

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

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

# resource_type values in discovery_findings for AWS data resources
_BUCKET_TYPES = {"bucket", "s3_bucket"}
_SECRET_TYPES = {"secret"}
_KEY_TYPES = {"key"}
_SNAPSHOT_TYPES = {"snapshot"}
_VOLUME_TYPES = {"volume"}
_FUNCTION_TYPES = {"function"}
_ALL_DATA_TYPES = (
    _BUCKET_TYPES | _SECRET_TYPES | _KEY_TYPES
    | _SNAPSHOT_TYPES | _VOLUME_TYPES | _FUNCTION_TYPES
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
                # Load high-value resource types first (buckets, secrets, keys) with priority
                _priority_types = list(_BUCKET_TYPES | _SECRET_TYPES | _KEY_TYPES)
                cur.execute(
                    """
                    SELECT resource_uid, resource_type, region, emitted_fields
                    FROM discovery_findings
                    WHERE scan_run_id = %s
                      AND tenant_id = %s
                      AND resource_type = ANY(%s)
                    LIMIT 2000
                    """,
                    (scan_run_id, tenant_id, _priority_types),
                )
                priority_rows = cur.fetchall()

                # Load snapshot/volume/function types separately (high volume)
                _bulk_types = list(_SNAPSHOT_TYPES | _VOLUME_TYPES | _FUNCTION_TYPES)
                cur.execute(
                    """
                    SELECT resource_uid, resource_type, region, emitted_fields
                    FROM discovery_findings
                    WHERE scan_run_id = %s
                      AND tenant_id = %s
                      AND resource_type = ANY(%s)
                    LIMIT 500
                    """,
                    (scan_run_id, tenant_id, _bulk_types),
                )
                bulk_rows = cur.fetchall()

                rows = priority_rows + bulk_rows

                # Also load bucket_encryption and public_access_block companion records
                cur.execute(
                    """
                    SELECT resource_uid, resource_type, region, emitted_fields
                    FROM discovery_findings
                    WHERE scan_run_id = %s
                      AND tenant_id = %s
                      AND resource_type IN ('bucket_encryption', 'public_access_block',
                                            'bucket_policy_status', 'object_lock_configuration',
                                            'bucket_replication', 'notification_configuration')
                    """,
                    (scan_run_id, tenant_id),
                )
                companion_rows = cur.fetchall()
        except Exception as exc:
            logger.error("AWS DSPM: failed to load discovery_findings: %s", exc)
            return []

        if not rows:
            logger.warning("AWS DSPM: no data-relevant discovery rows for scan_run_id=%s", scan_run_id)
            return []

        # Index companion rows by resource_uid prefix (buckets share uid prefix)
        enc_by_uid: Dict[str, Dict] = {}
        pub_by_uid: Dict[str, Dict] = {}
        policy_by_uid: Dict[str, Dict] = {}
        lock_by_uid: Dict[str, Dict] = {}
        replication_by_uid: Dict[str, Dict] = {}
        notification_by_uid: Dict[str, Dict] = {}

        for comp in companion_rows:
            # Companion rows often have resource_uid = None; skip them for indexing by uid
            # They are indexed per-scan (all belong to same tenant/scan) — use emitted_fields
            uid = comp.get("resource_uid") or ""
            emitted = comp.get("emitted_fields") or {}
            rtype = comp.get("resource_type", "")
            if rtype == "bucket_encryption":
                enc_by_uid[uid] = emitted
            elif rtype == "public_access_block":
                pub_by_uid[uid] = emitted
            elif rtype == "bucket_policy_status":
                policy_by_uid[uid] = emitted
            elif rtype == "object_lock_configuration":
                lock_by_uid[uid] = emitted
            elif rtype == "bucket_replication":
                replication_by_uid[uid] = emitted
            elif rtype == "notification_configuration":
                notification_by_uid[uid] = emitted

        # Process in batches of 200
        batch_size = 200
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
                    or emitted.get("resource_id")
                    or emitted.get("resource_name")
                    or resource_uid
                )
                description = emitted.get("Description", "")
                labels = _infer_labels(str(name), str(description))

                # ── Module 1: classification ────────────────────────────────
                if resource_type in _BUCKET_TYPES or resource_type in _SECRET_TYPES:
                    class_sev = "HIGH" if labels else "MEDIUM"
                    rule_id = f"aws.dspm.classification.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id,
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=region,
                        scan_run_id=scan_run_id,
                        tenant_id=tenant_id,
                        dspm_module="classification",
                        severity=class_sev,
                        status="FAIL" if labels else "PASS",
                        classification_labels=labels,
                        encryption_status="unknown",
                        public_access=False,
                        now=now,
                    ))

                # ── Module 2: encryption ────────────────────────────────────
                if resource_type in _BUCKET_TYPES:
                    # Check bucket_encryption companion — if no record, unencrypted
                    enc_emitted = enc_by_uid.get(resource_uid, enc_by_uid.get("", {}))
                    sse_config = enc_emitted.get("ServerSideEncryptionConfiguration", {})
                    is_encrypted = bool(sse_config)
                    enc_status = "encrypted" if is_encrypted else "unencrypted"
                    sev = "INFO" if is_encrypted else "CRITICAL"
                    status = "PASS" if is_encrypted else "FAIL"
                    rule_id = f"aws.dspm.encryption.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id,
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=region,
                        scan_run_id=scan_run_id,
                        tenant_id=tenant_id,
                        dspm_module="encryption",
                        severity=sev,
                        status=status,
                        classification_labels=labels,
                        encryption_status=enc_status,
                        public_access=False,
                        now=now,
                    ))
                elif resource_type in _SECRET_TYPES:
                    enc_status = "encrypted"  # Secrets Manager always encrypts
                    rule_id = f"aws.dspm.encryption.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id,
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=region,
                        scan_run_id=scan_run_id,
                        tenant_id=tenant_id,
                        dspm_module="encryption",
                        severity="INFO",
                        status="PASS",
                        classification_labels=labels,
                        encryption_status=enc_status,
                        public_access=False,
                        now=now,
                    ))
                elif resource_type in _SNAPSHOT_TYPES:
                    is_enc = bool(emitted.get("Encrypted") or emitted.get("KmsKeyId"))
                    enc_status = "encrypted" if is_enc else "unencrypted"
                    sev = "CRITICAL" if not is_enc else "INFO"
                    rule_id = f"aws.dspm.encryption.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id,
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=region,
                        scan_run_id=scan_run_id,
                        tenant_id=tenant_id,
                        dspm_module="encryption",
                        severity=sev,
                        status="FAIL" if not is_enc else "PASS",
                        classification_labels=[],
                        encryption_status=enc_status,
                        public_access=False,
                        now=now,
                    ))

                # ── Module 3: access_control ────────────────────────────────
                if resource_type in _BUCKET_TYPES:
                    pub_emitted = pub_by_uid.get(resource_uid, pub_by_uid.get("", {}))
                    pac = pub_emitted.get("PublicAccessBlockConfiguration", {})
                    is_public = not (
                        pac.get("BlockPublicAcls", False)
                        and pac.get("BlockPublicPolicy", False)
                        and pac.get("RestrictPublicBuckets", False)
                    )
                    # Also check policy_status
                    pol_emitted = policy_by_uid.get(resource_uid, policy_by_uid.get("", {}))
                    if pol_emitted.get("PolicyStatus", {}).get("IsPublic", False):
                        is_public = True
                    sev = "CRITICAL" if is_public else "INFO"
                    rule_id = f"aws.dspm.access_control.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id,
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=region,
                        scan_run_id=scan_run_id,
                        tenant_id=tenant_id,
                        dspm_module="access_control",
                        severity=sev,
                        status="FAIL" if is_public else "PASS",
                        classification_labels=labels,
                        encryption_status="unknown",
                        public_access=is_public,
                        now=now,
                    ))

                # ── Module 4: data_residency ────────────────────────────────
                if resource_type in _BUCKET_TYPES or resource_type in _SECRET_TYPES:
                    in_eu = region in _EU_REGIONS
                    in_us = region in _US_REGIONS
                    residency_ok = in_eu or in_us
                    sev = "MEDIUM" if not residency_ok else "INFO"
                    rule_id = f"aws.dspm.data_residency.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id,
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=region,
                        scan_run_id=scan_run_id,
                        tenant_id=tenant_id,
                        dspm_module="data_residency",
                        severity=sev,
                        status="FAIL" if not residency_ok else "PASS",
                        classification_labels=labels,
                        encryption_status="unknown",
                        public_access=False,
                        now=now,
                    ))

                # ── Module 5: activity_logging ──────────────────────────────
                if resource_type in _BUCKET_TYPES:
                    notif_emitted = notification_by_uid.get(resource_uid, notification_by_uid.get("", {}))
                    # Logging enabled if notification config exists and has queue/topic
                    has_logging = bool(
                        notif_emitted.get("QueueConfigurations")
                        or notif_emitted.get("TopicConfigurations")
                        or notif_emitted.get("LambdaFunctionConfigurations")
                    )
                    sev = "HIGH" if not has_logging else "INFO"
                    rule_id = f"aws.dspm.activity_logging.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id,
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=region,
                        scan_run_id=scan_run_id,
                        tenant_id=tenant_id,
                        dspm_module="activity_logging",
                        severity=sev,
                        status="FAIL" if not has_logging else "PASS",
                        classification_labels=labels,
                        encryption_status="unknown",
                        public_access=False,
                        now=now,
                    ))
                elif resource_type in _SNAPSHOT_TYPES:
                    # Snapshots always have audit trail via CloudTrail; mark PASS
                    rule_id = f"aws.dspm.activity_logging.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id,
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=region,
                        scan_run_id=scan_run_id,
                        tenant_id=tenant_id,
                        dspm_module="activity_logging",
                        severity="INFO",
                        status="PASS",
                        classification_labels=[],
                        encryption_status="unknown",
                        public_access=False,
                        now=now,
                    ))

                # ── Module 6: lifecycle ─────────────────────────────────────
                if resource_type in _BUCKET_TYPES:
                    lock_emitted = lock_by_uid.get(resource_uid, lock_by_uid.get("", {}))
                    has_lock = bool(lock_emitted.get("ObjectLockConfiguration", {}).get("ObjectLockEnabled") == "Enabled")
                    rep_emitted = replication_by_uid.get(resource_uid, replication_by_uid.get("", {}))
                    has_replication = bool(rep_emitted.get("ReplicationConfiguration", {}).get("Rules"))
                    lifecycle_ok = has_lock or has_replication
                    sev = "MEDIUM" if not lifecycle_ok else "INFO"
                    rule_id = f"aws.dspm.lifecycle.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id,
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=region,
                        scan_run_id=scan_run_id,
                        tenant_id=tenant_id,
                        dspm_module="lifecycle",
                        severity=sev,
                        status="FAIL" if not lifecycle_ok else "PASS",
                        classification_labels=labels,
                        encryption_status="unknown",
                        public_access=False,
                        now=now,
                    ))

                # ── Module 7: data_lineage ──────────────────────────────────
                if resource_type in _BUCKET_TYPES:
                    # Lambda notifications indicate S3→Lambda data flow
                    notif_emitted = notification_by_uid.get(resource_uid, notification_by_uid.get("", {}))
                    has_lambda_flow = bool(notif_emitted.get("LambdaFunctionConfigurations"))
                    sev = "LOW" if not has_lambda_flow else "INFO"
                    rule_id = f"aws.dspm.data_lineage.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id,
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=region,
                        scan_run_id=scan_run_id,
                        tenant_id=tenant_id,
                        dspm_module="data_lineage",
                        severity=sev,
                        status="PASS",
                        classification_labels=labels,
                        encryption_status="unknown",
                        public_access=False,
                        now=now,
                    ))

                # ── Module 8: governance_score ──────────────────────────────
                if resource_type in _BUCKET_TYPES or resource_type in _SECRET_TYPES:
                    # Governance score based on how many controls pass for this resource
                    # Simplified: check encryption + public access block
                    enc_ok = False
                    pub_ok = True
                    if resource_type in _BUCKET_TYPES:
                        enc_emitted = enc_by_uid.get(resource_uid, enc_by_uid.get("", {}))
                        enc_ok = bool(enc_emitted.get("ServerSideEncryptionConfiguration"))
                        pub_emitted2 = pub_by_uid.get(resource_uid, pub_by_uid.get("", {}))
                        pac2 = pub_emitted2.get("PublicAccessBlockConfiguration", {})
                        pub_ok = (
                            pac2.get("BlockPublicAcls", False)
                            and pac2.get("BlockPublicPolicy", False)
                        )
                    elif resource_type in _SECRET_TYPES:
                        enc_ok = True
                        pub_ok = True

                    passes = sum([enc_ok, pub_ok])
                    score = int(passes / 2 * 100)
                    gov_sev = "HIGH" if score < 50 else ("MEDIUM" if score < 80 else "LOW")
                    rule_id = f"aws.dspm.governance_score.{slug}"
                    findings.append(_base_finding(
                        rule_id=rule_id,
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=region,
                        scan_run_id=scan_run_id,
                        tenant_id=tenant_id,
                        dspm_module="governance_score",
                        severity=gov_sev,
                        status="FAIL" if score < 80 else "PASS",
                        classification_labels=labels,
                        encryption_status="unknown",
                        public_access=False,
                        now=now,
                    ))

        logger.info("AWS DSPM analyze(): produced %d findings from %d discovery rows", len(findings), len(rows))
        return findings
