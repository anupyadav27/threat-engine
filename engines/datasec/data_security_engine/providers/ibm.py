"""
IBM Cloud Data Security provider.

DSPM 8-module analysis for:
  - IBM Cloud Object Storage (COS): public access, SSE, versioning, activity tracking
  - IBM Db2 on Cloud: SSL enforcement, public endpoint, IP allowlist, audit logging
  - IBM Cloudant (NoSQL): CORS, HTTPS-only, IAM-only auth
  - IBM Event Streams (Kafka): private-only endpoint
"""
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from .base import BaseDataSecProvider

logger = logging.getLogger(__name__)

_PUBLIC_ACLS = {"public-read", "public-read-write"}


def _fid(rule_id: str, resource_uid: str, account_id: str, region: str) -> str:
    raw = f"{rule_id}|{resource_uid}|{account_id}|{region}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _finding(rule_id: str, module: str, resource_uid: str, resource_type: str,
             provider: str, account_id: str, region: str, severity: str,
             status: str, scan_run_id: str, tenant_id: str,
             classification_labels: List[str], extra: Dict) -> Dict[str, Any]:
    now = _now()
    return {
        "finding_id": _fid(rule_id, resource_uid, account_id, region),
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        "account_id": account_id,
        "provider": provider,
        "region": region,
        "resource_uid": resource_uid,
        "resource_type": resource_type,
        "severity": severity,
        "status": status,
        "dspm_module": module,
        "classification_labels": classification_labels,
        "encryption_status": extra.get("encryption_status", "unknown"),
        "public_access": extra.get("public_access", False),
        "blast_radius_score": 0,
        "first_seen_at": now,
        "last_seen_at": now,
        "rule_id": rule_id,
        "title": extra.get("title", rule_id),
        "description": extra.get("description", ""),
        "remediation": extra.get("remediation", ""),
    }


class IBMDataSecProvider(BaseDataSecProvider):
    """IBM Cloud DSPM provider — COS, Db2, Cloudant, Event Streams."""

    @property
    def storage_services(self) -> List[str]:
        return ["cloud-object-storage"]

    @property
    def database_services(self) -> List[str]:
        return ["db2", "cloudant", "databases-for-postgresql"]

    @property
    def streaming_services(self) -> List[str]:
        return ["event-streams"]

    @property
    def inventory_resource_prefixes(self) -> List[str]:
        return ["cos.", "db2.", "cloudant."]

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        discoveries_conn: Any,
        check_conn: Any = None,
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        try:
            from psycopg2.extras import RealDictCursor
            with discoveries_conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT resource_uid, resource_type, emitted_fields, account_id, region
                    FROM discovery_findings
                    WHERE scan_run_id = %s
                      AND tenant_id = %s
                      AND provider = 'ibm'
                      AND service IN ('cos', 'cloud-object-storage',
                                      'db2', 'cloudant', 'event-streams')
                    ORDER BY resource_uid
                    """,
                    (scan_run_id, tenant_id),
                )
                rows = cur.fetchall()
        except Exception as exc:
            logger.error("IBM DataSec: discovery query failed: %s", exc)
            return findings

        for row in rows:
            fields = row.get("emitted_fields") or {}
            uid = row.get("resource_uid", "")
            rtype = row.get("resource_type", "")
            region = row.get("region") or "global"
            acct = row.get("account_id") or account_id or ""
            svc = (row.get("service") or rtype).lower()

            # ── COS Bucket checks ──
            if "cos" in svc or "object-storage" in svc or "bucket" in rtype.lower():
                acl = (fields.get("ACL") or "").lower()
                if acl in _PUBLIC_ACLS:
                    findings.append(_finding(
                        "ibm.cos.bucket.public_access_blocked", "access_control",
                        uid, rtype, "ibm", acct, region, "critical", "FAIL",
                        scan_run_id, tenant_id, [],
                        {"public_access": True, "encryption_status": "unknown",
                         "title": "IBM COS bucket is publicly accessible",
                         "remediation": "Remove public-read/public-read-write ACL from COS bucket."},
                    ))

                sse_provider = (fields.get("ServerSideEncryptionConfiguration") or {})
                kms_key = fields.get("IBMSSEKPCrgn") or fields.get("KeyProtectCRN") or ""
                if not kms_key and not sse_provider:
                    findings.append(_finding(
                        "ibm.cos.bucket.server_side_encryption_kp", "encryption",
                        uid, rtype, "ibm", acct, region, "high", "FAIL",
                        scan_run_id, tenant_id, [],
                        {"encryption_status": "default_ibm_managed",
                         "title": "IBM COS bucket not encrypted with IBM Key Protect (customer key)",
                         "remediation": "Enable SSE-KP with IBM Key Protect for COS bucket."},
                    ))

                versioning = (fields.get("VersioningConfiguration") or {}).get("Status", "")
                if versioning.lower() != "enabled":
                    findings.append(_finding(
                        "ibm.cos.bucket.versioning_enabled", "data_lifecycle",
                        uid, rtype, "ibm", acct, region, "medium", "FAIL",
                        scan_run_id, tenant_id, [],
                        {"title": "IBM COS bucket versioning is not enabled",
                         "remediation": "Enable versioning on COS bucket for data lifecycle management."},
                    ))

                activity_tracking = fields.get("ActivityTracking") or {}
                read_events = activity_tracking.get("read_data_events", False)
                write_events = activity_tracking.get("write_data_events", False)
                if not (read_events and write_events):
                    findings.append(_finding(
                        "ibm.cos.bucket.activity_tracking_enabled", "activity_logging",
                        uid, rtype, "ibm", acct, region, "high", "FAIL",
                        scan_run_id, tenant_id, [],
                        {"title": "IBM COS bucket Activity Tracker events not fully enabled",
                         "remediation": "Enable read_data_events and write_data_events in Activity Tracking."},
                    ))

            # ── Db2 checks ──
            elif "db2" in svc or "db2" in rtype.lower():
                ssl_enabled = fields.get("ssl", fields.get("sslEnabled", False))
                if not ssl_enabled:
                    findings.append(_finding(
                        "ibm.db2.instance.ssl_enforced", "encryption",
                        uid, rtype, "ibm", acct, region, "high", "FAIL",
                        scan_run_id, tenant_id, [],
                        {"encryption_status": "plaintext",
                         "title": "IBM Db2 instance does not enforce SSL connections",
                         "remediation": "Enable SSL-only connections for IBM Db2 instance."},
                    ))

                public_conn = fields.get("publicConnectionString") or fields.get("public_connection_string")
                if public_conn:
                    findings.append(_finding(
                        "ibm.db2.instance.public_connectivity_disabled", "access_control",
                        uid, rtype, "ibm", acct, region, "critical", "FAIL",
                        scan_run_id, tenant_id, [],
                        {"public_access": True,
                         "title": "IBM Db2 instance has a public endpoint configured",
                         "remediation": "Disable public endpoint and use private endpoint only."},
                    ))

                allowlist = fields.get("allowlisted_ips") or fields.get("ip_allowlist") or []
                if not allowlist:
                    findings.append(_finding(
                        "ibm.db2.instance.ip_allowlist_configured", "access_control",
                        uid, rtype, "ibm", acct, region, "high", "FAIL",
                        scan_run_id, tenant_id, [],
                        {"title": "IBM Db2 instance has no IP allowlist configured",
                         "remediation": "Configure IP allowlist to restrict Db2 access to known CIDRs."},
                    ))

            # ── Cloudant checks ──
            elif "cloudant" in svc or "cloudant" in rtype.lower():
                cors = fields.get("cors") or {}
                origins = cors.get("origins") or []
                if "*" in origins or origins == ["*"]:
                    findings.append(_finding(
                        "ibm.cloudant.instance.cors_restricted", "access_control",
                        uid, rtype, "ibm", acct, region, "medium", "FAIL",
                        scan_run_id, tenant_id, [],
                        {"public_access": True,
                         "title": "IBM Cloudant CORS allows all origins (*)",
                         "remediation": "Restrict CORS origins to known application domains."},
                    ))

                auth_type = (fields.get("authentication_method") or fields.get("auth_type") or "").lower()
                if auth_type not in ("iam", "iam_only"):
                    findings.append(_finding(
                        "ibm.cloudant.instance.iam_only_auth", "access_control",
                        uid, rtype, "ibm", acct, region, "high", "FAIL",
                        scan_run_id, tenant_id, [],
                        {"title": "IBM Cloudant instance allows legacy credential authentication",
                         "remediation": "Set Cloudant authentication mode to IAM-only."},
                    ))

            # ── Event Streams checks ──
            elif "event-stream" in svc or "eventstream" in svc or "kafka" in rtype.lower():
                endpoints = fields.get("kafka_brokers_sasl") or []
                has_public = any("public" in str(ep).lower() for ep in endpoints)
                if has_public:
                    findings.append(_finding(
                        "ibm.eventstreams.instance.private_endpoint_only", "access_control",
                        uid, rtype, "ibm", acct, region, "high", "FAIL",
                        scan_run_id, tenant_id, [],
                        {"public_access": True,
                         "title": "IBM Event Streams instance exposes public broker endpoints",
                         "remediation": "Use private-only endpoints for Event Streams brokers."},
                    ))

        logger.info(
            "IBM DataSec provider: %d findings for scan=%s account=%s",
            len(findings), scan_run_id, account_id,
        )
        return findings
