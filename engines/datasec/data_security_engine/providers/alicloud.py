"""AliCloud provider for Data Security engine — 8-module DSPM analyze()."""

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from psycopg2.extras import RealDictCursor

from .base import BaseDataSecProvider

logger = logging.getLogger(__name__)

# Actual resource_type values in discovery_findings for AliCloud
# AliCloud discovery has: alicloud.ram/Role, alicloud.ram/User, alicloud.kms/Key,
#                         alicloud.actiontrail/Trail, alicloud.vpc/Vpc
_KMS_TYPES = {"alicloud.kms/Key"}
_TRAIL_TYPES = {"alicloud.actiontrail/Trail"}
_IAM_TYPES = {"alicloud.ram/User", "alicloud.ram/Role"}
_ALL_DATA_TYPES = _KMS_TYPES | _TRAIL_TYPES | _IAM_TYPES

_CONFIDENTIAL_TOKENS = {"key", "secret", "credential", "password", "token", "private", "sensitive"}
_PII_TOKENS = {"user", "personal", "customer", "member", "employee"}


def _make_finding_id(rule_id: str, resource_uid: str, account_id: str, region: str) -> str:
    raw = f"{rule_id}|{resource_uid}|{account_id}|{region}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _resource_type_slug(resource_type: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in resource_type.lower()).strip("_")


def _infer_labels(name: str, resource_type: str = "") -> List[str]:
    text = (name + " " + resource_type).lower()
    tokens = set(text.replace("-", " ").replace("_", " ").replace(".", " ").replace("/", " ").split())
    labels: List[str] = []
    if tokens & _PII_TOKENS:
        labels.append("PII")
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

        AliCloud discovery currently produces KMS keys, ActionTrail records,
        and RAM users/roles. These are evaluated for key management, audit
        logging, and identity data security posture.

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
                    (scan_run_id, tenant_id, list(_ALL_DATA_TYPES)),
                )
                rows = cur.fetchall()
        except Exception as exc:
            logger.error("AliCloud DSPM: failed to load discovery_findings: %s", exc)
            return []

        if not rows:
            logger.warning("AliCloud DSPM: no data-relevant rows for scan_run_id=%s", scan_run_id)
            return []

        for row in rows:
            resource_uid = row.get("resource_uid") or ""
            resource_type = row.get("resource_type", "")
            region = row.get("region") or "cn-hangzhou"
            emitted = row.get("emitted_fields") or {}
            slug = _resource_type_slug(resource_type)

            name = (
                emitted.get("KeyId")
                or emitted.get("Name")
                or emitted.get("UserName")
                or emitted.get("resource_id")
                or resource_uid
            )
            labels = _infer_labels(str(name), resource_type)

            # ── Module 1: classification ────────────────────────────────────
            rule_id = f"alicloud.dspm.classification.{slug}"
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
            if resource_type in _KMS_TYPES:
                key_state = emitted.get("KeyState", "")
                key_usage = emitted.get("KeyUsage", "ENCRYPT/DECRYPT")
                enc_status = "encrypted" if key_state == "Enabled" else "disabled"
                sev = "HIGH" if key_state != "Enabled" else "INFO"
                rule_id = f"alicloud.dspm.encryption.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="encryption",
                    severity=sev, status="FAIL" if key_state != "Enabled" else "PASS",
                    classification_labels=labels, encryption_status=enc_status,
                    public_access=False, now=now,
                ))
                # Suppress unused variable warning
                _ = key_usage
            else:
                # RAM users/roles and trails: flag as needing encryption review
                rule_id = f"alicloud.dspm.encryption.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="encryption",
                    severity="MEDIUM", status="FAIL",
                    classification_labels=labels, encryption_status="unknown",
                    public_access=False, now=now,
                ))

            # ── Module 3: access_control ────────────────────────────────────
            # RAM users without MFA = access control risk
            if resource_type in _IAM_TYPES:
                mfa = bool(emitted.get("MFAEnabled") or emitted.get("EnabledMFA"))
                sev = "HIGH" if not mfa else "INFO"
                rule_id = f"alicloud.dspm.access_control.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="access_control",
                    severity=sev, status="FAIL" if not mfa else "PASS",
                    classification_labels=labels, encryption_status="unknown",
                    public_access=False, now=now,
                ))
            else:
                rule_id = f"alicloud.dspm.access_control.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="access_control",
                    severity="INFO", status="PASS",
                    classification_labels=labels, encryption_status="unknown",
                    public_access=False, now=now,
                ))

            # ── Module 4: data_residency ────────────────────────────────────
            # AliCloud China regions for data sovereignty
            in_cn = region.startswith("cn-")
            sev = "MEDIUM" if not in_cn else "INFO"
            rule_id = f"alicloud.dspm.data_residency.{slug}"
            findings.append(_base_finding(
                rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                account_id=account_id, region=region, scan_run_id=scan_run_id,
                tenant_id=tenant_id, dspm_module="data_residency",
                severity=sev, status="PASS",
                classification_labels=labels, encryption_status="unknown",
                public_access=False, now=now,
            ))

            # ── Module 5: activity_logging ──────────────────────────────────
            if resource_type in _TRAIL_TYPES:
                # ActionTrail: Status "Fresh" or "Enable" means logging is running
                trail_status = emitted.get("Status", "")
                is_logging = trail_status in {"Enable", "Fresh"}
                sev = "HIGH" if not is_logging else "INFO"
                rule_id = f"alicloud.dspm.activity_logging.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="activity_logging",
                    severity=sev, status="FAIL" if not is_logging else "PASS",
                    classification_labels=labels, encryption_status="unknown",
                    public_access=False, now=now,
                ))
            else:
                rule_id = f"alicloud.dspm.activity_logging.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="activity_logging",
                    severity="MEDIUM", status="FAIL",
                    classification_labels=labels, encryption_status="unknown",
                    public_access=False, now=now,
                ))

            # ── Module 6: lifecycle ─────────────────────────────────────────
            if resource_type in _KMS_TYPES:
                # KMS key rotation
                rotation = bool(emitted.get("AutomaticRotation") == "Enabled")
                sev = "MEDIUM" if not rotation else "INFO"
                rule_id = f"alicloud.dspm.lifecycle.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="lifecycle",
                    severity=sev, status="FAIL" if not rotation else "PASS",
                    classification_labels=labels, encryption_status="unknown",
                    public_access=False, now=now,
                ))
            else:
                rule_id = f"alicloud.dspm.lifecycle.{slug}"
                findings.append(_base_finding(
                    rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                    account_id=account_id, region=region, scan_run_id=scan_run_id,
                    tenant_id=tenant_id, dspm_module="lifecycle",
                    severity="LOW", status="PASS",
                    classification_labels=labels, encryption_status="unknown",
                    public_access=False, now=now,
                ))

            # ── Module 7: data_lineage ──────────────────────────────────────
            rule_id = f"alicloud.dspm.data_lineage.{slug}"
            findings.append(_base_finding(
                rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                account_id=account_id, region=region, scan_run_id=scan_run_id,
                tenant_id=tenant_id, dspm_module="data_lineage",
                severity="LOW", status="PASS",
                classification_labels=labels, encryption_status="unknown",
                public_access=False, now=now,
            ))

            # ── Module 8: governance_score ──────────────────────────────────
            if resource_type in _KMS_TYPES:
                key_state2 = emitted.get("KeyState", "")
                enc_ok = key_state2 == "Enabled"
                pub_ok = True
            elif resource_type in _IAM_TYPES:
                enc_ok = False
                pub_ok = bool(emitted.get("MFAEnabled") or emitted.get("EnabledMFA"))
            else:
                enc_ok = True
                pub_ok = True
            score = int(sum([enc_ok, pub_ok]) / 2 * 100)
            gov_sev = "HIGH" if score < 50 else ("MEDIUM" if score < 80 else "LOW")
            rule_id = f"alicloud.dspm.governance_score.{slug}"
            findings.append(_base_finding(
                rule_id=rule_id, resource_uid=resource_uid, resource_type=resource_type,
                account_id=account_id, region=region, scan_run_id=scan_run_id,
                tenant_id=tenant_id, dspm_module="governance_score",
                severity=gov_sev, status="FAIL" if score < 80 else "PASS",
                classification_labels=labels, encryption_status="unknown",
                public_access=False, now=now,
            ))

        logger.info("AliCloud DSPM analyze(): produced %d findings from %d rows", len(findings), len(rows))
        return findings
