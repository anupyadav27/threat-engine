"""
IBM AI Security provider — MITRE ATLAS 5-pillar analysis for Watson Studio,
Watson Machine Learning, and IBM OpenScale workloads.
"""
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .base import BaseAISecurityProvider

logger = logging.getLogger(__name__)

_ATLAS = {
    "AML.T0000": {"name": "Model Evasion",           "pillar": "inference_security",      "severity": "high"},
    "AML.T0001": {"name": "Data Poisoning",           "pillar": "training_data_security",  "severity": "critical"},
    "AML.T0003": {"name": "Model Stealing",           "pillar": "model_security",          "severity": "medium"},
    "AML.T0012": {"name": "Overpermissive IAM to ML", "pillar": "ai_governance",           "severity": "high"},
    "AML.T0048": {"name": "Insufficient Monitoring",  "pillar": "ai_governance",           "severity": "high"},
}


def _fid(rule_id: str, resource_uid: str, account_id: str, region: str) -> str:
    raw = f"{rule_id}|{resource_uid}|{account_id}|{region}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _finding(rule_id: str, atlas_id: str, resource_uid: str, resource_type: str,
             provider: str, account_id: str, region: str, severity: str,
             scan_run_id: str, tenant_id: str, title: str, remediation: str) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    tech = _ATLAS.get(atlas_id, {})
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
        "status": "FAIL",
        "pillar": tech.get("pillar", "ai_governance"),
        "atlas_technique": atlas_id,
        "atlas_detail": {"name": tech.get("name", ""), "description": title},
        "blast_radius_score": 0,
        "first_seen_at": now,
        "last_seen_at": now,
        "rule_id": rule_id,
        "title": title,
        "remediation": remediation,
    }


class IBMAISecurityProvider(BaseAISecurityProvider):
    """IBM AI/ML security analysis provider (Watson Studio + WML + OpenScale)."""

    @property
    def discovery_services(self) -> List[str]:
        return ["watson-studio", "watson-ml", "natural-language-understanding", "openscale"]

    @property
    def inventory_resource_prefixes(self) -> List[str]:
        return ["watson.", "ibm-ml.", "openscale."]

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        discoveries_conn: Any,
        check_conn: Optional[Any] = None,
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
                      AND service IN ('watson-studio', 'watson-ml',
                                      'machine-learning', 'openscale',
                                      'watson_studio', 'machine_learning')
                    ORDER BY resource_uid
                    """,
                    (scan_run_id, tenant_id),
                )
                rows = cur.fetchall()
        except Exception as exc:
            logger.error("IBM AI Security: discovery query failed: %s", exc)
            return findings

        for row in rows:
            fields = row.get("emitted_fields") or {}
            uid = row.get("resource_uid", "")
            rtype = row.get("resource_type", "")
            region = row.get("region") or "global"
            acct = row.get("account_id") or account_id or ""
            svc = (row.get("service") or rtype).lower()

            # ── Watson Studio project ──
            if "watson_studio" in svc or "watson-studio" in svc or "project" in rtype.lower():
                # P4: Project visibility (private check)
                visibility = (fields.get("visibility") or fields.get("public_access") or "").lower()
                if visibility == "public":
                    findings.append(_finding(
                        "ibm.watson_studio.project.private_access_only", "AML.T0012",
                        uid, rtype, "ibm", acct, region, "critical",
                        scan_run_id, tenant_id,
                        "Watson Studio project has public visibility — exposes ML assets to unauthenticated users",
                        "Set Watson Studio project visibility to private.",
                    ))

                # P5: Activity tracking
                activity = fields.get("activity_tracking_enabled") or fields.get("activity_tracking") or False
                if not activity:
                    findings.append(_finding(
                        "ibm.watson_studio.project.activity_tracking_enabled", "AML.T0048",
                        uid, rtype, "ibm", acct, region, "high",
                        scan_run_id, tenant_id,
                        "Watson Studio project has no Activity Tracker events enabled",
                        "Enable Activity Tracker integration for Watson Studio project.",
                    ))

                # P5: Notebook idle timeout
                notebooks = fields.get("notebooks") or []
                for nb in notebooks:
                    if not isinstance(nb, dict):
                        continue
                    idle_timeout = nb.get("idle_timeout_minutes") or nb.get("kernel_idle_timeout") or 0
                    if not idle_timeout or int(idle_timeout) > 60:
                        nb_uid = nb.get("id") or f"{uid}/notebook/{nb.get('name', 'unknown')}"
                        findings.append(_finding(
                            "ibm.watson_studio.notebook.kernel_idle_timeout", "AML.T0048",
                            nb_uid, "watson_studio.notebook", "ibm", acct, region, "medium",
                            scan_run_id, tenant_id,
                            "Watson Studio notebook has no idle timeout or timeout > 60 min",
                            "Set notebook auto-shutdown to ≤ 60 minutes idle to prevent credential exposure.",
                        ))

            # ── Watson Machine Learning deployment ──
            elif ("machine_learning" in svc or "machine-learning" in svc or
                  "watson-ml" in svc or "deployment" in rtype.lower()):
                # P4: Public endpoint
                endpoint_url = fields.get("url") or fields.get("serving_url") or ""
                if endpoint_url and "private" not in endpoint_url.lower() and endpoint_url.startswith("http"):
                    findings.append(_finding(
                        "ibm.machine_learning.deployment.private_endpoint", "AML.T0000",
                        uid, rtype, "ibm", acct, region, "critical",
                        scan_run_id, tenant_id,
                        "Watson ML deployment uses a public inference endpoint",
                        "Configure WML deployment to use private endpoint only.",
                    ))

                # P5: Activity logging
                logging_enabled = fields.get("activity_logging") or fields.get("logging_enabled") or False
                if not logging_enabled:
                    findings.append(_finding(
                        "ibm.machine_learning.instance.activity_logging_enabled", "AML.T0048",
                        uid, rtype, "ibm", acct, region, "high",
                        scan_run_id, tenant_id,
                        "Watson ML instance has no Activity Tracker integration",
                        "Enable Activity Tracker logging for WML instance.",
                    ))

                # P2: Model artifact public download
                public_dl = fields.get("publicly_downloadable") or fields.get("public_download") or False
                if public_dl:
                    findings.append(_finding(
                        "ibm.machine_learning.model.no_public_download", "AML.T0003",
                        uid, rtype, "ibm", acct, region, "critical",
                        scan_run_id, tenant_id,
                        "Watson ML model artifacts are publicly downloadable",
                        "Disable public download on model artifacts in WML.",
                    ))

            # ── OpenScale / Watson OpenPages ──
            elif "openscale" in svc or "openscale" in rtype.lower():
                monitors = fields.get("monitors") or fields.get("monitor_instances") or []
                drift_active = any(
                    "drift" in str(m.get("monitor_definition_id", "")).lower() and
                    m.get("enabled", False)
                    for m in monitors if isinstance(m, dict)
                )
                fairness_active = any(
                    "fairness" in str(m.get("monitor_definition_id", "")).lower() and
                    m.get("enabled", False)
                    for m in monitors if isinstance(m, dict)
                )
                if not drift_active:
                    findings.append(_finding(
                        "ibm.openscale.subscription.drift_monitor_active", "AML.T0048",
                        uid, rtype, "ibm", acct, region, "high",
                        scan_run_id, tenant_id,
                        "IBM OpenScale subscription has no drift detection monitor active",
                        "Enable drift detection monitor in OpenScale for production models.",
                    ))
                if not fairness_active:
                    findings.append(_finding(
                        "ibm.openscale.subscription.fairness_monitor_active", "AML.T0048",
                        uid, rtype, "ibm", acct, region, "medium",
                        scan_run_id, tenant_id,
                        "IBM OpenScale subscription has no fairness (bias) monitor active",
                        "Enable fairness monitor in OpenScale to detect model bias.",
                    ))

        logger.info(
            "IBM AI Security provider: %d findings for scan=%s account=%s",
            len(findings), scan_run_id, account_id,
        )
        return findings
