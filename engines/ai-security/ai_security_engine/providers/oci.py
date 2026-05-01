"""OCI provider for AI Security engine — MITRE ATLAS 5-pillar analyze()."""
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .base import BaseAISecurityProvider

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# OCI resource types present in discovery_findings.
# OCI DataScience resource types are not yet enumerated by the discovery
# scanner.  We apply AI governance checks against the OCI proxy resource
# types that ARE present (audit events, security lists, object storage,
# VCN/RouteTable) to ensure AI workloads meet minimum ATLAS posture.
# ---------------------------------------------------------------------------


def _make_finding_id(rule_id: str, resource_uid: str, account_id: str, region: str) -> str:
    """Deterministic finding_id: sha256(rule_id|resource_uid|account_id|region)[:16]."""
    raw = f"{rule_id}|{resource_uid}|{account_id}|{region}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _atlas_detail(technique_id: Optional[str]) -> Dict[str, str]:
    """Return atlas_detail dict for a given technique ID."""
    atlas_map = {
        "AML.T0000": ("Model Evasion", "Adversary crafts inputs to evade model detection."),
        "AML.T0001": ("Data Poisoning", "Adversary injects malicious data into training set."),
        "AML.T0002": ("Model Inversion", "Adversary extracts training data from model outputs."),
        "AML.T0003": ("Model Stealing", "Adversary replicates model via repeated queries."),
        "AML.T0004": ("Backdoor ML Model", "Adversary implants hidden trigger in model weights."),
        "AML.T0005": ("Poison Training Data", "Adversary corrupts training data pipeline."),
    }
    if not technique_id:
        return {}
    name, desc = atlas_map.get(technique_id, ("", ""))
    return {"technique_id": technique_id, "technique_name": name, "description": desc}


def _finding(
    rule_id: str,
    resource_uid: str,
    resource_type: str,
    account_id: str,
    region: str,
    tenant_id: str,
    scan_run_id: str,
    severity: str,
    pillar: str,
    atlas_technique: Optional[str],
    title: str,
    detail: str,
    status: str = "FAIL",
) -> Dict[str, Any]:
    """Build a complete ATLAS finding dict for OCI."""
    now = datetime.now(timezone.utc)
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
        "pillar": pillar,
        "atlas_technique": atlas_technique,
        "atlas_detail": _atlas_detail(atlas_technique),
        "blast_radius_score": 0,
        "rule_id": rule_id,
        "title": title,
        "detail": detail,
        "first_seen_at": now,
        "last_seen_at": now,
    }


class OCIAISecurityProvider(BaseAISecurityProvider):
    """OCI AI security provider.

    OCI DataScience (notebooks, models, jobs) resource types are not yet
    enumerated by the discovery scanner.  This provider applies ATLAS-mapped
    checks against the OCI proxy resource types that ARE present:
    - oci.audit/Event — governance and logging coverage
    - oci.core/SecurityList — inference endpoint exposure
    - oci.objectstorage/Bucket — training data security
    - oci.core/Vcn — network isolation
    """

    @property
    def discovery_services(self) -> List[str]:
        """OCI AI/ML service names targeted by the scanner."""
        return ["datascience", "aidocument", "ailanguage", "aivision"]

    @property
    def inventory_resource_prefixes(self) -> List[str]:
        """Inventory resource_type prefixes for OCI AI assets."""
        return ["datascience.", "aidocument."]

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        discoveries_conn: Any,
        check_conn: Optional[Any] = None,
    ) -> List[Dict[str, Any]]:
        """Produce MITRE ATLAS findings for OCI resources.

        Applies AI governance and security checks to OCI proxy resource types
        (audit events, security lists, object storage, VCN) that are present
        in discovery_findings.

        Args:
            scan_run_id: Current pipeline scan run identifier.
            tenant_id: Tenant identifier — all queries filtered by this.
            account_id: OCI tenancy identifier.
            discoveries_conn: psycopg2 connection to discoveries DB.
            check_conn: Unused for OCI.

        Returns:
            List of ATLAS finding dicts.
        """
        findings: List[Dict[str, Any]] = []

        try:
            cur = discoveries_conn.cursor()
            cur.execute(
                """
                SELECT resource_uid, resource_type, region, emitted_fields
                FROM discovery_findings
                WHERE tenant_id = %s
                  AND scan_run_id = %s
                  AND provider = 'oci'
                """,
                (tenant_id, scan_run_id),
            )
            rows = cur.fetchall()
            cur.close()
        except Exception as exc:
            logger.error("OCI AI analyze(): DB query failed: %s", exc)
            return findings

        logger.info(
            "OCI AI analyze(): %d resource rows for scan %s", len(rows), scan_run_id
        )

        resource_types_seen = {r[1] for r in rows}
        has_audit = "oci.audit/Event" in resource_types_seen
        has_seclist = "oci.core/SecurityList" in resource_types_seen
        has_bucket = "oci.objectstorage/Bucket" in resource_types_seen
        has_vcn = "oci.core/Vcn" in resource_types_seen

        acct_uid = f"oci:{account_id}:ai_governance"

        for resource_uid, resource_type, res_region, ef in rows:
            if not ef:
                ef = {}
            r_region = res_region or "ap-mumbai-1"

            # ------------------------------------------------------------------
            # Pillar 5 — AI Governance: Audit event analysis
            # ------------------------------------------------------------------
            if resource_type == "oci.audit/Event":
                event_type = ef.get("eventType", "") or ef.get("type", "")
                # DataScience API calls in audit events — check for unauthenticated access
                if "datascience" in event_type.lower() or "datasci" in event_type.lower():
                    source_ip = ef.get("sourceIPAddress", "")
                    principal = ef.get("principalName", "") or ef.get("subject", "")

                    if not principal:
                        findings.append(_finding(
                            rule_id="oci.ai_sec.ai_governance.datascience_unauthenticated_event",
                            resource_uid=resource_uid,
                            resource_type=resource_type,
                            account_id=account_id,
                            region=r_region,
                            tenant_id=tenant_id,
                            scan_run_id=scan_run_id,
                            severity="CRITICAL",
                            pillar="ai_governance",
                            atlas_technique="AML.T0002",
                            title="OCI DataScience API call without authenticated principal in audit log",
                            detail=(
                                f"Audit event type={event_type} has no principalName. "
                                "This may indicate unauthenticated access to AI/ML resources."
                            ),
                        ))

            # ------------------------------------------------------------------
            # Pillar 3 — Inference Security: SecurityList checks
            # ------------------------------------------------------------------
            if resource_type == "oci.core/SecurityList":
                ingress_rules = ef.get("ingressSecurityRules") or []
                for rule in ingress_rules:
                    if not isinstance(rule, dict):
                        continue
                    source = rule.get("source", "")
                    protocol = str(rule.get("protocol", ""))
                    tcp_options = rule.get("tcpOptions") or {}
                    dest_port_range = tcp_options.get("destinationPortRange") or {}
                    max_port = dest_port_range.get("max", 0)
                    min_port = dest_port_range.get("min", 0)

                    # Ingress from 0.0.0.0/0 on any port
                    if source in ("0.0.0.0/0", "::/0"):
                        findings.append(_finding(
                            rule_id="oci.ai_sec.inference_security.seclist_public_ingress",
                            resource_uid=resource_uid,
                            resource_type=resource_type,
                            account_id=account_id,
                            region=r_region,
                            tenant_id=tenant_id,
                            scan_run_id=scan_run_id,
                            severity="HIGH",
                            pillar="inference_security",
                            atlas_technique="AML.T0002",
                            title="OCI Security List allows public ingress — AI inference endpoint exposed",
                            detail=(
                                f"Ingress rule allows traffic from {source} "
                                f"protocol={protocol} ports {min_port}-{max_port}. "
                                "OCI DataScience model deployment endpoints may be publicly reachable."
                            ),
                        ))
                        break

            # ------------------------------------------------------------------
            # Pillar 2 — Training Data Security: Object Storage checks
            # ------------------------------------------------------------------
            if resource_type == "oci.objectstorage/Bucket":
                public_access_type = ef.get("publicAccessType", "NoPublicAccess")
                versioning = ef.get("versioning", "Disabled")

                if public_access_type != "NoPublicAccess":
                    findings.append(_finding(
                        rule_id="oci.ai_sec.training_data_security.bucket_public_access",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="CRITICAL",
                        pillar="training_data_security",
                        atlas_technique="AML.T0001",
                        title="OCI Object Storage bucket is publicly accessible — AI training data at risk",
                        detail=(
                            f"publicAccessType='{public_access_type}'. Training datasets may be "
                            "readable by unauthenticated principals, enabling data poisoning."
                        ),
                    ))

                if versioning == "Disabled":
                    findings.append(_finding(
                        rule_id="oci.ai_sec.training_data_security.bucket_no_versioning",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="HIGH",
                        pillar="training_data_security",
                        atlas_technique="AML.T0005",
                        title="OCI Object Storage bucket versioning disabled — training data integrity unprotected",
                        detail=(
                            "Versioning is disabled. Overwrite attacks on training datasets "
                            "cannot be detected or rolled back."
                        ),
                    ))

        # ------------------------------------------------------------------
        # Account-level governance checks
        # ------------------------------------------------------------------
        if not has_audit:
            findings.append(_finding(
                rule_id="oci.ai_sec.ai_governance.no_audit_events",
                resource_uid=acct_uid,
                resource_type="OCITenancy",
                account_id=account_id,
                region="ap-mumbai-1",
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
                severity="HIGH",
                pillar="ai_governance",
                atlas_technique=None,
                title="No OCI Audit events found — AI workload activity cannot be monitored",
                detail=(
                    "No audit events detected. OCI Audit must be enabled to track "
                    "DataScience API calls and detect anomalous AI model access."
                ),
            ))

        if not has_vcn:
            findings.append(_finding(
                rule_id="oci.ai_sec.inference_security.no_vcn",
                resource_uid=acct_uid,
                resource_type="OCITenancy",
                account_id=account_id,
                region="ap-mumbai-1",
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
                severity="HIGH",
                pillar="inference_security",
                atlas_technique="AML.T0002",
                title="No OCI VCN found — AI inference workloads may lack network isolation",
                detail=(
                    "No Virtual Cloud Networks detected. OCI DataScience notebooks and "
                    "model deployments should run in private subnets within a VCN."
                ),
            ))

        # Pillar 1 — Model Security: no supply-chain control without SecList
        if not has_seclist:
            findings.append(_finding(
                rule_id="oci.ai_sec.model_security.no_security_list",
                resource_uid=acct_uid,
                resource_type="OCITenancy",
                account_id=account_id,
                region="ap-mumbai-1",
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
                severity="MEDIUM",
                pillar="model_security",
                atlas_technique="AML.T0003",
                title="No OCI Security Lists found — AI model endpoint access control not verified",
                detail=(
                    "No Security Lists detected. Model serving endpoints on OCI DataScience "
                    "require security list rules to restrict inbound access."
                ),
            ))

        # Pillar 4 — Supply Chain
        findings.append(_finding(
            rule_id="oci.ai_sec.supply_chain.datascience_service_not_enumerated",
            resource_uid=acct_uid,
            resource_type="OCITenancy",
            account_id=account_id,
            region="ap-mumbai-1",
            tenant_id=tenant_id,
            scan_run_id=scan_run_id,
            severity="MEDIUM",
            pillar="supply_chain",
            atlas_technique="AML.T0004",
            title="OCI DataScience service not yet enumerated by discovery scanner",
            detail=(
                "OCI DataScience Models, Notebooks, and Projects are not yet in "
                "discovery_findings. Enable OCI DataScience discovery to evaluate "
                "model provenance and supply chain integrity."
            ),
        ))

        logger.info(
            "OCI AI analyze(): produced %d ATLAS findings for scan %s",
            len(findings), scan_run_id,
        )
        return findings
