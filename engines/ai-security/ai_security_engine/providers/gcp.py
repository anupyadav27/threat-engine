"""GCP provider for AI Security engine — MITRE ATLAS 5-pillar analyze()."""
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .base import BaseAISecurityProvider

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# GCP resource types present in discovery_findings.
# Vertex AI / AIPlatform resource types are not yet enumerated.
# We apply AI governance checks against the GCP resources that ARE present.
# ---------------------------------------------------------------------------
GCP_PROXY_RESOURCE_TYPES = {
    "storage.googleapis.com/Bucket",
    "iam.googleapis.com/ServiceAccount",
    "compute.googleapis.com/Firewall",
    "compute.googleapis.com/Subnetwork",
    "compute.googleapis.com/Route",
}


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
    """Build a complete ATLAS finding dict for GCP."""
    now = datetime.now(timezone.utc)
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


class GCPAISecurityProvider(BaseAISecurityProvider):
    """GCP AI security provider.

    Vertex AI, AutoML, and AIPlatform resource types are not yet enumerated
    by the discovery scanner.  This provider applies ATLAS-mapped governance
    checks against the GCP resources that ARE present (Cloud Storage buckets
    for training data, Service Accounts for model identity, Firewall rules for
    inference endpoint exposure) to ensure AI workloads meet minimum posture.
    """

    @property
    def discovery_services(self) -> List[str]:
        """GCP AI/ML service names targeted by the scanner."""
        return [
            "aiplatform", "automl", "vision", "language",
            "speech", "videointelligence", "translate",
            "documentai", "dialogflow", "discoveryengine",
        ]

    @property
    def inventory_resource_prefixes(self) -> List[str]:
        """Inventory resource_type prefixes for GCP AI assets."""
        return ["aiplatform.", "automl.", "vision.", "dialogflow."]

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        discoveries_conn: Any,
        check_conn: Optional[Any] = None,
    ) -> List[Dict[str, Any]]:
        """Produce MITRE ATLAS findings for GCP resources.

        Applies AI governance and security checks to GCP proxy resource types
        (Cloud Storage buckets, Service Accounts, Firewall rules) that are
        present in discovery_findings.

        Args:
            scan_run_id: Current pipeline scan run identifier.
            tenant_id: Tenant identifier — all queries filtered by this.
            account_id: GCP project identifier.
            discoveries_conn: psycopg2 connection to discoveries DB.
            check_conn: Unused for GCP.

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
                  AND provider = 'gcp'
                """,
                (tenant_id, scan_run_id),
            )
            rows = cur.fetchall()
            cur.close()
        except Exception as exc:
            logger.error("GCP AI analyze(): DB query failed: %s", exc)
            return findings

        logger.info(
            "GCP AI analyze(): %d resource rows for scan %s", len(rows), scan_run_id
        )

        resource_types_seen = {r[1] for r in rows}
        has_storage = "storage.googleapis.com/Bucket" in resource_types_seen
        has_sa = "iam.googleapis.com/ServiceAccount" in resource_types_seen
        has_firewall = "compute.googleapis.com/Firewall" in resource_types_seen

        acct_uid = f"gcp:{account_id}:ai_governance"

        for resource_uid, resource_type, res_region, ef in rows:
            if not ef:
                ef = {}
            r_region = res_region or "global"

            # ------------------------------------------------------------------
            # Pillar 2 — Training Data Security: GCS Bucket checks
            # ------------------------------------------------------------------
            if resource_type == "storage.googleapis.com/Bucket":
                iam_config = ef.get("iamConfiguration") or {}
                public_access = iam_config.get("publicAccessPrevention", "")
                uniform_bucket_iam = iam_config.get("uniformBucketLevelAccess", {})
                uniform_enabled = (
                    uniform_bucket_iam.get("enabled", False)
                    if isinstance(uniform_bucket_iam, dict)
                    else False
                )

                # Not "enforced" means bucket may be publicly readable
                if public_access not in ("enforced", "inherited"):
                    findings.append(_finding(
                        rule_id="gcp.ai_sec.training_data_security.gcs_public_access_not_enforced",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="CRITICAL",
                        pillar="training_data_security",
                        atlas_technique="AML.T0001",
                        title="GCS bucket public access prevention not enforced — AI training data at risk",
                        detail=(
                            f"publicAccessPrevention='{public_access}'. Training datasets stored "
                            "in this bucket may be accessible to unauthenticated principals."
                        ),
                    ))

                if not uniform_enabled:
                    findings.append(_finding(
                        rule_id="gcp.ai_sec.training_data_security.gcs_non_uniform_iam",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="HIGH",
                        pillar="training_data_security",
                        atlas_technique="AML.T0005",
                        title="GCS bucket uses ACL-based access — training data poisoning risk",
                        detail=(
                            "Uniform bucket-level IAM is disabled. Object-level ACLs can grant "
                            "overly broad write access, enabling training data poisoning."
                        ),
                    ))

            # ------------------------------------------------------------------
            # Pillar 1 — Model Security: Service Account checks
            # ------------------------------------------------------------------
            if resource_type == "iam.googleapis.com/ServiceAccount":
                sa_keys = ef.get("keys") or []
                # If SA has user-managed keys, model identity can be stolen
                if isinstance(sa_keys, list) and len(sa_keys) > 0:
                    findings.append(_finding(
                        rule_id="gcp.ai_sec.model_security.sa_user_managed_keys",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="HIGH",
                        pillar="model_security",
                        atlas_technique="AML.T0003",
                        title="GCP Service Account has user-managed keys — AI model identity theft risk",
                        detail=(
                            f"Service account has {len(sa_keys)} user-managed key(s). "
                            "Leaked SA keys allow model-stealing via Vertex AI API access."
                        ),
                    ))

            # ------------------------------------------------------------------
            # Pillar 3 — Inference Security: Firewall rule checks
            # ------------------------------------------------------------------
            if resource_type == "compute.googleapis.com/Firewall":
                direction = ef.get("direction", "")
                allowed_rules = ef.get("allowed") or []
                source_ranges = ef.get("sourceRanges") or []

                # Inbound allow from 0.0.0.0/0
                is_public_inbound = (
                    direction == "INGRESS"
                    and ("0.0.0.0/0" in source_ranges or "::/0" in source_ranges)
                )
                if is_public_inbound and allowed_rules:
                    for rule in allowed_rules:
                        if not isinstance(rule, dict):
                            continue
                        ports = rule.get("ports") or []
                        # Check for ports used by ML serving frameworks
                        ml_ports = {"80", "443", "8080", "8443", "8501", "8500", "5000"}
                        exposed_ports = set(str(p) for p in ports) & ml_ports
                        if exposed_ports or not ports:
                            findings.append(_finding(
                                rule_id="gcp.ai_sec.inference_security.firewall_public_ingress",
                                resource_uid=resource_uid,
                                resource_type=resource_type,
                                account_id=account_id,
                                region=r_region,
                                tenant_id=tenant_id,
                                scan_run_id=scan_run_id,
                                severity="HIGH",
                                pillar="inference_security",
                                atlas_technique="AML.T0002",
                                title="GCP Firewall allows public ingress — AI inference endpoint exposed",
                                detail=(
                                    f"Firewall rule allows ingress from 0.0.0.0/0 on "
                                    f"ports {exposed_ports or 'all'}. "
                                    "Vertex AI and TF Serving endpoints may be publicly reachable."
                                ),
                            ))
                            break

        # ------------------------------------------------------------------
        # Pillar 5 — AI Governance: account-level checks
        # ------------------------------------------------------------------
        if not has_storage:
            findings.append(_finding(
                rule_id="gcp.ai_sec.ai_governance.no_gcs_bucket",
                resource_uid=acct_uid,
                resource_type="GCPProject",
                account_id=account_id,
                region="global",
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
                severity="MEDIUM",
                pillar="ai_governance",
                atlas_technique=None,
                title="No GCS buckets found — AI training data governance cannot be assessed",
                detail=(
                    "No Cloud Storage buckets detected in this project. "
                    "Verify AI training data is not stored in unscanned regions/projects."
                ),
            ))

        if not has_sa:
            findings.append(_finding(
                rule_id="gcp.ai_sec.ai_governance.no_service_accounts",
                resource_uid=acct_uid,
                resource_type="GCPProject",
                account_id=account_id,
                region="global",
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
                severity="HIGH",
                pillar="ai_governance",
                atlas_technique=None,
                title="No GCP Service Accounts found — AI workload identity governance gap",
                detail=(
                    "No Service Accounts detected. AI workloads on Vertex AI require "
                    "dedicated service accounts with least-privilege IAM bindings."
                ),
            ))

        # Pillar 4 — Supply Chain: no firewall means no perimeter
        if not has_firewall:
            findings.append(_finding(
                rule_id="gcp.ai_sec.supply_chain.no_firewall",
                resource_uid=acct_uid,
                resource_type="GCPProject",
                account_id=account_id,
                region="global",
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
                severity="HIGH",
                pillar="supply_chain",
                atlas_technique="AML.T0004",
                title="No GCP Firewall rules found — AI model registry and artifact store unprotected",
                detail=(
                    "No Compute Firewall rules detected. Model registries and Artifact Registry "
                    "should be protected by VPC firewall rules to prevent supply-chain attacks."
                ),
            ))

        logger.info(
            "GCP AI analyze(): produced %d ATLAS findings for scan %s",
            len(findings), scan_run_id,
        )
        return findings
