"""Azure provider for AI Security engine — MITRE ATLAS 5-pillar analyze()."""
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .base import BaseAISecurityProvider

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Azure resource types that serve as AI/ML proxies in discovery_findings.
# The discovery scanner does not yet enumerate Azure ML-specific services
# (MachineLearning::Workspace, CognitiveServices::Account) so we use the
# general resource types present and apply AI governance checks.
# ---------------------------------------------------------------------------
AZURE_PROXY_RESOURCE_TYPES = {
    "KeyVault",           # AI model/key governance
    "StorageAccount",     # Training data storage
    "NetworkSecurityGroup",  # Network exposure for AI workloads
    "VirtualNetwork",     # AI workload isolation
    "Microsoft.Resources/resourceGroups",  # Governance boundary
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
    """Build a complete ATLAS finding dict for Azure."""
    now = datetime.now(timezone.utc)
    return {
        "finding_id": _make_finding_id(rule_id, resource_uid, account_id, region),
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        "account_id": account_id,
        "provider": "azure",
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


class AzureAISecurityProvider(BaseAISecurityProvider):
    """Azure AI security provider.

    Azure-specific AI/ML services (MachineLearning::Workspace,
    CognitiveServices::Account, OpenAI::Account) are not yet enumerated by
    the discovery scanner.  This provider applies ATLAS-mapped governance
    checks against the proxy resource types that ARE present (KeyVault,
    StorageAccount, NSG, VNet) to ensure AI workloads running in this Azure
    account meet minimum security posture.
    """

    @property
    def discovery_services(self) -> List[str]:
        """Azure AI/ML service names targeted by the scanner."""
        return [
            "ml", "cognitiveservices", "openai", "bot",
            "language", "vision", "speech", "formrecognizer",
            "anomalydetector", "personalizer", "contentmoderator",
        ]

    @property
    def inventory_resource_prefixes(self) -> List[str]:
        """Inventory resource_type prefixes for Azure AI assets."""
        return ["ml.", "cognitiveservices.", "openai.", "bot."]

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        discoveries_conn: Any,
        check_conn: Optional[Any] = None,
    ) -> List[Dict[str, Any]]:
        """Produce MITRE ATLAS findings for Azure resources.

        Because Azure ML-specific resource types are not yet in discovery_findings,
        this method applies AI governance checks to proxy resource types
        (KeyVault, StorageAccount, NSG) that are present, and emits account-level
        findings for missing AI governance controls.

        Args:
            scan_run_id: Current pipeline scan run identifier.
            tenant_id: Tenant identifier — all queries filtered by this.
            account_id: Azure subscription identifier.
            discoveries_conn: psycopg2 connection to discoveries DB.
            check_conn: Unused for Azure.

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
                  AND provider = 'azure'
                """,
                (tenant_id, scan_run_id),
            )
            rows = cur.fetchall()
            cur.close()
        except Exception as exc:
            logger.error("Azure AI analyze(): DB query failed: %s", exc)
            return findings

        logger.info(
            "Azure AI analyze(): %d resource rows for scan %s", len(rows), scan_run_id
        )

        resource_types_seen = {r[1] for r in rows}
        has_keyvault = "KeyVault" in resource_types_seen
        has_storage = "StorageAccount" in resource_types_seen
        has_nsg = "NetworkSecurityGroup" in resource_types_seen
        has_vnet = "VirtualNetwork" in resource_types_seen

        # Account-level sentinel UID for account-scope findings
        acct_uid = f"azure:{account_id}:ai_governance"
        region = "global"

        for resource_uid, resource_type, res_region, ef in rows:
            if not ef:
                ef = {}
            r_region = res_region or "global"

            # ------------------------------------------------------------------
            # Pillar 2 — Training Data Security: StorageAccount checks
            # ------------------------------------------------------------------
            if resource_type == "StorageAccount":
                # Public blob access enabled → CRITICAL (AML.T0001 training data poisoning)
                allow_blob_public = ef.get("allowBlobPublicAccess", True)
                https_only = ef.get("supportsHttpsTrafficOnly", False)

                if allow_blob_public is True or allow_blob_public == "true":
                    findings.append(_finding(
                        rule_id="azure.ai_sec.training_data_security.storage_public_blob_access",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="CRITICAL",
                        pillar="training_data_security",
                        atlas_technique="AML.T0001",
                        title="Azure Storage Account allows public blob access — AI training data at risk",
                        detail=(
                            "allowBlobPublicAccess=true exposes training datasets to unauthenticated "
                            "reads and potential poisoning via public write endpoints."
                        ),
                    ))

                if not https_only:
                    findings.append(_finding(
                        rule_id="azure.ai_sec.training_data_security.storage_http_allowed",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="HIGH",
                        pillar="training_data_security",
                        atlas_technique="AML.T0005",
                        title="Azure Storage Account permits HTTP traffic — training data in transit unencrypted",
                        detail=(
                            "supportsHttpsTrafficOnly=false allows training data to be intercepted "
                            "and poisoned in transit."
                        ),
                    ))

            # ------------------------------------------------------------------
            # Pillar 1 — Model Security: KeyVault checks
            # ------------------------------------------------------------------
            if resource_type == "KeyVault":
                soft_delete = ef.get("softDeleteEnabled", False)
                purge_protection = ef.get("enablePurgeProtection", False)

                if not soft_delete:
                    findings.append(_finding(
                        rule_id="azure.ai_sec.model_security.keyvault_no_soft_delete",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="HIGH",
                        pillar="model_security",
                        atlas_technique="AML.T0003",
                        title="Azure Key Vault soft-delete disabled — AI model keys unprotected",
                        detail=(
                            "Without soft-delete, accidental or malicious deletion of model signing "
                            "keys is unrecoverable, enabling model substitution attacks."
                        ),
                    ))

                if not purge_protection:
                    findings.append(_finding(
                        rule_id="azure.ai_sec.model_security.keyvault_no_purge_protection",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="MEDIUM",
                        pillar="model_security",
                        atlas_technique="AML.T0003",
                        title="Azure Key Vault purge protection disabled — model keys can be permanently deleted",
                        detail=(
                            "enablePurgeProtection=false. Model encryption keys can be permanently "
                            "deleted within the soft-delete retention window."
                        ),
                    ))

            # ------------------------------------------------------------------
            # Pillar 3 — Inference Security: NSG checks
            # ------------------------------------------------------------------
            if resource_type == "NetworkSecurityGroup":
                security_rules = ef.get("securityRules") or []
                for rule in security_rules:
                    if not isinstance(rule, dict):
                        continue
                    access = rule.get("access", "")
                    direction = rule.get("direction", "")
                    dest_port = str(rule.get("destinationPortRange", "") or "")
                    src_addr = rule.get("sourceAddressPrefix", "")

                    # Inbound allow from Internet on high-risk ports
                    if (
                        access == "Allow"
                        and direction == "Inbound"
                        and src_addr in ("*", "Internet", "0.0.0.0/0")
                        and dest_port in ("*", "443", "80", "8080", "8443")
                    ):
                        findings.append(_finding(
                            rule_id="azure.ai_sec.inference_security.nsg_public_inbound",
                            resource_uid=resource_uid,
                            resource_type=resource_type,
                            account_id=account_id,
                            region=r_region,
                            tenant_id=tenant_id,
                            scan_run_id=scan_run_id,
                            severity="HIGH",
                            pillar="inference_security",
                            atlas_technique="AML.T0002",
                            title="Azure NSG permits public inbound traffic to potential AI endpoint ports",
                            detail=(
                                f"Rule allows {direction} {access} from {src_addr} "
                                f"on port {dest_port}. AI inference endpoints may be publicly reachable."
                            ),
                        ))
                        break  # One finding per NSG is sufficient

        # ------------------------------------------------------------------
        # Pillar 5 — AI Governance: account-level checks
        # ------------------------------------------------------------------
        # Missing KeyVault in account → HIGH governance gap
        if not has_keyvault:
            findings.append(_finding(
                rule_id="azure.ai_sec.ai_governance.no_keyvault",
                resource_uid=acct_uid,
                resource_type="AzureAccount",
                account_id=account_id,
                region=region,
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
                severity="HIGH",
                pillar="ai_governance",
                atlas_technique=None,
                title="No Azure Key Vault found — AI model key management governance gap",
                detail=(
                    "No Key Vault detected in this subscription. AI model signing keys, "
                    "API keys, and secrets should be managed in Key Vault."
                ),
            ))

        # No VNet isolation → inference security gap
        if not has_vnet:
            findings.append(_finding(
                rule_id="azure.ai_sec.inference_security.no_vnet",
                resource_uid=acct_uid,
                resource_type="AzureAccount",
                account_id=account_id,
                region=region,
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
                severity="HIGH",
                pillar="inference_security",
                atlas_technique="AML.T0002",
                title="No Azure VNet found — AI inference workloads may lack network isolation",
                detail=(
                    "No Virtual Network detected. Azure ML inference endpoints should be "
                    "deployed within a VNet with private endpoints to prevent public exposure."
                ),
            ))

        # No NSG → supply chain risk (no perimeter control)
        if not has_nsg:
            findings.append(_finding(
                rule_id="azure.ai_sec.supply_chain.no_nsg",
                resource_uid=acct_uid,
                resource_type="AzureAccount",
                account_id=account_id,
                region=region,
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
                severity="MEDIUM",
                pillar="supply_chain",
                atlas_technique="AML.T0004",
                title="No Azure NSG found — AI model supply chain perimeter uncontrolled",
                detail=(
                    "No Network Security Groups detected. Model registries and artifact "
                    "stores should be protected by NSGs to prevent supply-chain tampering."
                ),
            ))

        logger.info(
            "Azure AI analyze(): produced %d ATLAS findings for scan %s",
            len(findings), scan_run_id,
        )
        return findings
