"""Azure provider for AI Security engine — MITRE ATLAS 5-pillar analyze()."""
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .base import BaseAISecurityProvider

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Valid ATLAS values (AC-S6, AC-S7)
# ---------------------------------------------------------------------------
VALID_PILLARS = frozenset({
    "model_security",
    "training_data_security",
    "inference_security",
    "supply_chain",
    "ai_governance",
})

ATLAS_TECHNIQUES: Dict[str, Dict[str, str]] = {
    "AML.T0000": ("inference_security",     "HIGH",     "Model Evasion",           "Adversary crafts inputs to evade model detection."),
    "AML.T0001": ("training_data_security", "CRITICAL", "Data Poisoning",          "Adversary injects malicious data into training set."),
    "AML.T0002": ("inference_security",     "HIGH",     "Model Inversion",         "Adversary extracts training data from model outputs."),
    "AML.T0003": ("model_security",         "MEDIUM",   "Model Stealing",          "Adversary replicates model via repeated queries."),
    "AML.T0004": ("supply_chain",           "CRITICAL", "Backdoor ML Model",       "Adversary implants hidden trigger in model weights."),
    "AML.T0005": ("training_data_security", "CRITICAL", "Poison Training Data",    "Adversary corrupts training data pipeline."),
}

VALID_TECHNIQUES = frozenset(ATLAS_TECHNIQUES.keys())

# ---------------------------------------------------------------------------
# Azure AI/ML resource types consumed from discovery_findings (story spec)
# ---------------------------------------------------------------------------
AZURE_AI_RESOURCE_TYPES = {
    "MachineLearning::Workspace",
    "CognitiveServices::Account",
    "OpenAI::Account",
    "Bot::BotService",
    # Proxy resource types present in discovery_findings
    "KeyVault",
    "StorageAccount",
    "NetworkSecurityGroup",
    "VirtualNetwork",
    "Microsoft.Resources/resourceGroups",
}


def _make_finding_id(atlas_pillar: str, atlas_technique: Optional[str],
                     resource_uid: str, account_id: str, region: str) -> str:
    """Deterministic finding_id per AC-S3.

    sha256(f"{atlas_pillar}_{atlas_technique}|{resource_uid}|{account_id}|{region}")[:16]
    """
    technique_part = atlas_technique or "none"
    raw = f"{atlas_pillar}_{technique_part}|{resource_uid}|{account_id}|{region}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _validate_pillar(pillar: str) -> str:
    """Validate atlas_pillar (AC-S6)."""
    if pillar not in VALID_PILLARS:
        logger.warning("Unknown atlas_pillar '%s' — defaulting to ai_governance", pillar)
        return "ai_governance"
    return pillar


def _validate_technique(technique: Optional[str]) -> Optional[str]:
    """Validate atlas_technique (AC-S7). Unknown techniques logged at WARNING."""
    if technique is None:
        return None
    if technique not in VALID_TECHNIQUES:
        logger.warning("Unknown atlas_technique '%s' — dropping technique field", technique)
        return None
    return technique


def _atlas_detail(technique_id: Optional[str]) -> Dict[str, str]:
    """Return atlas_detail dict for a given technique ID."""
    if not technique_id:
        return {}
    row = ATLAS_TECHNIQUES.get(technique_id)
    if not row:
        return {}
    return {"technique_id": technique_id, "technique_name": row[2], "description": row[3]}


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
    validated_pillar = _validate_pillar(pillar)
    validated_technique = _validate_technique(atlas_technique)
    now = datetime.now(timezone.utc)
    return {
        "finding_id": _make_finding_id(validated_pillar, validated_technique,
                                        resource_uid, account_id, region),
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        "account_id": account_id,
        "provider": "azure",
        "region": region,
        "resource_uid": resource_uid,
        "resource_type": resource_type,
        "severity": severity,
        "status": status,
        "atlas_pillar": validated_pillar,
        "pillar": validated_pillar,
        "atlas_technique": validated_technique,
        "atlas_detail": _atlas_detail(validated_technique),
        "blast_radius_score": 0,
        "rule_id": rule_id,
        "title": title,
        "detail": detail,
        "first_seen_at": now,
        "last_seen_at": now,
    }


class AzureAISecurityProvider(BaseAISecurityProvider):
    """Azure AI security provider — MITRE ATLAS 5-pillar.

    Queries discovery_findings for Azure AI/ML resource types
    (MachineLearning::Workspace, CognitiveServices::Account, OpenAI::Account,
    Bot::BotService) and applies ATLAS-mapped governance checks.  Also applies
    proxy-resource checks (KeyVault, StorageAccount, NSG, VNet) which are
    consistently present in discovery_findings regardless of whether Azure ML
    services are explicitly scanned.
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
        """Produce MITRE ATLAS findings for Azure AI/ML resources.

        Queries discovery_findings for native Azure AI resource types and proxy
        resource types (StorageAccount, KeyVault, NSG, VNet) and emits ATLAS-
        mapped findings across all 5 pillars.  All queries include tenant_id
        filter (AC-S1).  Endpoint URLs and model IDs are never logged (AC-S2).

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

        logger.info("Azure AI analyze(): %d resource rows for scan %s", len(rows), scan_run_id)

        resource_types_seen = {r[1] for r in rows}
        has_keyvault = "KeyVault" in resource_types_seen
        has_storage = "StorageAccount" in resource_types_seen
        has_nsg = "NetworkSecurityGroup" in resource_types_seen
        has_vnet = "VirtualNetwork" in resource_types_seen
        has_ml_workspace = "MachineLearning::Workspace" in resource_types_seen
        has_cognitive = "CognitiveServices::Account" in resource_types_seen
        has_openai = "OpenAI::Account" in resource_types_seen

        acct_uid = f"azure:{account_id}:ai_governance"
        acct_region = "global"

        for resource_uid, resource_type, res_region, ef in rows:
            if not ef:
                ef = {}
            r_region = res_region or "global"

            # ------------------------------------------------------------------
            # Pillar 1 — Model Security: MachineLearning::Workspace
            # ------------------------------------------------------------------
            if resource_type == "MachineLearning::Workspace":
                # Public network access enabled → model stealing risk (AML.T0003)
                public_network_access = ef.get("publicNetworkAccess", "Enabled")
                if public_network_access in ("Enabled", True, "true"):
                    findings.append(_finding(
                        rule_id="azure.ai_sec.model_security.ml_workspace_public_network",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="HIGH",
                        pillar="model_security",
                        atlas_technique="AML.T0003",
                        title="Azure ML Workspace has public network access enabled",
                        detail=(
                            "publicNetworkAccess=Enabled exposes the workspace management API "
                            "to the internet. Use private endpoints to restrict access."
                        ),
                    ))

                # No CMK encryption → supply chain risk
                encryption = ef.get("encryption") or {}
                if not encryption or not encryption.get("keyVaultProperties"):
                    findings.append(_finding(
                        rule_id="azure.ai_sec.supply_chain.ml_workspace_no_cmk",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="HIGH",
                        pillar="supply_chain",
                        atlas_technique="AML.T0004",
                        title="Azure ML Workspace has no customer-managed key encryption",
                        detail=(
                            "No CMK encryption configured for model artifacts. "
                            "Without CMK, model provenance and integrity cannot be independently verified."
                        ),
                    ))

                # No managed identity configured → governance gap
                identity = ef.get("identity") or {}
                if not identity:
                    findings.append(_finding(
                        rule_id="azure.ai_sec.ai_governance.ml_workspace_no_managed_identity",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="MEDIUM",
                        pillar="ai_governance",
                        atlas_technique=None,
                        title="Azure ML Workspace has no managed identity configured",
                        detail=(
                            "No managed identity on the workspace. AI workloads cannot use "
                            "passwordless authentication to Key Vault, Storage, or ACR."
                        ),
                    ))

            # ------------------------------------------------------------------
            # Pillar 3 — Inference Security: CognitiveServices::Account
            # ------------------------------------------------------------------
            if resource_type == "CognitiveServices::Account":
                # Public endpoint without VNet restriction → inference exposure
                public_access = ef.get("publicNetworkAccess", "Enabled")
                network_acls = ef.get("networkAcls") or {}
                default_action = network_acls.get("defaultAction", "Allow")

                if public_access in ("Enabled", True, "true") and default_action == "Allow":
                    findings.append(_finding(
                        rule_id="azure.ai_sec.inference_security.cognitive_services_public_endpoint",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="HIGH",
                        pillar="inference_security",
                        atlas_technique="AML.T0000",
                        title="Azure Cognitive Services account has public endpoint with no network ACLs",
                        detail=(
                            "publicNetworkAccess=Enabled with networkAcls.defaultAction=Allow. "
                            "Inference endpoint is publicly reachable — adversarial input attacks "
                            "and model evasion are facilitated by unrestricted access."
                        ),
                    ))

                # No outbound network restrictions → model inversion risk
                findings.append(_finding(
                    rule_id="azure.ai_sec.inference_security.cognitive_services_no_output_filtering",
                    resource_uid=resource_uid,
                    resource_type=resource_type,
                    account_id=account_id,
                    region=r_region,
                    tenant_id=tenant_id,
                    scan_run_id=scan_run_id,
                    severity="HIGH",
                    pillar="inference_security",
                    atlas_technique="AML.T0002",
                    title="Azure Cognitive Services account — verify output filtering and differential privacy",
                    detail=(
                        "Cognitive Services endpoints should implement output filtering to prevent "
                        "model inversion attacks that reconstruct training data from API responses."
                    ),
                ))

            # ------------------------------------------------------------------
            # Pillar 3 — Inference Security: OpenAI::Account
            # ------------------------------------------------------------------
            if resource_type == "OpenAI::Account":
                # Azure OpenAI without content filters → inference security
                properties = ef.get("properties") or {}
                public_access = properties.get("publicNetworkAccess") or ef.get("publicNetworkAccess", "Enabled")

                if public_access in ("Enabled", True, "true"):
                    findings.append(_finding(
                        rule_id="azure.ai_sec.inference_security.openai_public_endpoint",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="HIGH",
                        pillar="inference_security",
                        atlas_technique="AML.T0000",
                        title="Azure OpenAI account has public network access enabled",
                        detail=(
                            "Azure OpenAI endpoint is publicly accessible. Restrict access via "
                            "private endpoints and configure content filtering to prevent prompt injection."
                        ),
                    ))

                # Check for content filter (governance)
                content_filter = properties.get("contentFilter") or ef.get("contentFilter")
                if not content_filter:
                    findings.append(_finding(
                        rule_id="azure.ai_sec.ai_governance.openai_no_content_filter",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="HIGH",
                        pillar="ai_governance",
                        atlas_technique=None,
                        title="Azure OpenAI account has no content filter configured",
                        detail=(
                            "No content filter detected. Azure OpenAI content filtering "
                            "should be enabled to prevent harmful outputs and prompt injection."
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
            # Pillar 2 — Training Data Security: StorageAccount checks
            # ------------------------------------------------------------------
            if resource_type == "StorageAccount":
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
        if not has_keyvault:
            findings.append(_finding(
                rule_id="azure.ai_sec.ai_governance.no_keyvault",
                resource_uid=acct_uid,
                resource_type="AzureAccount",
                account_id=account_id,
                region=acct_region,
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

        if not has_vnet:
            findings.append(_finding(
                rule_id="azure.ai_sec.inference_security.no_vnet",
                resource_uid=acct_uid,
                resource_type="AzureAccount",
                account_id=account_id,
                region=acct_region,
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

        if not has_nsg:
            findings.append(_finding(
                rule_id="azure.ai_sec.supply_chain.no_nsg",
                resource_uid=acct_uid,
                resource_type="AzureAccount",
                account_id=account_id,
                region=acct_region,
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

        # Pillar 2 — Training Data Security: account-level check if no storage
        if not has_storage:
            findings.append(_finding(
                rule_id="azure.ai_sec.training_data_security.no_storage_accounts",
                resource_uid=acct_uid,
                resource_type="AzureAccount",
                account_id=account_id,
                region=acct_region,
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
                severity="MEDIUM",
                pillar="training_data_security",
                atlas_technique="AML.T0001",
                title="No Azure Storage Accounts found — AI training data governance cannot be assessed",
                detail=(
                    "No Storage Accounts detected. Verify AI training datasets are stored "
                    "in scanned Azure regions with appropriate access controls."
                ),
            ))

        # Pillar 1 — Model Security: note if no ML workspace found
        if not has_ml_workspace:
            findings.append(_finding(
                rule_id="azure.ai_sec.model_security.no_ml_workspace",
                resource_uid=acct_uid,
                resource_type="AzureAccount",
                account_id=account_id,
                region=acct_region,
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
                severity="LOW",
                pillar="model_security",
                atlas_technique="AML.T0003",
                title="No Azure ML Workspace found in discovery — model security assessment limited",
                detail=(
                    "MachineLearning::Workspace resources not found in discovery_findings. "
                    "Enable Azure ML discovery to fully assess model access controls and versioning."
                ),
            ))

        logger.info(
            "Azure AI analyze(): produced %d ATLAS findings for scan %s",
            len(findings), scan_run_id,
        )
        return findings
