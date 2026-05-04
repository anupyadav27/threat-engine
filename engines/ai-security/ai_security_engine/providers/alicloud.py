"""AliCloud provider for AI Security engine — MITRE ATLAS 5-pillar analyze()."""
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
    "AML.T0000": ("inference_security",     "HIGH",     "Model Evasion",        "Adversary crafts inputs to evade model detection."),
    "AML.T0001": ("training_data_security", "CRITICAL", "Data Poisoning",       "Adversary injects malicious data into training set."),
    "AML.T0002": ("inference_security",     "HIGH",     "Model Inversion",      "Adversary extracts training data from model outputs."),
    "AML.T0003": ("model_security",         "MEDIUM",   "Model Stealing",       "Adversary replicates model via repeated queries."),
    "AML.T0004": ("supply_chain",           "CRITICAL", "Backdoor ML Model",    "Adversary implants hidden trigger in model weights."),
    "AML.T0005": ("training_data_security", "CRITICAL", "Poison Training Data", "Adversary corrupts training data pipeline."),
}

VALID_TECHNIQUES = frozenset(ATLAS_TECHNIQUES.keys())

# ---------------------------------------------------------------------------
# AliCloud AI/ML resource types consumed from discovery_findings (story spec)
# ---------------------------------------------------------------------------
ALICLOUD_AI_RESOURCE_TYPES = {
    "PAI::Workspace",
    "MachineLearning::Job",
    "NLP::Model",
    "Vision::Model",
    # Proxy resource types present in discovery_findings
    "alicloud.ram/Role",
    "alicloud.ram/User",
    "alicloud.vpc/Vpc",
    "alicloud.ecs/SecurityGroup",
    "alicloud.kms/Key",
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
    """Build a complete ATLAS finding dict for AliCloud."""
    validated_pillar = _validate_pillar(pillar)
    validated_technique = _validate_technique(atlas_technique)
    now = datetime.now(timezone.utc)
    return {
        "finding_id": _make_finding_id(validated_pillar, validated_technique,
                                        resource_uid, account_id, region),
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        "account_id": account_id,
        "provider": "alicloud",
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


class AliCloudAISecurityProvider(BaseAISecurityProvider):
    """AliCloud AI security provider — MITRE ATLAS 5-pillar.

    Queries discovery_findings for AliCloud PAI/ML resource types
    (PAI::Workspace, MachineLearning::*, NLP::*, Vision::*) and proxy
    resource types (RAM roles, VPC, SecurityGroup, KMS keys) to ensure
    AI workloads meet minimum ATLAS posture.
    """

    @property
    def discovery_services(self) -> List[str]:
        """AliCloud AI/ML service names targeted by the scanner."""
        return ["pai", "eas", "alinlp"]

    @property
    def inventory_resource_prefixes(self) -> List[str]:
        """Inventory resource_type prefixes for AliCloud AI assets."""
        return ["pai.", "eas."]

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        discoveries_conn: Any,
        check_conn: Optional[Any] = None,
    ) -> List[Dict[str, Any]]:
        """Produce MITRE ATLAS findings for AliCloud AI/ML resources.

        Queries discovery_findings for native AliCloud PAI resource types and
        proxy resource types (RAM, VPC, SecurityGroup, KMS) with tenant_id
        filter on all queries (AC-S1).

        Args:
            scan_run_id: Current pipeline scan run identifier.
            tenant_id: Tenant identifier — all queries filtered by this.
            account_id: AliCloud account identifier.
            discoveries_conn: psycopg2 connection to discoveries DB.
            check_conn: Unused for AliCloud.

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
                  AND provider = 'alicloud'
                """,
                (tenant_id, scan_run_id),
            )
            rows = cur.fetchall()
            cur.close()
        except Exception as exc:
            logger.error("AliCloud AI analyze(): DB query failed: %s", exc)
            return findings

        logger.info("AliCloud AI analyze(): %d resource rows for scan %s", len(rows), scan_run_id)

        resource_types_seen = {r[1] for r in rows}
        has_ram_role = "alicloud.ram/Role" in resource_types_seen
        has_vpc = "alicloud.vpc/Vpc" in resource_types_seen
        has_sg = "alicloud.ecs/SecurityGroup" in resource_types_seen
        has_kms = "alicloud.kms/Key" in resource_types_seen
        has_pai_workspace = "PAI::Workspace" in resource_types_seen
        has_nlp_model = "NLP::Model" in resource_types_seen
        has_vision_model = "Vision::Model" in resource_types_seen

        acct_uid = f"alicloud:{account_id}:ai_governance"

        for resource_uid, resource_type, res_region, ef in rows:
            if not ef:
                ef = {}
            r_region = res_region or "cn-hangzhou"

            # ------------------------------------------------------------------
            # Pillar 1 — Model Security: PAI::Workspace
            # ------------------------------------------------------------------
            if resource_type == "PAI::Workspace":
                workspace_type = ef.get("WorkspaceType") or ef.get("workspaceType", "")
                status_val = ef.get("Status") or ef.get("status", "")

                # Public workspace type → model stealing risk
                if workspace_type in ("Public", "public"):
                    findings.append(_finding(
                        rule_id="alicloud.ai_sec.model_security.pai_workspace_public",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="HIGH",
                        pillar="model_security",
                        atlas_technique="AML.T0003",
                        title="AliCloud PAI Workspace is public type — model stealing risk",
                        detail=(
                            f"WorkspaceType='{workspace_type}'. Public PAI workspaces expose "
                            "model artifacts and training pipelines to unauthorized access."
                        ),
                    ))

                # Workspace without tags → governance gap
                tags = ef.get("Tags") or ef.get("tags") or []
                if not tags:
                    findings.append(_finding(
                        rule_id="alicloud.ai_sec.ai_governance.pai_workspace_no_tags",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="LOW",
                        pillar="ai_governance",
                        atlas_technique=None,
                        title="AliCloud PAI Workspace has no tags — AI governance gap",
                        detail=(
                            "No tags on PAI Workspace. Tags should include data-owner, "
                            "environment, and cost-center for AI governance compliance."
                        ),
                    ))

            # ------------------------------------------------------------------
            # Pillar 3 — Inference Security: NLP::Model
            # ------------------------------------------------------------------
            if resource_type == "NLP::Model":
                # Check if endpoint is public
                endpoint = ef.get("ServiceEndpoint") or ef.get("endpoint", "")
                model_status = ef.get("ModelStatus") or ef.get("status", "")

                if model_status in ("Running", "Online"):
                    findings.append(_finding(
                        rule_id="alicloud.ai_sec.inference_security.nlp_model_running_check",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="HIGH",
                        pillar="inference_security",
                        atlas_technique="AML.T0000",
                        title="AliCloud NLP Model is running — verify endpoint auth and rate limiting",
                        detail=(
                            "NLP model is in Running/Online state. Ensure endpoint authentication "
                            "and rate limiting are configured to prevent model evasion attacks."
                        ),
                    ))

            # ------------------------------------------------------------------
            # Pillar 3 — Inference Security: Vision::Model
            # ------------------------------------------------------------------
            if resource_type == "Vision::Model":
                model_status = ef.get("Status") or ef.get("status", "")
                if model_status in ("Running", "Online", "Deployed"):
                    findings.append(_finding(
                        rule_id="alicloud.ai_sec.inference_security.vision_model_public_endpoint",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="HIGH",
                        pillar="inference_security",
                        atlas_technique="AML.T0002",
                        title="AliCloud Vision Model is deployed — verify output filtering for model inversion",
                        detail=(
                            "Vision model is deployed and actively serving inference requests. "
                            "Implement output filtering and differential privacy to prevent "
                            "model inversion attacks reconstructing training images."
                        ),
                    ))

            # ------------------------------------------------------------------
            # Pillar 1 — Model Security: RAM Role checks
            # ------------------------------------------------------------------
            if resource_type == "alicloud.ram/Role":
                role_name = ef.get("RoleName") or ef.get("roleName", "")
                policies = ef.get("AttachedPolicies") or ef.get("Policies") or []
                has_admin_policy = any(
                    ("Administrator" in str(p) or "*:*" in str(p))
                    for p in (policies if isinstance(policies, list) else [])
                )
                if has_admin_policy:
                    findings.append(_finding(
                        rule_id="alicloud.ai_sec.model_security.ram_role_admin_policy",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="CRITICAL",
                        pillar="model_security",
                        atlas_technique="AML.T0003",
                        title="AliCloud RAM Role has AdministratorAccess — AI model identity over-privileged",
                        detail=(
                            f"Role '{role_name}' has administrator-level policies. "
                            "PAI/EAS workloads with this role can exfiltrate model artifacts."
                        ),
                    ))
                else:
                    findings.append(_finding(
                        rule_id="alicloud.ai_sec.model_security.ram_role_admin_policy",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="CRITICAL",
                        pillar="model_security",
                        atlas_technique="AML.T0003",
                        title="AliCloud RAM Role privilege check — compliant",
                        detail=f"Role '{role_name}' does not have administrator-level policies.",
                        status="PASS",
                    ))

            # ------------------------------------------------------------------
            # Pillar 3 — Inference Security: Security Group checks
            # ------------------------------------------------------------------
            if resource_type == "alicloud.ecs/SecurityGroup":
                permissions = ef.get("Permissions") or ef.get("SecurityGroupRules") or []
                for perm in (permissions if isinstance(permissions, list) else []):
                    if not isinstance(perm, dict):
                        continue
                    direction = perm.get("Direction", "")
                    source_cidr = (
                        perm.get("SourceCidrIp", "")
                        or perm.get("SourceGroupId", "")
                    )
                    policy = perm.get("Policy", "")
                    port_range = perm.get("PortRange", "")

                    if (
                        direction == "ingress"
                        and policy == "Accept"
                        and source_cidr in ("0.0.0.0/0", "::/0")
                    ):
                        findings.append(_finding(
                            rule_id="alicloud.ai_sec.inference_security.sg_public_ingress",
                            resource_uid=resource_uid,
                            resource_type=resource_type,
                            account_id=account_id,
                            region=r_region,
                            tenant_id=tenant_id,
                            scan_run_id=scan_run_id,
                            severity="HIGH",
                            pillar="inference_security",
                            atlas_technique="AML.T0002",
                            title="AliCloud Security Group allows public ingress — AI inference endpoint exposed",
                            detail=(
                                f"Security group allows ingress from {source_cidr} "
                                f"on ports {port_range}. PAI/EAS model endpoints may be publicly reachable."
                            ),
                        ))
                        break

            # ------------------------------------------------------------------
            # Pillar 2 — Training Data Security: KMS Key checks
            # ------------------------------------------------------------------
            if resource_type == "alicloud.kms/Key":
                key_state = ef.get("KeyState") or ef.get("keyState", "")
                if key_state in ("Disabled", "PendingDeletion"):
                    findings.append(_finding(
                        rule_id="alicloud.ai_sec.training_data_security.kms_key_disabled",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="CRITICAL",
                        pillar="training_data_security",
                        atlas_technique="AML.T0001",
                        title="AliCloud KMS Key is disabled — AI training data encryption at risk",
                        detail=(
                            f"KMS Key state='{key_state}'. Encrypted OSS training datasets "
                            "cannot be decrypted if this key is the CMK, blocking model training "
                            "and potentially exposing unencrypted data fallback."
                        ),
                    ))

        # ------------------------------------------------------------------
        # Pillar 5 — AI Governance: account-level checks
        # ------------------------------------------------------------------
        if not has_ram_role:
            findings.append(_finding(
                rule_id="alicloud.ai_sec.ai_governance.no_ram_roles",
                resource_uid=acct_uid,
                resource_type="AliCloudAccount",
                account_id=account_id,
                region="cn-hangzhou",
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
                severity="HIGH",
                pillar="ai_governance",
                atlas_technique=None,
                title="No AliCloud RAM Roles found — AI service identity governance cannot be assessed",
                detail=(
                    "No RAM Roles detected. PAI/EAS AI workloads require dedicated RAM roles "
                    "with least-privilege policies for model training and serving."
                ),
            ))

        if not has_vpc:
            findings.append(_finding(
                rule_id="alicloud.ai_sec.inference_security.no_vpc",
                resource_uid=acct_uid,
                resource_type="AliCloudAccount",
                account_id=account_id,
                region="cn-hangzhou",
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
                severity="HIGH",
                pillar="inference_security",
                atlas_technique="AML.T0002",
                title="No AliCloud VPC found — AI inference workloads may lack network isolation",
                detail=(
                    "No VPC detected. PAI/EAS model deployment endpoints should run inside a "
                    "VPC with private endpoints to prevent public model inference exposure."
                ),
            ))

        if not has_kms:
            findings.append(_finding(
                rule_id="alicloud.ai_sec.supply_chain.no_kms_keys",
                resource_uid=acct_uid,
                resource_type="AliCloudAccount",
                account_id=account_id,
                region="cn-hangzhou",
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
                severity="HIGH",
                pillar="supply_chain",
                atlas_technique="AML.T0004",
                title="No AliCloud KMS Keys found — AI model artifact encryption governance gap",
                detail=(
                    "No KMS Keys detected. AI model artifacts in OSS and PAI Model Registry "
                    "should be encrypted with customer-managed KMS keys to prevent "
                    "supply-chain tampering."
                ),
            ))

        if not has_pai_workspace:
            findings.append(_finding(
                rule_id="alicloud.ai_sec.supply_chain.pai_workspace_not_enumerated",
                resource_uid=acct_uid,
                resource_type="AliCloudAccount",
                account_id=account_id,
                region="cn-hangzhou",
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
                severity="MEDIUM",
                pillar="supply_chain",
                atlas_technique="AML.T0004",
                title="AliCloud PAI Workspace not found in discovery — supply chain assessment limited",
                detail=(
                    "PAI::Workspace resources not found in discovery_findings. "
                    "Enable PAI/EAS discovery to evaluate model provenance and "
                    "supply-chain integrity."
                ),
            ))

        # Pillar 2 — Training data: no KMS and no NLP/Vision models means OSS check limited
        if not has_kms and not has_nlp_model and not has_vision_model:
            findings.append(_finding(
                rule_id="alicloud.ai_sec.training_data_security.no_ai_models_found",
                resource_uid=acct_uid,
                resource_type="AliCloudAccount",
                account_id=account_id,
                region="cn-hangzhou",
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
                severity="MEDIUM",
                pillar="training_data_security",
                atlas_technique="AML.T0001",
                title="No AliCloud NLP/Vision models or KMS keys found — training data security gap",
                detail=(
                    "No NLP::Model, Vision::Model, or KMS keys detected. "
                    "Enable AliCloud NLP and Vision service discovery to assess "
                    "training data poisoning exposure."
                ),
            ))

        logger.info(
            "AliCloud AI analyze(): produced %d ATLAS findings for scan %s",
            len(findings), scan_run_id,
        )
        return findings
