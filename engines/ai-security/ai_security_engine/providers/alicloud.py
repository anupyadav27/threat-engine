"""AliCloud provider for AI Security engine — MITRE ATLAS 5-pillar analyze()."""
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .base import BaseAISecurityProvider

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# AliCloud resource types present in discovery_findings.
# AliCloud PAI (Platform for AI) resource types are not yet enumerated by
# the discovery scanner.  We apply AI governance checks against the resource
# types that ARE present (RAM roles/users, VPC, SecurityGroup, KMS keys)
# to ensure AI workloads meet minimum ATLAS posture.
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
    """Build a complete ATLAS finding dict for AliCloud."""
    now = datetime.now(timezone.utc)
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


class AliCloudAISecurityProvider(BaseAISecurityProvider):
    """AliCloud AI security provider.

    AliCloud PAI (Platform for AI), EAS (Elastic Algorithm Service), and
    ALINLP resource types are not yet enumerated by the discovery scanner.
    This provider applies ATLAS-mapped checks against the AliCloud resources
    that ARE present:
    - alicloud.ram/Role — model identity and over-privilege
    - alicloud.ram/User — AI service account posture
    - alicloud.vpc/Vpc — AI workload network isolation
    - alicloud.ecs/SecurityGroup — inference endpoint exposure
    - alicloud.kms/Key — model encryption and key governance
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
        """Produce MITRE ATLAS findings for AliCloud resources.

        Applies AI governance and security checks to AliCloud proxy resource
        types (RAM, VPC, SecurityGroup, KMS) that are present in
        discovery_findings.

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

        logger.info(
            "AliCloud AI analyze(): %d resource rows for scan %s", len(rows), scan_run_id
        )

        resource_types_seen = {r[1] for r in rows}
        has_ram_role = "alicloud.ram/Role" in resource_types_seen
        has_vpc = "alicloud.vpc/Vpc" in resource_types_seen
        has_sg = "alicloud.ecs/SecurityGroup" in resource_types_seen
        has_kms = "alicloud.kms/Key" in resource_types_seen

        acct_uid = f"alicloud:{account_id}:ai_governance"

        for resource_uid, resource_type, res_region, ef in rows:
            if not ef:
                ef = {}
            r_region = res_region or "cn-hangzhou"

            # ------------------------------------------------------------------
            # Pillar 1 — Model Security: RAM Role checks
            # ------------------------------------------------------------------
            if resource_type == "alicloud.ram/Role":
                role_name = ef.get("RoleName") or ef.get("roleName", "")
                # Overly permissive AI service role (AdministratorAccess or *:*)
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
                    # Emit governance PASS for this role
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
                    source_cidr = perm.get("SourceCidrIp", "") or perm.get("SourceGroupId", "")
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
                key_usage = ef.get("KeyUsage") or ef.get("keyUsage", "")
                # Disabled or pending deletion key → training data encryption at risk
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

        # Pillar 4 — Supply Chain: PAI service not enumerated
        findings.append(_finding(
            rule_id="alicloud.ai_sec.supply_chain.pai_service_not_enumerated",
            resource_uid=acct_uid,
            resource_type="AliCloudAccount",
            account_id=account_id,
            region="cn-hangzhou",
            tenant_id=tenant_id,
            scan_run_id=scan_run_id,
            severity="MEDIUM",
            pillar="supply_chain",
            atlas_technique="AML.T0004",
            title="AliCloud PAI/EAS service not yet enumerated by discovery scanner",
            detail=(
                "AliCloud PAI Workspaces, EAS model deployments, and ALINLP resources are "
                "not yet in discovery_findings. Enable PAI/EAS discovery to evaluate "
                "model provenance and supply-chain integrity."
            ),
        ))

        logger.info(
            "AliCloud AI analyze(): produced %d ATLAS findings for scan %s",
            len(findings), scan_run_id,
        )
        return findings
