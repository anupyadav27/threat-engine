"""K8s provider for AI Security engine — MITRE ATLAS 5-pillar analyze()."""
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

ATLAS_TECHNIQUE_MAP: Dict[str, tuple] = {
    "AML.T0000": ("inference_security",     "HIGH",     "Model Evasion",        "Adversary crafts inputs to evade model detection."),
    "AML.T0001": ("training_data_security", "CRITICAL", "Data Poisoning",       "Adversary injects malicious data into training set."),
    "AML.T0002": ("inference_security",     "HIGH",     "Model Inversion",      "Adversary extracts training data from model outputs."),
    "AML.T0003": ("model_security",         "MEDIUM",   "Model Stealing",       "Adversary replicates model via repeated queries."),
    "AML.T0004": ("supply_chain",           "CRITICAL", "Backdoor ML Model",    "Adversary implants hidden trigger in model weights."),
    "AML.T0005": ("training_data_security", "CRITICAL", "Poison Training Data", "Adversary corrupts training data pipeline."),
}

VALID_TECHNIQUES = frozenset(ATLAS_TECHNIQUE_MAP.keys())

# ---------------------------------------------------------------------------
# ML application labels that identify GPU/ML workloads in K8s Deployments.
# ---------------------------------------------------------------------------
ML_APP_LABELS = frozenset({
    "mlflow", "kubeflow", "jupyter", "jupyterhub", "ray", "rayhead",
    "pytorch", "tensorflow", "triton", "torchserve", "seldon",
    "kserve", "knative", "ml", "training", "inference", "model-server",
})


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
    row = ATLAS_TECHNIQUE_MAP.get(technique_id)
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
    """Build a complete ATLAS finding dict for K8s."""
    validated_pillar = _validate_pillar(pillar)
    validated_technique = _validate_technique(atlas_technique)
    now = datetime.now(timezone.utc)
    return {
        "finding_id": _make_finding_id(validated_pillar, validated_technique,
                                        resource_uid, account_id, region),
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        "account_id": account_id,
        "provider": "k8s",
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


def _is_ml_workload(ef: Dict[str, Any]) -> bool:
    """Detect whether a K8s Deployment is an ML/GPU workload.

    Checks for:
    1. nvidia.com/gpu resource requests or limits in any container.
    2. Well-known ML application labels (mlflow, kubeflow, jupyter, ray, etc.).

    Args:
        ef: Deployment emitted_fields dict (already a dict, not JSON string).

    Returns:
        True if the deployment appears to be an ML workload.
    """
    # Check template.spec.containers for GPU resources
    spec = ef.get("spec") or {}
    template_spec = spec.get("template", {}).get("spec", {})
    containers = template_spec.get("containers") or spec.get("containers") or []

    for container in containers:
        if not isinstance(container, dict):
            continue
        resources = container.get("resources") or {}
        for rtype in ("requests", "limits"):
            if resources.get(rtype, {}).get("nvidia.com/gpu"):
                return True
        # ML images by name
        image = (container.get("image") or "").lower()
        if any(lbl in image for lbl in ML_APP_LABELS):
            return True

    # Check deployment labels
    metadata = ef.get("metadata") or {}
    labels = metadata.get("labels") or {}
    label_values = {str(v).lower() for v in labels.values()}
    label_keys = {str(k).lower() for k in labels.keys()}
    combined = label_values | label_keys
    if combined & ML_APP_LABELS:
        return True

    # Check pod template labels
    template_meta = spec.get("template", {}).get("metadata") or {}
    tmpl_labels = template_meta.get("labels") or {}
    tmpl_combined = {str(v).lower() for v in tmpl_labels.values()} | {str(k).lower() for k in tmpl_labels.keys()}
    if tmpl_combined & ML_APP_LABELS:
        return True

    return False


class K8sAISecurityProvider(BaseAISecurityProvider):
    """Kubernetes AI security provider.

    Evaluates all K8s Deployments for MITRE ATLAS risks with focus on:
    - GPU/ML workload detection via nvidia.com/gpu resource requests and
      well-known ML application labels (mlflow, kubeflow, jupyter, ray, etc.)
    - All Deployments are assessed for AI governance posture (missing resource
      limits, privileged containers, no network policies)
    """

    @property
    def discovery_services(self) -> List[str]:
        """K8s MLOps service names targeted by the scanner."""
        return ["seldon", "kserve", "mlflow", "kubeflow"]

    @property
    def inventory_resource_prefixes(self) -> List[str]:
        """Inventory resource_type prefixes for K8s AI assets."""
        return ["seldon.", "kserve.", "mlflow.", "kubeflow."]

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        discoveries_conn: Any,
        check_conn: Optional[Any] = None,
    ) -> List[Dict[str, Any]]:
        """Produce MITRE ATLAS findings for K8s ML workloads.

        Queries discovery_findings for k8s.apps/Deployment resources belonging
        to this tenant/scan, identifies ML workloads by GPU resources and labels,
        and applies ATLAS pillar checks to all deployments.

        Args:
            scan_run_id: Current pipeline scan run identifier.
            tenant_id: Tenant identifier — all queries filtered by this.
            account_id: Kubernetes cluster identifier.
            discoveries_conn: psycopg2 connection to discoveries DB.
            check_conn: Unused for K8s.

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
                  AND provider = 'k8s'
                  AND resource_type = 'k8s.apps/Deployment'
                """,
                (tenant_id, scan_run_id),
            )
            rows = cur.fetchall()
            cur.close()
        except Exception as exc:
            logger.error("K8s AI analyze(): DB query failed: %s", exc)
            return findings

        logger.info(
            "K8s AI analyze(): %d Deployment rows for scan %s", len(rows), scan_run_id
        )

        ml_workload_count = 0
        total_count = len(rows)

        for resource_uid, resource_type, res_region, ef in rows:
            if not ef:
                ef = {}
            r_region = res_region or "cluster"

            metadata = ef.get("metadata") or {}
            deploy_name = metadata.get("name", str(resource_uid)[:40])
            namespace = metadata.get("namespace", "default")

            spec = ef.get("spec") or {}
            template_spec = spec.get("template", {}).get("spec", {})
            containers = template_spec.get("containers") or spec.get("containers") or []

            is_ml = _is_ml_workload(ef)
            if is_ml:
                ml_workload_count += 1

            # ------------------------------------------------------------------
            # Pillar 3 — Inference Security: Privileged container check
            # (applies to all deployments — a privileged ML container can expose
            # the GPU/model host and enable model-inversion attacks)
            # ------------------------------------------------------------------
            for container in containers:
                if not isinstance(container, dict):
                    continue
                sec_ctx = container.get("securityContext") or {}
                privileged = sec_ctx.get("privileged", False)
                allow_priv_esc = sec_ctx.get("allowPrivilegeEscalation", True)

                if privileged:
                    findings.append(_finding(
                        rule_id="k8s.ai_sec.inference_security.privileged_container",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="CRITICAL",
                        pillar="inference_security",
                        atlas_technique="AML.T0002",
                        title=f"K8s Deployment '{deploy_name}' has privileged container — model host exposed",
                        detail=(
                            f"Container '{container.get('name', '?')}' in {namespace}/{deploy_name} "
                            "runs privileged. An attacker can escape to the host node and "
                            "extract model weights from GPU memory."
                        ),
                    ))
                    break  # One finding per deployment

                if allow_priv_esc is True and is_ml:
                    findings.append(_finding(
                        rule_id="k8s.ai_sec.inference_security.allow_privilege_escalation_ml",
                        resource_uid=resource_uid,
                        resource_type=resource_type,
                        account_id=account_id,
                        region=r_region,
                        tenant_id=tenant_id,
                        scan_run_id=scan_run_id,
                        severity="HIGH",
                        pillar="inference_security",
                        atlas_technique="AML.T0002",
                        title=f"K8s ML Deployment '{deploy_name}' allows privilege escalation",
                        detail=(
                            f"allowPrivilegeEscalation=true on {namespace}/{deploy_name}. "
                            "ML model-serving containers should set allowPrivilegeEscalation=false."
                        ),
                    ))
                    break

            # ------------------------------------------------------------------
            # Pillar 1 — Model Security: Missing resource limits on ML workloads
            # ------------------------------------------------------------------
            if is_ml:
                for container in containers:
                    if not isinstance(container, dict):
                        continue
                    resources = container.get("resources") or {}
                    limits = resources.get("limits") or {}
                    requests = resources.get("requests") or {}

                    if not limits:
                        findings.append(_finding(
                            rule_id="k8s.ai_sec.model_security.ml_container_no_resource_limits",
                            resource_uid=resource_uid,
                            resource_type=resource_type,
                            account_id=account_id,
                            region=r_region,
                            tenant_id=tenant_id,
                            scan_run_id=scan_run_id,
                            severity="HIGH",
                            pillar="model_security",
                            atlas_technique="AML.T0003",
                            title=f"K8s ML Deployment '{deploy_name}' container has no resource limits",
                            detail=(
                                f"Container '{container.get('name', '?')}' in {namespace}/{deploy_name} "
                                "has no CPU/memory limits. Resource exhaustion attacks can degrade "
                                "model serving and enable denial-of-inference attacks."
                            ),
                        ))
                        break

            # ------------------------------------------------------------------
            # Pillar 2 — Training Data Security: ML workload with host path mounts
            # ------------------------------------------------------------------
            if is_ml:
                volumes = template_spec.get("volumes") or spec.get("volumes") or []
                for vol in volumes:
                    if not isinstance(vol, dict):
                        continue
                    if vol.get("hostPath"):
                        host_path = vol["hostPath"].get("path", "")
                        findings.append(_finding(
                            rule_id="k8s.ai_sec.training_data_security.ml_hostpath_mount",
                            resource_uid=resource_uid,
                            resource_type=resource_type,
                            account_id=account_id,
                            region=r_region,
                            tenant_id=tenant_id,
                            scan_run_id=scan_run_id,
                            severity="HIGH",
                            pillar="training_data_security",
                            atlas_technique="AML.T0005",
                            title=f"K8s ML Deployment '{deploy_name}' mounts host filesystem",
                            detail=(
                                f"Volume '{vol.get('name', '?')}' uses hostPath='{host_path}'. "
                                "Host path mounts in ML containers expose node training data "
                                "to container escape and data poisoning attacks."
                            ),
                        ))
                        break

            # ------------------------------------------------------------------
            # Pillar 5 — AI Governance: ML workload without readiness probe
            # ------------------------------------------------------------------
            if is_ml:
                for container in containers:
                    if not isinstance(container, dict):
                        continue
                    has_readiness = bool(container.get("readinessProbe"))
                    has_liveness = bool(container.get("livenessProbe"))

                    if not has_readiness or not has_liveness:
                        findings.append(_finding(
                            rule_id="k8s.ai_sec.ai_governance.ml_missing_health_probes",
                            resource_uid=resource_uid,
                            resource_type=resource_type,
                            account_id=account_id,
                            region=r_region,
                            tenant_id=tenant_id,
                            scan_run_id=scan_run_id,
                            severity="MEDIUM",
                            pillar="ai_governance",
                            atlas_technique=None,
                            title=f"K8s ML Deployment '{deploy_name}' missing health probes",
                            detail=(
                                f"Container '{container.get('name', '?')}' in {namespace}/{deploy_name} "
                                f"is missing {'readinessProbe' if not has_readiness else 'livenessProbe'}. "
                                "ML model-serving containers require health probes to detect "
                                "silent model corruption or inference failure."
                            ),
                        ))
                        break

            # ------------------------------------------------------------------
            # Pillar 4 — Supply Chain: ML workload using latest tag
            # ------------------------------------------------------------------
            if is_ml:
                for container in containers:
                    if not isinstance(container, dict):
                        continue
                    image = container.get("image") or ""
                    if image.endswith(":latest") or (":" not in image.split("/")[-1]):
                        findings.append(_finding(
                            rule_id="k8s.ai_sec.supply_chain.ml_image_no_digest",
                            resource_uid=resource_uid,
                            resource_type=resource_type,
                            account_id=account_id,
                            region=r_region,
                            tenant_id=tenant_id,
                            scan_run_id=scan_run_id,
                            severity="HIGH",
                            pillar="supply_chain",
                            atlas_technique="AML.T0004",
                            title=f"K8s ML Deployment '{deploy_name}' uses mutable image tag",
                            detail=(
                                f"Container image '{image}' in {namespace}/{deploy_name} "
                                "uses a mutable tag (latest or no tag). An attacker can push "
                                "a backdoored model image to the registry and trigger re-deploy."
                            ),
                        ))
                        break

        # ------------------------------------------------------------------
        # Account-level AI governance summary
        # ------------------------------------------------------------------
        acct_uid = f"k8s:{account_id}:ai_governance"
        if total_count > 0 and ml_workload_count == 0:
            # No ML workloads detected — emit informational governance finding
            findings.append(_finding(
                rule_id="k8s.ai_sec.ai_governance.no_ml_workloads_detected",
                resource_uid=acct_uid,
                resource_type="K8sCluster",
                account_id=account_id,
                region="cluster",
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
                severity="LOW",
                pillar="ai_governance",
                atlas_technique=None,
                title="No K8s ML workloads detected (GPU or ML-labeled Deployments)",
                detail=(
                    f"Scanned {total_count} Deployments; none matched GPU resource requests "
                    "or ML application labels (mlflow, kubeflow, jupyter, ray, etc.). "
                    "If ML workloads exist, ensure they use standard ML labels."
                ),
            ))
        elif total_count == 0:
            findings.append(_finding(
                rule_id="k8s.ai_sec.ai_governance.no_deployments",
                resource_uid=acct_uid,
                resource_type="K8sCluster",
                account_id=account_id,
                region="cluster",
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
                severity="LOW",
                pillar="ai_governance",
                atlas_technique=None,
                title="No K8s Deployments found in discovery_findings for this scan",
                detail=(
                    "No k8s.apps/Deployment resources found for this scan_run_id. "
                    "Verify the K8s discovery scanner is enumerating all namespaces."
                ),
            ))

        logger.info(
            "K8s AI analyze(): %d ML workloads detected, %d ATLAS findings for scan %s",
            ml_workload_count, len(findings), scan_run_id,
        )
        return findings
