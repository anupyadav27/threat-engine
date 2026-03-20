"""
Shared K8s Job creation utility for all CSPM engines.

Each engine's API pod uses this module to create scan Jobs on spot nodes.
The same Docker image serves both the API pod (CMD=uvicorn) and the Job pod
(command overridden to `python -m run_scan`).

Usage:
    from engine_common.job_creator import create_engine_job

    job_name = create_engine_job(
        engine_name="check",
        scan_id=check_scan_id,
        orchestration_id=orch_id,
        image="yadavanup84/engine-check:v-job",
    )
"""

import os
import logging
from typing import List, Optional

logger = logging.getLogger(__name__)

# ── Defaults (overridable via env vars per engine) ──────────────────────────

DEFAULT_NAMESPACE = os.getenv("SCANNER_NAMESPACE", "threat-engine-engines")
DEFAULT_SERVICE_ACCOUNT = os.getenv("SCANNER_SERVICE_ACCOUNT", "engine-sa")
DEFAULT_TTL_AFTER_FINISHED = 300  # cleanup completed/failed pods after 5 min
DEFAULT_BACKOFF_LIMIT = 0  # no retries — pipeline handles retry logic


def create_engine_job(
    engine_name: str,
    scan_id: str,
    orchestration_id: str,
    image: str,
    cpu_request: str = "500m",
    mem_request: str = "1Gi",
    cpu_limit: str = "1",
    mem_limit: str = "2Gi",
    active_deadline_seconds: int = 3600,
    extra_env: Optional[List] = None,
    extra_args: Optional[List[str]] = None,
    namespace: Optional[str] = None,
    service_account: Optional[str] = None,
) -> str:
    """Create a K8s Job to run an engine scan on a spot node.

    Args:
        engine_name: Engine identifier (e.g., "check", "threat", "discoveries")
        scan_id: Engine-specific scan ID (e.g., check_scan_id)
        orchestration_id: Pipeline orchestration ID
        image: Docker image for the scanner pod
        cpu_request: CPU request for the scanner pod
        mem_request: Memory request for the scanner pod
        cpu_limit: CPU limit for the scanner pod
        mem_limit: Memory limit for the scanner pod
        active_deadline_seconds: Max runtime before K8s kills the Job
        extra_env: Additional V1EnvVar objects to inject
        extra_args: Additional CLI arguments appended to the command
        namespace: Override K8s namespace (default: threat-engine-engines)
        service_account: Override service account (default: engine-sa)

    Returns:
        Job name (str)
    """
    from kubernetes import client as k8s_client, config as k8s_config

    try:
        k8s_config.load_incluster_config()
    except k8s_config.ConfigException:
        k8s_config.load_kube_config()  # local dev fallback

    ns = namespace or DEFAULT_NAMESPACE
    sa = service_account or DEFAULT_SERVICE_ACCOUNT
    job_name = f"{engine_name}-scan-{scan_id[:12]}"
    scan_id_arg = f"--{engine_name}-scan-id"

    # Build command
    command = [
        "python", "-m", "run_scan",
        "--orchestration-id", orchestration_id,
        scan_id_arg, scan_id,
    ]
    if extra_args:
        command.extend(extra_args)

    # Standard env vars
    env = [
        k8s_client.V1EnvVar(name="PYTHONPATH", value="/app"),
        k8s_client.V1EnvVar(name="LOG_LEVEL", value=os.getenv("LOG_LEVEL", "INFO")),
        k8s_client.V1EnvVar(name="AWS_REGION", value=os.getenv("AWS_REGION", "ap-south-1")),
        k8s_client.V1EnvVar(name="AWS_STS_REGIONAL_ENDPOINTS", value="legacy"),
        k8s_client.V1EnvVar(name="ENGINE_NAME", value=engine_name),
    ]
    if extra_env:
        env.extend(extra_env)

    # Standard envFrom (DB config + secrets)
    env_from = [
        k8s_client.V1EnvFromSource(
            config_map_ref=k8s_client.V1ConfigMapEnvSource(name="threat-engine-db-config"),
        ),
        k8s_client.V1EnvFromSource(
            secret_ref=k8s_client.V1SecretEnvSource(name="threat-engine-db-passwords"),
        ),
    ]

    job = k8s_client.V1Job(
        api_version="batch/v1",
        kind="Job",
        metadata=k8s_client.V1ObjectMeta(
            name=job_name,
            namespace=ns,
            labels={
                "app": f"{engine_name}-scanner",
                "workload-type": "scan",
                "engine": engine_name,
                "scan-id": scan_id[:12],
            },
        ),
        spec=k8s_client.V1JobSpec(
            ttl_seconds_after_finished=DEFAULT_TTL_AFTER_FINISHED,
            active_deadline_seconds=active_deadline_seconds,
            backoff_limit=DEFAULT_BACKOFF_LIMIT,
            template=k8s_client.V1PodTemplateSpec(
                metadata=k8s_client.V1ObjectMeta(
                    labels={
                        "app": f"{engine_name}-scanner",
                        "workload-type": "scan",
                        "engine": engine_name,
                    },
                ),
                spec=k8s_client.V1PodSpec(
                    service_account_name=sa,
                    restart_policy="Never",
                    tolerations=[
                        k8s_client.V1Toleration(
                            key="spot-scanner",
                            operator="Equal",
                            value="true",
                            effect="NoSchedule",
                        ),
                    ],
                    node_selector={
                        "workload-type": "scan",
                        "node-type": "spot",
                    },
                    containers=[
                        k8s_client.V1Container(
                            name="scanner",
                            image=image,
                            image_pull_policy="Always",
                            command=command,
                            env=env,
                            env_from=env_from,
                            resources=k8s_client.V1ResourceRequirements(
                                requests={"cpu": cpu_request, "memory": mem_request},
                                limits={"cpu": cpu_limit, "memory": mem_limit},
                            ),
                        ),
                    ],
                ),
            ),
        ),
    )

    batch_api = k8s_client.BatchV1Api()
    batch_api.create_namespaced_job(namespace=ns, body=job)
    logger.info(f"Created {engine_name} scanner Job: {job_name} (image={image})")
    return job_name
