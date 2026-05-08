"""
Platform Admin Engine — Kubernetes in-cluster API client.

Uses the service account token mounted at the standard path when running
inside a pod. Falls back to kubeconfig for local development.

engine-sa must have a ClusterRole granting get/list on pods and deployments
(see deployment/aws/eks/engines/engine-platform-admin.yaml).
"""

from __future__ import annotations

import logging
import os
from typing import Tuple

logger = logging.getLogger(__name__)

NAMESPACE: str = os.environ.get("K8S_NAMESPACE", "threat-engine-engines")

ENGINE_NAMES: list[str] = [
    "engine-discoveries",
    "engine-check-aws",
    "engine-inventory",
    "engine-threat",
    "engine-compliance",
    "engine-iam",
    "engine-ciem",
    "engine-network-security",
    "engine-risk",
    "engine-datasec",
    "engine-secops",
    "engine-vulnerability",
    "engine-ai-security",
    "engine-encryption",
    "engine-dbsec",
    "engine-container-sec",
    "engine-billing",
    "engine-platform-admin",
]


def get_k8s_client():
    """Load the Kubernetes API client using in-cluster config or kubeconfig fallback.

    Returns:
        Tuple of (CoreV1Api, AppsV1Api) clients.

    Raises:
        Exception: If neither in-cluster config nor kubeconfig is available.
    """
    try:
        from kubernetes import client, config as k8s_config  # type: ignore

        try:
            k8s_config.load_incluster_config()
            logger.debug("Loaded in-cluster Kubernetes config")
        except k8s_config.ConfigException:
            k8s_config.load_kube_config()
            logger.debug("Loaded local kubeconfig (dev fallback)")

        return client.CoreV1Api(), client.AppsV1Api()
    except ImportError as exc:
        raise RuntimeError("kubernetes Python package not installed") from exc
