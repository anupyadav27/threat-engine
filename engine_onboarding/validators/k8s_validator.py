"""
Kubernetes credential validator
Supports in-cluster and kubeconfig credential types
"""
import asyncio
from typing import Dict, Any
from concurrent.futures import ThreadPoolExecutor

from engine_onboarding.validators.base_validator import BaseValidator, ValidationResult

_K8S_EXECUTOR = ThreadPoolExecutor(max_workers=2)


class K8sValidator(BaseValidator):
    """Validates Kubernetes cluster credentials"""

    async def validate(self, credentials: Dict[str, Any]) -> ValidationResult:
        """
        Validate Kubernetes credentials

        Supported credential types:
        - in_cluster: Uses service account mounted in pod (no extra creds needed)
        - kubeconfig: Uses kubeconfig content or path

        Args:
            credentials: Dictionary containing credential data

        Returns:
            ValidationResult with success status and cluster info
        """
        try:
            # Support nested credentials key (Secrets Manager wrapper)
            creds = credentials.get('credentials', credentials)
            credential_type = creds.get('credential_type', 'in_cluster')

            if credential_type == 'in_cluster':
                return await self._validate_in_cluster(creds)
            elif credential_type == 'kubeconfig':
                return await self._validate_kubeconfig(creds)
            else:
                return self._create_error_result(
                    f"Unsupported K8s credential type: {credential_type}",
                    errors=[f"Supported types: in_cluster, kubeconfig"]
                )

        except ImportError:
            return self._create_error_result(
                "kubernetes SDK not installed",
                errors=["Install with: pip install kubernetes>=28.1.0"]
            )
        except Exception as e:
            return self._create_error_result(
                f"K8s validation failed: {str(e)}",
                errors=[str(e)]
            )

    async def _validate_in_cluster(self, creds: Dict[str, Any]) -> ValidationResult:
        """Validate using in-cluster service account"""
        try:
            from kubernetes import client, config as k8s_config

            def _do_validate():
                # Load in-cluster config (uses mounted service account token)
                k8s_config.load_incluster_config()
                v1 = client.CoreV1Api()

                # Test connectivity by listing namespaces (limit=1 for speed)
                ns_list = v1.list_namespace(limit=1)
                ns_count = len(ns_list.items)

                # Get cluster info
                cluster_name = creds.get('cluster_name', 'unknown-cluster')

                return cluster_name, ns_count

            loop = asyncio.get_event_loop()
            cluster_name, ns_count = await loop.run_in_executor(
                _K8S_EXECUTOR, _do_validate
            )

            return self._create_success_result(
                message=f"K8s in-cluster authentication successful. "
                        f"Cluster: {cluster_name}, accessible namespaces: {ns_count}+",
                account_number=cluster_name
            )

        except Exception as e:
            error_msg = str(e)
            if 'KUBERNETES_SERVICE_HOST' in error_msg or 'InClusterConfigException' in error_msg:
                return self._create_error_result(
                    "Not running inside a Kubernetes cluster. "
                    "In-cluster auth requires the pod to have a service account.",
                    errors=[error_msg]
                )
            return self._create_error_result(
                f"K8s in-cluster validation failed: {error_msg}",
                errors=[error_msg]
            )

    async def _validate_kubeconfig(self, creds: Dict[str, Any]) -> ValidationResult:
        """Validate using kubeconfig content"""
        try:
            import tempfile
            import os
            from kubernetes import client, config as k8s_config

            kubeconfig_content = creds.get('kubeconfig')
            kubeconfig_path = creds.get('kubeconfig_path')

            if not kubeconfig_content and not kubeconfig_path:
                return self._create_error_result(
                    "kubeconfig credential type requires 'kubeconfig' (content) "
                    "or 'kubeconfig_path'",
                    errors=["Missing kubeconfig data"]
                )

            def _do_validate():
                if kubeconfig_content:
                    # Write to temp file for the SDK
                    tmp = tempfile.NamedTemporaryFile(
                        mode='w', suffix='.yaml', delete=False
                    )
                    try:
                        tmp.write(kubeconfig_content)
                        tmp.flush()
                        tmp.close()
                        k8s_config.load_kube_config(config_file=tmp.name)
                    finally:
                        os.unlink(tmp.name)
                else:
                    k8s_config.load_kube_config(config_file=kubeconfig_path)

                v1 = client.CoreV1Api()
                ns_list = v1.list_namespace(limit=1)
                ns_count = len(ns_list.items)

                # Try to get current context name
                cluster_name = creds.get('cluster_name', 'kubeconfig-cluster')

                return cluster_name, ns_count

            loop = asyncio.get_event_loop()
            cluster_name, ns_count = await loop.run_in_executor(
                _K8S_EXECUTOR, _do_validate
            )

            return self._create_success_result(
                message=f"K8s kubeconfig authentication successful. "
                        f"Cluster: {cluster_name}, accessible namespaces: {ns_count}+",
                account_number=cluster_name
            )

        except Exception as e:
            return self._create_error_result(
                f"K8s kubeconfig validation failed: {str(e)}",
                errors=[str(e)]
            )
