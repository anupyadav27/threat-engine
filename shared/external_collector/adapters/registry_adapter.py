"""
Container Registry Adapter — Task 0.3.3 [Seq 27 | BD]

Multi-CSP container registry adapter. Fetches container image metadata
(manifests, tags, layers, sizes) from registries across all supported
cloud providers:

  AWS:   ECR (Elastic Container Registry)
  Azure: ACR (Azure Container Registry)
  GCP:   Artifact Registry / GCR
  OCI:   OCIR (Oracle Container Infrastructure Registry)

Also supports Docker Hub and Quay.io for public images.

Dependencies:
  - Task 0.3.2 (credential_manager for registry credentials)
  - Task 0.3.1 (registry_images table)
"""

import json
import logging
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

import boto3
import requests

logger = logging.getLogger("external_collector.adapters.registry")


# ---------------------------------------------------------------------------
# Base adapter interface
# ---------------------------------------------------------------------------
class BaseRegistryAdapter(ABC):
    """Abstract base class for container registry adapters."""

    @abstractmethod
    def authenticate(self) -> None:
        """Authenticate to the registry."""

    @abstractmethod
    def list_tags(self, repository: str) -> List[str]:
        """List all tags for a repository."""

    @abstractmethod
    def get_manifest(self, repository: str, reference: str) -> Dict[str, Any]:
        """Get the manifest for a specific image reference (tag or digest)."""

    @property
    @abstractmethod
    def registry_type(self) -> str:
        """Return the registry type identifier."""


# ---------------------------------------------------------------------------
# Docker Hub Adapter
# ---------------------------------------------------------------------------
class DockerHubAdapter(BaseRegistryAdapter):
    """Docker Hub registry adapter using Docker Registry HTTP API v2.

    Args:
        credential_manager: CredentialManager instance.
    """

    BASE_URL = "https://registry-1.docker.io"
    AUTH_URL = "https://auth.docker.io/token"

    def __init__(self, credential_manager: Any) -> None:
        self._cred_mgr = credential_manager
        self._token: Optional[str] = None
        self._token_expiry: float = 0

    @property
    def registry_type(self) -> str:
        return "docker_hub"

    def authenticate(self) -> None:
        """Get Docker Hub bearer token using PAT."""
        pat = self._cred_mgr.get_credential("dockerhub")
        params = {
            "service": "registry.docker.io",
            "scope": "repository:library/alpine:pull",
        }
        headers = {}
        if pat:
            headers["Authorization"] = f"Bearer {pat}"

        resp = requests.get(self.AUTH_URL, params=params, headers=headers, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        self._token = data.get("token")
        self._token_expiry = time.time() + data.get("expires_in", 300)

    def _get_token_for_repo(self, repository: str) -> str:
        """Get a scoped token for a specific repository."""
        pat = self._cred_mgr.get_credential("dockerhub")
        params = {
            "service": "registry.docker.io",
            "scope": f"repository:{repository}:pull",
        }
        headers = {}
        if pat:
            import base64
            headers["Authorization"] = f"Bearer {pat}"

        resp = requests.get(self.AUTH_URL, params=params, headers=headers, timeout=10)
        resp.raise_for_status()
        return resp.json().get("token", "")

    def list_tags(self, repository: str) -> List[str]:
        """List all tags for a Docker Hub repository."""
        token = self._get_token_for_repo(repository)
        headers = {"Authorization": f"Bearer {token}"}
        url = f"{self.BASE_URL}/v2/{repository}/tags/list"

        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        return resp.json().get("tags", [])

    def get_manifest(self, repository: str, reference: str) -> Dict[str, Any]:
        """Get manifest for a Docker Hub image."""
        token = self._get_token_for_repo(repository)
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.docker.distribution.manifest.v2+json",
        }
        url = f"{self.BASE_URL}/v2/{repository}/manifests/{reference}"

        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()

        manifest = resp.json()
        digest = resp.headers.get("Docker-Content-Digest", "")

        return {
            "digest": digest,
            "media_type": manifest.get("mediaType", ""),
            "layers": manifest.get("layers", []),
            "config": manifest.get("config", {}),
            "size_bytes": sum(layer.get("size", 0) for layer in manifest.get("layers", [])),
        }


# ---------------------------------------------------------------------------
# ECR Adapter
# ---------------------------------------------------------------------------
class ECRAdapter(BaseRegistryAdapter):
    """AWS ECR registry adapter using boto3.

    Args:
        region: AWS region.
    """

    def __init__(self, region: str = "us-east-1") -> None:
        self._region = region
        self._ecr = boto3.client("ecr", region_name=region)
        self._auth_token: Optional[str] = None

    @property
    def registry_type(self) -> str:
        return "ecr"

    def authenticate(self) -> None:
        """Get ECR authorization token via boto3."""
        resp = self._ecr.get_authorization_token()
        auth_data = resp.get("authorizationData", [{}])[0]
        self._auth_token = auth_data.get("authorizationToken", "")

    def list_tags(self, repository: str) -> List[str]:
        """List all image tags in an ECR repository."""
        tags: List[str] = []
        paginator = self._ecr.get_paginator("list_images")
        for page in paginator.paginate(repositoryName=repository):
            for image_id in page.get("imageIds", []):
                tag = image_id.get("imageTag")
                if tag:
                    tags.append(tag)
        return tags

    def get_manifest(self, repository: str, reference: str) -> Dict[str, Any]:
        """Get image details from ECR."""
        resp = self._ecr.batch_get_image(
            repositoryName=repository,
            imageIds=[{"imageTag": reference}],
            acceptedMediaTypes=["application/vnd.docker.distribution.manifest.v2+json"],
        )
        images = resp.get("images", [])
        if not images:
            return {}

        image = images[0]
        manifest = json.loads(image.get("imageManifest", "{}"))

        return {
            "digest": image.get("imageId", {}).get("imageDigest", ""),
            "media_type": manifest.get("mediaType", ""),
            "layers": manifest.get("layers", []),
            "config": manifest.get("config", {}),
            "size_bytes": sum(layer.get("size", 0) for layer in manifest.get("layers", [])),
        }


# ---------------------------------------------------------------------------
# Azure ACR Adapter
# ---------------------------------------------------------------------------
class ACRAdapter(BaseRegistryAdapter):
    """Azure Container Registry adapter using Docker Registry HTTP API v2.

    ACR supports the standard Docker Registry HTTP API v2, so we authenticate
    via OAuth2 token exchange using AAD credentials or admin user.

    Args:
        login_server: ACR login server (e.g., 'myregistry.azurecr.io').
        credential_manager: CredentialManager for Azure credentials.
    """

    def __init__(self, login_server: str, credential_manager: Any) -> None:
        self._login_server = login_server
        self._cred_mgr = credential_manager
        self._token: Optional[str] = None

    @property
    def registry_type(self) -> str:
        return "acr"

    def authenticate(self) -> None:
        """Authenticate to ACR using refresh token exchange."""
        creds = self._cred_mgr.get_credential("azure_acr")
        if not creds:
            raise ValueError("Azure ACR credentials not configured")

        # ACR supports Basic auth with admin user or AAD token exchange
        # Using Basic auth (admin username/password) for simplicity
        url = f"https://{self._login_server}/oauth2/token"
        resp = requests.post(
            url,
            data={
                "grant_type": "password",
                "service": self._login_server,
                "scope": "registry:catalog:*",
                "username": creds.get("username", ""),
                "password": creds.get("password", ""),
            },
            timeout=15,
        )
        resp.raise_for_status()
        self._token = resp.json().get("access_token", "")

    def _get_auth_headers(self, repository: str) -> Dict[str, str]:
        """Get scoped auth headers for a repository."""
        creds = self._cred_mgr.get_credential("azure_acr")
        url = f"https://{self._login_server}/oauth2/token"
        resp = requests.post(
            url,
            data={
                "grant_type": "password",
                "service": self._login_server,
                "scope": f"repository:{repository}:pull",
                "username": creds.get("username", ""),
                "password": creds.get("password", ""),
            },
            timeout=15,
        )
        resp.raise_for_status()
        token = resp.json().get("access_token", "")
        return {"Authorization": f"Bearer {token}"}

    def list_tags(self, repository: str) -> List[str]:
        """List all tags for an ACR repository."""
        headers = self._get_auth_headers(repository)
        url = f"https://{self._login_server}/v2/{repository}/tags/list"
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        return resp.json().get("tags", [])

    def get_manifest(self, repository: str, reference: str) -> Dict[str, Any]:
        """Get manifest from ACR."""
        headers = self._get_auth_headers(repository)
        headers["Accept"] = "application/vnd.docker.distribution.manifest.v2+json"
        url = f"https://{self._login_server}/v2/{repository}/manifests/{reference}"
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        manifest = resp.json()
        return {
            "digest": resp.headers.get("Docker-Content-Digest", ""),
            "media_type": manifest.get("mediaType", ""),
            "layers": manifest.get("layers", []),
            "config": manifest.get("config", {}),
            "size_bytes": sum(layer.get("size", 0) for layer in manifest.get("layers", [])),
        }


# ---------------------------------------------------------------------------
# GCP Artifact Registry / GCR Adapter
# ---------------------------------------------------------------------------
class GCPArtifactRegistryAdapter(BaseRegistryAdapter):
    """GCP Artifact Registry adapter using Docker Registry HTTP API v2.

    Supports both Artifact Registry (*.pkg.dev) and legacy GCR (gcr.io).

    Args:
        host: Registry host (e.g., 'us-docker.pkg.dev' or 'gcr.io').
        project_id: GCP project ID.
        credential_manager: CredentialManager for GCP credentials.
    """

    def __init__(
        self, host: str, project_id: str, credential_manager: Any
    ) -> None:
        self._host = host
        self._project_id = project_id
        self._cred_mgr = credential_manager
        self._token: Optional[str] = None

    @property
    def registry_type(self) -> str:
        return "gcr"

    def authenticate(self) -> None:
        """Authenticate using GCP access token or service account key."""
        token = self._cred_mgr.get_credential("gcp_registry")
        if token:
            self._token = token
            return

        # Fallback: try to get token from gcloud SDK
        try:
            import subprocess
            result = subprocess.run(
                ["gcloud", "auth", "print-access-token"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                self._token = result.stdout.strip()
        except Exception as exc:
            logger.warning("GCP auth fallback failed: %s", exc)

    def _get_auth_headers(self) -> Dict[str, str]:
        """Get auth headers for GCP registry."""
        if not self._token:
            self.authenticate()
        return {"Authorization": f"Bearer {self._token}"} if self._token else {}

    def list_tags(self, repository: str) -> List[str]:
        """List all tags for a GCP Artifact Registry repository."""
        headers = self._get_auth_headers()
        url = f"https://{self._host}/v2/{repository}/tags/list"
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        return resp.json().get("tags", [])

    def get_manifest(self, repository: str, reference: str) -> Dict[str, Any]:
        """Get manifest from GCP Artifact Registry."""
        headers = self._get_auth_headers()
        headers["Accept"] = "application/vnd.docker.distribution.manifest.v2+json"
        url = f"https://{self._host}/v2/{repository}/manifests/{reference}"
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        manifest = resp.json()
        return {
            "digest": resp.headers.get("Docker-Content-Digest", ""),
            "media_type": manifest.get("mediaType", ""),
            "layers": manifest.get("layers", []),
            "config": manifest.get("config", {}),
            "size_bytes": sum(layer.get("size", 0) for layer in manifest.get("layers", [])),
        }


# ---------------------------------------------------------------------------
# OCI OCIR Adapter (Oracle Cloud)
# ---------------------------------------------------------------------------
class OCIRAdapter(BaseRegistryAdapter):
    """Oracle Cloud Infrastructure Registry (OCIR) adapter.

    OCIR also supports Docker Registry HTTP API v2.

    Args:
        region: OCI region (e.g., 'us-ashburn-1').
        tenancy_namespace: OCI tenancy namespace.
        credential_manager: CredentialManager for OCI credentials.
    """

    def __init__(
        self, region: str, tenancy_namespace: str, credential_manager: Any
    ) -> None:
        self._host = f"{region}.ocir.io"
        self._namespace = tenancy_namespace
        self._cred_mgr = credential_manager
        self._token: Optional[str] = None

    @property
    def registry_type(self) -> str:
        return "ocir"

    def authenticate(self) -> None:
        """Authenticate using OCI auth token."""
        creds = self._cred_mgr.get_credential("oci_ocir")
        if creds:
            self._token = creds

    def _get_auth_headers(self) -> Dict[str, str]:
        """Get Basic auth headers for OCIR."""
        import base64
        creds = self._cred_mgr.get_credential("oci_ocir")
        if isinstance(creds, dict):
            username = creds.get("username", "")
            password = creds.get("password", "")
        else:
            return {}
        encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
        return {"Authorization": f"Basic {encoded}"}

    def list_tags(self, repository: str) -> List[str]:
        """List tags for an OCIR repository."""
        headers = self._get_auth_headers()
        url = f"https://{self._host}/v2/{self._namespace}/{repository}/tags/list"
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        return resp.json().get("tags", [])

    def get_manifest(self, repository: str, reference: str) -> Dict[str, Any]:
        """Get manifest from OCIR."""
        headers = self._get_auth_headers()
        headers["Accept"] = "application/vnd.docker.distribution.manifest.v2+json"
        url = f"https://{self._host}/v2/{self._namespace}/{repository}/manifests/{reference}"
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        manifest = resp.json()
        return {
            "digest": resp.headers.get("Docker-Content-Digest", ""),
            "media_type": manifest.get("mediaType", ""),
            "layers": manifest.get("layers", []),
            "config": manifest.get("config", {}),
            "size_bytes": sum(layer.get("size", 0) for layer in manifest.get("layers", [])),
        }


# ---------------------------------------------------------------------------
# Unified Registry Client
# ---------------------------------------------------------------------------
class RegistryClient:
    """Unified client that dispatches to the correct registry adapter.

    Supports all CSPs: AWS ECR, Azure ACR, GCP Artifact Registry, OCI OCIR,
    plus Docker Hub for public images.

    Args:
        credential_manager: CredentialManager instance.
    """

    def __init__(self, credential_manager: Any) -> None:
        self._cred_mgr = credential_manager
        self._adapters: Dict[str, BaseRegistryAdapter] = {
            "docker_hub": DockerHubAdapter(credential_manager),
            "ecr": ECRAdapter(),
            # ACR, GCR, OCIR are initialized on-demand via register_adapter()
        }

    def register_adapter(
        self, registry_type: str, adapter: BaseRegistryAdapter
    ) -> None:
        """Register a CSP-specific adapter at runtime.

        Use this to add ACR, GCR, or OCIR adapters based on the customer's
        cloud environment configuration.

        Args:
            registry_type: Registry type key (e.g., 'acr', 'gcr', 'ocir').
            adapter: Adapter instance.
        """
        self._adapters[registry_type] = adapter
        logger.info("Registered registry adapter: %s", registry_type)

    def get_adapter(self, registry_type: str) -> Optional[BaseRegistryAdapter]:
        """Get the adapter for a specific registry type."""
        return self._adapters.get(registry_type)

    def list_tags(self, registry_type: str, repository: str) -> List[str]:
        """List tags across any supported registry."""
        adapter = self.get_adapter(registry_type)
        if not adapter:
            raise ValueError(f"Unsupported registry type: {registry_type}")
        return adapter.list_tags(repository)

    def get_manifest(
        self, registry_type: str, repository: str, reference: str
    ) -> Dict[str, Any]:
        """Get manifest from any supported registry."""
        adapter = self.get_adapter(registry_type)
        if not adapter:
            raise ValueError(f"Unsupported registry type: {registry_type}")
        return adapter.get_manifest(repository, reference)

    async def fetch_and_store(
        self,
        pool: Any,
        registry_type: str,
        repository: str,
        tag: str,
        customer_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Fetch manifest and store in registry_images table.

        Returns:
            The stored row as a dict.
        """
        manifest = self.get_manifest(registry_type, repository, tag)

        sql = """
            INSERT INTO registry_images
                (registry_type, repository, tag, digest, manifest,
                 size_bytes, scan_status, customer_id, tenant_id, refreshed_at)
            VALUES ($1, $2, $3, $4, $5::jsonb, $6, 'pending', $7, $8, NOW())
            ON CONFLICT (registry_type, repository, tag, digest, customer_id, tenant_id)
            DO UPDATE SET
                manifest = EXCLUDED.manifest,
                size_bytes = EXCLUDED.size_bytes,
                refreshed_at = NOW()
            RETURNING *
        """
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                sql,
                registry_type,
                repository,
                tag,
                manifest.get("digest", ""),
                json.dumps(manifest),
                manifest.get("size_bytes"),
                customer_id,
                tenant_id,
            )
        return dict(row) if row else {}
