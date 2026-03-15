"""
Package Registry Adapter — Task 0.3.9 [Seq 33 | BD]

Queries public package registries (npm, PyPI, Maven Central, crates.io)
to detect dependency confusion attacks and gather package metadata.

APIs:
  - npm: https://registry.npmjs.org/{package_name}
  - PyPI: https://pypi.org/pypi/{package_name}/json
  - Maven Central: https://search.maven.org/solrsearch/select
  - crates.io: https://crates.io/api/v1/crates/{package_name}

Dependencies:
  - Task 0.3.1 (package_metadata table)
"""

import asyncio
import json
import logging
import time
from typing import Any, Dict, List, Optional

import asyncpg
import requests

logger = logging.getLogger("external_collector.adapters.package_registry")


class BasePackageRegistry:
    """Base class for package registry adapters."""

    registry_name: str = "unknown"

    def __init__(self) -> None:
        self._session = requests.Session()

    def lookup(self, package_name: str) -> Optional[Dict[str, Any]]:
        """Look up a package by name. Subclasses must implement."""
        raise NotImplementedError


class NpmRegistry(BasePackageRegistry):
    """npm registry adapter."""

    registry_name = "npm"

    def lookup(self, package_name: str) -> Optional[Dict[str, Any]]:
        """Look up an npm package.

        Args:
            package_name: Package name (e.g., 'lodash', '@scope/pkg').

        Returns:
            Parsed package metadata or None.
        """
        url = f"https://registry.npmjs.org/{package_name}"
        try:
            resp = self._session.get(url, timeout=15)
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            data = resp.json()

            dist_tags = data.get("dist-tags", {})
            latest_version = dist_tags.get("latest", "")
            latest_info = data.get("versions", {}).get(latest_version, {})
            npm_time = data.get("time", {})

            maintainers = data.get("maintainers", [])

            return {
                "package_name": package_name,
                "registry": "npm",
                "latest_version": latest_version,
                "publish_date": npm_time.get(latest_version, ""),
                "maintainer_count": len(maintainers),
                "license": latest_info.get("license", ""),
                "deprecated": bool(latest_info.get("deprecated")),
                "description": data.get("description", "")[:500],
            }
        except requests.RequestException as exc:
            logger.error("npm lookup error for %s: %s", package_name, exc)
            return None


class PyPIRegistry(BasePackageRegistry):
    """PyPI registry adapter."""

    registry_name = "pypi"

    def lookup(self, package_name: str) -> Optional[Dict[str, Any]]:
        """Look up a PyPI package.

        Args:
            package_name: Package name (e.g., 'requests').

        Returns:
            Parsed package metadata or None.
        """
        url = f"https://pypi.org/pypi/{package_name}/json"
        try:
            resp = self._session.get(url, timeout=15)
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            data = resp.json()

            info = data.get("info", {})
            return {
                "package_name": package_name,
                "registry": "pypi",
                "latest_version": info.get("version", ""),
                "publish_date": "",  # PyPI doesn't expose per-version date easily
                "maintainer_count": 1 if info.get("maintainer") else 0,
                "license": info.get("license", "")[:200],
                "deprecated": "inactive" in (info.get("classifiers") or []),
                "description": info.get("summary", "")[:500],
            }
        except requests.RequestException as exc:
            logger.error("PyPI lookup error for %s: %s", package_name, exc)
            return None


class MavenRegistry(BasePackageRegistry):
    """Maven Central registry adapter."""

    registry_name = "maven"

    def lookup(self, package_name: str) -> Optional[Dict[str, Any]]:
        """Look up a Maven artifact.

        Args:
            package_name: Artifact name ('groupId:artifactId' format).

        Returns:
            Parsed package metadata or None.
        """
        parts = package_name.split(":", 1)
        if len(parts) != 2:
            return None

        group_id, artifact_id = parts
        url = "https://search.maven.org/solrsearch/select"
        params = {"q": f'g:"{group_id}" AND a:"{artifact_id}"', "rows": 1, "wt": "json"}

        try:
            resp = self._session.get(url, params=params, timeout=15)
            resp.raise_for_status()
            data = resp.json()

            docs = data.get("response", {}).get("docs", [])
            if not docs:
                return None

            doc = docs[0]
            return {
                "package_name": package_name,
                "registry": "maven",
                "latest_version": doc.get("latestVersion", ""),
                "publish_date": str(doc.get("timestamp", "")),
                "maintainer_count": 0,
                "license": "",
                "deprecated": False,
                "description": "",
            }
        except requests.RequestException as exc:
            logger.error("Maven lookup error for %s: %s", package_name, exc)
            return None


class CratesRegistry(BasePackageRegistry):
    """crates.io registry adapter (Rust)."""

    registry_name = "crates"

    def __init__(self) -> None:
        super().__init__()
        self._session.headers["User-Agent"] = "threat-engine/1.0"

    def lookup(self, package_name: str) -> Optional[Dict[str, Any]]:
        """Look up a Rust crate.

        Args:
            package_name: Crate name (e.g., 'serde').

        Returns:
            Parsed package metadata or None.
        """
        url = f"https://crates.io/api/v1/crates/{package_name}"
        try:
            resp = self._session.get(url, timeout=15)
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            data = resp.json()

            crate = data.get("crate", {})
            return {
                "package_name": package_name,
                "registry": "crates",
                "latest_version": crate.get("max_version", ""),
                "publish_date": crate.get("updated_at", ""),
                "maintainer_count": 0,
                "license": "",
                "deprecated": False,
                "description": crate.get("description", "")[:500],
                "downloads": crate.get("downloads", 0),
            }
        except requests.RequestException as exc:
            logger.error("crates.io lookup error for %s: %s", package_name, exc)
            return None


# Registry dispatcher
REGISTRIES: Dict[str, BasePackageRegistry] = {
    "npm": NpmRegistry(),
    "pypi": PyPIRegistry(),
    "maven": MavenRegistry(),
    "crates": CratesRegistry(),
}


class PackageRegistryCollector:
    """Orchestrates package lookups across registries and stores results.

    Args:
        pool: asyncpg connection pool for threat_engine_external.
    """

    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def lookup_package(
        self, package_name: str, registry: str
    ) -> Optional[Dict[str, Any]]:
        """Look up a package in a specific registry.

        Args:
            package_name: Package name.
            registry: Registry name (npm, pypi, maven, crates).

        Returns:
            Package metadata dict or None.
        """
        adapter = REGISTRIES.get(registry)
        if not adapter:
            logger.warning("Unknown registry: %s", registry)
            return None

        result = await asyncio.get_event_loop().run_in_executor(
            None, adapter.lookup, package_name
        )

        if result:
            await self._store_metadata(result)

        return result

    async def check_dependency_confusion(
        self, internal_packages: List[Dict[str, str]]
    ) -> List[Dict[str, Any]]:
        """Check if internal package names exist on public registries.

        Args:
            internal_packages: List of {name, registry} dicts for internal packages.

        Returns:
            List of packages that exist on public registries (potential confusion).
        """
        conflicts: List[Dict[str, Any]] = []

        for pkg in internal_packages:
            name = pkg["name"]
            registry = pkg.get("registry", "npm")

            result = await self.lookup_package(name, registry)
            if result:
                conflicts.append({
                    "internal_name": name,
                    "registry": registry,
                    "public_version": result.get("latest_version", ""),
                    "public_maintainers": result.get("maintainer_count", 0),
                    "risk": "dependency_confusion",
                })

        logger.info(
            "Dependency confusion check: %d/%d names found on public registries",
            len(conflicts), len(internal_packages),
        )
        return conflicts

    async def _store_metadata(self, metadata: Dict[str, Any]) -> None:
        """Store package metadata in package_metadata table."""
        sql = """
            INSERT INTO package_metadata (
                package_name, registry, version, metadata, refreshed_at
            ) VALUES ($1, $2, $3, $4::jsonb, NOW())
            ON CONFLICT (package_name, registry, version)
            DO UPDATE SET
                metadata = EXCLUDED.metadata,
                refreshed_at = NOW()
        """
        async with self._pool.acquire() as conn:
            await conn.execute(
                sql,
                metadata["package_name"],
                metadata["registry"],
                metadata.get("latest_version", "unknown"),
                json.dumps(metadata),
            )
