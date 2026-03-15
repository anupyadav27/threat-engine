"""
Trivy Scanner Wrapper — Task 0.3.4 [Seq 28 | BD]

Runs Trivy vulnerability scanner on container images to extract CVE lists
and SBOM. Trivy binary is embedded in the Docker image.

Input:  {registry_type, repository, tag, digest}
Output: {cve_list, sbom, scan_status, scan_time}

Dependencies:
  - Task 0.3.3 (registry_adapter for image access)
  - Task 0.3.1 (registry_images table)
"""

import asyncio
import json
import logging
import subprocess
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import asyncpg

logger = logging.getLogger("external_collector.scanners.trivy")

# Max concurrent Trivy processes
MAX_CONCURRENT_SCANS = 3
_semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)

# Trivy binary path (embedded in Docker image)
TRIVY_BIN = "/usr/local/bin/trivy"
TRIVY_TIMEOUT = 300  # 5 minutes per scan


class TrivyScanner:
    """Runs Trivy scans on container images and stores results.

    Args:
        pool: asyncpg connection pool for threat_engine_external.
        trivy_bin: Path to Trivy binary.
    """

    def __init__(
        self,
        pool: asyncpg.Pool,
        trivy_bin: str = TRIVY_BIN,
    ) -> None:
        self._pool = pool
        self._trivy_bin = trivy_bin

    async def scan_image(
        self,
        image_ref: str,
        registry_image_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Run Trivy scan on a container image.

        Args:
            image_ref: Full image reference (e.g., 'nginx:latest', 'myrepo/myapp:v1').
            registry_image_id: ID of the registry_images row to update.

        Returns:
            Dict with cve_list, sbom, scan_status, scan_time, error.
        """
        async with _semaphore:
            return await self._run_scan(image_ref, registry_image_id)

    async def _run_scan(
        self,
        image_ref: str,
        registry_image_id: Optional[int],
    ) -> Dict[str, Any]:
        """Execute Trivy and parse results."""
        logger.info("Starting Trivy scan for: %s", image_ref)
        start_time = time.monotonic()

        # Mark as scanning
        if registry_image_id:
            await self._update_scan_status(registry_image_id, "scanning")

        try:
            # Run trivy image --format json
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                self._execute_trivy,
                image_ref,
            )

            if result["returncode"] != 0:
                error_msg = result["stderr"][:1000]
                logger.error("Trivy scan failed for %s: %s", image_ref, error_msg)
                if registry_image_id:
                    await self._update_scan_status(
                        registry_image_id, "failed", error=error_msg
                    )
                return {
                    "cve_list": [],
                    "sbom": {},
                    "scan_status": "failed",
                    "scan_time": time.monotonic() - start_time,
                    "error": error_msg,
                }

            # Parse Trivy JSON output
            trivy_output = json.loads(result["stdout"])
            cve_list = self._extract_cves(trivy_output)
            sbom = self._extract_sbom(trivy_output)

            scan_time = time.monotonic() - start_time

            # Store results
            if registry_image_id:
                await self._store_results(
                    registry_image_id, trivy_output, cve_list, sbom
                )

            logger.info(
                "Trivy scan complete for %s: %d CVEs found in %.1fs",
                image_ref, len(cve_list), scan_time,
            )

            return {
                "cve_list": cve_list,
                "sbom": sbom,
                "scan_status": "completed",
                "scan_time": scan_time,
                "error": None,
            }

        except json.JSONDecodeError as exc:
            error_msg = f"Failed to parse Trivy output: {exc}"
            logger.error(error_msg)
            if registry_image_id:
                await self._update_scan_status(
                    registry_image_id, "failed", error=error_msg
                )
            return {
                "cve_list": [],
                "sbom": {},
                "scan_status": "failed",
                "scan_time": time.monotonic() - start_time,
                "error": error_msg,
            }
        except Exception as exc:
            error_msg = str(exc)
            logger.error("Trivy scan error for %s: %s", image_ref, exc, exc_info=True)
            if registry_image_id:
                await self._update_scan_status(
                    registry_image_id, "failed", error=error_msg
                )
            return {
                "cve_list": [],
                "sbom": {},
                "scan_status": "failed",
                "scan_time": time.monotonic() - start_time,
                "error": error_msg,
            }

    def _execute_trivy(self, image_ref: str) -> Dict[str, Any]:
        """Execute Trivy as a subprocess (blocking — run in executor).

        Returns:
            Dict with returncode, stdout, stderr.
        """
        cmd = [
            self._trivy_bin,
            "image",
            "--format", "json",
            "--severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
            "--no-progress",
            image_ref,
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=TRIVY_TIMEOUT,
            )
            return {
                "returncode": proc.returncode,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
            }
        except subprocess.TimeoutExpired:
            return {
                "returncode": -1,
                "stdout": "",
                "stderr": f"Trivy scan timed out after {TRIVY_TIMEOUT}s",
            }

    def _extract_cves(self, trivy_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract CVE list from Trivy JSON output.

        Returns:
            List of {cve_id, package_name, installed_version, severity, fixed_version}.
        """
        cves: List[Dict[str, Any]] = []
        results = trivy_output.get("Results", [])

        for result in results:
            vulns = result.get("Vulnerabilities", [])
            for vuln in vulns:
                cves.append({
                    "cve_id": vuln.get("VulnerabilityID", ""),
                    "package_name": vuln.get("PkgName", ""),
                    "installed_version": vuln.get("InstalledVersion", ""),
                    "severity": vuln.get("Severity", "UNKNOWN"),
                    "fixed_version": vuln.get("FixedVersion", ""),
                    "title": vuln.get("Title", ""),
                    "primary_url": vuln.get("PrimaryURL", ""),
                })

        return cves

    def _extract_sbom(self, trivy_output: Dict[str, Any]) -> Dict[str, Any]:
        """Extract SBOM (package inventory) from Trivy output in CycloneDX-like format.

        Returns:
            CycloneDX-style SBOM dict with components list.
        """
        components: List[Dict[str, Any]] = []
        results = trivy_output.get("Results", [])

        for result in results:
            target = result.get("Target", "")
            pkg_type = result.get("Type", "")

            for pkg in result.get("Packages", []):
                components.append({
                    "type": "library",
                    "name": pkg.get("Name", ""),
                    "version": pkg.get("Version", ""),
                    "purl": pkg.get("Identifier", {}).get("PURL", ""),
                    "ecosystem": pkg_type,
                    "source": target,
                })

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": components,
            "metadata": {
                "tool": "trivy",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        }

    async def _update_scan_status(
        self,
        registry_image_id: int,
        status: str,
        error: Optional[str] = None,
    ) -> None:
        """Update the scan_status on a registry_images row."""
        sql = """
            UPDATE registry_images SET
                scan_status = $1,
                scan_time = NOW(),
                scan_error = $2
            WHERE id = $3
        """
        async with self._pool.acquire() as conn:
            await conn.execute(sql, status, error, registry_image_id)

    async def _store_results(
        self,
        registry_image_id: int,
        trivy_output: Dict[str, Any],
        cve_list: List[Dict[str, Any]],
        sbom: Dict[str, Any],
    ) -> None:
        """Store full scan results in registry_images table."""
        sql = """
            UPDATE registry_images SET
                trivy_output = $1::jsonb,
                cve_list = $2::jsonb,
                sbom = $3::jsonb,
                scan_status = 'completed',
                scan_time = NOW(),
                scan_error = NULL,
                refreshed_at = NOW()
            WHERE id = $4
        """
        async with self._pool.acquire() as conn:
            await conn.execute(
                sql,
                json.dumps(trivy_output),
                json.dumps(cve_list),
                json.dumps(sbom),
                registry_image_id,
            )

    async def scan_pending_images(self, limit: int = 10) -> int:
        """Scan all images with scan_status='pending' in registry_images.

        Args:
            limit: Max images to scan in one batch.

        Returns:
            Number of images scanned.
        """
        sql = """
            SELECT id, registry_type, repository, tag
            FROM registry_images
            WHERE scan_status = 'pending'
            ORDER BY created_at ASC
            LIMIT $1
        """
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(sql, limit)

        if not rows:
            return 0

        # Scan concurrently (up to MAX_CONCURRENT_SCANS)
        tasks = []
        for row in rows:
            image_ref = f"{row['repository']}:{row['tag']}" if row["tag"] else row["repository"]
            tasks.append(self.scan_image(image_ref, registry_image_id=row["id"]))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        scanned = sum(1 for r in results if not isinstance(r, Exception))

        logger.info("Batch scan complete: %d/%d images scanned", scanned, len(rows))
        return scanned
