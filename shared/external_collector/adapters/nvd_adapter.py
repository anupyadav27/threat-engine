"""
NVD/CVE Adapter — Task 0.3.6 [Seq 30 | BD]

IMPORTANT — DEDUPLICATION NOTE:
  The existing vulnerability/ engine (vuln_db) already has a full NVD pipeline
  (step1_nvd_initial_downloader → step2_nvd_parser → step3_nvd_uploader →
  step4_nvd_incremental_updater) with CVSS v2/v3.0/v3.1/v4.0 support stored
  in the threat_engine_vulnerability database (cves table).

  This adapter provides a LIGHTWEIGHT cache in threat_engine_external.vuln_cache
  for use by the NEW engines (container, supplychain, risk) that need fast
  CVE lookups without cross-database queries. It is NOT a replacement for
  vuln_db — it acts as a local read-through cache seeded from vuln_db or NVD.

  During pipeline execution the preferred flow is:
    1. Check vuln_cache (this adapter's cache)
    2. If miss → query vulnerability engine's cves table (cross-DB)
    3. If miss → fetch from NVD API (last resort)

Modes:
  - On-demand: Query by CVE ID (cache-through)
  - Bulk refresh: Download recent CVEs (daily), parse into vuln_cache table

Dependencies:
  - Task 0.3.2 (credential_manager for NVD API key)
  - Task 0.3.1 (vuln_cache table)
  - vulnerability/vuln_db (primary CVE data source)
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

import asyncpg
import requests

logger = logging.getLogger("external_collector.adapters.nvd")

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Rate limits
NVD_RATE_FREE = 50       # 50 requests per 30 seconds (no API key)
NVD_RATE_KEYED = 5000    # 5000 requests per 30 seconds (with API key)
NVD_RATE_WINDOW = 30     # seconds

# Batch size for bulk queries
NVD_RESULTS_PER_PAGE = 2000


class NVDAdapter:
    """Fetches CVE data from the NVD REST API v2.0.

    Args:
        pool: asyncpg connection pool for threat_engine_external.
        api_key: Optional NVD API key (increases rate limit).
    """

    def __init__(
        self,
        pool: asyncpg.Pool,
        api_key: Optional[str] = None,
    ) -> None:
        self._pool = pool
        self._api_key = api_key
        self._session = requests.Session()
        if api_key:
            self._session.headers["apiKey"] = api_key

        self._request_count = 0
        self._window_start = time.monotonic()

    def _rate_limit_check(self) -> None:
        """Enforce rate limiting before making a request."""
        max_rate = NVD_RATE_KEYED if self._api_key else NVD_RATE_FREE
        elapsed = time.monotonic() - self._window_start

        if elapsed >= NVD_RATE_WINDOW:
            self._request_count = 0
            self._window_start = time.monotonic()

        if self._request_count >= max_rate:
            sleep_time = NVD_RATE_WINDOW - elapsed
            if sleep_time > 0:
                logger.info("NVD rate limit reached, sleeping %.1fs", sleep_time)
                time.sleep(sleep_time)
            self._request_count = 0
            self._window_start = time.monotonic()

        self._request_count += 1

    def fetch_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single CVE by ID.

        Args:
            cve_id: CVE identifier (e.g., 'CVE-2024-1234').

        Returns:
            Parsed CVE dict or None if not found.
        """
        self._rate_limit_check()

        try:
            resp = self._session.get(
                NVD_API_BASE,
                params={"cveId": cve_id},
                timeout=30,
            )

            if resp.status_code == 404:
                return None
            if resp.status_code == 429:
                retry_after = int(resp.headers.get("Retry-After", "30"))
                logger.warning("NVD 429, sleeping %ds", retry_after)
                time.sleep(retry_after)
                return self.fetch_cve(cve_id)

            resp.raise_for_status()
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return None

            return self._parse_cve(vulns[0].get("cve", {}))

        except requests.RequestException as exc:
            logger.error("NVD API error for %s: %s", cve_id, exc)
            return None

    def fetch_recent_cves(
        self,
        lookback_days: int = 1,
        max_results: int = 10000,
    ) -> List[Dict[str, Any]]:
        """Fetch CVEs modified in the last N days (bulk refresh).

        Args:
            lookback_days: Number of days to look back.
            max_results: Maximum total CVEs to fetch.

        Returns:
            List of parsed CVE dicts.
        """
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=lookback_days)

        params = {
            "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "lastModEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": NVD_RESULTS_PER_PAGE,
            "startIndex": 0,
        }

        all_cves: List[Dict[str, Any]] = []

        while len(all_cves) < max_results:
            self._rate_limit_check()

            try:
                resp = self._session.get(NVD_API_BASE, params=params, timeout=60)

                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After", "30"))
                    logger.warning("NVD 429 during bulk fetch, sleeping %ds", retry_after)
                    time.sleep(retry_after)
                    continue

                resp.raise_for_status()
                data = resp.json()

            except requests.RequestException as exc:
                logger.error("NVD bulk fetch error: %s", exc)
                break

            vulns = data.get("vulnerabilities", [])
            for vuln in vulns:
                parsed = self._parse_cve(vuln.get("cve", {}))
                if parsed:
                    all_cves.append(parsed)

            total_results = data.get("totalResults", 0)
            fetched = params["startIndex"] + len(vulns)

            if fetched >= total_results or not vulns:
                break

            params["startIndex"] = fetched

        logger.info("NVD bulk fetch: %d CVEs retrieved (lookback=%dd)", len(all_cves), lookback_days)
        return all_cves

    def _parse_cve(self, cve: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse a single NVD CVE object into our normalized format.

        Returns:
            Dict with cve_id, cvss_v3_score, severity, description, etc.
        """
        cve_id = cve.get("id", "")
        if not cve_id:
            return None

        # Extract CVSS v3.1 metrics
        metrics = cve.get("metrics", {})
        cvss_v31 = metrics.get("cvssMetricV31", [])
        cvss_v30 = metrics.get("cvssMetricV30", [])
        cvss_data = {}

        for source in (cvss_v31, cvss_v30):
            if source:
                primary = next(
                    (m for m in source if m.get("type") == "Primary"),
                    source[0],
                )
                cd = primary.get("cvssData", {})
                cvss_data = {
                    "score": cd.get("baseScore", 0.0),
                    "vector": cd.get("vectorString", ""),
                    "severity": cd.get("baseSeverity", "UNKNOWN"),
                }
                break

        # Extract description (English)
        descriptions = cve.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # Extract affected CPE
        affected_cpe: List[str] = []
        configurations = cve.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable"):
                        affected_cpe.append(match.get("criteria", ""))

        # Extract references for fix versions
        fix_versions: List[str] = []
        references = cve.get("references", [])
        for ref in references:
            tags = ref.get("tags", [])
            if "Patch" in tags or "Vendor Advisory" in tags:
                fix_versions.append(ref.get("url", ""))

        return {
            "cve_id": cve_id,
            "cvss_v3_score": cvss_data.get("score", 0.0),
            "cvss_v3_vector": cvss_data.get("vector", ""),
            "severity": cvss_data.get("severity", "UNKNOWN"),
            "description": description[:2000],  # Truncate long descriptions
            "affected_cpe": affected_cpe,
            "fix_references": fix_versions,
            "published": cve.get("published", ""),
            "last_modified": cve.get("lastModified", ""),
        }

    async def store_cves(self, cves: List[Dict[str, Any]]) -> int:
        """Store parsed CVEs into vuln_cache table.

        Args:
            cves: List of parsed CVE dicts.

        Returns:
            Number of rows upserted.
        """
        if not cves:
            return 0

        sql = """
            INSERT INTO vuln_cache (
                cve_id, source, cvss_v3_score, cvss_v3_vector,
                severity, description, affected_cpe, fix_versions,
                raw_json, refreshed_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9::jsonb, NOW())
            ON CONFLICT (cve_id)
            DO UPDATE SET
                cvss_v3_score = EXCLUDED.cvss_v3_score,
                cvss_v3_vector = EXCLUDED.cvss_v3_vector,
                severity = EXCLUDED.severity,
                description = EXCLUDED.description,
                affected_cpe = EXCLUDED.affected_cpe,
                fix_versions = EXCLUDED.fix_versions,
                raw_json = EXCLUDED.raw_json,
                refreshed_at = NOW()
        """

        stored = 0
        async with self._pool.acquire() as conn:
            for cve in cves:
                try:
                    await conn.execute(
                        sql,
                        cve["cve_id"],
                        "nvd",
                        cve["cvss_v3_score"],
                        cve["cvss_v3_vector"],
                        cve["severity"],
                        cve["description"],
                        json.dumps(cve["affected_cpe"]),
                        json.dumps(cve["fix_references"]),
                        json.dumps(cve),
                    )
                    stored += 1
                except Exception as exc:
                    logger.error("Failed to store CVE %s: %s", cve["cve_id"], exc)

        logger.info("Stored %d/%d CVEs in vuln_cache", stored, len(cves))
        return stored

    async def refresh(self, lookback_days: int = 1) -> Dict[str, Any]:
        """Full refresh: fetch recent CVEs and store them.

        Args:
            lookback_days: Days to look back for modified CVEs.

        Returns:
            Dict with cves_fetched, cves_stored.
        """
        cves = await asyncio.get_event_loop().run_in_executor(
            None, self.fetch_recent_cves, lookback_days
        )
        stored = await self.store_cves(cves)
        return {"cves_fetched": len(cves), "cves_stored": stored}

    async def lookup_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Look up a single CVE (cache-first, then NVD API).

        Args:
            cve_id: CVE identifier.

        Returns:
            CVE dict or None.
        """
        # Check cache first
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM vuln_cache WHERE cve_id = $1", cve_id
            )
            if row:
                return dict(row)

        # Fetch from NVD
        cve = await asyncio.get_event_loop().run_in_executor(
            None, self.fetch_cve, cve_id
        )
        if cve:
            await self.store_cves([cve])
        return cve
