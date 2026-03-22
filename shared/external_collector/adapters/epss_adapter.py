"""
EPSS Adapter — Task 0.3.7 [Seq 31 | BD]

Fetches EPSS (Exploit Prediction Scoring System) scores from FIRST.org
and updates vuln_cache rows with exploitation probability scores.

DEDUPLICATION NOTE:
  If the existing vulnerability engine (vuln_db) already stores EPSS data,
  this adapter should be configured to read from vuln_db first, falling back
  to the FIRST.org API only for CVEs not yet enriched. The vuln_cache in
  threat_engine_external is a lightweight cache for the new engines.

Process: Download CSV daily → parse (cve_id, epss_score, percentile) →
         UPDATE vuln_cache SET epss_score WHERE cve_id matches.

Dependencies:
  - Task 0.3.6 (CVEs must exist in vuln_cache)
  - Task 0.3.1 (vuln_cache table)
"""

import asyncio
import csv
import io
import logging
from typing import Any, Dict, List, Optional, Tuple

import asyncpg
import requests

logger = logging.getLogger("external_collector.adapters.epss")

EPSS_API_URL = "https://api.first.org/data/v1/epss"
EPSS_CSV_URL = "https://api.first.org/data/v1/epss?envelope=true&pretty=true"

# Batch size for DB updates
BATCH_SIZE = 500


class EPSSAdapter:
    """Fetches EPSS scores and enriches vuln_cache.

    Args:
        pool: asyncpg connection pool for threat_engine_external.
    """

    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool
        self._session = requests.Session()

    def fetch_epss_scores(
        self, cve_ids: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """Fetch EPSS scores from FIRST.org API.

        Args:
            cve_ids: Optional list of CVE IDs to query. If None, fetches all.

        Returns:
            List of {cve_id, epss_score, percentile} dicts.
        """
        scores: List[Dict[str, Any]] = []

        if cve_ids:
            # Query specific CVEs in batches
            for i in range(0, len(cve_ids), 100):
                batch = cve_ids[i:i + 100]
                params = {"cve": ",".join(batch)}
                try:
                    resp = self._session.get(EPSS_API_URL, params=params, timeout=30)
                    resp.raise_for_status()
                    data = resp.json()
                    for entry in data.get("data", []):
                        scores.append({
                            "cve_id": entry.get("cve", ""),
                            "epss_score": float(entry.get("epss", 0)),
                            "percentile": float(entry.get("percentile", 0)),
                        })
                except requests.RequestException as exc:
                    logger.error("EPSS API error: %s", exc)
        else:
            # Fetch full dataset (all CVEs with EPSS scores)
            try:
                resp = self._session.get(
                    EPSS_API_URL,
                    params={"envelope": "true", "limit": 100000},
                    timeout=120,
                )
                resp.raise_for_status()
                data = resp.json()
                for entry in data.get("data", []):
                    scores.append({
                        "cve_id": entry.get("cve", ""),
                        "epss_score": float(entry.get("epss", 0)),
                        "percentile": float(entry.get("percentile", 0)),
                    })
            except requests.RequestException as exc:
                logger.error("EPSS full dataset fetch error: %s", exc)

        logger.info("Fetched %d EPSS scores", len(scores))
        return scores

    async def update_vuln_cache(
        self, scores: List[Dict[str, Any]]
    ) -> Dict[str, int]:
        """Update vuln_cache with EPSS scores.

        Args:
            scores: List of {cve_id, epss_score, percentile} dicts.

        Returns:
            Dict with updated and skipped counts.
        """
        updated = 0
        skipped = 0

        sql = """
            UPDATE vuln_cache SET
                epss_score = $1,
                epss_percentile = $2,
                refreshed_at = NOW()
            WHERE cve_id = $3
        """

        async with self._pool.acquire() as conn:
            for i in range(0, len(scores), BATCH_SIZE):
                batch = scores[i:i + BATCH_SIZE]
                for entry in batch:
                    try:
                        result = await conn.execute(
                            sql,
                            entry["epss_score"],
                            entry["percentile"],
                            entry["cve_id"],
                        )
                        if result == "UPDATE 1":
                            updated += 1
                        else:
                            skipped += 1
                    except Exception as exc:
                        logger.error(
                            "Failed to update EPSS for %s: %s",
                            entry["cve_id"], exc,
                        )
                        skipped += 1

        logger.info("EPSS update: %d updated, %d skipped", updated, skipped)
        return {"updated": updated, "skipped": skipped}

    async def refresh(self) -> Dict[str, Any]:
        """Full refresh: fetch all EPSS scores and update vuln_cache.

        Returns:
            Dict with scores_fetched, updated, skipped.
        """
        # Only fetch EPSS for CVEs we have in cache
        async with self._pool.acquire() as conn:
            rows = await conn.fetch("SELECT cve_id FROM vuln_cache")

        cve_ids = [row["cve_id"] for row in rows]
        if not cve_ids:
            return {"scores_fetched": 0, "updated": 0, "skipped": 0}

        scores = await asyncio.get_event_loop().run_in_executor(
            None, self.fetch_epss_scores, cve_ids
        )
        result = await self.update_vuln_cache(scores)
        return {"scores_fetched": len(scores), **result}
