"""
KEV Adapter — Task 0.3.8 [Seq 32 | BD]

Fetches the CISA Known Exploited Vulnerabilities (KEV) catalog and marks
matching CVEs in vuln_cache as actively exploited.

Process: Download JSON daily → parse KEV entries → UPDATE vuln_cache
         SET is_kev=true, kev_due_date WHERE cve_id matches.

Dependencies:
  - Task 0.3.6 (CVEs must exist in vuln_cache)
  - Task 0.3.1 (vuln_cache table)
"""

import asyncio
import logging
from datetime import date, datetime, timezone
from typing import Any, Dict, List, Optional

import asyncpg
import requests

logger = logging.getLogger("external_collector.adapters.kev")

KEV_JSON_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


class KEVAdapter:
    """Fetches CISA KEV catalog and marks CVEs in vuln_cache.

    Args:
        pool: asyncpg connection pool for threat_engine_external.
    """

    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool
        self._session = requests.Session()

    def fetch_kev_catalog(self) -> List[Dict[str, Any]]:
        """Download the full KEV catalog from CISA.

        Returns:
            List of KEV entries with cveID, dateAdded, dueDate, etc.
        """
        try:
            resp = self._session.get(KEV_JSON_URL, timeout=60)
            resp.raise_for_status()
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            logger.info("Fetched %d KEV entries from CISA", len(vulns))
            return vulns
        except requests.RequestException as exc:
            logger.error("KEV catalog fetch error: %s", exc)
            return []

    def parse_kev_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a single KEV entry into our format.

        Args:
            entry: Raw KEV JSON entry.

        Returns:
            Dict with cve_id, date_added, due_date, ransomware_use, vendor, product.
        """
        due_date_str = entry.get("dueDate", "")
        date_added_str = entry.get("dateAdded", "")

        due_date = None
        if due_date_str:
            try:
                due_date = datetime.strptime(due_date_str, "%Y-%m-%d").date()
            except ValueError:
                pass

        date_added = None
        if date_added_str:
            try:
                date_added = datetime.strptime(date_added_str, "%Y-%m-%d").date()
            except ValueError:
                pass

        return {
            "cve_id": entry.get("cveID", ""),
            "vendor": entry.get("vendorProject", ""),
            "product": entry.get("product", ""),
            "vulnerability_name": entry.get("vulnerabilityName", ""),
            "date_added": date_added,
            "due_date": due_date,
            "ransomware_use": entry.get("knownRansomwareCampaignUse", "Unknown"),
            "short_description": entry.get("shortDescription", ""),
            "required_action": entry.get("requiredAction", ""),
        }

    async def update_vuln_cache(
        self, kev_entries: List[Dict[str, Any]]
    ) -> Dict[str, int]:
        """Mark KEV CVEs in vuln_cache.

        Args:
            kev_entries: Parsed KEV entries.

        Returns:
            Dict with marked and skipped counts.
        """
        marked = 0
        skipped = 0

        sql = """
            UPDATE vuln_cache SET
                is_kev = TRUE,
                kev_due_date = $1,
                refreshed_at = NOW()
            WHERE cve_id = $2
        """

        async with self._pool.acquire() as conn:
            for entry in kev_entries:
                if not entry["cve_id"]:
                    skipped += 1
                    continue

                try:
                    result = await conn.execute(
                        sql,
                        entry["due_date"],
                        entry["cve_id"],
                    )
                    if result == "UPDATE 1":
                        marked += 1
                    else:
                        skipped += 1
                except Exception as exc:
                    logger.error(
                        "Failed to mark KEV for %s: %s",
                        entry["cve_id"], exc,
                    )
                    skipped += 1

        logger.info("KEV update: %d marked, %d skipped", marked, skipped)
        return {"marked": marked, "skipped": skipped}

    async def refresh(self) -> Dict[str, Any]:
        """Full refresh: fetch KEV catalog and update vuln_cache.

        Returns:
            Dict with kev_fetched, marked, skipped.
        """
        raw_entries = await asyncio.get_event_loop().run_in_executor(
            None, self.fetch_kev_catalog
        )
        parsed = [self.parse_kev_entry(e) for e in raw_entries]
        result = await self.update_vuln_cache(parsed)
        return {"kev_fetched": len(parsed), **result}
