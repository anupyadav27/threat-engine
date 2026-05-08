"""
Threat Intelligence Provider — Feature 1

Enriches CVEs with two authoritative, free, real-time data sources:

  CISA KEV (Known Exploited Vulnerabilities)
    URL: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
    Meaning: US government list of CVEs being actively exploited in the wild RIGHT NOW.
             If a CVE is here, real attackers are using it against real systems today.
    Update:  Refreshed daily. ~1,000 entries.

  EPSS (Exploit Prediction Scoring System) by FIRST.org
    URL: https://api.first.org/data/v1/epss?cve=CVE-xxxx,CVE-yyyy
    Meaning: Machine-learning model predicting the probability (0–100%) that a CVE
             will be exploited in the next 30 days. Covers all 200,000+ published CVEs.
    Update:  Daily. Free, no authentication required.

Both are cached in the sbom_threat_intel table.
Cache TTL: 24 hours. If API unreachable, stale cache is used gracefully.
"""

import asyncio
import aiohttp
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

CISA_KEV_URL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL  = "https://api.first.org/data/v1/epss"
EPSS_BATCH    = 100     # max CVEs per EPSS request
CACHE_TTL_HRS = 24      # hours before cache entry is considered stale


class ThreatIntelProvider:
    """
    Provides EPSS scores and CISA KEV membership for CVE IDs.
    Uses DB as a cache. Falls back to stale cache if API is unreachable.
    Designed for graceful degradation — system works without internet access,
    just without enhanced threat context.
    """

    def __init__(self, db_manager):
        self.db = db_manager
        self._session: Optional[aiohttp.ClientSession] = None
        self._kev_last_refresh: Optional[datetime] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
            )
        return self._session

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    # ── Public interface ─────────────────────────────────────────────────────

    async def get_intel(self, cve_id: str) -> Dict:
        """
        Return threat intel dict for one CVE.
        Checks DB cache first; fetches from API if stale or missing.
        Always returns a dict (empty fields if unavailable).
        """
        if not cve_id or not cve_id.upper().startswith("CVE-"):
            return _empty_intel()

        cached = await self._get_cached(cve_id)
        if cached and not _is_stale(cached.get("last_updated")):
            return cached

        # Try to fetch fresh data
        fresh = await self._fetch_epss_single(cve_id)
        if fresh:
            await self._save_intel(cve_id, fresh)
            return fresh

        # Return stale cache rather than nothing
        return cached or _empty_intel()

    async def get_intel_batch(self, cve_ids: List[str]) -> Dict[str, Dict]:
        """
        Bulk-fetch threat intel for a list of CVE IDs.
        Returns {cve_id: intel_dict}.
        Minimises API calls by batching and skipping fresh cache entries.
        """
        if not cve_ids:
            return {}

        valid = [c for c in cve_ids if c and c.upper().startswith("CVE-")]
        if not valid:
            return {}

        # Load all from cache
        cached_all = await self._get_cached_batch(valid)
        result = {}
        needs_fetch = []

        for cve in valid:
            c = cached_all.get(cve)
            if c and not _is_stale(c.get("last_updated")):
                result[cve] = c
            else:
                needs_fetch.append(cve)
                if c:
                    result[cve] = c  # use stale while we refresh

        if needs_fetch:
            fresh_data = await self._fetch_epss_batch(needs_fetch)
            for cve, intel in fresh_data.items():
                result[cve] = intel
            if fresh_data:
                await self._save_intel_batch(fresh_data)

        return result

    async def refresh_kev_catalog(self) -> int:
        """
        Download the full CISA KEV catalog and update the cache.
        Returns number of KEV entries saved.
        Safe to call repeatedly — uses upsert.
        """
        logger.info("Refreshing CISA KEV catalog...")
        try:
            session = await self._get_session()
            async with session.get(CISA_KEV_URL) as resp:
                if resp.status != 200:
                    logger.warning(f"CISA KEV returned HTTP {resp.status}")
                    return 0
                data = await resp.json(content_type=None)

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                logger.warning("CISA KEV response contained no vulnerabilities")
                return 0

            rows = []
            for v in vulns:
                cve_id = v.get("cveID", "").upper()
                if not cve_id.startswith("CVE-"):
                    continue
                rows.append({
                    "cve_id":             cve_id,
                    "in_cisa_kev":        True,
                    "kev_date_added":     v.get("dateAdded"),
                    "kev_due_date":       v.get("dueDate"),
                    "kev_ransomware_use": v.get("knownRansomwareCampaignUse"),
                    "kev_vendor":         v.get("vendorProject"),
                    "kev_product":        v.get("product"),
                    "kev_required_action": v.get("requiredAction"),
                })

            await self._save_kev_batch(rows)
            self._kev_last_refresh = datetime.now(timezone.utc)
            logger.info(f"CISA KEV catalog refreshed: {len(rows)} entries")
            return len(rows)

        except asyncio.TimeoutError:
            logger.warning("CISA KEV fetch timed out — using cached data")
            return 0
        except Exception as e:
            logger.error(f"CISA KEV refresh failed: {e}")
            return 0

    # ── EPSS API ─────────────────────────────────────────────────────────────

    async def _fetch_epss_single(self, cve_id: str) -> Optional[Dict]:
        results = await self._fetch_epss_batch([cve_id])
        return results.get(cve_id)

    async def _fetch_epss_batch(self, cve_ids: List[str]) -> Dict[str, Dict]:
        results = {}
        # Process in batches of EPSS_BATCH
        for i in range(0, len(cve_ids), EPSS_BATCH):
            chunk = cve_ids[i:i + EPSS_BATCH]
            batch_result = await self._fetch_epss_chunk(chunk)
            results.update(batch_result)
        return results

    async def _fetch_epss_chunk(self, cve_ids: List[str]) -> Dict[str, Dict]:
        try:
            session = await self._get_session()
            params = {"cve": ",".join(cve_ids)}
            async with session.get(EPSS_API_URL, params=params) as resp:
                if resp.status != 200:
                    logger.warning(f"EPSS API returned HTTP {resp.status}")
                    return {}
                data = await resp.json()

            results = {}
            for entry in data.get("data", []):
                cve = entry.get("cve", "").upper()
                if cve:
                    results[cve] = {
                        "cve_id":         cve,
                        "epss_score":     float(entry.get("epss", 0)),
                        "epss_percentile": float(entry.get("percentile", 0)),
                        "in_cisa_kev":    False,  # filled by KEV catalog
                    }
            return results
        except asyncio.TimeoutError:
            logger.warning("EPSS API timed out")
            return {}
        except Exception as e:
            logger.error(f"EPSS fetch failed: {e}")
            return {}

    # ── DB cache helpers ─────────────────────────────────────────────────────

    async def _get_cached(self, cve_id: str) -> Optional[Dict]:
        try:
            async with self.db.pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT * FROM sbom_threat_intel WHERE cve_id = $1",
                    cve_id.upper(),
                )
            return dict(row) if row else None
        except Exception as e:
            logger.debug(f"Threat intel cache read failed for {cve_id}: {e}")
            return None

    async def _get_cached_batch(self, cve_ids: List[str]) -> Dict[str, Dict]:
        try:
            upper_ids = [c.upper() for c in cve_ids]
            async with self.db.pool.acquire() as conn:
                rows = await conn.fetch(
                    "SELECT * FROM sbom_threat_intel WHERE cve_id = ANY($1::varchar[])",
                    upper_ids,
                )
            return {dict(r)["cve_id"]: dict(r) for r in rows}
        except Exception as e:
            logger.debug(f"Threat intel batch cache read failed: {e}")
            return {}

    async def _save_intel(self, cve_id: str, intel: Dict):
        await self._save_intel_batch({cve_id: intel})

    async def _save_intel_batch(self, intel_map: Dict[str, Dict]):
        if not intel_map:
            return
        try:
            rows = [
                (
                    cve_id.upper(),
                    intel.get("epss_score"),
                    intel.get("epss_percentile"),
                    intel.get("in_cisa_kev", False),
                    intel.get("kev_date_added"),
                    intel.get("kev_due_date"),
                    intel.get("kev_ransomware_use"),
                    intel.get("kev_vendor"),
                    intel.get("kev_product"),
                    intel.get("kev_required_action"),
                )
                for cve_id, intel in intel_map.items()
            ]
            async with self.db.pool.acquire() as conn:
                await conn.executemany("""
                    INSERT INTO sbom_threat_intel (
                        cve_id, epss_score, epss_percentile,
                        in_cisa_kev, kev_date_added, kev_due_date,
                        kev_ransomware_use, kev_vendor, kev_product,
                        kev_required_action, last_updated
                    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10, NOW())
                    ON CONFLICT (cve_id) DO UPDATE SET
                        epss_score          = COALESCE(EXCLUDED.epss_score, sbom_threat_intel.epss_score),
                        epss_percentile     = COALESCE(EXCLUDED.epss_percentile, sbom_threat_intel.epss_percentile),
                        in_cisa_kev         = CASE WHEN EXCLUDED.in_cisa_kev THEN TRUE
                                                   ELSE sbom_threat_intel.in_cisa_kev END,
                        kev_date_added      = COALESCE(EXCLUDED.kev_date_added, sbom_threat_intel.kev_date_added),
                        kev_due_date        = COALESCE(EXCLUDED.kev_due_date, sbom_threat_intel.kev_due_date),
                        kev_ransomware_use  = COALESCE(EXCLUDED.kev_ransomware_use, sbom_threat_intel.kev_ransomware_use),
                        kev_vendor          = COALESCE(EXCLUDED.kev_vendor, sbom_threat_intel.kev_vendor),
                        kev_product         = COALESCE(EXCLUDED.kev_product, sbom_threat_intel.kev_product),
                        kev_required_action = COALESCE(EXCLUDED.kev_required_action, sbom_threat_intel.kev_required_action),
                        last_updated        = NOW()
                """, rows)
        except Exception as e:
            logger.error(f"Threat intel cache save failed: {e}")

    async def _save_kev_batch(self, rows: List[Dict]):
        if not rows:
            return
        try:
            data = [
                (
                    r["cve_id"],
                    True,
                    r.get("kev_date_added"),
                    r.get("kev_due_date"),
                    r.get("kev_ransomware_use"),
                    r.get("kev_vendor"),
                    r.get("kev_product"),
                    r.get("kev_required_action"),
                )
                for r in rows
            ]
            async with self.db.pool.acquire() as conn:
                await conn.executemany("""
                    INSERT INTO sbom_threat_intel (
                        cve_id, in_cisa_kev,
                        kev_date_added, kev_due_date, kev_ransomware_use,
                        kev_vendor, kev_product, kev_required_action,
                        last_updated
                    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8, NOW())
                    ON CONFLICT (cve_id) DO UPDATE SET
                        in_cisa_kev         = TRUE,
                        kev_date_added      = EXCLUDED.kev_date_added,
                        kev_due_date        = EXCLUDED.kev_due_date,
                        kev_ransomware_use  = EXCLUDED.kev_ransomware_use,
                        kev_vendor          = EXCLUDED.kev_vendor,
                        kev_product         = EXCLUDED.kev_product,
                        kev_required_action = EXCLUDED.kev_required_action,
                        last_updated        = NOW()
                """, data)
        except Exception as e:
            logger.error(f"KEV batch save failed: {e}")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _empty_intel() -> Dict:
    return {
        "cve_id":             None,
        "epss_score":         None,
        "epss_percentile":    None,
        "in_cisa_kev":        False,
        "kev_date_added":     None,
        "kev_due_date":       None,
        "kev_ransomware_use": None,
        "kev_vendor":         None,
        "kev_product":        None,
        "kev_required_action": None,
    }


def _is_stale(last_updated) -> bool:
    if last_updated is None:
        return True
    if isinstance(last_updated, str):
        try:
            last_updated = datetime.fromisoformat(last_updated)
        except Exception:
            return True
    if last_updated.tzinfo is None:
        last_updated = last_updated.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - last_updated > timedelta(hours=CACHE_TTL_HRS)
