"""
Threat Intel Adapter — Task 0.3.10 [Seq 34 | BD]

Fetches threat intelligence indicators (malicious IPs, domains, file hashes)
from AbuseIPDB and OTX (AlienVault) feeds. Results are stored in
threat_intel_ioc table for use by engine_network and engine_threat.

Sources:
  - AbuseIPDB: REST API → confidence score, threat types
  - OTX (AlienVault): REST API /api/v1/pulses/subscribed → IOC feeds

Dependencies:
  - Task 0.3.2 (credential_manager for API keys)
  - Task 0.3.1 (threat_intel_ioc table)
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import asyncpg
import requests

logger = logging.getLogger("external_collector.adapters.threat_intel")

ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2"
OTX_API_URL = "https://otx.alienvault.com/api/v1"


class AbuseIPDBAdapter:
    """Fetches IP reputation data from AbuseIPDB.

    Rate limit: 4000 requests/24h (free tier).

    Args:
        api_key: AbuseIPDB API key.
    """

    def __init__(self, api_key: str) -> None:
        self._session = requests.Session()
        self._session.headers.update({
            "Key": api_key,
            "Accept": "application/json",
        })

    def check_ip(self, ip: str, max_age_days: int = 90) -> Optional[Dict[str, Any]]:
        """Check an IP address against AbuseIPDB.

        Args:
            ip: IP address to check.
            max_age_days: Max age of reports to consider.

        Returns:
            IOC dict or None if not malicious.
        """
        try:
            resp = self._session.get(
                f"{ABUSEIPDB_API_URL}/check",
                params={"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": ""},
                timeout=15,
            )
            if resp.status_code == 429:
                logger.warning("AbuseIPDB rate limited")
                return None
            resp.raise_for_status()
            data = resp.json().get("data", {})

            confidence = data.get("abuseConfidenceScore", 0)
            if confidence < 10:
                return None  # Not considered malicious

            categories = data.get("reports", [])
            threat_types = set()
            for report in categories[:50]:
                for cat_id in report.get("categories", []):
                    threat_types.add(_ABUSEIPDB_CATEGORIES.get(cat_id, "unknown"))

            return {
                "indicator_type": "ipv4",
                "indicator_value": ip,
                "source": "abuseipdb",
                "confidence": confidence,
                "threat_type": ", ".join(sorted(threat_types)) if threat_types else "malicious",
                "first_seen": data.get("lastReportedAt", ""),
                "last_seen": data.get("lastReportedAt", ""),
                "metadata": {
                    "country_code": data.get("countryCode", ""),
                    "isp": data.get("isp", ""),
                    "domain": data.get("domain", ""),
                    "total_reports": data.get("totalReports", 0),
                    "is_tor": data.get("isTor", False),
                },
            }
        except requests.RequestException as exc:
            logger.error("AbuseIPDB check error for %s: %s", ip, exc)
            return None

    def get_blacklist(self, confidence_minimum: int = 90, limit: int = 10000) -> List[Dict[str, Any]]:
        """Fetch the AbuseIPDB blacklist (high-confidence malicious IPs).

        Args:
            confidence_minimum: Minimum abuse confidence score.
            limit: Max IPs to retrieve.

        Returns:
            List of IOC dicts.
        """
        try:
            resp = self._session.get(
                f"{ABUSEIPDB_API_URL}/blacklist",
                params={"confidenceMinimum": confidence_minimum, "limit": limit},
                timeout=60,
            )
            resp.raise_for_status()
            data = resp.json().get("data", [])

            iocs: List[Dict[str, Any]] = []
            for entry in data:
                iocs.append({
                    "indicator_type": "ipv4",
                    "indicator_value": entry.get("ipAddress", ""),
                    "source": "abuseipdb",
                    "confidence": entry.get("abuseConfidenceScore", 0),
                    "threat_type": "malicious",
                    "first_seen": entry.get("lastReportedAt", ""),
                    "last_seen": entry.get("lastReportedAt", ""),
                    "metadata": {
                        "country_code": entry.get("countryCode", ""),
                    },
                })

            logger.info("AbuseIPDB blacklist: %d IPs fetched", len(iocs))
            return iocs

        except requests.RequestException as exc:
            logger.error("AbuseIPDB blacklist error: %s", exc)
            return []


class OTXAdapter:
    """Fetches IOC feeds from AlienVault OTX.

    Args:
        api_key: OTX API key.
    """

    def __init__(self, api_key: str) -> None:
        self._session = requests.Session()
        self._session.headers.update({"X-OTX-API-KEY": api_key})

    def get_subscribed_pulses(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Fetch subscribed OTX pulses (threat feeds).

        Args:
            limit: Max pulses to fetch.

        Returns:
            List of pulse dicts with IOCs.
        """
        try:
            resp = self._session.get(
                f"{OTX_API_URL}/pulses/subscribed",
                params={"limit": limit, "modified_since": ""},
                timeout=60,
            )
            resp.raise_for_status()
            return resp.json().get("results", [])
        except requests.RequestException as exc:
            logger.error("OTX pulse fetch error: %s", exc)
            return []

    def extract_iocs_from_pulses(self, pulses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract IOCs from OTX pulses.

        Args:
            pulses: List of OTX pulse dicts.

        Returns:
            List of normalized IOC dicts.
        """
        iocs: List[Dict[str, Any]] = []

        type_map = {
            "IPv4": "ipv4",
            "IPv6": "ipv6",
            "domain": "domain",
            "hostname": "domain",
            "URL": "url",
            "FileHash-MD5": "hash_md5",
            "FileHash-SHA1": "hash_sha1",
            "FileHash-SHA256": "hash_sha256",
            "email": "email",
        }

        for pulse in pulses:
            pulse_name = pulse.get("name", "")
            pulse_tags = pulse.get("tags", [])
            threat_type = ", ".join(pulse_tags[:5]) if pulse_tags else "unknown"

            for indicator in pulse.get("indicators", []):
                ioc_type = type_map.get(indicator.get("type", ""), "")
                if not ioc_type:
                    continue

                iocs.append({
                    "indicator_type": ioc_type,
                    "indicator_value": indicator.get("indicator", ""),
                    "source": "otx",
                    "confidence": 70,  # OTX doesn't provide per-indicator confidence
                    "threat_type": threat_type,
                    "first_seen": indicator.get("created", ""),
                    "last_seen": indicator.get("created", ""),
                    "metadata": {
                        "pulse_name": pulse_name,
                        "pulse_id": pulse.get("id", ""),
                        "title": indicator.get("title", ""),
                    },
                })

        logger.info("Extracted %d IOCs from %d OTX pulses", len(iocs), len(pulses))
        return iocs

    def fetch_all_iocs(self, pulse_limit: int = 50) -> List[Dict[str, Any]]:
        """Fetch and extract all IOCs from subscribed pulses.

        Returns:
            List of normalized IOC dicts.
        """
        pulses = self.get_subscribed_pulses(limit=pulse_limit)
        return self.extract_iocs_from_pulses(pulses)


class ThreatIntelCollector:
    """Orchestrates threat intel collection from all sources.

    Args:
        pool: asyncpg connection pool for threat_engine_external.
        abuseipdb: Optional AbuseIPDBAdapter.
        otx: Optional OTXAdapter.
    """

    def __init__(
        self,
        pool: asyncpg.Pool,
        abuseipdb: Optional[AbuseIPDBAdapter] = None,
        otx: Optional[OTXAdapter] = None,
    ) -> None:
        self._pool = pool
        self._abuseipdb = abuseipdb
        self._otx = otx

    async def refresh(self) -> Dict[str, Any]:
        """Full refresh: collect IOCs from all sources and store.

        Returns:
            Dict with per-source counts.
        """
        total_stored = 0
        results: Dict[str, Any] = {}

        # AbuseIPDB blacklist
        if self._abuseipdb:
            iocs = await asyncio.get_event_loop().run_in_executor(
                None, self._abuseipdb.get_blacklist, 90, 10000
            )
            stored = await self._store_iocs(iocs)
            results["abuseipdb"] = {"fetched": len(iocs), "stored": stored}
            total_stored += stored

        # OTX feeds
        if self._otx:
            iocs = await asyncio.get_event_loop().run_in_executor(
                None, self._otx.fetch_all_iocs, 50
            )
            stored = await self._store_iocs(iocs)
            results["otx"] = {"fetched": len(iocs), "stored": stored}
            total_stored += stored

        results["total_stored"] = total_stored
        return results

    async def check_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Check an IP against cached IOCs, then AbuseIPDB.

        Args:
            ip: IP address to check.

        Returns:
            IOC dict or None.
        """
        # Cache lookup first
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM threat_intel_ioc WHERE indicator_value = $1 AND is_active = TRUE",
                ip,
            )
            if row:
                return dict(row)

        # Live check via AbuseIPDB
        if self._abuseipdb:
            result = await asyncio.get_event_loop().run_in_executor(
                None, self._abuseipdb.check_ip, ip
            )
            if result:
                await self._store_iocs([result])
            return result

        return None

    async def _store_iocs(self, iocs: List[Dict[str, Any]]) -> int:
        """Store IOCs in threat_intel_ioc table.

        Args:
            iocs: List of IOC dicts.

        Returns:
            Number of rows stored.
        """
        if not iocs:
            return 0

        sql = """
            INSERT INTO threat_intel_ioc (
                indicator_type, indicator_value, source, confidence,
                threat_type, first_seen, last_seen, metadata, refreshed_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, NOW())
            ON CONFLICT (indicator_type, indicator_value, source)
            DO UPDATE SET
                confidence = EXCLUDED.confidence,
                threat_type = EXCLUDED.threat_type,
                last_seen = EXCLUDED.last_seen,
                metadata = EXCLUDED.metadata,
                refreshed_at = NOW()
        """
        stored = 0
        async with self._pool.acquire() as conn:
            for ioc in iocs:
                try:
                    await conn.execute(
                        sql,
                        ioc["indicator_type"],
                        ioc["indicator_value"],
                        ioc["source"],
                        ioc.get("confidence", 0),
                        ioc.get("threat_type", "unknown"),
                        ioc.get("first_seen", ""),
                        ioc.get("last_seen", ""),
                        json.dumps(ioc.get("metadata", {})),
                    )
                    stored += 1
                except Exception as exc:
                    logger.error(
                        "Failed to store IOC %s: %s",
                        ioc.get("indicator_value", "?"), exc,
                    )

        return stored


# AbuseIPDB category mapping
_ABUSEIPDB_CATEGORIES = {
    1: "dns_compromise",
    2: "dns_poisoning",
    3: "fraud_orders",
    4: "ddos_attack",
    5: "ftp_brute_force",
    6: "ping_of_death",
    7: "phishing",
    8: "fraud_voip",
    9: "open_proxy",
    10: "web_spam",
    11: "email_spam",
    12: "blog_spam",
    13: "vpn_ip",
    14: "port_scan",
    15: "hacking",
    16: "sql_injection",
    17: "spoofing",
    18: "brute_force",
    19: "bad_web_bot",
    20: "exploited_host",
    21: "web_app_attack",
    22: "ssh",
    23: "iot_targeted",
}
