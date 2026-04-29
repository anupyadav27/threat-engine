"""
Background CVE Watch — Feature 2

Runs continuously (default: every 24 hours) and re-checks every stored
SBOM component against the latest vulnerability database.

When a new CVE is published that matches a package already stored in any
SBOM, this monitor catches it without waiting for the next manual scan.

Algorithm (designed for efficiency):
  1. Get distinct (pkg_name, version, ecosystem) from sbom_components
     → deduplicates: 1000 SBOMs with the same package = 1 lookup
  2. For each unique package, query osv_advisory for current vulnerabilities
  3. For each sbom_component row, compare current vulns vs stored vulnerability_ids
  4. New CVEs found → create sbom_alert + update component
  5. Refresh CISA KEV + EPSS for all newly-found CVEs
  6. Create high-priority KEV alerts for active exploitation

Alert types:
  new_vulnerability  — CVE found that wasn't there on last scan
  kev_match          — existing or new vulnerability is in the CISA KEV catalog
  epss_spike         — EPSS score ≥ 0.50 (50% exploitation probability)
  high_risk          — composite risk score ≥ 8.0
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

from core.threat_intel import ThreatIntelProvider
from core.risk_scorer import calculate_composite_risk
from core.vuln_enricher import is_version_affected

logger = logging.getLogger(__name__)

# How often the monitor runs (configurable via env var, default 24h)
import os
MONITOR_INTERVAL_HOURS = int(os.getenv("MONITOR_INTERVAL_HOURS", 24))
MONITOR_STARTUP_DELAY  = int(os.getenv("MONITOR_STARTUP_DELAY_MINUTES", 5))


class BackgroundMonitor:

    def __init__(self, db_manager, threat_intel: ThreatIntelProvider):
        self.db = db_manager
        self.threat_intel = threat_intel
        self._running = False
        self._last_run: Optional[datetime] = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def start(self):
        """Start the background monitoring loop as an asyncio task."""
        logger.info(
            f"Background monitor scheduled — "
            f"first run in {MONITOR_STARTUP_DELAY} minutes, "
            f"then every {MONITOR_INTERVAL_HOURS} hours"
        )
        asyncio.create_task(self._loop())

    async def _loop(self):
        # Short delay on startup so the service is fully initialised
        await asyncio.sleep(MONITOR_STARTUP_DELAY * 60)
        while True:
            try:
                await self.run_scan()
            except Exception as e:
                logger.error(f"Background monitor error: {e}", exc_info=True)
            await asyncio.sleep(MONITOR_INTERVAL_HOURS * 3600)

    # ── Manual trigger ────────────────────────────────────────────────────────

    async def run_scan(self) -> Dict:
        """
        Execute one full monitoring cycle.
        Can be triggered manually via the API as well as by the loop.
        """
        if self._running:
            logger.warning("Background monitor already running — skipping")
            return {"status": "skipped", "reason": "already_running"}

        self._running = True
        start = datetime.now(timezone.utc)
        logger.info("=" * 60)
        logger.info("BACKGROUND CVE WATCH — SCAN STARTED")
        logger.info("=" * 60)

        stats = {
            "packages_checked":   0,
            "new_vulns_found":    0,
            "kev_alerts":         0,
            "epss_spike_alerts":  0,
            "high_risk_alerts":   0,
            "sboms_updated":      0,
        }

        try:
            # Step 1 — Refresh KEV catalog first (daily)
            kev_count = await self.threat_intel.refresh_kev_catalog()
            logger.info(f"KEV catalog: {kev_count} entries refreshed")

            # Step 2 — Get all distinct packages stored across all SBOMs
            packages = await self._get_distinct_packages()
            logger.info(f"Checking {len(packages)} distinct package/version/ecosystem combos")

            # Step 3 — Re-query osv_advisory for each unique package
            # Build lookup: (pkg_name, ecosystem) → [current advisory rows]
            advisory_lookup = await self._build_advisory_lookup(packages)

            # Step 4 — Get all component rows and compare
            new_alerts = await self._compare_and_alert(packages, advisory_lookup, stats)

            # Step 5 — Enrich new alerts with threat intel + risk score
            if new_alerts:
                await self._enrich_alerts(new_alerts, stats)
                await self._save_alerts(new_alerts)

            self._last_run = datetime.now(timezone.utc)
            duration = (self._last_run - start).total_seconds()

            logger.info(
                f"BACKGROUND SCAN COMPLETE — "
                f"checked={stats['packages_checked']} "
                f"new_vulns={stats['new_vulns_found']} "
                f"kev_alerts={stats['kev_alerts']} "
                f"duration={duration:.1f}s"
            )
            stats["duration_seconds"] = duration
            stats["status"] = "completed"
            return stats

        finally:
            self._running = False

    # ── Step 2: Distinct packages ─────────────────────────────────────────────

    async def _get_distinct_packages(self) -> List[Dict]:
        """
        Returns unique (sbom_id, component_id, name, version, ecosystem, purl,
        vulnerability_ids) rows — one per component, not per SBOM.
        Includes host_id via join with sbom_documents.
        """
        async with self.db.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT
                    sc.id            AS component_id,
                    sc.sbom_id,
                    sc.name,
                    sc.version,
                    sc.ecosystem,
                    sc.purl,
                    sc.vulnerability_ids,
                    sd.host_id
                FROM sbom_components sc
                JOIN sbom_documents  sd ON sd.sbom_id = sc.sbom_id
                WHERE sc.version IS NOT NULL
                  AND sc.ecosystem IS NOT NULL
                ORDER BY sc.name, sc.version
                LIMIT 50000
            """)
        return [dict(r) for r in rows]

    # ── Step 3: Advisory lookup ───────────────────────────────────────────────

    async def _build_advisory_lookup(
        self, packages: List[Dict]
    ) -> Dict[Tuple[str, str], List[Dict]]:
        """
        Build a dict: (lower_name, lower_ecosystem) → [advisory rows]
        Uses a single batched query per distinct (name, ecosystem) pair.
        """
        distinct_pairs: Set[Tuple[str, str]] = {
            (r["name"].lower(), r["ecosystem"].lower())
            for r in packages
            if r.get("name") and r.get("ecosystem")
        }

        lookup: Dict[Tuple[str, str], List[Dict]] = {}

        for name_lower, eco_lower in distinct_pairs:
            try:
                rows = await self.db.query_osv_advisory(name_lower, eco_lower)
                if rows:
                    lookup[(name_lower, eco_lower)] = rows
            except Exception as e:
                logger.debug(f"Advisory lookup failed for {name_lower}/{eco_lower}: {e}")

        return lookup

    # ── Step 4: Compare and generate alerts ───────────────────────────────────

    async def _compare_and_alert(
        self,
        packages: List[Dict],
        advisory_lookup: Dict,
        stats: Dict,
    ) -> List[Dict]:
        """
        For each component row, compare current osv_advisory results against
        stored vulnerability_ids. Generate alert dicts for new findings.
        """
        alerts = []
        sboms_updated: Set[str] = set()

        for comp in packages:
            stats["packages_checked"] += 1
            name    = comp.get("name", "")
            version = comp.get("version")
            eco     = comp.get("ecosystem", "")

            if not name or not eco or not version:
                continue

            key = (name.lower(), eco.lower())
            advisories = advisory_lookup.get(key, [])

            stored_ids: Set[str] = set(comp.get("vulnerability_ids") or [])
            new_vuln_ids: List[str] = []

            for adv in advisories:
                advisory_id = adv.get("advisory_id", "")
                ranges_raw  = adv.get("affected_ranges")
                affected_v  = adv.get("affected_versions") or []

                # Version match
                in_range   = is_version_affected(version, ranges_raw)
                in_versions = version in affected_v
                if not in_range and not in_versions:
                    continue

                cve_aliases = adv.get("cve_aliases") or []
                cve_id = cve_aliases[0] if cve_aliases else None

                # Check if already known
                known = advisory_id in stored_ids or (cve_id and cve_id in stored_ids)
                if not known:
                    new_vuln_ids.append(advisory_id)
                    stats["new_vulns_found"] += 1

                    alerts.append({
                        "sbom_id":          comp["sbom_id"],
                        "host_id":          comp.get("host_id"),
                        "component_id":     comp["component_id"],
                        "component_name":   name,
                        "component_version": version,
                        "component_purl":   comp.get("purl"),
                        "alert_type":       "new_vulnerability",
                        "vulnerability_id": cve_id or advisory_id,
                        "advisory_id":      advisory_id,
                        "cve_id":           cve_id,
                        "severity":         adv.get("severity"),
                        "cvss_score":       float(adv["cvss_score"]) if adv.get("cvss_score") else None,
                        "fixed_version":    adv.get("fixed_version"),
                        "message": (
                            f"New vulnerability {cve_id or advisory_id} found in "
                            f"{name} {version} — "
                            f"{'fix available: ' + adv['fixed_version'] if adv.get('fixed_version') else 'no fix available'}"
                        ),
                    })

            # Update component vulnerability_ids if new ones found
            if new_vuln_ids:
                all_ids = list(stored_ids | set(new_vuln_ids))
                await self._update_component_vulns(comp["component_id"], all_ids)
                sboms_updated.add(comp["sbom_id"])

        # Update vulnerability_count on affected documents
        for sbom_id in sboms_updated:
            await self._update_sbom_vuln_count(sbom_id)
            stats["sboms_updated"] += 1

        return alerts

    # ── Step 5: Enrich alerts ─────────────────────────────────────────────────

    async def _enrich_alerts(self, alerts: List[Dict], stats: Dict):
        """Add EPSS + KEV + composite risk to each alert."""
        cve_ids = list({
            a["cve_id"] for a in alerts if a.get("cve_id")
        })

        intel_map = await self.threat_intel.get_intel_batch(cve_ids)

        for alert in alerts:
            cve_id = alert.get("cve_id")
            intel  = intel_map.get(cve_id, {}) if cve_id else {}

            epss_score  = intel.get("epss_score")
            in_kev      = bool(intel.get("in_cisa_kev", False))

            alert["epss_score"]  = epss_score
            alert["in_cisa_kev"] = in_kev
            alert["kev_date_added"]    = str(intel["kev_date_added"])    if intel.get("kev_date_added")    else None
            alert["kev_ransomware_use"] = intel.get("kev_ransomware_use")

            risk = calculate_composite_risk(
                severity      = alert.get("severity"),
                cvss_score    = alert.get("cvss_score"),
                epss_score    = epss_score,
                in_cisa_kev   = in_kev,
                fixed_version = alert.get("fixed_version"),
            )
            alert["composite_risk"] = risk["composite_risk"]
            alert["priority"]       = risk["priority"]

            # Elevate alert type for critical threats
            if in_kev:
                alert["alert_type"] = "kev_match"
                alert["message"] += (
                    f" ⚠️  IN CISA KEV — actively exploited in the wild"
                    + (f" | ransomware: {intel.get('kev_ransomware_use')}"
                       if intel.get("kev_ransomware_use") == "Known" else "")
                )
                stats["kev_alerts"] += 1
            elif epss_score and epss_score >= 0.50:
                alert["alert_type"] = "epss_spike"
                alert["message"] += f" ⚡ EPSS {epss_score*100:.1f}% — high exploitation probability"
                stats["epss_spike_alerts"] += 1
            elif risk["composite_risk"] >= 8.0:
                alert["alert_type"] = "high_risk"
                alert["message"] += f" 🔴 Composite risk {risk['composite_risk']:.1f}/10"
                stats["high_risk_alerts"] += 1

    # ── Step 6: Save alerts ───────────────────────────────────────────────────

    async def _save_alerts(self, alerts: List[Dict]):
        rows = [
            (
                a["sbom_id"],
                a.get("host_id"),
                a.get("alert_type", "new_vulnerability"),
                a.get("vulnerability_id", ""),
                a.get("component_name"),
                a.get("component_version"),
                a.get("component_purl"),
                a.get("severity"),
                a.get("composite_risk"),
                a.get("epss_score"),
                bool(a.get("in_cisa_kev", False)),
                a.get("message"),
            )
            for a in alerts
        ]
        try:
            async with self.db.pool.acquire() as conn:
                await conn.executemany("""
                    INSERT INTO sbom_alerts (
                        sbom_id, host_id, alert_type, vulnerability_id,
                        component_name, component_version, component_purl,
                        severity, composite_risk, epss_score, in_cisa_kev, message
                    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
                """, rows)
            logger.info(f"Saved {len(rows)} new alerts")
        except Exception as e:
            logger.error(f"Alert save failed: {e}")

    # ── DB helpers ────────────────────────────────────────────────────────────

    async def _update_component_vulns(self, component_id: int, vuln_ids: List[str]):
        try:
            async with self.db.pool.acquire() as conn:
                await conn.execute("""
                    UPDATE sbom_components
                    SET is_vulnerable    = TRUE,
                        vulnerability_ids = $1
                    WHERE id = $2
                """, vuln_ids, component_id)
        except Exception as e:
            logger.error(f"Component update failed id={component_id}: {e}")

    async def _update_sbom_vuln_count(self, sbom_id: str):
        try:
            async with self.db.pool.acquire() as conn:
                await conn.execute("""
                    UPDATE sbom_documents SET
                        vulnerability_count = (
                            SELECT COUNT(*) FROM sbom_components
                            WHERE sbom_id = $1 AND is_vulnerable = TRUE
                        )
                    WHERE sbom_id = $1
                """, sbom_id)
        except Exception as e:
            logger.error(f"SBOM vuln count update failed {sbom_id}: {e}")

    @property
    def status(self) -> Dict:
        return {
            "running":    self._running,
            "last_run":   self._last_run.isoformat() if self._last_run else None,
            "interval_hours": MONITOR_INTERVAL_HOURS,
            "next_run":   _next_run_iso(self._last_run),
        }


def _next_run_iso(last_run: Optional[datetime]) -> Optional[str]:
    if not last_run:
        return None
    from datetime import timedelta
    return (last_run + timedelta(hours=MONITOR_INTERVAL_HOURS)).isoformat()
