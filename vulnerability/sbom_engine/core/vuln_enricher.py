"""
Vulnerability Enricher for SBOM Engine.

For each SBOM component:
  1. Extract ecosystem + package name from purl (or direct fields)
  2. Query osv_advisory table (read-only)
  3. For rows with missing severity/CVSS, fall back to cves table (NVD)
  4. Apply VEX suppression: skip advisories where status = 'not_affected'
  5. Return enrichment results per component

Version range matching mirrors osv_engine/core/scanner.py logic
but is self-contained so osv_engine stays untouched.
"""

import json
import logging
from typing import Dict, List, Optional, Any, Tuple

logger = logging.getLogger(__name__)

try:
    from packaging.version import Version, InvalidVersion
    _HAS_PACKAGING = True
except ImportError:
    _HAS_PACKAGING = False


# ── Ecosystem aliases ────────────────────────────────────────────────────────

_PURL_TYPE_TO_ECOSYSTEM = {
    "pypi":     "PyPI",
    "npm":      "npm",
    "golang":   "Go",
    "maven":    "Maven",
    "gem":      "RubyGems",
    "nuget":    "NuGet",
    "cargo":    "crates.io",
    "composer": "Packagist",
    "hex":      "Hex",
    "pub":      "Pub",
}

_MANAGER_TO_ECOSYSTEM = {
    "pip": "PyPI", "pip3": "PyPI", "pypi": "PyPI",
    "npm": "npm", "yarn": "npm", "pnpm": "npm",
    "go": "Go", "golang": "Go",
    "maven": "Maven", "gradle": "Maven",
    "gem": "RubyGems", "bundler": "RubyGems",
    "nuget": "NuGet", "dotnet": "NuGet",
    "cargo": "crates.io",
    "composer": "Packagist",
    "hex": "Hex", "mix": "Hex",
    "pub": "Pub", "dart": "Pub",
}


def _resolve_ecosystem(component: Dict) -> Tuple[str, str]:
    """
    Return (lookup_name, ecosystem) for a component dict.
    Uses purl first, then explicit ecosystem field, then infers from manager.
    """
    from core.sbom_parser import parse_purl

    purl = component.get("purl", "")
    ecosystem = component.get("ecosystem", "")
    name = component.get("name", "")

    if purl:
        parsed = parse_purl(purl)
        if parsed:
            eco = parsed.get("ecosystem") or ecosystem
            pkg_name = parsed.get("full_name") or parsed.get("name") or name
            return pkg_name, eco

    if not ecosystem and component.get("manager"):
        ecosystem = _MANAGER_TO_ECOSYSTEM.get(
            component["manager"].lower(), ""
        )

    return name, ecosystem


# ── Version range matching ────────────────────────────────────────────────────

def _parse_ver(v: str):
    if not v:
        return None
    if _HAS_PACKAGING:
        try:
            return Version(v)
        except InvalidVersion:
            pass
    # Fallback: tuple of ints
    try:
        return tuple(int(x) for x in v.split(".") if x.isdigit())
    except Exception:
        return None


def _ver_lt(a, b) -> bool:
    try:
        return a < b
    except Exception:
        return False


def _ver_lte(a, b) -> bool:
    try:
        return a <= b
    except Exception:
        return False


def is_version_affected(version_str: str, affected_ranges_raw) -> bool:
    """
    Check if version_str falls within any affected range from osv_advisory.
    affected_ranges_raw may be a JSON string or already a list.
    """
    if not version_str:
        return False

    if isinstance(affected_ranges_raw, str):
        try:
            ranges = json.loads(affected_ranges_raw)
        except Exception:
            return False
    elif isinstance(affected_ranges_raw, list):
        ranges = affected_ranges_raw
    else:
        return False

    current = _parse_ver(version_str)
    if current is None:
        return False

    for rng in ranges:
        rtype = str(rng.get("type", "")).upper()
        if rtype == "GIT":
            continue

        events = rng.get("events", [])
        introduced = None
        fixed = None
        last_affected = None

        for ev in events:
            if "introduced" in ev:
                v = ev["introduced"]
                if v and v != "0":
                    introduced = _parse_ver(v)
                else:
                    introduced = _parse_ver("0.0.0")
            if "fixed" in ev:
                fixed = _parse_ver(ev["fixed"])
            if "last_affected" in ev:
                last_affected = _parse_ver(ev["last_affected"])

        if introduced is None:
            continue

        try:
            if not _ver_lte(introduced, current):
                continue
            if fixed is not None and not _ver_lt(current, fixed):
                continue
            if last_affected is not None and not _ver_lte(current, last_affected):
                continue
            return True
        except Exception:
            continue

    return False


# ── Main enricher ─────────────────────────────────────────────────────────────

class VulnEnricher:
    """
    Enriches SBOM components with vulnerability data.
    Uses db_manager to query osv_advisory + cves tables.
    Optionally enriches with EPSS + CISA KEV via ThreatIntelProvider
    and calculates composite risk scores via risk_scorer.
    """

    def __init__(self, db_manager, threat_intel=None):
        self.db = db_manager
        self.threat_intel = threat_intel  # ThreatIntelProvider, optional

    async def enrich_components(
        self,
        components: List[Dict],
        vex_index: Optional[Dict] = None,
    ) -> List[Dict]:
        """
        Enrich each component with vulnerability findings.
        vex_index: {(vuln_id, purl): "not_affected"|...} for VEX suppression.
        Returns same list with added keys: is_vulnerable, vulnerability_ids, vulnerabilities.
        When ThreatIntelProvider is available, each vulnerability also gets:
          epss_score, epss_percentile, in_cisa_kev, composite_risk, priority, sla.
        """
        from core.risk_scorer import enrich_vuln_with_risk
        vex_index = vex_index or {}

        for comp in components:
            comp.setdefault("is_vulnerable", False)
            comp.setdefault("vulnerability_ids", [])
            comp.setdefault("vulnerabilities", [])

            pkg_name, ecosystem = _resolve_ecosystem(comp)
            if not pkg_name or not ecosystem:
                continue

            version = comp.get("version")

            try:
                advisories = await self.db.query_osv_advisory(pkg_name, ecosystem)
            except Exception as e:
                logger.warning(f"osv_advisory query failed for {pkg_name}/{ecosystem}: {e}")
                continue

            for adv in advisories:
                advisory_id = adv.get("advisory_id", "")
                ranges_raw = adv.get("affected_ranges")
                affected_versions = adv.get("affected_versions") or []

                # Version match
                if version:
                    in_range = is_version_affected(version, ranges_raw)
                    in_versions = version in affected_versions
                    if not in_range and not in_versions:
                        continue

                # VEX suppression
                purl = comp.get("purl", "")
                cve_aliases = adv.get("cve_aliases") or []
                cve_id = cve_aliases[0] if cve_aliases else None

                suppressed = False
                for check_id in ([advisory_id] + list(cve_aliases)):
                    if vex_index.get((check_id, purl)) == "not_affected":
                        suppressed = True
                        break
                if suppressed:
                    continue

                severity  = adv.get("severity")
                cvss_score = adv.get("cvss_score")
                cvss_vector = adv.get("cvss_vector")

                # Enrich from cves table if CVSS missing
                if (not cvss_score or not severity) and cve_id:
                    try:
                        cve_row = await self.db.enrich_from_cves(cve_id)
                        if cve_row:
                            cvss_score  = cvss_score  or cve_row.get("cvss_score")
                            cvss_vector = cvss_vector or cve_row.get("cvss_vector")
                            severity    = severity    or cve_row.get("severity")
                    except Exception as e:
                        logger.debug(f"cves enrichment failed for {cve_id}: {e}")

                vuln = {
                    "advisory_id":  advisory_id,
                    "cve_id":       cve_id,
                    "severity":     severity,
                    "cvss_score":   float(cvss_score) if cvss_score else None,
                    "cvss_vector":  cvss_vector,
                    "description":  adv.get("description"),
                    "fixed_version": adv.get("fixed_version"),
                    "source":       adv.get("source", "osv"),
                    "published_at": str(adv["published_at"]) if adv.get("published_at") else None,
                    "modified_at":  str(adv["modified_at"])  if adv.get("modified_at")  else None,
                }

                # ── Threat intel + composite risk score (Feature 1 + 5) ──────
                if self.threat_intel and cve_id:
                    try:
                        intel = await self.threat_intel.get_intel(cve_id)
                        vuln = enrich_vuln_with_risk(vuln, intel)
                    except Exception as e:
                        logger.debug(f"Threat intel enrichment failed for {cve_id}: {e}")
                else:
                    # Still calculate composite risk without threat intel
                    vuln = enrich_vuln_with_risk(vuln, {})

                comp["vulnerabilities"].append(vuln)
                vuln_ids = [advisory_id]
                if cve_id:
                    vuln_ids.append(cve_id)
                for vid in vuln_ids:
                    if vid not in comp["vulnerability_ids"]:
                        comp["vulnerability_ids"].append(vid)

            if comp["vulnerabilities"]:
                comp["is_vulnerable"] = True

        return components

    async def build_vex_index(self, sbom_id: str) -> Dict:
        """
        Build a VEX suppression index for a given SBOM.
        Returns {(vulnerability_id, component_purl): status}
        """
        try:
            stmts = await self.db.get_vex_statements(sbom_id=sbom_id)
            return {
                (s["vulnerability_id"], s.get("component_purl", "")): s["status"]
                for s in stmts
            }
        except Exception:
            return {}
