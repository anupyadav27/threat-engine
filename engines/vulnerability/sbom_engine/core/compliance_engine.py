"""
Compliance / Policy Engine for SBOM Engine.

Evaluates an SBOM against configurable policy rules and produces
a compliance report with pass/fail/warn per policy.

Built-in policies:
  - NO_CRITICAL_VULNS:      no unmitigated CRITICAL vulnerabilities
  - NO_HIGH_VULNS_UNPATCHED: no HIGH vulns where fixed_version is known
  - NO_STRONG_COPYLEFT:     no GPL/AGPL components (configurable)
  - ALL_COMPONENTS_LICENSED: every component must have a declared license
  - NO_UNKNOWN_LICENSES:    no components with unrecognised licenses
  - MAX_CRITICAL_COUNT:     maximum number of CRITICAL vulns (configurable)

Policies can be extended via the policy_config dict.
"""

import logging
from typing import Dict, List, Optional, Any

from core.license_checker import classify_component_licenses, classify_license

logger = logging.getLogger(__name__)

# ── Policy result constants ──────────────────────────────────────────────────

PASS  = "pass"
FAIL  = "fail"
WARN  = "warn"
SKIP  = "skip"

_SEVERITY_RANK = {
    "critical": 4,
    "high":     3,
    "medium":   2,
    "low":      1,
    "none":     0,
}


def _rank(sev: Optional[str]) -> int:
    return _SEVERITY_RANK.get((sev or "").lower(), 0)


# ── Default policy configuration ─────────────────────────────────────────────

DEFAULT_POLICY: Dict[str, Any] = {
    "NO_CRITICAL_VULNS":       True,   # fail if any CRITICAL vuln
    "NO_HIGH_VULNS_UNPATCHED": True,   # fail if HIGH + fix available
    "NO_STRONG_COPYLEFT":      False,  # warn (not fail) on GPL/AGPL
    "ALL_COMPONENTS_LICENSED": True,   # warn if no license
    "NO_UNKNOWN_LICENSES":     False,  # warn on unknown licenses
    "MAX_CRITICAL_COUNT":      0,      # max allowed CRITICAL vulns (0 = zero tolerance)
    "MAX_HIGH_COUNT":          -1,     # -1 = unlimited
}


# ── Compliance engine ─────────────────────────────────────────────────────────

class ComplianceEngine:

    def __init__(self, policy: Optional[Dict] = None):
        self.policy = {**DEFAULT_POLICY, **(policy or {})}

    def evaluate(
        self,
        components: List[Dict],
        vulnerabilities: List[Dict],
        vex_statements: Optional[List[Dict]] = None,
    ) -> Dict:
        """
        Run all enabled policy checks.

        components:     list of component dicts (from DB or enriched)
        vulnerabilities: flat list of all vulnerability findings
        vex_statements: list of VEX dicts for suppression

        Returns compliance report dict.
        """
        vex_not_affected = set()
        for stmt in (vex_statements or []):
            if stmt.get("status") == "not_affected":
                vex_not_affected.add(
                    (stmt.get("vulnerability_id", ""), stmt.get("component_purl", ""))
                )

        # Filter vulns to only those not suppressed by VEX
        active_vulns = [
            v for v in vulnerabilities
            if not self._is_vex_suppressed(v, vex_not_affected)
        ]

        results = []
        results.append(self._check_no_critical(active_vulns))
        results.append(self._check_no_high_unpatched(active_vulns))
        results.append(self._check_max_critical(active_vulns))
        results.append(self._check_max_high(active_vulns))
        results.append(self._check_strong_copyleft(components))
        results.append(self._check_all_licensed(components))
        results.append(self._check_no_unknown_licenses(components))

        overall = self._overall_status(results)
        severity_summary = self._severity_summary(active_vulns)

        return {
            "overall_status":   overall,
            "policy_results":   results,
            "severity_summary": severity_summary,
            "active_vuln_count": len(active_vulns),
            "suppressed_by_vex": len(vulnerabilities) - len(active_vulns),
            "total_components":  len(components),
        }

    # ── Individual policy checks ─────────────────────────────────────────────

    def _check_no_critical(self, vulns: List[Dict]) -> Dict:
        if not self.policy.get("NO_CRITICAL_VULNS"):
            return self._result("NO_CRITICAL_VULNS", SKIP, "Policy disabled")
        crits = [v for v in vulns if _rank(v.get("severity")) >= 4]
        if crits:
            return self._result(
                "NO_CRITICAL_VULNS", FAIL,
                f"{len(crits)} CRITICAL vulnerabilities found",
                findings=[self._vuln_summary(v) for v in crits[:10]],
            )
        return self._result("NO_CRITICAL_VULNS", PASS, "No CRITICAL vulnerabilities")

    def _check_max_critical(self, vulns: List[Dict]) -> Dict:
        limit = self.policy.get("MAX_CRITICAL_COUNT", 0)
        if limit < 0:
            return self._result("MAX_CRITICAL_COUNT", SKIP, "No limit set")
        crits = [v for v in vulns if _rank(v.get("severity")) >= 4]
        count = len(crits)
        if count > limit:
            return self._result(
                "MAX_CRITICAL_COUNT", FAIL,
                f"{count} CRITICAL vulns exceed allowed maximum of {limit}",
            )
        return self._result(
            "MAX_CRITICAL_COUNT", PASS,
            f"{count}/{limit} CRITICAL vulnerabilities (within limit)",
        )

    def _check_no_high_unpatched(self, vulns: List[Dict]) -> Dict:
        if not self.policy.get("NO_HIGH_VULNS_UNPATCHED"):
            return self._result("NO_HIGH_VULNS_UNPATCHED", SKIP, "Policy disabled")
        unpatched = [
            v for v in vulns
            if _rank(v.get("severity")) == 3 and v.get("fixed_version")
        ]
        if unpatched:
            return self._result(
                "NO_HIGH_VULNS_UNPATCHED", FAIL,
                f"{len(unpatched)} HIGH vulnerabilities with available patch",
                findings=[self._vuln_summary(v) for v in unpatched[:10]],
            )
        return self._result("NO_HIGH_VULNS_UNPATCHED", PASS,
                            "No unpatched HIGH vulnerabilities")

    def _check_max_high(self, vulns: List[Dict]) -> Dict:
        limit = self.policy.get("MAX_HIGH_COUNT", -1)
        if limit < 0:
            return self._result("MAX_HIGH_COUNT", SKIP, "No limit set")
        highs = [v for v in vulns if _rank(v.get("severity")) == 3]
        if len(highs) > limit:
            return self._result(
                "MAX_HIGH_COUNT", FAIL,
                f"{len(highs)} HIGH vulns exceed allowed maximum of {limit}",
            )
        return self._result("MAX_HIGH_COUNT", PASS,
                            f"{len(highs)}/{limit} HIGH vulnerabilities (within limit)")

    def _check_strong_copyleft(self, components: List[Dict]) -> Dict:
        enabled = self.policy.get("NO_STRONG_COPYLEFT", False)
        if not enabled:
            return self._result("NO_STRONG_COPYLEFT", SKIP, "Policy disabled")

        flagged = []
        for comp in components:
            lics = comp.get("licenses") or []
            for lic in lics:
                if classify_license(lic) == "strong_copyleft":
                    flagged.append({
                        "name":    comp.get("name"),
                        "version": comp.get("version"),
                        "license": lic,
                    })
                    break

        if flagged:
            return self._result(
                "NO_STRONG_COPYLEFT", WARN,
                f"{len(flagged)} components with strong-copyleft licenses",
                findings=flagged[:20],
            )
        return self._result("NO_STRONG_COPYLEFT", PASS, "No strong-copyleft licenses")

    def _check_all_licensed(self, components: List[Dict]) -> Dict:
        if not self.policy.get("ALL_COMPONENTS_LICENSED"):
            return self._result("ALL_COMPONENTS_LICENSED", SKIP, "Policy disabled")
        unlicensed = [
            {"name": c.get("name"), "version": c.get("version"), "purl": c.get("purl")}
            for c in components
            if not (c.get("licenses") or c.get("license_expression"))
        ]
        if unlicensed:
            return self._result(
                "ALL_COMPONENTS_LICENSED", WARN,
                f"{len(unlicensed)} components with no declared license",
                findings=unlicensed[:20],
            )
        return self._result("ALL_COMPONENTS_LICENSED", PASS,
                            "All components have declared licenses")

    def _check_no_unknown_licenses(self, components: List[Dict]) -> Dict:
        if not self.policy.get("NO_UNKNOWN_LICENSES"):
            return self._result("NO_UNKNOWN_LICENSES", SKIP, "Policy disabled")
        unknown_comps = []
        for comp in components:
            lics = comp.get("licenses") or []
            if lics and all(classify_license(l) == "unknown" for l in lics):
                unknown_comps.append({
                    "name":     comp.get("name"),
                    "version":  comp.get("version"),
                    "licenses": lics,
                })
        if unknown_comps:
            return self._result(
                "NO_UNKNOWN_LICENSES", WARN,
                f"{len(unknown_comps)} components with unrecognised licenses",
                findings=unknown_comps[:20],
            )
        return self._result("NO_UNKNOWN_LICENSES", PASS,
                            "All licenses are recognisable SPDX identifiers")

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _is_vex_suppressed(self, vuln: Dict, not_affected_set: set) -> bool:
        purl = vuln.get("component_purl") or vuln.get("purl") or ""
        for vid in [vuln.get("advisory_id"), vuln.get("cve_id")]:
            if vid and (vid, purl) in not_affected_set:
                return True
        return False

    @staticmethod
    def _vuln_summary(v: Dict) -> Dict:
        return {
            "advisory_id":  v.get("advisory_id"),
            "cve_id":       v.get("cve_id"),
            "package_name": v.get("package_name") or v.get("name"),
            "version":      v.get("package_version") or v.get("version"),
            "severity":     v.get("severity"),
            "fixed_version": v.get("fixed_version"),
        }

    @staticmethod
    def _result(policy: str, status: str, message: str,
                findings: Optional[List] = None) -> Dict:
        r = {"policy": policy, "status": status, "message": message}
        if findings:
            r["findings"] = findings
        return r

    @staticmethod
    def _overall_status(results: List[Dict]) -> str:
        statuses = {r["status"] for r in results}
        if FAIL in statuses:
            return FAIL
        if WARN in statuses:
            return WARN
        return PASS

    @staticmethod
    def _severity_summary(vulns: List[Dict]) -> Dict:
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
        for v in vulns:
            sev = (v.get("severity") or "unknown").lower()
            if sev in summary:
                summary[sev] += 1
            else:
                summary["unknown"] += 1
        return summary
