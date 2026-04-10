"""
License Checker for SBOM Engine.

Classifies SPDX license IDs into categories:
  - permissive: MIT, Apache-2.0, BSD, ISC, ...
  - weak_copyleft: LGPL, MPL, EPL, CDDL, ...
  - strong_copyleft: GPL-2.0, GPL-3.0, AGPL, ...
  - proprietary / unknown

Provides per-component license analysis and SBOM-level license summary.
"""

import re
import logging
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# ── License classification ────────────────────────────────────────────────────

PERMISSIVE: Set[str] = {
    "MIT", "Apache-2.0", "Apache-1.0", "Apache-1.1",
    "BSD-2-Clause", "BSD-3-Clause", "BSD-4-Clause",
    "ISC", "0BSD", "Zlib", "Unlicense", "CC0-1.0",
    "Python-2.0", "PSF-2.0", "Artistic-1.0", "Artistic-2.0",
    "BSL-1.0", "MS-PL", "MS-RL",
    "X11", "WTFPL", "NCSA",
}

WEAK_COPYLEFT: Set[str] = {
    "LGPL-2.0", "LGPL-2.0-only", "LGPL-2.0-or-later",
    "LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later",
    "LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later",
    "MPL-1.0", "MPL-1.1", "MPL-2.0",
    "EPL-1.0", "EPL-2.0",
    "CDDL-1.0", "CDDL-1.1",
    "EUPL-1.0", "EUPL-1.1", "EUPL-1.2",
    "CECILL-C",
    "OSL-1.0", "OSL-1.1", "OSL-2.0", "OSL-2.1", "OSL-3.0",
    "Nokia",
}

STRONG_COPYLEFT: Set[str] = {
    "GPL-1.0", "GPL-1.0-only", "GPL-1.0-or-later",
    "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later",
    "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later",
    "AGPL-1.0", "AGPL-1.0-only", "AGPL-1.0-or-later",
    "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
    "SSPL-1.0",
    "BUSL-1.1",
    "EUPL-1.2",
    "CC-BY-SA-4.0", "CC-BY-NC-4.0", "CC-BY-NC-SA-4.0",
    "CECILL-1.0", "CECILL-1.1", "CECILL-2.0", "CECILL-2.1",
}

PROPRIETARY_KEYWORDS = {"commercial", "proprietary", "all rights reserved"}


def classify_license(spdx_id: str) -> str:
    """
    Classify a single SPDX license ID.
    Returns: permissive | weak_copyleft | strong_copyleft | proprietary | unknown
    """
    if not spdx_id:
        return "unknown"

    clean = spdx_id.strip()

    # Direct match
    if clean in PERMISSIVE:
        return "permissive"
    if clean in WEAK_COPYLEFT:
        return "weak_copyleft"
    if clean in STRONG_COPYLEFT:
        return "strong_copyleft"

    lower = clean.lower()

    # Keyword heuristics
    if any(kw in lower for kw in PROPRIETARY_KEYWORDS):
        return "proprietary"
    if "agpl" in lower or "sspl" in lower:
        return "strong_copyleft"
    if re.search(r'\bgpl\b', lower) and "lgpl" not in lower:
        return "strong_copyleft"
    if "lgpl" in lower or "mpl" in lower or "epl" in lower or "cddl" in lower:
        return "weak_copyleft"
    if any(kw in lower for kw in ("mit", "apache", "bsd", "isc", "unlicense", "cc0")):
        return "permissive"

    return "unknown"


def classify_component_licenses(licenses: List[str]) -> Dict:
    """
    Return classification summary for a component's license list.
    {
      "licenses": [...],
      "categories": ["permissive", ...],
      "highest_risk": "strong_copyleft" | ...,
      "is_copyleft": bool,
      "is_strong_copyleft": bool,
      "flags": ["GPL detected", ...]
    }
    """
    if not licenses:
        return {
            "licenses":         [],
            "categories":       ["unknown"],
            "highest_risk":     "unknown",
            "is_copyleft":      False,
            "is_strong_copyleft": False,
            "flags":            ["no license declared"],
        }

    categories = [classify_license(lic) for lic in licenses]
    flags = []

    _rank = {
        "strong_copyleft": 4,
        "weak_copyleft":   3,
        "proprietary":     4,
        "unknown":         1,
        "permissive":      0,
    }
    highest = max(categories, key=lambda c: _rank.get(c, 0))

    is_strong = "strong_copyleft" in categories
    is_copyleft = is_strong or "weak_copyleft" in categories

    if is_strong:
        flags.append("strong copyleft — review before distribution")
    elif "weak_copyleft" in categories:
        flags.append("weak copyleft — dynamic linking may require disclosure")
    if "proprietary" in categories:
        flags.append("proprietary license — verify usage rights")
    if "unknown" in categories:
        flags.append("unrecognised license — manual review recommended")

    return {
        "licenses":           licenses,
        "categories":         list(set(categories)),
        "highest_risk":       highest,
        "is_copyleft":        is_copyleft,
        "is_strong_copyleft": is_strong,
        "flags":              flags,
    }


# ── SBOM-level license summary ────────────────────────────────────────────────

def analyse_sbom_licenses(components: List[Dict]) -> Dict:
    """
    Produce a license summary for an entire SBOM's component list.
    Returns summary dict with counts, risk breakdown, and flagged components.
    """
    total = len(components)
    no_license = 0
    by_category: Dict[str, int] = {}
    license_freq: Dict[str, int] = {}
    flagged: List[Dict] = []

    for comp in components:
        licenses = comp.get("licenses") or []
        if not licenses:
            no_license += 1

        analysis = classify_component_licenses(licenses)
        cat = analysis["highest_risk"]
        by_category[cat] = by_category.get(cat, 0) + 1

        for lic in licenses:
            license_freq[lic] = license_freq.get(lic, 0) + 1

        if analysis["flags"]:
            flagged.append({
                "name":    comp.get("name"),
                "version": comp.get("version"),
                "purl":    comp.get("purl"),
                "licenses": licenses,
                "flags":   analysis["flags"],
                "risk":    cat,
            })

    # Top 20 most common licenses
    top_licenses = sorted(license_freq.items(), key=lambda x: -x[1])[:20]

    return {
        "total_components":     total,
        "components_no_license": no_license,
        "by_category":          by_category,
        "top_licenses":         [{"license": k, "count": v} for k, v in top_licenses],
        "flagged_components":   flagged,
        "strong_copyleft_count": by_category.get("strong_copyleft", 0),
        "weak_copyleft_count":   by_category.get("weak_copyleft", 0),
        "permissive_count":      by_category.get("permissive", 0),
        "unknown_count":         by_category.get("unknown", 0),
    }
