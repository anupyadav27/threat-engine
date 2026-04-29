"""
NTIA Minimum Elements Validator — Feature 3

Validates an SBOM against the NTIA (National Telecommunications and
Information Administration) minimum required elements, as defined in:
  "The Minimum Elements For a Software Bill of Materials (SBOM)"
  Published: July 12, 2021
  https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials

Also checks compliance with US Executive Order 14028 (May 2021)
which mandates SBOMs for software sold to the US federal government.

The 7 NTIA minimum elements:
  1. Supplier Name          — who made the component
  2. Component Name         — what is it called
  3. Version                — which version is installed
  4. Unique Identifier      — purl, CPE, or hash
  5. Dependency Relationship — what depends on what
  6. Author of SBOM Data    — who created the SBOM document
  7. Timestamp              — when was the SBOM created

Scoring:
  Elements 1–4: scored per-component (% of components that satisfy)
  Elements 5–7: document-level binary (present / missing)
  Overall score: weighted average (0–100)

Compliance thresholds:
  0–40%:   Non-compliant  (not acceptable for federal contracts)
  41–70%:  Partial        (needs remediation before submission)
  71–100%: Compliant      (meets NTIA minimum requirements)
"""

from typing import Dict, List, Optional, Any


# ── Weights for each element ──────────────────────────────────────────────────
# Component-level elements (1–4) are weighted more heavily because they
# are what actually enable vulnerability tracking and supply-chain analysis.

ELEMENT_WEIGHTS = {
    "supplier_name":       0.10,
    "component_name":      0.20,
    "version":             0.20,
    "unique_identifier":   0.20,
    "dependency_rel":      0.10,
    "sbom_author":         0.10,
    "timestamp":           0.10,
}

COMPLIANCE_THRESHOLDS = {
    "compliant":    71,
    "partial":      41,
    "non_compliant": 0,
}


# ── CycloneDX element extractors ─────────────────────────────────────────────

def _cdx_has_supplier(comp: Dict) -> bool:
    return bool(
        comp.get("supplier") or
        comp.get("author") or
        comp.get("publisher") or
        (comp.get("supplier") and comp["supplier"].get("name"))
    )


def _cdx_has_unique_id(comp: Dict) -> bool:
    return bool(
        comp.get("purl") or
        comp.get("cpe") or
        comp.get("hashes")
    )


def _cdx_has_dependency_rel(raw: Dict) -> bool:
    deps = raw.get("dependencies", [])
    return isinstance(deps, list) and len(deps) > 0


def _cdx_has_author(raw: Dict) -> bool:
    meta = raw.get("metadata", {})
    return bool(
        meta.get("authors") or
        meta.get("tools") or
        meta.get("supplier")
    )


def _cdx_has_timestamp(raw: Dict) -> bool:
    return bool(raw.get("metadata", {}).get("timestamp"))


# ── SPDX element extractors ──────────────────────────────────────────────────

def _spdx_has_supplier(pkg: Dict) -> bool:
    return bool(pkg.get("supplier") or pkg.get("originator"))


def _spdx_has_unique_id(pkg: Dict) -> bool:
    refs = pkg.get("externalRefs", [])
    for r in refs:
        rtype = r.get("referenceType", "").lower()
        if rtype in ("purl", "cpe23type", "cpe22type"):
            return True
    return bool(pkg.get("checksums"))


def _spdx_has_dependency_rel(raw: Dict) -> bool:
    rels = raw.get("relationships", [])
    return isinstance(rels, list) and len(rels) > 0


def _spdx_has_author(raw: Dict) -> bool:
    creators = raw.get("creationInfo", {}).get("creators", [])
    return bool(creators)


def _spdx_has_timestamp(raw: Dict) -> bool:
    return bool(raw.get("creationInfo", {}).get("created"))


# ── Per-component scoring ─────────────────────────────────────────────────────

def _score_component(comp: Dict, fmt: str) -> Dict:
    """
    Score a single component against the 4 component-level NTIA elements.
    Returns {element: True/False}.
    """
    if fmt == "CycloneDX":
        return {
            "supplier_name":     _cdx_has_supplier(comp),
            "component_name":    bool(comp.get("name")),
            "version":           bool(comp.get("version")),
            "unique_identifier": _cdx_has_unique_id(comp),
        }
    else:  # SPDX
        return {
            "supplier_name":     _spdx_has_supplier(comp),
            "component_name":    bool(comp.get("name")),
            "version":           bool(comp.get("versionInfo") or comp.get("version")),
            "unique_identifier": _spdx_has_unique_id(comp),
        }


# ── Main validator ────────────────────────────────────────────────────────────

def validate_ntia(raw_payload: Dict, parsed_components: List[Dict]) -> Dict:
    """
    Validate an SBOM against NTIA minimum elements.

    raw_payload:        the original SBOM JSON (CycloneDX or SPDX)
    parsed_components:  component list from sbom_parser (normalised dicts)

    Returns a detailed compliance report.
    """
    # Detect format
    if raw_payload.get("bomFormat") == "CycloneDX" or raw_payload.get("specVersion"):
        fmt = "CycloneDX"
        raw_components = raw_payload.get("components", [])
        has_dep_rel  = _cdx_has_dependency_rel(raw_payload)
        has_author   = _cdx_has_author(raw_payload)
        has_timestamp = _cdx_has_timestamp(raw_payload)
    else:
        fmt = "SPDX"
        raw_components = raw_payload.get("packages", [])
        has_dep_rel  = _spdx_has_dependency_rel(raw_payload)
        has_author   = _spdx_has_author(raw_payload)
        has_timestamp = _spdx_has_timestamp(raw_payload)

    # Score per-component elements
    total = len(raw_components)
    if total == 0:
        total = 1  # avoid div/0

    counts = {
        "supplier_name":     0,
        "component_name":    0,
        "version":           0,
        "unique_identifier": 0,
    }
    missing_details: Dict[str, List] = {
        "no_supplier":    [],
        "no_version":     [],
        "no_unique_id":   [],
    }

    for comp in raw_components:
        scores = _score_component(comp, fmt)
        for k in counts:
            if scores[k]:
                counts[k] += 1
        name = comp.get("name", "unknown")
        ver  = comp.get("version") or comp.get("versionInfo", "")
        label = f"{name}@{ver}" if ver else name

        if not scores["supplier_name"]:
            missing_details["no_supplier"].append(label)
        if not scores["version"]:
            missing_details["no_version"].append(label)
        if not scores["unique_identifier"]:
            missing_details["no_unique_id"].append(label)

    pct = {k: round(v / total * 100, 1) for k, v in counts.items()}

    # Build element results
    elements = [
        _elem_result(
            "1. Supplier Name",
            "supplier_name",
            pct["supplier_name"],
            component_level=True,
            description="Name of entity that creates or distributes the component",
            missing_count=total - counts["supplier_name"],
        ),
        _elem_result(
            "2. Component Name",
            "component_name",
            pct["component_name"],
            component_level=True,
            description="Designation assigned to a unit of software by its originator",
        ),
        _elem_result(
            "3. Version",
            "version",
            pct["version"],
            component_level=True,
            description="Identifier used by the supplier to specify a change in software",
            missing_count=total - counts["version"],
        ),
        _elem_result(
            "4. Unique Identifier",
            "unique_identifier",
            pct["unique_identifier"],
            component_level=True,
            description="Other unique identifiers used to identify a component (purl, CPE, hash)",
            missing_count=total - counts["unique_identifier"],
        ),
        _elem_result(
            "5. Dependency Relationships",
            "dependency_rel",
            100.0 if has_dep_rel else 0.0,
            component_level=False,
            description="Characterises the relationship between upstream and downstream components",
        ),
        _elem_result(
            "6. Author of SBOM Data",
            "sbom_author",
            100.0 if has_author else 0.0,
            component_level=False,
            description="Name of entity that creates the SBOM data (tool or person)",
        ),
        _elem_result(
            "7. Timestamp",
            "timestamp",
            100.0 if has_timestamp else 0.0,
            component_level=False,
            description="Record of date and time of SBOM data assembly",
        ),
    ]

    # Weighted overall score
    scores_by_key = {e["key"]: e["score_pct"] for e in elements}
    overall = round(
        sum(scores_by_key[k] * w for k, w in ELEMENT_WEIGHTS.items()),
        1,
    )

    status = _compliance_status(overall)

    return {
        "overall_score":     overall,
        "compliance_status": status,
        "format":            fmt,
        "total_components":  len(raw_components),
        "elements":          elements,
        "missing_details": {
            "components_without_supplier":   missing_details["no_supplier"][:20],
            "components_without_version":    missing_details["no_version"][:20],
            "components_without_unique_id":  missing_details["no_unique_id"][:20],
        },
        "recommendations":   _build_recommendations(elements, overall),
        "standard_reference": "NTIA Minimum Elements for SBOM (July 2021) + US EO 14028",
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _elem_result(
    name: str,
    key: str,
    score_pct: float,
    component_level: bool,
    description: str,
    missing_count: int = 0,
) -> Dict:
    if score_pct >= 90:
        status = "pass"
    elif score_pct >= 50:
        status = "partial"
    else:
        status = "fail"

    r = {
        "element":         name,
        "key":             key,
        "status":          status,
        "score_pct":       score_pct,
        "component_level": component_level,
        "description":     description,
    }
    if component_level and missing_count:
        r["missing_count"] = missing_count
    return r


def _compliance_status(score: float) -> str:
    if score >= COMPLIANCE_THRESHOLDS["compliant"]:
        return "compliant"
    if score >= COMPLIANCE_THRESHOLDS["partial"]:
        return "partial"
    return "non_compliant"


def _build_recommendations(elements: List[Dict], overall: float) -> List[str]:
    recs = []
    for e in elements:
        if e["status"] == "fail":
            if e["key"] == "supplier_name":
                recs.append(
                    "Add supplier/author field to components — required for supply-chain traceability"
                )
            elif e["key"] == "version":
                recs.append(
                    "Ensure all components include a version — required for vulnerability matching"
                )
            elif e["key"] == "unique_identifier":
                recs.append(
                    "Add purl (Package URL) to all components — enables precise vulnerability lookup"
                )
            elif e["key"] == "dependency_rel":
                recs.append(
                    "Include a dependencies[] section — required to map the full component graph"
                )
            elif e["key"] == "sbom_author":
                recs.append(
                    "Add metadata.tools or metadata.authors — identifies who/what created this SBOM"
                )
            elif e["key"] == "timestamp":
                recs.append(
                    "Add metadata.timestamp — NTIA requires a creation date/time"
                )
        elif e["status"] == "partial":
            if e["key"] == "supplier_name":
                recs.append(
                    f"Improve supplier coverage — only {e['score_pct']:.0f}% of components have a supplier"
                )
            elif e["key"] == "unique_identifier":
                recs.append(
                    f"Improve purl coverage — only {e['score_pct']:.0f}% of components have a unique identifier"
                )

    if overall < COMPLIANCE_THRESHOLDS["compliant"]:
        recs.append(
            f"Overall score {overall:.0f}% is below the 71% threshold required for "
            "US federal contract compliance (EO 14028)"
        )

    return recs
