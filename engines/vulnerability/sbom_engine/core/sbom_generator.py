"""
SBOM Generator — produces CycloneDX 1.5 JSON documents.

Two modes:
  1. enrich(parsed_sbom, enriched_components)
     → takes an already-parsed SBOM, attaches vulnerability section
  2. generate_from_packages(packages, app_name, host_id)
     → builds a fresh CycloneDX from a raw package list
"""

import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

TOOL_NAME    = "SBOM Engine"
TOOL_VERSION = "1.0.0"
CDX_FORMAT   = "CycloneDX"
CDX_SPEC     = "1.5"

_SEVERITY_MAP = {
    "critical": "critical",
    "high":     "high",
    "medium":   "medium",
    "low":      "low",
    "none":     "none",
}


# ── Component builder ─────────────────────────────────────────────────────────

def _build_cdx_component(comp: Dict) -> Dict:
    c: Dict[str, Any] = {
        "type":    comp.get("component_type", "library"),
        "name":    comp.get("name", ""),
    }

    bom_ref = comp.get("bom_ref") or comp.get("purl") or f"comp-{uuid.uuid4().hex[:8]}"
    c["bom-ref"] = bom_ref

    if comp.get("version"):
        c["version"] = comp["version"]
    if comp.get("purl"):
        c["purl"] = comp["purl"]
    if comp.get("cpe"):
        c["cpe"] = comp["cpe"]
    if comp.get("description"):
        c["description"] = comp["description"]
    if comp.get("author"):
        c["author"] = comp["author"]
    if comp.get("supplier"):
        c["supplier"] = {"name": comp["supplier"]}
    if comp.get("scope"):
        c["scope"] = comp["scope"]

    # Licenses
    licenses = comp.get("licenses") or []
    if licenses:
        c["licenses"] = []
        for lic in licenses:
            # Treat as SPDX ID if it looks like one, otherwise use name
            if _looks_like_spdx(lic):
                c["licenses"].append({"license": {"id": lic}})
            else:
                c["licenses"].append({"license": {"name": lic}})

    # Hashes
    hashes = comp.get("hashes") or []
    if isinstance(hashes, str):
        import json
        try:
            hashes = json.loads(hashes)
        except Exception:
            hashes = []
    if hashes:
        c["hashes"] = [
            {"alg": h.get("alg", "SHA-256"), "content": h.get("content", "")}
            for h in hashes
            if h.get("alg") and h.get("content")
        ]

    return c


def _looks_like_spdx(s: str) -> bool:
    """Heuristic: SPDX IDs use alphanumeric + dash, no spaces."""
    return bool(s) and " " not in s and len(s) < 80


# ── Vulnerability section builder ─────────────────────────────────────────────

def _build_cdx_vulnerability(vuln: Dict, affected_ref: str) -> Dict:
    v: Dict[str, Any] = {
        "bom-ref": f"vuln-{uuid.uuid4().hex[:8]}",
        "id":      vuln.get("cve_id") or vuln.get("advisory_id", "UNKNOWN"),
        "source":  {
            "name": "OSV",
            "url":  "https://osv.dev",
        },
        "affects": [{"ref": affected_ref}],
    }

    if vuln.get("advisory_id") and vuln.get("advisory_id") != v["id"]:
        v["advisories"] = [{"title": vuln["advisory_id"]}]

    # Ratings
    sev = (vuln.get("severity") or "").lower()
    rating: Dict[str, Any] = {
        "severity": _SEVERITY_MAP.get(sev, "unknown"),
        "method":   "CVSSv3",
    }
    if vuln.get("cvss_score") is not None:
        rating["score"] = float(vuln["cvss_score"])
    if vuln.get("cvss_vector"):
        rating["vector"] = vuln["cvss_vector"]
    v["ratings"] = [rating]

    if vuln.get("description"):
        v["description"] = vuln["description"][:2000]

    if vuln.get("fixed_version"):
        v["recommendation"] = f"Upgrade to {vuln['fixed_version']}"

    if vuln.get("published_at"):
        v["published"] = str(vuln["published_at"])
    if vuln.get("modified_at"):
        v["updated"] = str(vuln["modified_at"])

    return v


# ── Enrich: attach vulnerability section to parsed SBOM ──────────────────────

def enrich_cyclonedx(parsed_sbom: Dict, enriched_components: List[Dict]) -> Dict:
    """
    Build a CycloneDX 1.5 document from a parsed SBOM + enriched component list.
    The raw original metadata is preserved; the vulnerabilities section is rebuilt.
    """
    # Preserve original if it was CycloneDX
    if parsed_sbom.get("sbom_format") == "CycloneDX" and parsed_sbom.get("raw"):
        base = dict(parsed_sbom["raw"])
    else:
        base = {}

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    serial = f"urn:uuid:{uuid.uuid4()}"

    doc: Dict[str, Any] = {
        "bomFormat":    CDX_FORMAT,
        "specVersion":  CDX_SPEC,
        "serialNumber": base.get("serialNumber", serial),
        "version":      base.get("version", 1),
        "metadata": {
            "timestamp": now,
            "tools": [{
                "vendor":  "SBOM Engine",
                "name":    TOOL_NAME,
                "version": TOOL_VERSION,
            }],
        },
    }

    # Preserve original metadata component (the application)
    orig_meta = base.get("metadata", {})
    if orig_meta.get("component"):
        doc["metadata"]["component"] = orig_meta["component"]
    elif parsed_sbom.get("application_name"):
        doc["metadata"]["component"] = {
            "type": "application",
            "name": parsed_sbom["application_name"],
        }

    # Rebuild components from enriched list
    doc["components"] = [
        _build_cdx_component(c)
        for c in enriched_components
        if c.get("component_type") != "application"
    ]

    # Build vulnerabilities section
    vulns_section = []
    for comp in enriched_components:
        bom_ref = (
            comp.get("bom_ref") or
            comp.get("purl") or
            f"comp-{comp.get('name', 'unknown')}"
        )
        for vuln in (comp.get("vulnerabilities") or []):
            vulns_section.append(_build_cdx_vulnerability(vuln, bom_ref))

    if vulns_section:
        doc["vulnerabilities"] = vulns_section

    return doc


# ── Generate: build CycloneDX from scratch ────────────────────────────────────

def generate_cyclonedx(
    packages: List[Dict],
    enriched_components: List[Dict],
    app_name: str = "unknown",
    host_id: Optional[str] = None,
    sbom_id: Optional[str] = None,
) -> Dict:
    """
    Build a CycloneDX 1.5 document from a raw package list + enrichment results.
    packages: [{"name":"requests","version":"2.28.0","ecosystem":"PyPI",...}]
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    serial = sbom_id or f"urn:uuid:{uuid.uuid4()}"

    doc: Dict[str, Any] = {
        "bomFormat":    CDX_FORMAT,
        "specVersion":  CDX_SPEC,
        "serialNumber": serial,
        "version":      1,
        "metadata": {
            "timestamp": now,
            "tools": [{
                "vendor":  "SBOM Engine",
                "name":    TOOL_NAME,
                "version": TOOL_VERSION,
            }],
            "component": {
                "type":       "application",
                "bom-ref":    "main-application",
                "name":       app_name,
                **({"properties": [{"name": "host_id", "value": host_id}]}
                   if host_id else {}),
            },
        },
    }

    doc["components"] = [_build_cdx_component(c) for c in enriched_components]

    vulns_section = []
    for comp in enriched_components:
        bom_ref = comp.get("bom_ref") or comp.get("purl") or comp.get("name", "unknown")
        for vuln in (comp.get("vulnerabilities") or []):
            vulns_section.append(_build_cdx_vulnerability(vuln, bom_ref))

    if vulns_section:
        doc["vulnerabilities"] = vulns_section

    return doc
