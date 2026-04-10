"""
SBOM Parser - CycloneDX 1.4/1.5 and SPDX 2.3 JSON

Accepts raw JSON payloads from Syft, Trivy, cdxgen and extracts
a normalised list of components for vulnerability enrichment and storage.
"""

import urllib.parse
import logging
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

# ── PURL type → OSV ecosystem ───────────────────────────────────────────────

PURL_TYPE_TO_ECOSYSTEM: Dict[str, str] = {
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


def parse_purl(purl: str) -> Dict[str, Optional[str]]:
    """
    Parse a Package URL into its components.
    pkg:<type>/<namespace>/<name>@<version>?<qualifiers>#<subpath>
    Returns dict: type, namespace, name, version, full_name, ecosystem
    """
    if not purl or not purl.startswith("pkg:"):
        return {}
    try:
        rest = purl[4:]
        rest = rest.split("?")[0].split("#")[0]
        slash = rest.index("/")
        pkg_type = rest[:slash].lower()
        rest = rest[slash + 1:]

        version = None
        if "@" in rest:
            rest, version = rest.rsplit("@", 1)
            version = urllib.parse.unquote(version)

        parts = rest.split("/")
        name = urllib.parse.unquote(parts[-1])
        namespace = urllib.parse.unquote("/".join(parts[:-1])) if len(parts) > 1 else ""

        # Maven full name: group:artifact
        if pkg_type == "maven" and namespace:
            full_name = f"{namespace}:{name}"
        elif namespace:
            full_name = f"{namespace}/{name}"
        else:
            full_name = name

        ecosystem = PURL_TYPE_TO_ECOSYSTEM.get(pkg_type)

        return {
            "type":      pkg_type,
            "namespace": namespace,
            "name":      name,
            "full_name": full_name,
            "version":   version,
            "ecosystem": ecosystem,
        }
    except Exception as e:
        logger.debug(f"PURL parse error for '{purl}': {e}")
        return {}


# ── Normalised component dict ────────────────────────────────────────────────

def _empty_component() -> Dict:
    return {
        "bom_ref":          None,
        "component_type":   "library",
        "name":             "",
        "version":          None,
        "purl":             None,
        "cpe":              None,
        "ecosystem":        None,
        "licenses":         [],
        "license_expression": None,
        "hashes":           [],
        "supplier":         None,
        "author":           None,
        "description":      None,
        "scope":            None,
    }


# ── CycloneDX parser ─────────────────────────────────────────────────────────

def _extract_cdx_licenses(lic_list: List) -> List[str]:
    ids = []
    for entry in (lic_list or []):
        lic = entry.get("license", {})
        lid = lic.get("id") or lic.get("name") or ""
        if lid:
            ids.append(lid)
        # expression at top level
        expr = entry.get("expression", "")
        if expr:
            ids.append(expr)
    return ids


def _parse_cyclonedx_component(raw: Dict) -> Dict:
    c = _empty_component()
    c["bom_ref"]        = raw.get("bom-ref")
    c["component_type"] = raw.get("type", "library")
    c["name"]           = raw.get("name", "")
    c["version"]        = raw.get("version")
    c["purl"]           = raw.get("purl")
    c["description"]    = raw.get("description")
    c["scope"]          = raw.get("scope")
    c["author"]         = raw.get("author")

    # supplier
    supplier = raw.get("supplier") or raw.get("publisher")
    if isinstance(supplier, dict):
        c["supplier"] = supplier.get("name")
    elif isinstance(supplier, str):
        c["supplier"] = supplier

    # CPE
    for ev in raw.get("externalReferences", []):
        if ev.get("type") == "cpe":
            c["cpe"] = ev.get("url")
    if not c["cpe"]:
        c["cpe"] = raw.get("cpe")

    # licenses
    lic_list = _extract_cdx_licenses(raw.get("licenses", []))
    c["licenses"] = lic_list
    c["license_expression"] = " AND ".join(lic_list) if lic_list else None

    # hashes
    c["hashes"] = [
        {"alg": h.get("alg"), "content": h.get("content")}
        for h in raw.get("hashes", [])
        if h.get("alg") and h.get("content")
    ]

    # ecosystem from purl
    if c["purl"]:
        parsed = parse_purl(c["purl"])
        c["ecosystem"] = parsed.get("ecosystem")
        if not c["name"] and parsed.get("name"):
            c["name"] = parsed.get("full_name") or parsed.get("name")

    return c


def parse_cyclonedx(payload: Dict) -> Dict:
    """
    Parse a CycloneDX 1.4/1.5 JSON document.
    Returns dict with metadata and components list.
    """
    spec_version = str(payload.get("specVersion", "1.5"))
    serial_number = payload.get("serialNumber", "")
    version = int(payload.get("version", 1))

    meta = payload.get("metadata", {})
    meta_comp = meta.get("component", {})
    app_name = meta_comp.get("name") or meta.get("component", {}).get("name") or ""
    timestamp = meta.get("timestamp")

    source_tool = ""
    for t in meta.get("tools", []):
        if isinstance(t, dict):
            source_tool = t.get("name", "") or t.get("vendor", "")
            break
        elif isinstance(t, str):
            source_tool = t
            break

    components = []
    for raw in payload.get("components", []):
        c = _parse_cyclonedx_component(raw)
        if c["name"]:
            components.append(c)

    # Metadata component itself (the application being scanned)
    if meta_comp.get("name"):
        mc = _parse_cyclonedx_component(meta_comp)
        mc["component_type"] = "application"
        if mc["name"]:
            components.insert(0, mc)

    return {
        "sbom_format":    "CycloneDX",
        "spec_version":   spec_version,
        "serial_number":  serial_number,
        "version":        version,
        "application_name": app_name,
        "source":         _normalise_tool_name(source_tool),
        "timestamp":      timestamp,
        "components":     components,
        "raw":            payload,
    }


# ── SPDX 2.3 parser ──────────────────────────────────────────────────────────

def _spdx_purl_from_ext_refs(ext_refs: List[Dict]) -> Optional[str]:
    for ref in (ext_refs or []):
        if ref.get("referenceType") == "purl":
            return ref.get("referenceLocator")
    return None


def _spdx_cpe_from_ext_refs(ext_refs: List[Dict]) -> Optional[str]:
    for ref in (ext_refs or []):
        rtype = ref.get("referenceType", "").lower()
        if rtype in ("cpe23type", "cpe22type"):
            return ref.get("referenceLocator")
    return None


def _spdx_license(lic_str: Optional[str]) -> List[str]:
    if not lic_str or lic_str in ("NOASSERTION", "NONE"):
        return []
    # Split on AND/OR/WITH for multiple licenses
    import re
    parts = re.split(r'\s+(?:AND|OR|WITH)\s+', lic_str)
    return [p.strip() for p in parts if p.strip() and p.strip() not in ("NOASSERTION", "NONE")]


def _parse_spdx_package(pkg: Dict) -> Dict:
    c = _empty_component()
    c["bom_ref"]        = pkg.get("SPDXID")
    c["name"]           = pkg.get("name", "")
    c["version"]        = pkg.get("versionInfo")
    c["description"]    = pkg.get("comment") or pkg.get("summary")
    c["supplier"]       = pkg.get("supplier") or pkg.get("originator")
    c["component_type"] = "library"

    ext_refs = pkg.get("externalRefs", [])
    c["purl"] = _spdx_purl_from_ext_refs(ext_refs)
    c["cpe"]  = _spdx_cpe_from_ext_refs(ext_refs)

    lic_concluded = pkg.get("licenseConcluded", "")
    lic_declared  = pkg.get("licenseDeclared", "")
    chosen = lic_concluded if lic_concluded not in ("NOASSERTION", "NONE", "") else lic_declared
    c["licenses"] = _spdx_license(chosen)
    c["license_expression"] = chosen if chosen not in ("NOASSERTION", "NONE", "") else None

    if c["purl"]:
        parsed = parse_purl(c["purl"])
        c["ecosystem"] = parsed.get("ecosystem")

    return c


def parse_spdx(payload: Dict) -> Dict:
    """
    Parse an SPDX 2.3 JSON document.
    Returns dict with metadata and components list.
    """
    version = payload.get("spdxVersion", "SPDX-2.3").replace("SPDX-", "")
    doc_name = payload.get("name", "")

    creators = payload.get("creationInfo", {}).get("creators", [])
    source_tool = ""
    for c in creators:
        if c.startswith("Tool:"):
            source_tool = c[5:].strip()
            break

    components = []
    for pkg in payload.get("packages", []):
        c = _parse_spdx_package(pkg)
        # Skip the document itself (SPDXID: SPDXRef-DOCUMENT)
        if c["bom_ref"] and c["bom_ref"].upper() == "SPDXREF-DOCUMENT":
            continue
        if c["name"]:
            components.append(c)

    return {
        "sbom_format":    "SPDX",
        "spec_version":   version,
        "serial_number":  payload.get("documentNamespace", ""),
        "version":        1,
        "application_name": doc_name,
        "source":         _normalise_tool_name(source_tool),
        "timestamp":      payload.get("creationInfo", {}).get("created"),
        "components":     components,
        "raw":            payload,
    }


# ── Auto-detect and parse ─────────────────────────────────────────────────────

def detect_and_parse(payload: Dict) -> Dict:
    """
    Auto-detect SBOM format (CycloneDX or SPDX) and parse.
    Raises ValueError if format is unrecognised.
    """
    if payload.get("bomFormat") == "CycloneDX" or payload.get("specVersion"):
        return parse_cyclonedx(payload)
    if "spdxVersion" in payload or "SPDXID" in payload:
        return parse_spdx(payload)
    # Fallback: check for key structural indicators
    if "components" in payload and "metadata" in payload:
        return parse_cyclonedx(payload)
    if "packages" in payload and "documentNamespace" in payload:
        return parse_spdx(payload)
    raise ValueError(
        "Unrecognised SBOM format. Expected CycloneDX (bomFormat/specVersion) "
        "or SPDX (spdxVersion / SPDXID)."
    )


def _normalise_tool_name(raw: str) -> Optional[str]:
    if not raw:
        return None
    lower = raw.lower()
    for tool in ("syft", "trivy", "cdxgen", "grype", "sbom-engine"):
        if tool in lower:
            return tool
    return raw[:50]
