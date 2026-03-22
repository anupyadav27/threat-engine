"""
SBOM API Routes

POST /upload       - Upload CycloneDX or SPDX from Syft/Trivy/cdxgen
POST /generate     - Generate SBOM from a package list
GET  /             - List SBOM documents
GET  /{sbom_id}    - Get SBOM document (CycloneDX JSON)
GET  /host/{host_id} - Latest SBOM for a host
GET  /{sbom_id}/diff/{other_sbom_id} - Diff two SBOMs
DELETE /{sbom_id}  - Delete a SBOM
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from core.auth import get_current_user
from core.database import SBOMDatabaseManager
from core.sbom_parser import detect_and_parse
from core.sbom_generator import enrich_cyclonedx, generate_cyclonedx
from core.vuln_enricher import VulnEnricher
from core.license_checker import analyse_sbom_licenses
from core.repo_scanner import GitRepoScanner

logger = logging.getLogger(__name__)

router = APIRouter()


def get_db() -> SBOMDatabaseManager:
    from main import db_manager
    return db_manager


def get_enricher() -> VulnEnricher:
    from main import vuln_enricher
    return vuln_enricher


# ── Models ────────────────────────────────────────────────────────────────────

class PackageItem(BaseModel):
    name: str
    version: Optional[str] = None
    ecosystem: Optional[str] = None
    purl: Optional[str] = None
    licenses: Optional[List[str]] = None
    hashes: Optional[List[Dict]] = None
    scope: Optional[str] = None


class GenerateSBOMRequest(BaseModel):
    host_id: Optional[str] = None
    application_name: Optional[str] = "unknown"
    packages: List[PackageItem]
    parent_sbom_id: Optional[str] = None


# ── Scan Git Repository ───────────────────────────────────────────────────────

class ScanRepoRequest(BaseModel):
    git_url: str
    branch: Optional[str] = None
    host_id: Optional[str] = None
    application_name: Optional[str] = None
    git_token: Optional[str] = None       # injected by orchestrator from AWS SM — never stored
    git_username: Optional[str] = None    # required for Bitbucket and some self-hosted servers


@router.post("/scan-repo", summary="Scan a Git repository and generate SBOM")
async def scan_repo(
    req: ScanRepoRequest,
    db: SBOMDatabaseManager = Depends(get_db),
    enricher: VulnEnricher = Depends(get_enricher),
    _: str = Depends(get_current_user),
):
    """
    Primary SBOM generation endpoint.

    Accepts a Git repository URL. The engine:
      1. Clones the repository (shallow clone, no history)
      2. Traverses all files and detects every dependency manifest:
           requirements.txt, package.json, go.mod, Cargo.toml,
           pom.xml, Gemfile.lock, *.csproj, composer.lock, and more
      3. Parses each manifest to extract (name, version, ecosystem)
      4. Deduplicates components — lock files take precedence over manifests
      5. Enriches every component with vulnerability data (osv_advisory + cves)
      6. Adds EPSS scores + CISA KEV status to each vulnerability
      7. Calculates composite risk score per vulnerability
      8. Stores the full SBOM (all components, not just vulnerable)
      9. Returns a standard CycloneDX 1.5 document

    Supported ecosystems:
      Python (PyPI), JavaScript/Node.js (npm), Go, Rust (crates.io),
      Java (Maven), Ruby (RubyGems), .NET (NuGet), PHP (Packagist)
    """
    import asyncio

    scanner = GitRepoScanner()

    # Run git clone in a thread pool (blocking I/O)
    loop = asyncio.get_event_loop()
    try:
        scan_result = await loop.run_in_executor(
            None,
            lambda: scanner.scan(req.git_url, req.branch, req.git_token, req.git_username),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=422, detail=str(e))

    components = scan_result["components"]
    app_name   = req.application_name or scan_result["application_name"]

    if not components:
        return {
            "sbom_id":           None,
            "repo_url":          req.git_url,
            "commit_sha":        scan_result.get("commit_sha"),
            "application_name":  app_name,
            "detected_files":    scan_result["detected_files"],
            "languages":         scan_result["languages"],
            "components":        0,
            "message": (
                "No dependency manifests found in this repository. "
                "Ensure the repo contains at least one of: requirements.txt, "
                "package.json, go.mod, Cargo.toml, pom.xml, Gemfile.lock, *.csproj"
            ),
        }

    enriched = await enricher.enrich_components(components)
    vuln_count = sum(1 for c in enriched if c.get("is_vulnerable"))

    sbom_id = db.generate_sbom_id()

    # Find previous SBOM for this host to link as parent
    parent_sbom_id = None
    if req.host_id:
        latest = await db.get_latest_sbom_for_host(req.host_id)
        if latest:
            parent_sbom_id = latest["sbom_id"]

    doc = {
        "sbom_id":          sbom_id,
        "host_id":          req.host_id or app_name,
        "application_name": app_name,
        "sbom_format":      "CycloneDX",
        "spec_version":     "1.5",
        "version":          1,
        "parent_sbom_id":   parent_sbom_id,
        "component_count":  len(enriched),
        "vulnerability_count": vuln_count,
        "source":           "sbom-engine-git",
        "raw_document":     None,   # no raw upload; generated internally
        "created_by":       req.host_id,
    }
    await db.save_sbom_document(doc)
    await db.save_sbom_components(sbom_id, enriched)

    cdx = generate_cyclonedx(
        packages=enriched,
        enriched_components=enriched,
        app_name=app_name,
        host_id=req.host_id,
        sbom_id=sbom_id,
    )

    # Add repo metadata to CycloneDX metadata section
    cdx.setdefault("metadata", {})["properties"] = [
        {"name": "sbom:repo_url",    "value": req.git_url},
        {"name": "sbom:commit_sha",  "value": scan_result.get("commit_sha", "")},
        {"name": "sbom:languages",   "value": ", ".join(scan_result["languages"])},
        {"name": "sbom:branch",      "value": req.branch or "default"},
    ]

    return {
        "sbom_id":               sbom_id,
        "repo_url":              req.git_url,
        "commit_sha":            scan_result.get("commit_sha"),
        "branch":                req.branch or "default",
        "application_name":      app_name,
        "languages":             scan_result["languages"],
        "detected_files":        scan_result["detected_files"],
        "components":            len(enriched),
        "vulnerable_components": vuln_count,
        "parent_sbom_id":        parent_sbom_id,
        "cyclonedx":             cdx,
    }


# ── Upload Endpoint ───────────────────────────────────────────────────────────

@router.post("/upload", summary="Upload CycloneDX or SPDX SBOM")
async def upload_sbom(
    payload: Dict[str, Any],
    host_id: Optional[str] = Query(None, description="Host or system identifier"),
    created_by: Optional[str] = Query(None, description="CI pipeline / username"),
    db: SBOMDatabaseManager = Depends(get_db),
    enricher: VulnEnricher = Depends(get_enricher),
    _: str = Depends(get_current_user),
):
    """
    Accept a CycloneDX (1.4/1.5) or SPDX (2.3) JSON document.
    Parse all components, enrich with vulnerability data from osv_advisory/cves,
    store SBOM + components, return enriched CycloneDX 1.5.
    """
    try:
        parsed = detect_and_parse(payload)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    sbom_id = db.generate_sbom_id()
    components = parsed["components"]

    # Enrich with vulnerability data
    vex_index = {}
    enriched = await enricher.enrich_components(components, vex_index)

    vuln_count = sum(1 for c in enriched if c.get("is_vulnerable"))

    # Build document record
    doc = {
        "sbom_id":          sbom_id,
        "host_id":          host_id or parsed.get("application_name"),
        "application_name": parsed.get("application_name"),
        "sbom_format":      parsed["sbom_format"],
        "spec_version":     parsed.get("spec_version"),
        "version":          parsed.get("version", 1),
        "component_count":  len(enriched),
        "vulnerability_count": vuln_count,
        "source":           parsed.get("source"),
        "raw_document":     payload,
        "created_by":       created_by,
    }
    await db.save_sbom_document(doc)
    await db.save_sbom_components(sbom_id, enriched)

    # Generate enriched CycloneDX output
    cdx = enrich_cyclonedx(parsed, enriched)
    cdx["x-sbom-id"] = sbom_id  # attach our internal ID

    return {
        "sbom_id":           sbom_id,
        "format":            parsed["sbom_format"],
        "spec_version":      parsed.get("spec_version"),
        "components":        len(enriched),
        "vulnerable_components": vuln_count,
        "cyclonedx":         cdx,
    }


# ── Generate Endpoint ─────────────────────────────────────────────────────────

@router.post("/generate", summary="Generate SBOM from package list")
async def generate_sbom(
    req: GenerateSBOMRequest,
    db: SBOMDatabaseManager = Depends(get_db),
    enricher: VulnEnricher = Depends(get_enricher),
    _: str = Depends(get_current_user),
):
    """
    Build a CycloneDX 1.5 SBOM from a list of packages.
    Each package is enriched with vulnerability data.
    """
    sbom_id = db.generate_sbom_id()

    # Convert PackageItem → component dicts
    components = [
        {
            "name":      p.name,
            "version":   p.version,
            "ecosystem": p.ecosystem,
            "purl":      p.purl,
            "licenses":  p.licenses or [],
            "hashes":    p.hashes or [],
            "scope":     p.scope,
            "component_type": "library",
        }
        for p in req.packages
    ]

    enriched = await enricher.enrich_components(components)
    vuln_count = sum(1 for c in enriched if c.get("is_vulnerable"))

    # Find latest SBOM for this host to set as parent
    parent_sbom_id = req.parent_sbom_id
    if not parent_sbom_id and req.host_id:
        latest = await db.get_latest_sbom_for_host(req.host_id)
        if latest:
            parent_sbom_id = latest["sbom_id"]

    doc = {
        "sbom_id":          sbom_id,
        "host_id":          req.host_id,
        "application_name": req.application_name,
        "sbom_format":      "CycloneDX",
        "spec_version":     "1.5",
        "version":          1,
        "parent_sbom_id":   parent_sbom_id,
        "component_count":  len(enriched),
        "vulnerability_count": vuln_count,
        "source":           "sbom-engine",
        "created_by":       req.host_id,
    }
    await db.save_sbom_document(doc)
    await db.save_sbom_components(sbom_id, enriched)

    cdx = generate_cyclonedx(
        packages=req.packages,
        enriched_components=enriched,
        app_name=req.application_name or "unknown",
        host_id=req.host_id,
        sbom_id=sbom_id,
    )

    return {
        "sbom_id":               sbom_id,
        "components":            len(enriched),
        "vulnerable_components": vuln_count,
        "parent_sbom_id":        parent_sbom_id,
        "cyclonedx":             cdx,
    }


# ── List SBOMs ────────────────────────────────────────────────────────────────

@router.get("/", summary="List SBOM documents")
async def list_sboms(
    host_id: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: SBOMDatabaseManager = Depends(get_db),
    _: str = Depends(get_current_user),
):
    docs = await db.list_sbom_documents(host_id=host_id, limit=limit, offset=offset)
    return {"total": len(docs), "sboms": docs}


# ── Get single SBOM ───────────────────────────────────────────────────────────

@router.get("/{sbom_id}", summary="Get SBOM document")
async def get_sbom(
    sbom_id: str,
    format: str = Query("summary", description="summary | cyclonedx | raw"),
    db: SBOMDatabaseManager = Depends(get_db),
    _: str = Depends(get_current_user),
):
    doc = await db.get_sbom_document(sbom_id)
    if not doc:
        raise HTTPException(status_code=404, detail=f"SBOM {sbom_id} not found")

    if format == "raw":
        return doc.get("raw_document") or {}

    components = await db.get_sbom_components(sbom_id)

    if format == "cyclonedx":
        raw = doc.get("raw_document")
        if raw and isinstance(raw, dict) and raw.get("bomFormat") == "CycloneDX":
            return raw
        # Reconstruct minimal CycloneDX
        from core.sbom_generator import generate_cyclonedx, CDX_FORMAT, CDX_SPEC
        import uuid
        from datetime import datetime, timezone
        cdx = {
            "bomFormat":    CDX_FORMAT,
            "specVersion":  CDX_SPEC,
            "serialNumber": sbom_id,
            "version":      doc.get("version", 1),
            "metadata": {
                "timestamp": doc["created_at"].isoformat() if doc.get("created_at") else "",
                "component": {"type": "application",
                              "name": doc.get("application_name", "unknown")},
            },
            "components": [
                {
                    "type":    c.get("component_type", "library"),
                    "bom-ref": c.get("bom_ref") or c.get("purl") or c.get("name"),
                    "name":    c["name"],
                    **( {"version": c["version"]} if c.get("version") else {}),
                    **( {"purl":    c["purl"]}    if c.get("purl")    else {}),
                }
                for c in components
            ],
        }
        return cdx

    # Default: summary
    vuln_comps = [c for c in components if c.get("is_vulnerable")]
    license_analysis = analyse_sbom_licenses(components)

    return {
        "sbom_id":           doc["sbom_id"],
        "host_id":           doc.get("host_id"),
        "application_name":  doc.get("application_name"),
        "sbom_format":       doc["sbom_format"],
        "spec_version":      doc.get("spec_version"),
        "version":           doc.get("version"),
        "source":            doc.get("source"),
        "component_count":   doc.get("component_count"),
        "vulnerability_count": doc.get("vulnerability_count"),
        "created_at":        doc["created_at"].isoformat() if doc.get("created_at") else None,
        "parent_sbom_id":    doc.get("parent_sbom_id"),
        "vulnerable_components": [
            {
                "name":             c["name"],
                "version":          c.get("version"),
                "purl":             c.get("purl"),
                "vulnerability_ids": c.get("vulnerability_ids") or [],
            }
            for c in vuln_comps
        ],
        "license_summary":   license_analysis,
    }


# ── Latest SBOM for a host ────────────────────────────────────────────────────

@router.get("/host/{host_id}", summary="Latest SBOM for a host")
async def get_host_sbom(
    host_id: str,
    db: SBOMDatabaseManager = Depends(get_db),
    _: str = Depends(get_current_user),
):
    doc = await db.get_latest_sbom_for_host(host_id)
    if not doc:
        raise HTTPException(status_code=404,
                            detail=f"No SBOM found for host '{host_id}'")
    return {
        "sbom_id":          doc["sbom_id"],
        "host_id":          doc["host_id"],
        "application_name": doc.get("application_name"),
        "sbom_format":      doc["sbom_format"],
        "component_count":  doc.get("component_count"),
        "vulnerability_count": doc.get("vulnerability_count"),
        "created_at":       doc["created_at"].isoformat() if doc.get("created_at") else None,
    }


# ── SBOM Diff ─────────────────────────────────────────────────────────────────

@router.get("/{sbom_id}/diff/{other_sbom_id}", summary="Diff two SBOMs")
async def diff_sboms(
    sbom_id: str,
    other_sbom_id: str,
    db: SBOMDatabaseManager = Depends(get_db),
    _: str = Depends(get_current_user),
):
    """
    Compare two SBOMs.  Returns added/removed/changed components
    and new/resolved vulnerabilities.
    """
    doc_a = await db.get_sbom_document(sbom_id)
    doc_b = await db.get_sbom_document(other_sbom_id)

    if not doc_a:
        raise HTTPException(status_code=404, detail=f"SBOM {sbom_id} not found")
    if not doc_b:
        raise HTTPException(status_code=404, detail=f"SBOM {other_sbom_id} not found")

    comps_a = await db.get_sbom_components(sbom_id)
    comps_b = await db.get_sbom_components(other_sbom_id)

    # Index by (name, ecosystem) — version is what changes
    def _index(comps):
        idx = {}
        for c in comps:
            key = (c["name"].lower(), (c.get("ecosystem") or "").lower())
            idx[key] = c
        return idx

    idx_a = _index(comps_a)
    idx_b = _index(comps_b)

    keys_a = set(idx_a.keys())
    keys_b = set(idx_b.keys())

    added   = [idx_b[k] for k in keys_b - keys_a]
    removed = [idx_a[k] for k in keys_a - keys_b]
    changed = []
    for k in keys_a & keys_b:
        ca, cb = idx_a[k], idx_b[k]
        if ca.get("version") != cb.get("version"):
            changed.append({
                "name":        ca["name"],
                "ecosystem":   ca.get("ecosystem"),
                "purl_before": ca.get("purl"),
                "purl_after":  cb.get("purl"),
                "version_before": ca.get("version"),
                "version_after":  cb.get("version"),
            })

    # Vulnerability diff
    def _vuln_set(comps):
        ids = set()
        for c in comps:
            for vid in (c.get("vulnerability_ids") or []):
                ids.add(vid)
        return ids

    vulns_a = _vuln_set(comps_a)
    vulns_b = _vuln_set(comps_b)
    new_vulns      = list(vulns_b - vulns_a)
    resolved_vulns = list(vulns_a - vulns_b)

    return {
        "sbom_id_before":  sbom_id,
        "sbom_id_after":   other_sbom_id,
        "created_before":  doc_a["created_at"].isoformat() if doc_a.get("created_at") else None,
        "created_after":   doc_b["created_at"].isoformat() if doc_b.get("created_at") else None,
        "components_added":   len(added),
        "components_removed": len(removed),
        "components_changed": len(changed),
        "added":    [{"name": c["name"], "version": c.get("version"), "purl": c.get("purl")} for c in added],
        "removed":  [{"name": c["name"], "version": c.get("version"), "purl": c.get("purl")} for c in removed],
        "changed":  changed,
        "new_vulnerabilities":      new_vulns,
        "resolved_vulnerabilities": resolved_vulns,
    }


# ── Delete SBOM ───────────────────────────────────────────────────────────────

@router.delete("/{sbom_id}", summary="Delete a SBOM document")
async def delete_sbom(
    sbom_id: str,
    db: SBOMDatabaseManager = Depends(get_db),
    _: str = Depends(get_current_user),
):
    deleted = await db.delete_sbom_document(sbom_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"SBOM {sbom_id} not found")
    return {"deleted": sbom_id}
