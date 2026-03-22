"""
SCA Router — Software Composition Analysis (SBOM + dependency vulnerability scanning).

Mounts the sca_sbom_engine FastAPI sub-application under /api/v1/secops/sca.
The SBOM engine is a complete async service with its own:
  - asyncpg connection pool (to threat_engine_vulnerability DB)
  - CycloneDX 1.5 SBOM generation
  - Vulnerability enrichment (osv_advisory + cves tables)
  - VEX statement management
  - License/compliance checking
  - EPSS + CISA KEV threat intel

Sub-routes (all relative to /api/v1/secops/sca):
  /api/v1/sbom/scan-repo   POST  — Clone repo, detect lockfiles, generate SBOM, enrich with CVEs
  /api/v1/sbom/upload      POST  — Ingest pre-built CycloneDX/SPDX SBOM
  /api/v1/sbom/generate    POST  — Generate SBOM from raw package list
  /api/v1/sbom/            GET   — List SBOM documents
  /api/v1/sbom/{id}        GET   — Get SBOM document
  /api/v1/vex/             POST  — Create VEX suppression statement
  /api/v1/compliance/{id}  GET   — Compliance report
  /api/v1/alerts/          GET   — CVE watch alerts
  /health                  GET   — SCA health check
"""

import logging

logger = logging.getLogger("secops.sca")


def get_sca_app():
    """
    Import and return the sca_sbom_engine FastAPI app.

    Path resolution:
      Docker:  /app/routers/sca.py → sca_sbom_engine at /app/sca_sbom_engine/
      Local:   engines/secops/sast_engine/routers/sca.py → engines/secops/sca_sbom_engine/
    """
    import sys
    import os

    # In Docker: PYTHONPATH=/app, sca_sbom_engine is at /app/sca_sbom_engine/
    # We need /app on sys.path (for `import sca_sbom_engine`)
    # AND /app/sca_sbom_engine on sys.path (for internal `from core.xxx` / `from api.xxx`)
    app_dir = os.environ.get("PYTHONPATH", "/app")
    if app_dir not in sys.path:
        sys.path.insert(0, app_dir)

    sca_dir = os.path.join(app_dir, "sca_sbom_engine")
    if not os.path.isdir(sca_dir):
        # Local dev fallback: relative to this file
        sca_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "..", "sca_sbom_engine")
        )
    if os.path.isdir(sca_dir) and sca_dir not in sys.path:
        sys.path.insert(0, sca_dir)

    from sca_sbom_engine.main import app as sca_app
    logger.info("SCA/SBOM sub-application loaded successfully")
    return sca_app
