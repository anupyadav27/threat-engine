"""
catalog_client.py — Pulls discovery + check catalog from central tech-check server.

Falls back to loading from local catalog/ path when CENTRAL_URL is not set
(useful for development and testing without a running central server).
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
import yaml

logger = logging.getLogger(__name__)

# Resolved at runtime relative to repo root when LOCAL_CATALOG_ROOT is not set.
# tech-agent/ → technology-engine/ → engines/ → threat-engine/ → catalog/
_DEFAULT_CATALOG_ROOT = Path(__file__).resolve().parent.parent.parent.parent / "catalog"

REQUEST_TIMEOUT = 15  # seconds


class CatalogClient:
    """Fetches merged discovery entries and check rules for a tech_type.

    Args:
        central_url: Base URL of the tech-check engine, e.g.
            ``https://tech-check.threat-engine.internal``.  When ``None``
            the client falls back to the local catalog on disk.
        token: Bearer token for the central server.  Required when
            ``central_url`` is set.
        catalog_root: Override the local catalog root path (for tests).
    """

    def __init__(
        self,
        central_url: Optional[str] = None,
        token: Optional[str] = None,
        catalog_root: Optional[Path] = None,
    ) -> None:
        self._central_url = central_url or os.getenv("CENTRAL_URL")
        self._token = token or os.getenv("AGENT_TOKEN", "")
        self._catalog_root = catalog_root or Path(
            os.getenv("LOCAL_CATALOG_ROOT", str(_DEFAULT_CATALOG_ROOT))
        )

    # ── public API ────────────────────────────────────────────────────────────

    def get_catalog(self, tech_type: str) -> Dict[str, Any]:
        """Return merged catalog for *tech_type*.

        Args:
            tech_type: Technology identifier, e.g. ``postgresql``, ``ubuntu``,
                ``docker``.

        Returns:
            Dict with keys ``tech_type``, ``discovery_entries`` (list),
            ``check_rules`` (list).

        Raises:
            RuntimeError: When the remote call fails and no local fallback
                exists.
        """
        if self._central_url:
            return self._fetch_remote(tech_type)
        return self._load_local(tech_type)

    # ── remote fetch ──────────────────────────────────────────────────────────

    def _fetch_remote(self, tech_type: str) -> Dict[str, Any]:
        """GET /api/v1/tech/catalog/{tech_type} from the central server."""
        url = f"{self._central_url.rstrip('/')}/api/v1/tech/catalog/{tech_type}"
        headers: Dict[str, str] = {}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        try:
            resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            data: Dict[str, Any] = resp.json()
            logger.info(
                "Fetched catalog from %s: %d discovery, %d rules",
                url,
                len(data.get("discovery_entries", [])),
                len(data.get("check_rules", [])),
            )
            return data
        except requests.RequestException as exc:
            logger.warning("Remote catalog fetch failed (%s), falling back to local", exc)
            return self._load_local(tech_type)

    # ── local fallback ────────────────────────────────────────────────────────

    def _load_local(self, tech_type: str) -> Dict[str, Any]:
        """Load discovery YAMLs and rule YAMLs from local catalog directory."""
        discovery_entries = self._load_discovery_yamls(tech_type)
        check_rules = self._load_rule_yamls(tech_type)

        if not discovery_entries and not check_rules:
            raise RuntimeError(
                f"No catalog data found for tech_type={tech_type!r} in {self._catalog_root}"
            )

        logger.info(
            "Loaded local catalog for %s: %d discovery entries, %d rules",
            tech_type,
            len(discovery_entries),
            len(check_rules),
        )
        return {
            "tech_type": tech_type,
            "discovery_entries": discovery_entries,
            "check_rules": check_rules,
        }

    def _load_discovery_yamls(self, tech_type: str) -> List[Dict[str, Any]]:
        """Glob step6_section_*.discovery.yaml under catalog/discovery_generator_data/*/{tech_type}/."""
        entries: List[Dict[str, Any]] = []
        pattern = f"*/{ tech_type }/step6_section_*.discovery.yaml"
        discovery_root = self._catalog_root / "discovery_generator_data"

        files = sorted(discovery_root.glob(pattern))
        if not files:
            # Legacy single-file fallback
            legacy = sorted(discovery_root.glob(f"*/{tech_type}/step6_discovery.yaml"))
            files = legacy

        for path in files:
            try:
                with path.open() as fh:
                    doc = yaml.safe_load(fh) or {}
                entries.extend(doc.get("discovery", []))
            except Exception as exc:
                logger.warning("Failed to load %s: %s", path, exc)

        return entries

    def _load_rule_yamls(self, tech_type: str) -> List[Dict[str, Any]]:
        """Glob *_cis_section_*.rules.yaml under catalog/rule/**_rule_check/{tech_type}/."""
        rules: List[Dict[str, Any]] = []
        rule_root = self._catalog_root / "rule"

        pattern = f"*_rule_check/{tech_type}/*_cis_section_*.rules.yaml"
        files = sorted(rule_root.glob(pattern))

        for path in files:
            try:
                with path.open() as fh:
                    doc = yaml.safe_load(fh) or {}
                rules.extend(doc.get("rules", []))
            except Exception as exc:
                logger.warning("Failed to load %s: %s", path, exc)

        return rules
