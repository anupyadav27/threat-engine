"""
YAML-driven tech discovery executor.

Loads all step6_section_*.discovery.yaml files for a tech_type (one per CIS
section) and merges their discovery lists.  Also accepts legacy single-file
step6_discovery.yaml for backward compatibility.

action types dispatched:
  query_setting  → SQL SELECT returning a single setting row
  query_table    → full SELECT SQL, returns one or many rows
  run_command    → shell/CLI command (SSH, mongosh, nodetool, PowerShell)

emit_as:
  single  → one TechFinding for the whole result set (first row or aggregate)
  rows    → one TechFinding per result row
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)

CATALOG_ROOT = Path(__file__).resolve().parent.parent.parent.parent.parent / "catalog"

# ── Deployment type detection ─────────────────────────────────────────────────

_CLOUD_MANAGED_SUFFIXES: tuple = (
    ".rds.amazonaws.com",
    ".database.azure.com",
    ".postgres.database.azure.com",
    ".mysql.database.azure.com",
    ".database.windows.net",
    ".cloudsql.google.com",
)


def _detect_deployment_type(host: str) -> str:
    """Return 'cloud_managed' or 'self_hosted' based on the DB hostname."""
    h = host.lower().split(":")[0]  # strip port if present
    if any(h.endswith(s) for s in _CLOUD_MANAGED_SUFFIXES):
        return "cloud_managed"
    return "self_hosted"


class TechYAMLExecutor:
    """Loads and dispatches the discovery YAMLs for a tech_type."""

    def __init__(self, tech_category: str, tech_type: str) -> None:
        self.tech_category = tech_category
        self.tech_type     = tech_type
        self._entries: List[Dict[str, Any]] = []

    def load(self) -> "TechYAMLExecutor":
        """Load all per-section discovery YAMLs and merge their entries.

        Globs for ``step6_section_*.discovery.yaml`` first.  Falls back to
        the legacy ``step6_discovery.yaml`` when no section files exist.

        Raises:
            FileNotFoundError: When neither file pattern finds any YAMLs.
        """
        base = CATALOG_ROOT / "discovery_generator_data" / self.tech_category / self.tech_type

        section_files = sorted(base.glob("step6_section_*.discovery.yaml"))
        legacy_file   = base / "step6_discovery.yaml"

        files_to_load: List[Path] = section_files if section_files else (
            [legacy_file] if legacy_file.exists() else []
        )

        if not files_to_load:
            raise FileNotFoundError(
                f"No discovery YAMLs found for {self.tech_category}/{self.tech_type} in {base}"
            )

        # Append manually-authored internal checks when present.
        # This file uses a distinct name so generate_tech_rules.py --apply never touches it.
        internal_file = base / "step6_internal.discovery.yaml"
        if internal_file.exists():
            files_to_load = list(files_to_load) + [internal_file]

        for path in files_to_load:
            with path.open() as f:
                doc = yaml.safe_load(f) or {}
            entries = doc.get("discovery", [])
            self._entries.extend(entries)
            logger.debug("Loaded %d entries from %s", len(entries), path.name)

        logger.info(
            "Loaded %d total discovery entries for %s/%s (%d file(s))",
            len(self._entries), self.tech_category, self.tech_type, len(files_to_load),
        )
        return self

    @property
    def queries(self) -> List[Dict[str, Any]]:
        """All merged discovery entries."""
        return self._entries

    @property
    def action_type(self) -> str:
        return "mixed"

    def execute_entry(
        self,
        entry: Dict[str, Any],
        connector: Any,
        host: str,
    ) -> List[Dict[str, Any]]:
        """Execute one discovery entry and return raw result dicts.

        Dispatches on ``action`` field:

        * ``query_setting`` / ``query_table`` — SQL via ``connector.execute_query()``
        * ``run_command`` — shell/CLI via ``connector.run_command()``

        The SQL query is read from the ``query`` key first, then ``sql``
        (both are accepted for forward/backward compatibility).

        Args:
            entry:     Parsed discovery YAML entry dict.
            connector: Tech connector with ``execute_query()`` / ``run_command()``.
            host:      Host string used for resource_uid construction.

        Returns:
            List of dicts each containing ``raw_data`` and ``resource_uid``.
        """
        disc_id = entry.get("discovery_id", "unknown")
        emit_as = entry.get("emit_as", "single")

        # Action may be at the top level OR inside calls[0] (generated YAMLs use calls[])
        action = entry.get("action")
        if not action:
            first_call = next(iter(entry.get("calls") or []), {})
            action = first_call.get("action", "query_table")

        # ── applicable_to filter ──────────────────────────────────────────────
        applicable = entry.get("applicable_to")
        if applicable:
            deployment_type = _detect_deployment_type(host)
            if deployment_type not in applicable:
                logger.debug(
                    "Skipping %s — applicable_to=%s but deployment_type=%s",
                    disc_id, applicable, deployment_type,
                )
                return []

        # ── dispatch ──────────────────────────────────────────────────────────
        if action == "run_command":
            return self._exec_command(entry, connector, host, disc_id, emit_as)

        # SQL actions (query_setting, query_table, or unknown default)
        # Try top-level query/sql first, then fall back to calls[].query
        # (catalog YAMLs nest the query inside calls[] — mirror local_executor._extract_sql)
        sql = (entry.get("query") or entry.get("sql") or "").strip()
        if not sql:
            for call in entry.get("calls", []):
                if call.get("action") in ("query_setting", "query_table"):
                    sql = (call.get("query") or call.get("sql") or "").strip()
                    break
        if not sql:
            logger.warning("No SQL for discovery_id=%s — skipping", disc_id)
            return []
        return self._exec_sql(sql, entry, connector, host, disc_id, emit_as)

    # ── private helpers ───────────────────────────────────────────────────────

    def _exec_sql(
        self,
        sql: str,
        entry: Dict[str, Any],
        connector: Any,
        host: str,
        disc_id: str,
        emit_as: str,
    ) -> List[Dict[str, Any]]:
        try:
            rows: List[Dict[str, Any]] = connector.execute_query(sql)
        except Exception as exc:
            logger.warning("SQL failed for %s: %s", disc_id, exc)
            return [{"raw_data": {"error": str(exc), "sql": sql},
                     "resource_uid": f"{host}.{disc_id}"}]

        return self._emit(rows, entry, host, disc_id, emit_as)

    def _exec_command(
        self,
        entry: Dict[str, Any],
        connector: Any,
        host: str,
        disc_id: str,
        emit_as: str,
    ) -> List[Dict[str, Any]]:
        # Extract command from the calls list (generated YAML structure)
        calls = entry.get("calls", [])
        command = ""
        for call in calls:
            if call.get("action") == "run_command":
                command = call.get("command", "")
                break
        if not command:
            command = entry.get("command", "")

        if not command:
            logger.warning("No command for discovery_id=%s — skipping", disc_id)
            return []

        if not hasattr(connector, "run_command"):
            logger.warning(
                "Connector %s has no run_command() — skipping %s",
                type(connector).__name__, disc_id,
            )
            return []

        try:
            stdout = connector.run_command(command)
        except Exception as exc:
            logger.warning("Command failed for %s: %s", disc_id, exc)
            return [{"raw_data": {"error": str(exc), "command": command},
                     "resource_uid": f"{host}.{disc_id}"}]

        rows = [{"stdout": stdout, "command": command}]
        return self._emit(rows, entry, host, disc_id, emit_as)

    @staticmethod
    def _emit(
        rows: List[Dict[str, Any]],
        entry: Dict[str, Any],
        host: str,
        disc_id: str,
        emit_as: str,
    ) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []

        if emit_as == "rows":
            template = entry.get("resource_uid_template", f"{host}.{disc_id}.{{idx}}")
            for idx, row in enumerate(rows):
                try:
                    uid = template.format(**{k: str(v) for k, v in row.items()}, idx=idx)
                except (KeyError, ValueError):
                    uid = f"{host}.{disc_id}.{idx}"
                results.append({"raw_data": row, "resource_uid": uid})
        else:
            raw = rows[0] if rows else {}
            uid = entry.get("resource_uid", f"{host}.{disc_id}")
            results.append({"raw_data": raw, "resource_uid": uid})

        return results
