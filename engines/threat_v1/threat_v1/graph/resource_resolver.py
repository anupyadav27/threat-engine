"""
Resolves the best scan_run_id per engine for a given (tenant_id, account_id) pair.

"Best" = the scan with the most findings — not the most recent. A partial scan
that completed 10 minutes ago may be newer but have 90% fewer findings, producing
a sparse graph. Using most-findings scan gives the richest possible graph.

See REQUIREMENTS §3.2 for the resolution algorithm.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class ResourceResolver:
    """Resolves the best scan_run_id per source engine for a tenant/account pair."""

    def __init__(
        self,
        check_conn: Any,
        vuln_conn: Any,
        cdr_conn: Any,
        inventory_conn: Any,
    ) -> None:
        self._check_conn = check_conn
        self._vuln_conn = vuln_conn
        self._cdr_conn = cdr_conn
        self._inventory_conn = inventory_conn

    def resolve(
        self,
        tenant_id: str,
        account_id: str,
    ) -> Dict[str, Optional[str]]:
        """Return mapping of engine → best scan_run_id for this tenant/account.

        CDR is tenant-wide (no account_id filter) per W-04 design decision.
        Inventory uses tenant_id + account_id like check/vuln.

        Returns:
            Dict with keys: check, vuln, cdr, inventory — values are UUID strings
            or None when the engine has no findings for this tenant/account.
        """
        result: Dict[str, Optional[str]] = {
            "check": None,
            "vuln": None,
            "cdr": None,
            "inventory": None,
        }

        result["check"] = self._best_scan_run(
            conn=self._check_conn,
            table="check_findings",
            tenant_id=tenant_id,
            account_id=account_id,
            include_account=True,
        )
        # scan_vulnerabilities uses scan_id (not scan_run_id) — non-standard schema (tech debt).
        # Resolution is not possible until vuln migration adds scan_run_id.
        result["vuln"] = None
        # CDR has no account_id filter — tenant-wide by design (W-04)
        result["cdr"] = self._best_scan_run(
            conn=self._cdr_conn,
            table="cdr_findings",
            tenant_id=tenant_id,
            account_id=None,
            include_account=False,
        )
        result["inventory"] = self._best_scan_run(
            conn=self._inventory_conn,
            table="inventory_findings",
            tenant_id=tenant_id,
            account_id=account_id,
            include_account=True,
        )

        logger.info(
            "Resource resolution complete",
            extra={
                "tenant_id": tenant_id,
                "account_id": account_id,
                "check_scan": result["check"],
                "vuln_scan": result["vuln"],
                "cdr_scan": result["cdr"],
                "inventory_scan": result["inventory"],
            },
        )
        return result

    def _best_scan_run(
        self,
        conn: Any,
        table: str,
        tenant_id: str,
        account_id: Optional[str],
        include_account: bool,
    ) -> Optional[str]:
        """Query a source DB for the scan_run_id with the most rows."""
        try:
            cur = conn.cursor()
            if include_account:
                cur.execute(
                    f"""
                    SELECT scan_run_id
                    FROM {table}
                    WHERE tenant_id = %s AND account_id = %s
                    GROUP BY scan_run_id
                    ORDER BY count(*) DESC
                    LIMIT 1
                    """,
                    (tenant_id, account_id),
                )
            else:
                cur.execute(
                    f"""
                    SELECT scan_run_id
                    FROM {table}
                    WHERE tenant_id = %s
                    GROUP BY scan_run_id
                    ORDER BY count(*) DESC
                    LIMIT 1
                    """,
                    (tenant_id,),
                )
            row = cur.fetchone()
            cur.close()
            return str(row["scan_run_id"]) if row else None
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Resolution query failed for table %s: %s",
                table,
                exc,
                extra={"tenant_id": tenant_id, "account_id": account_id},
            )
            try:
                conn.rollback()
            except Exception:
                pass
            return None
