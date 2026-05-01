"""
Base check reader — loads check_findings joined with rule_metadata,
filtered to a specific engine scope via the JSONB column.

Each domain engine defines its ENGINE_SCOPE (the rule_metadata column name):
  - encryption: "encryption_security"
  - container:  "container_security"
  - database:   "database_security"
  - ai:         "ai_security"

Usage:
    from engine_common.base_check_reader import BaseCheckReader

    class CheckReader(BaseCheckReader):
        ENGINE_SCOPE = "encryption_security"

        def load_encryption_check_findings(self, scan_run_id, tenant_id):
            return self.load_check_findings(scan_run_id, tenant_id)
"""

from typing import Any, Dict, List, Optional

from .base_reader import BaseDBReader
from .db_connections import get_check_conn

_CHECK_FINDING_COLS = """
    cf.scan_run_id, cf.rule_id, cf.service,
    cf.resource_uid, cf.resource_type, cf.resource_id,
    cf.region, cf.account_id, cf.provider,
    cf.status, cf.checked_fields, cf.actual_values, cf.finding_data
"""

_RULE_META_COLS = "rule_id, service, severity, title, description, remediation, compliance_frameworks, domain"


class BaseCheckReader(BaseDBReader):
    ENGINE_SCOPE: str = ""  # subclasses must set this

    def __init__(self):
        super().__init__(get_check_conn)

    def load_check_findings(
        self,
        scan_run_id: str,
        tenant_id: str,
        engine_scope_col: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Load check_findings filtered by engine scope JSONB column.

        Uses ENGINE_SCOPE class attribute when engine_scope_col not provided.
        """
        col = engine_scope_col or self.ENGINE_SCOPE
        sql = f"""
            SELECT {_CHECK_FINDING_COLS}
            FROM check_findings cf
            JOIN rule_metadata rm ON cf.rule_id = rm.rule_id
            WHERE cf.scan_run_id = %s
              AND cf.tenant_id = %s
              AND (rm.{col} ->> 'applicable')::boolean = true
        """
        return self._safe_fetch(
            sql, (scan_run_id, tenant_id),
            f"check findings [{col}] for scan {scan_run_id}",
        )

    def load_rule_metadata(
        self,
        engine_scope_col: Optional[str] = None,
        rule_ids: Optional[List[str]] = None,
        provider: Optional[str] = None,
    ) -> Dict[str, Dict[str, Any]]:
        """Load rule_metadata for this engine's scope.

        Uses ENGINE_SCOPE class attribute when engine_scope_col not provided.
        """
        col = engine_scope_col or self.ENGINE_SCOPE
        if rule_ids:
            sql = f"SELECT {_RULE_META_COLS}, {col} FROM rule_metadata WHERE rule_id = ANY(%s)"
            rows = self._safe_fetch(sql, (rule_ids,), f"rule metadata by ids [{col}]")
        else:
            sql = f"""
                SELECT {_RULE_META_COLS}, {col}
                FROM rule_metadata
                WHERE ({col} ->> 'applicable')::boolean = true
            """
            params: list = []
            if provider:
                sql += " AND provider = %s"
                params.append(provider)
            rows = self._safe_fetch(sql, params, f"rule metadata [{col}]")
        return {r["rule_id"]: dict(r) for r in rows}
