"""Check reader for Database Security Engine."""

from typing import Any, Dict, List, Optional

from engine_common.base_check_reader import BaseCheckReader


class CheckReader(BaseCheckReader):
    ENGINE_SCOPE = "database_security"

    def load_db_check_findings(self, scan_run_id: str, tenant_id: str) -> List[Dict[str, Any]]:
        return self.load_check_findings(scan_run_id, tenant_id)
