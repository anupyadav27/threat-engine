"""Check reader for AI Security Engine."""

from typing import Any, Dict, List, Optional

from engine_common.base_check_reader import BaseCheckReader


class AICheckReader(BaseCheckReader):
    ENGINE_SCOPE = "ai_security"

    def load_ai_check_findings(self, scan_run_id: str, tenant_id: str) -> List[Dict[str, Any]]:
        return self.load_check_findings(scan_run_id, tenant_id)

    def load_ai_rule_metadata(self, provider: Optional[str] = None) -> List[Dict[str, Any]]:
        return list(self.load_rule_metadata(provider=provider).values())
