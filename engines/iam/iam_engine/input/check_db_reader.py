"""
Check DB Reader for IAM Engine

Extends BaseCheckReader with ENGINE_SCOPE = "iam_security".
Loads check_findings joined with rule_metadata where
  (rule_metadata.iam_security ->> 'applicable')::boolean = true

Same pattern as network-security, encryption-security, container-security, etc.
"""

from engine_common.base_check_reader import BaseCheckReader


class CheckDBReader(BaseCheckReader):
    ENGINE_SCOPE = "iam_security"

    def load_iam_check_findings(self, scan_run_id: str, tenant_id: str):
        """Load IAM-relevant check findings for a scan."""
        return self.load_check_findings(scan_run_id, tenant_id)

    def load_iam_rule_metadata(self, provider: str = None):
        """Return {rule_id: metadata} for all IAM-relevant rules."""
        return self.load_rule_metadata(provider=provider)
