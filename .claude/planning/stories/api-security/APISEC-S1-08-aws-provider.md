# Story APISEC-S1-08: AWS Provider — AWSAPISecProvider

## Status: done

## Metadata
- **Sprint**: APISEC Sprint 1
- **Points**: 3
- **Depends on**: APISEC-S1-06, APISEC-S1-07, APISEC-S1-09
- **Blocks**: APISEC-S1-05 (run_scan calls provider)
- **Security Gate**: bmad-security-reviewer (tenant isolation in provider, no cross-tenant findings)

## Implementation

**File**: `engines/api-security/api_security_engine/providers/aws.py`

```python
import logging
from typing import List, Dict, Any

from api_security_engine.providers.base import BaseAPISecProvider
from api_security_engine.input.check_finding_reader import load_check_findings
from api_security_engine.input.discovery_reader import load_api_discoveries, load_waf_associations
from api_security_engine.modules.auth_scheme import AuthSchemeModule
from api_security_engine.modules.throttle_audit import ThrottleAuditModule
from api_security_engine.modules.waf_coverage import WAFCoverageModule
from api_security_engine.modules.versioning_audit import VersioningAuditModule
from api_security_engine.modules.api_key_exposure import APIKeyExposureModule

logger = logging.getLogger("api_security.aws_provider")


class AWSAPISecProvider(BaseAPISecProvider):
    """
    AWS API Security provider.

    Layer 1: Loads existing FAIL check_findings for API gateway rules.
    Layer 2: Loads discovery_findings for API gateway resources, runs
             depth-analysis modules, produces additional findings not
             covered by config-level check rules.
    """

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        discoveries_conn,
        check_conn,
    ) -> List[Dict[str, Any]]:

        logger.info(f"AWS provider: loading Layer 1 check findings "
                    f"scan_run_id={scan_run_id} tenant={tenant_id}")

        # Layer 1 — existing check_findings for API gateway rules
        check_findings = load_check_findings(check_conn, scan_run_id, tenant_id)
        logger.info(f"AWS provider: {len(check_findings)} check findings loaded")

        # Layer 2 — discovery data for depth analysis
        api_resources = load_api_discoveries(
            discoveries_conn, scan_run_id, tenant_id, provider="aws"
        )
        waf_map = load_waf_associations(
            discoveries_conn, scan_run_id, tenant_id, provider="aws"
        )
        logger.info(f"AWS provider: {len(api_resources)} API resources discovered, "
                    f"{len(waf_map)} WAF associations")

        # Run depth-analysis modules
        all_findings: List[Dict[str, Any]] = list(check_findings)

        modules = [
            AuthSchemeModule(),
            ThrottleAuditModule(),
            WAFCoverageModule(waf_map=waf_map),
            VersioningAuditModule(),
            APIKeyExposureModule(),
        ]

        for module in modules:
            try:
                module_findings = module.run(
                    api_resources=api_resources,
                    scan_run_id=scan_run_id,
                    tenant_id=tenant_id,
                    account_id=account_id,
                )
                all_findings.extend(module_findings)
                logger.info(f"Module {module.__class__.__name__}: "
                            f"{len(module_findings)} findings")
            except Exception as exc:
                logger.error(f"Module {module.__class__.__name__} failed: {exc}",
                             exc_info=True)

        logger.info(f"AWS provider complete: {len(all_findings)} total findings")
        return all_findings
```

## Module Interface

Each module implements:

```python
class BaseModule:
    def run(
        self,
        api_resources: List[Dict[str, Any]],
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
    ) -> List[Dict[str, Any]]:
        ...
```

Each returned finding dict must include these keys (matching `api_security_findings` columns):
- `rule_id` — `str` matching pattern `aws.apigateway.<check_name>`
- `resource_uid` — `str` ARN or stable ID
- `resource_type` — `str` e.g. `aws.apigateway.rest_api`
- `severity` — `str` one of `critical|high|medium|low`
- `title` — `str`
- `description` — `str`
- `remediation` — `str`
- `owasp_api_category` — `str` e.g. `API2`
- `finding_source` — `str` `config` (module findings) or `behavioral` (CDR enriched, S2)
- `has_waf` — `bool`
- `has_rate_limit` — `bool`
- `is_publicly_accessible` — `bool`
- `auth_type` — `str`
- `api_gateway_id` — `str`
- `api_name` — `str` (optional)
- `api_stage` — `str` (optional)
- `evidence` — `dict` (will be stored as JSONB)

## Acceptance Criteria

- [ ] AC-1: `AWSAPISecProvider().analyze(...)` returns a list (never raises for module errors — logs and continues)
- [ ] AC-2: Findings from Layer 1 (check_findings) pass through unchanged
- [ ] AC-3: Module exception does NOT abort scan — only that module's findings are skipped, others complete
- [ ] AC-4: Each finding dict has `rule_id`, `resource_uid`, `severity`, `tenant_id` is NOT in the finding dict (injected by writer)
- [ ] AC-5: `get_provider("aws")` in providers/__init__.py returns AWSAPISecProvider instance
- [ ] AC-6: `get_provider("AWS")` (uppercase) also works — factory does `.lower()` on input

## Definition of Done
- [ ] `engines/api-security/api_security_engine/providers/aws.py` committed
- [ ] All 5 modules imported without ImportError
- [ ] Integrated with run_scan.py: `prov = get_provider("aws"); findings = prov.analyze(...)`
- [ ] Logger shows per-module finding counts in pod logs
