import logging
from typing import Any, Dict, List

from api_security_engine.providers.base import BaseAPISecProvider
from api_security_engine.input.check_finding_reader import load_check_findings
from api_security_engine.input.discovery_reader import load_api_discoveries, load_waf_associations
from api_security_engine.modules.auth_scheme import AuthSchemeModule
from api_security_engine.modules.throttle_audit import ThrottleAuditModule
from api_security_engine.modules.waf_coverage import WAFCoverageModule
from api_security_engine.modules.versioning_audit import VersioningAuditModule
from api_security_engine.modules.api_key_exposure import APIKeyExposureModule
from api_security_engine.modules.backend_ssrf import BackendSSRFModule
from api_security_engine.modules.mtls_gap import MTLSGapModule
from api_security_engine.modules.graphql_introspection import GraphQLIntrospectionModule
from api_security_engine.modules.spec_validation import SpecValidationModule

logger = logging.getLogger("api_security.aws_provider")


class AWSAPISecProvider(BaseAPISecProvider):
    """AWS API Security provider.

    Layer 1: Loads existing FAIL check_findings for API gateway rules.
    Layer 2: Loads discovery_findings for API gateway resources and runs
             depth-analysis modules to produce additional findings.
    """

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        discoveries_conn,
        check_conn,
    ) -> List[Dict[str, Any]]:
        logger.info(
            f"AWS provider: loading Layer 1 check findings "
            f"scan_run_id={scan_run_id} tenant={tenant_id}"
        )

        check_findings = load_check_findings(check_conn, scan_run_id, tenant_id)
        logger.info(f"AWS provider: {len(check_findings)} check findings loaded")

        api_resources = load_api_discoveries(
            discoveries_conn, scan_run_id, tenant_id, provider="aws"
        )
        waf_map = load_waf_associations(
            discoveries_conn, scan_run_id, tenant_id, provider="aws"
        )
        logger.info(
            f"AWS provider: {len(api_resources)} API resources discovered, "
            f"{len(waf_map)} WAF associations"
        )

        all_findings: List[Dict[str, Any]] = list(check_findings)

        modules = [
            AuthSchemeModule(),
            ThrottleAuditModule(),
            WAFCoverageModule(waf_map=waf_map),
            VersioningAuditModule(),
            APIKeyExposureModule(),
            BackendSSRFModule(),
            MTLSGapModule(),
            GraphQLIntrospectionModule(),
            SpecValidationModule(),
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
                logger.info(
                    f"Module {module.__class__.__name__}: {len(module_findings)} findings"
                )
            except Exception as exc:
                logger.error(
                    f"Module {module.__class__.__name__} failed: {exc}", exc_info=True
                )

        logger.info(f"AWS provider complete: {len(all_findings)} total findings")
        return all_findings
