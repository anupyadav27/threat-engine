"""
DataSec Module Orchestrator — runs all evaluation modules and collects results.
Replaces the monolithic DataSecurityReporter.generate_report() flow.
"""
import logging
from typing import Dict, List, Any

from ..modules.base_module import BaseDataSecModule, ModuleResult
from ..modules.encryption_module import EncryptionModule
from ..modules.access_module import AccessModule
from ..modules.classification_module import ClassificationModule
from ..modules.residency_module import ResidencyModule
from ..modules.lifecycle_module import LifecycleModule
from ..modules.activity_module import ActivityModule
from ..modules.lineage_module import LineageModule
from ..rules.rule_loader import DataSecRuleLoader

logger = logging.getLogger(__name__)


MODULE_REGISTRY = {
    "data_protection_encryption": EncryptionModule,
    "data_access_governance": AccessModule,
    "data_classification": ClassificationModule,
    "data_residency": ResidencyModule,
    "data_lifecycle": LifecycleModule,
    "data_activity_monitoring": ActivityModule,
    "data_lineage": LineageModule,
}


class ModuleOrchestrator:
    def __init__(self, rule_loader: DataSecRuleLoader, tenant_id: str, csp: str = "aws"):
        self.rule_loader = rule_loader
        self.tenant_id = tenant_id
        self.csp = csp
        self.modules: Dict[str, BaseDataSecModule] = {}

    def initialize_modules(self):
        """Load rules from DB and instantiate all modules."""
        all_rules = self.rule_loader.load_all_rules(csp=self.csp, tenant_id=self.tenant_id)
        sensitive_patterns = self.rule_loader.load_sensitive_data_patterns()

        # Flatten sensitive_patterns: {category: [list of dicts]} → {type_key: regex_string}
        flat_patterns: Dict[str, str] = {}
        for cat_patterns in sensitive_patterns.values():
            for p in cat_patterns:
                pattern_str = p.get("pattern")
                if pattern_str and isinstance(pattern_str, str):
                    flat_patterns[p["type_key"]] = pattern_str

        for category, module_class in MODULE_REGISTRY.items():
            category_rules = all_rules.get(category, [])
            if module_class == ClassificationModule:
                self.modules[category] = module_class(
                    rules=category_rules, tenant_id=self.tenant_id,
                    sensitive_patterns=flat_patterns,
                )
            else:
                self.modules[category] = module_class(
                    rules=category_rules, tenant_id=self.tenant_id,
                )
        logger.info(f"Initialized {len(self.modules)} datasec modules for csp={self.csp}")

    def run_scan(
        self,
        findings: List[Dict[str, Any]],
        data_stores: List[Dict[str, Any]],
        context: Dict[str, Any],
    ) -> Dict[str, List[ModuleResult]]:
        """Execute all modules, return results grouped by category."""
        context.setdefault("csp", self.csp)
        results: Dict[str, List[ModuleResult]] = {}
        total = 0

        for category, module in self.modules.items():
            try:
                module_results = module.evaluate(findings, data_stores, context)
                results[category] = module_results
                total += len(module_results)
                logger.info(f"  {category}: {len(module_results)} results ({sum(1 for r in module_results if r.status == 'FAIL')} failures)")
            except Exception as e:
                logger.error(f"Module {category} failed: {e}", exc_info=True)
                results[category] = []

        logger.info(f"DataSec scan complete: {total} total results across {len(results)} modules")
        return results

    def get_summary(self, results: Dict[str, List[ModuleResult]]) -> Dict[str, Any]:
        """Generate summary statistics from module results."""
        total_findings = 0
        findings_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        findings_by_module = {}
        findings_by_status = {"PASS": 0, "FAIL": 0, "ERROR": 0, "SKIP": 0}

        for category, module_results in results.items():
            module_fail = sum(1 for r in module_results if r.status == "FAIL")
            module_pass = sum(1 for r in module_results if r.status == "PASS")
            findings_by_module[category] = {"total": len(module_results), "pass": module_pass, "fail": module_fail}

            for r in module_results:
                total_findings += 1
                findings_by_severity[r.severity] = findings_by_severity.get(r.severity, 0) + 1
                findings_by_status[r.status] = findings_by_status.get(r.status, 0) + 1

        return {
            "total_findings": total_findings,
            "findings_by_severity": findings_by_severity,
            "findings_by_module": findings_by_module,
            "findings_by_status": findings_by_status,
        }
