from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field


@dataclass
class ModuleResult:
    rule_id: str
    resource_uid: str
    resource_id: str
    resource_type: str
    status: str                              # PASS, FAIL, ERROR, SKIP
    severity: str                            # critical, high, medium, low, info
    category: str                            # matches datasec_rules.category
    title: str
    description: str = ""
    remediation: str = ""
    compliance_frameworks: List[str] = field(default_factory=list)
    sensitive_data_types: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaseDataSecModule(ABC):
    CATEGORY: str = ""

    def __init__(self, rules: List[Dict[str, Any]], tenant_id: str = "default"):
        self.rules = [r for r in rules if r.get("is_active", True)]
        self.tenant_id = tenant_id

    @abstractmethod
    def evaluate(self, findings: List[Dict], data_stores: List[Dict], context: Dict) -> List[ModuleResult]:
        pass

    def get_applicable_rules(self, csp: str, service: Optional[str] = None) -> List[Dict]:
        applicable = []
        for rule in self.rules:
            if rule.get("csp") != csp:
                continue
            if service and rule.get("service") != service:
                continue
            applicable.append(rule)
        return applicable
