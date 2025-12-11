#!/usr/bin/env python3
"""
Failure Analyzer - Categorizes and prioritizes K8s compliance check failures
Provides detailed analysis and intelligent correction suggestions
"""

import re
import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum
from dataclasses import dataclass, asdict
from datetime import datetime

logger = logging.getLogger(__name__)


class FailureCategory(Enum):
    """Categories of compliance check failures"""
    API_SCHEMA_MISMATCH = "api_schema_mismatch"
    RESOURCE_NOT_FOUND = "resource_not_found"
    PERMISSION_DENIED = "permission_denied"
    FIELD_PATH_ERROR = "field_path_error"
    VALUE_TYPE_ERROR = "value_type_error"
    OPERATOR_ERROR = "operator_error"
    CONFIGURATION_MISSING = "configuration_missing"
    NAMESPACE_ISOLATION = "namespace_isolation"
    RBAC_POLICY = "rbac_policy"
    NETWORK_POLICY = "network_policy"
    SECURITY_CONTEXT = "security_context"
    RESOURCE_LIMITS = "resource_limits"
    UNKNOWN = "unknown"


class FailureSeverity(Enum):
    """Severity levels for failure analysis"""
    CRITICAL = "critical"    # Blocks multiple checks, core functionality
    HIGH = "high"           # Security-related, compliance critical
    MEDIUM = "medium"       # Functional issues, moderate impact
    LOW = "low"            # Minor issues, cosmetic


@dataclass
class FailureAnalysis:
    """Structured failure analysis result"""
    check_id: str
    service: str
    category: FailureCategory
    severity: FailureSeverity
    error_message: str
    field_path: Optional[str] = None
    suggested_fix: Optional[str] = None
    fix_confidence: float = 0.0  # 0.0 to 1.0
    related_failures: List[str] = None
    fix_pattern: Optional[str] = None
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()
        if self.related_failures is None:
            self.related_failures = []


class FailureAnalyzer:
    """Analyzes K8s compliance check failures and suggests corrections"""
    
    def __init__(self):
        self.failure_patterns = self._load_failure_patterns()
        self.fix_suggestions = self._load_fix_suggestions()
        
    def _load_failure_patterns(self) -> Dict[str, Dict]:
        """Load patterns for failure categorization"""
        return {
            # API Schema Mismatches
            "api_schema_mismatch": {
                "patterns": [
                    r"KeyError.*'(\w+)'.*not found",
                    r"AttributeError.*'(\w+)'.*has no attribute",
                    r"field.*does not exist",
                    r"unknown field.*in.*spec"
                ],
                "severity": FailureSeverity.HIGH,
                "fix_confidence": 0.8
            },
            
            # Resource Not Found
            "resource_not_found": {
                "patterns": [
                    r"NotFound.*(\w+).*not found",
                    r"404.*Not Found",
                    r"resource.*does not exist",
                    r"no matches for.*"
                ],
                "severity": FailureSeverity.MEDIUM,
                "fix_confidence": 0.6
            },
            
            # Permission Issues
            "permission_denied": {
                "patterns": [
                    r"403.*Forbidden",
                    r"Unauthorized.*401",
                    r"permission denied",
                    r"RBAC.*denied"
                ],
                "severity": FailureSeverity.CRITICAL,
                "fix_confidence": 0.3
            },
            
            # Field Path Errors
            "field_path_error": {
                "patterns": [
                    r"invalid field path",
                    r"field.*(\w+\.\w+\.\w+).*not found",
                    r"path.*does not exist",
                    r"cannot resolve.*path"
                ],
                "severity": FailureSeverity.HIGH,
                "fix_confidence": 0.9
            },
            
            # Value Type Errors
            "value_type_error": {
                "patterns": [
                    r"expected.*but got.*",
                    r"TypeError.*expected.*",
                    r"invalid value type",
                    r"cannot convert.*to.*"
                ],
                "severity": FailureSeverity.MEDIUM,
                "fix_confidence": 0.7
            },
            
            # Operator Errors
            "operator_error": {
                "patterns": [
                    r"operator.*not supported",
                    r"invalid operator.*",
                    r"comparison failed",
                    r"evaluation error"
                ],
                "severity": FailureSeverity.HIGH,
                "fix_confidence": 0.8
            },
            
            # Configuration Missing
            "configuration_missing": {
                "patterns": [
                    r"configuration.*missing",
                    r"required field.*not specified",
                    r"mandatory.*not found",
                    r"missing required.*"
                ],
                "severity": FailureSeverity.HIGH,
                "fix_confidence": 0.6
            }
        }
    
    def _load_fix_suggestions(self) -> Dict[str, Dict]:
        """Load fix suggestions for common failure patterns"""
        return {
            "field_path_error": {
                "item.name": "item.metadata.name",
                "item.labels": "item.metadata.labels",
                "item.annotations": "item.metadata.annotations",
                "item.namespace": "item.metadata.namespace",
                "item.uid": "item.metadata.uid",
                "item.arguments": "item.spec.containers[0].args",
                "item.policy_types": "item.spec.policyTypes",
                "item.ports": "item.spec.ports",
                "item.selector": "item.spec.selector",
                "item.security_context": "item.spec.securityContext",
                "item.volumes": "item.spec.volumes"
            },
            
            "operator_error": {
                "contains": "in",
                "not_contains": "not_in", 
                "equal": "equals",
                "not_equal": "not_equals",
                "greater": "gt",
                "less": "lt"
            },
            
            "value_type_error": {
                "string_to_bool": {"true": True, "false": False, "True": True, "False": False},
                "string_to_int": {"auto_convert": True},
                "list_to_string": {"join_with": ","}
            }
        }
    
    def analyze_failure(self, check_result: Dict[str, Any]) -> FailureAnalysis:
        """Analyze a single check failure and return structured analysis"""
        check_id = check_result.get("check_id", "unknown")
        service = self._extract_service_from_check_id(check_id)
        error_message = check_result.get("error", "")
        
        # Categorize failure
        category = self._categorize_failure(error_message)
        
        # Determine severity
        severity = self._determine_severity(category, check_id, error_message)
        
        # Extract field path if available
        field_path = self._extract_field_path(error_message)
        
        # Generate fix suggestion
        suggested_fix, fix_confidence, fix_pattern = self._suggest_fix(
            category, error_message, field_path, check_id
        )
        
        return FailureAnalysis(
            check_id=check_id,
            service=service,
            category=category,
            severity=severity,
            error_message=error_message,
            field_path=field_path,
            suggested_fix=suggested_fix,
            fix_confidence=fix_confidence,
            fix_pattern=fix_pattern
        )
    
    def analyze_batch_failures(self, failures: List[Dict[str, Any]]) -> List[FailureAnalysis]:
        """Analyze multiple failures and identify relationships"""
        analyses = []
        
        # Analyze individual failures
        for failure in failures:
            analysis = self.analyze_failure(failure)
            analyses.append(analysis)
        
        # Identify related failures
        self._identify_related_failures(analyses)
        
        return analyses
    
    def _categorize_failure(self, error_message: str) -> FailureCategory:
        """Categorize failure based on error message patterns"""
        for category_name, config in self.failure_patterns.items():
            for pattern in config["patterns"]:
                if re.search(pattern, error_message, re.IGNORECASE):
                    return FailureCategory(category_name)
        
        return FailureCategory.UNKNOWN
    
    def _determine_severity(self, category: FailureCategory, check_id: str, error_message: str) -> FailureSeverity:
        """Determine severity based on category, check type, and context"""
        # Use pattern-based severity as baseline
        pattern_config = self.failure_patterns.get(category.value, {})
        base_severity = pattern_config.get("severity", FailureSeverity.MEDIUM)
        
        # Adjust based on check type
        if any(keyword in check_id.lower() for keyword in ["security", "rbac", "policy"]):
            if base_severity == FailureSeverity.MEDIUM:
                return FailureSeverity.HIGH
            elif base_severity == FailureSeverity.LOW:
                return FailureSeverity.MEDIUM
        
        # Critical security contexts
        if any(keyword in check_id.lower() for keyword in ["root", "privileged", "hostnetwork"]):
            return FailureSeverity.CRITICAL
        
        return base_severity
    
    def _extract_field_path(self, error_message: str) -> Optional[str]:
        """Extract field path from error message"""
        # Common field path patterns
        patterns = [
            r"field path[:\s]*['\"]([^'\"]+)['\"]",
            r"path[:\s]*['\"]([^'\"]+)['\"]",
            r"field[:\s]*['\"]([^'\"]+)['\"]",
            r"KeyError[:\s]*['\"]([^'\"]+)['\"]"
        ]
        
        for pattern in patterns:
            match = re.search(pattern, error_message, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def _suggest_fix(self, category: FailureCategory, error_message: str, 
                    field_path: Optional[str], check_id: str) -> Tuple[Optional[str], float, Optional[str]]:
        """Generate fix suggestion based on failure analysis"""
        suggestions = self.fix_suggestions.get(category.value, {})
        base_confidence = self.failure_patterns.get(category.value, {}).get("fix_confidence", 0.5)
        
        if category == FailureCategory.FIELD_PATH_ERROR and field_path:
            # Field path corrections
            if field_path in suggestions:
                return suggestions[field_path], base_confidence, f"field_path:{field_path}"
            
            # Smart field path suggestions
            if "." in field_path:
                parts = field_path.split(".")
                if len(parts) >= 2 and parts[1] in ["name", "labels", "annotations", "namespace"]:
                    corrected = f"{parts[0]}.metadata.{parts[1]}"
                    return corrected, base_confidence * 0.9, f"metadata_prefix:{field_path}"
        
        elif category == FailureCategory.OPERATOR_ERROR:
            # Operator corrections
            for wrong_op, correct_op in suggestions.items():
                if wrong_op in error_message.lower():
                    return f"Change operator to '{correct_op}'", base_confidence, f"operator:{wrong_op}"
        
        elif category == FailureCategory.API_SCHEMA_MISMATCH:
            # Schema-based suggestions
            if "arguments" in error_message.lower():
                return "item.spec.containers[0].args", base_confidence, "container_args_fix"
            elif "policy_types" in error_message.lower():
                return "item.spec.policyTypes", base_confidence, "policy_types_fix"
        
        # Generic suggestions based on check type
        if "security" in check_id.lower():
            return "Review securityContext fields and paths", base_confidence * 0.3, "security_generic"
        elif "rbac" in check_id.lower():
            return "Check RBAC resource paths and permissions", base_confidence * 0.3, "rbac_generic"
        elif "network" in check_id.lower():
            return "Verify NetworkPolicy spec fields", base_confidence * 0.3, "network_generic"
        
        return None, 0.0, None
    
    def _extract_service_from_check_id(self, check_id: str) -> str:
        """Extract service name from check ID"""
        parts = check_id.split(".")
        if len(parts) >= 2:
            return parts[1]  # e.g., k8s.pod.security -> pod
        return "unknown"
    
    def _identify_related_failures(self, analyses: List[FailureAnalysis]) -> None:
        """Identify related failures that might have common root causes"""
        for i, analysis in enumerate(analyses):
            related = []
            
            for j, other in enumerate(analyses):
                if i != j:
                    # Same service failures
                    if analysis.service == other.service:
                        related.append(other.check_id)
                    
                    # Same category failures
                    elif analysis.category == other.category and analysis.category != FailureCategory.UNKNOWN:
                        related.append(other.check_id)
                    
                    # Same fix pattern
                    elif (analysis.fix_pattern and other.fix_pattern and 
                          analysis.fix_pattern == other.fix_pattern):
                        related.append(other.check_id)
            
            analysis.related_failures = related[:5]  # Limit to top 5 related
    
    def generate_failure_report(self, analyses: List[FailureAnalysis]) -> Dict[str, Any]:
        """Generate comprehensive failure analysis report"""
        if not analyses:
            return {"summary": "No failures to analyze"}
        
        # Summary statistics
        total_failures = len(analyses)
        by_category = {}
        by_severity = {}
        by_service = {}
        fixable_count = 0
        high_confidence_fixes = 0
        
        for analysis in analyses:
            # Category stats
            cat = analysis.category.value
            by_category[cat] = by_category.get(cat, 0) + 1
            
            # Severity stats
            sev = analysis.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1
            
            # Service stats
            service = analysis.service
            by_service[service] = by_service.get(service, 0) + 1
            
            # Fixability stats
            if analysis.suggested_fix:
                fixable_count += 1
                if analysis.fix_confidence >= 0.7:
                    high_confidence_fixes += 1
        
        # Top issues
        top_categories = sorted(by_category.items(), key=lambda x: x[1], reverse=True)[:5]
        top_services = sorted(by_service.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # High-confidence fixes
        high_confidence_analyses = [a for a in analyses if a.fix_confidence >= 0.7]
        
        return {
            "summary": {
                "total_failures": total_failures,
                "by_category": by_category,
                "by_severity": by_severity,
                "by_service": by_service,
                "fixable_failures": fixable_count,
                "high_confidence_fixes": high_confidence_fixes,
                "fixability_rate": round(fixable_count / total_failures * 100, 2) if total_failures > 0 else 0
            },
            "top_issues": {
                "categories": top_categories,
                "services": top_services
            },
            "high_confidence_fixes": [asdict(a) for a in high_confidence_analyses],
            "all_analyses": [asdict(a) for a in analyses],
            "timestamp": datetime.now().isoformat()
        }
    
    def prioritize_fixes(self, analyses: List[FailureAnalysis]) -> List[FailureAnalysis]:
        """Prioritize failures for fixing based on impact and confidence"""
        def priority_score(analysis: FailureAnalysis) -> float:
            # Base score from severity
            severity_scores = {
                FailureSeverity.CRITICAL: 100,
                FailureSeverity.HIGH: 75,
                FailureSeverity.MEDIUM: 50,
                FailureSeverity.LOW: 25
            }
            score = severity_scores.get(analysis.severity, 25)
            
            # Boost for high-confidence fixes
            score *= (1 + analysis.fix_confidence)
            
            # Boost for failures with many related issues (root cause potential)
            score *= (1 + len(analysis.related_failures) * 0.1)
            
            # Penalty for unknown category
            if analysis.category == FailureCategory.UNKNOWN:
                score *= 0.5
            
            return score
        
        return sorted(analyses, key=priority_score, reverse=True)


def main():
    """CLI interface for failure analysis"""
    import argparse
    import json
    
    parser = argparse.ArgumentParser(description="Analyze K8s compliance check failures")
    parser.add_argument("failures_file", help="JSON file containing failure data")
    parser.add_argument("--output", help="Output file for analysis report")
    
    args = parser.parse_args()
    
    # Load failures
    with open(args.failures_file, 'r') as f:
        data = json.load(f)
    
    failures = []
    if isinstance(data, dict) and "results" in data:
        for service_result in data["results"].values():
            failures.extend(service_result.get("failures", []))
    elif isinstance(data, list):
        failures = data
    
    if not failures:
        print("No failures found in input file")
        return
    
    # Analyze failures
    analyzer = FailureAnalyzer()
    analyses = analyzer.analyze_batch_failures(failures)
    
    # Generate report
    report = analyzer.generate_failure_report(analyses)
    
    # Save or print report
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"Analysis report saved to: {args.output}")
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()