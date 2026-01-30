#!/usr/bin/env python3
"""
Smart YAML Corrector - Intelligent correction engine for K8s compliance YAML files
Uses failure analysis to apply targeted fixes with confidence scoring
"""

import os
import re
import yaml
import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime

from .failure_analyzer import FailureAnalyzer, FailureAnalysis, FailureCategory

logger = logging.getLogger(__name__)


@dataclass
class CorrectionResult:
    """Result of a YAML correction operation"""
    file_path: str
    check_id: str
    applied: bool
    correction_type: str
    original_value: Any
    corrected_value: Any
    confidence: float
    error: Optional[str] = None
    backup_created: bool = False


class SmartYAMLCorrector:
    """Intelligent YAML corrector using failure analysis"""
    
    def __init__(self, services_dir: str = None, backup_dir: str = None):
        self.services_dir = Path(services_dir) if services_dir else Path(__file__).parent.parent / "services"
        self.backup_dir = Path(backup_dir) if backup_dir else self.services_dir.parent / "services_backup"
        self.backup_dir.mkdir(exist_ok=True)
        
        self.analyzer = FailureAnalyzer()
        self.correction_patterns = self._load_correction_patterns()
        self.applied_corrections = []
        
    def _load_correction_patterns(self) -> Dict[str, Dict]:
        """Load comprehensive correction patterns"""
        return {
            # Field path corrections
            "field_path_fixes": {
                "item.name": "item.metadata.name",
                "item.labels": "item.metadata.labels", 
                "item.annotations": "item.metadata.annotations",
                "item.namespace": "item.metadata.namespace",
                "item.uid": "item.metadata.uid",
                "item.creation_timestamp": "item.metadata.creationTimestamp",
                
                # Spec-level corrections
                "item.arguments": "item.spec.containers[0].args",
                "item.policy_types": "item.spec.policyTypes",
                "item.ports": "item.spec.ports",
                "item.selector": "item.spec.selector",
                "item.security_context": "item.spec.securityContext",
                "item.volumes": "item.spec.volumes",
                "item.containers": "item.spec.containers",
                "item.replicas": "item.spec.replicas",
                "item.strategy": "item.spec.strategy",
                
                # Status-level corrections
                "item.phase": "item.status.phase",
                "item.conditions": "item.status.conditions",
                "item.ready_replicas": "item.status.readyReplicas",
                
                # Pod-specific corrections
                "item.host_network": "item.spec.hostNetwork",
                "item.host_pid": "item.spec.hostPID", 
                "item.host_ipc": "item.spec.hostIPC",
                "item.service_account": "item.spec.serviceAccountName",
                "item.node_name": "item.spec.nodeName",
                "item.restart_policy": "item.spec.restartPolicy",
                
                # Container-specific corrections
                "item.image": "item.spec.containers[0].image",
                "item.image_pull_policy": "item.spec.containers[0].imagePullPolicy",
                "item.command": "item.spec.containers[0].command",
                "item.args": "item.spec.containers[0].args",
                "item.env": "item.spec.containers[0].env",
                "item.ports": "item.spec.containers[0].ports",
                "item.resources": "item.spec.containers[0].resources",
                "item.volume_mounts": "item.spec.containers[0].volumeMounts",
                
                # SecurityContext corrections
                "item.run_as_user": "item.spec.securityContext.runAsUser",
                "item.run_as_group": "item.spec.securityContext.runAsGroup", 
                "item.run_as_non_root": "item.spec.securityContext.runAsNonRoot",
                "item.read_only_root_filesystem": "item.spec.securityContext.readOnlyRootFilesystem",
                "item.allow_privilege_escalation": "item.spec.securityContext.allowPrivilegeEscalation",
                "item.privileged": "item.spec.securityContext.privileged",
                "item.capabilities": "item.spec.securityContext.capabilities",
                
                # Service-specific corrections
                "item.cluster_ip": "item.spec.clusterIP",
                "item.external_ips": "item.spec.externalIPs",
                "item.load_balancer_ip": "item.spec.loadBalancerIP",
                "item.session_affinity": "item.spec.sessionAffinity",
                "item.type": "item.spec.type",
                
                # NetworkPolicy corrections  
                "item.ingress": "item.spec.ingress",
                "item.egress": "item.spec.egress",
                "item.pod_selector": "item.spec.podSelector",
                
                # RBAC corrections
                "item.subjects": "item.subjects",
                "item.role_ref": "item.roleRef",
                "item.rules": "item.rules",
                "item.verbs": "item.rules[0].verbs",
                "item.resources": "item.rules[0].resources",
                "item.api_groups": "item.rules[0].apiGroups"
            },
            
            # Operator corrections
            "operator_fixes": {
                "contains": "in",
                "not_contains": "not_in",
                "equal": "equals",
                "not_equal": "not_equals", 
                "greater": "gt",
                "greater_equal": "gte",
                "less": "lt",
                "less_equal": "lte",
                "match": "regex",
                "not_match": "not_regex"
            },
            
            # Value type corrections
            "type_fixes": {
                "string_to_bool": {
                    "true": True, "false": False,
                    "True": True, "False": False,
                    "yes": True, "no": False,
                    "on": True, "off": False,
                    "enabled": True, "disabled": False
                },
                "bool_to_string": {
                    True: "true", False: "false"
                },
                "string_to_int": {
                    "auto_convert": True
                },
                "int_to_string": {
                    "auto_convert": True
                }
            },
            
            # K8s specific corrections
            "k8s_specific": {
                # Common field name corrections
                "policyTypes": "spec.policyTypes", 
                "podSelector": "spec.podSelector",
                "ingress": "spec.ingress",
                "egress": "spec.egress",
                "containers": "spec.containers",
                "securityContext": "spec.securityContext",
                "serviceAccountName": "spec.serviceAccountName",
                
                # Common annotation keys
                "kubernetes.io/managed-by": "metadata.annotations['kubernetes.io/managed-by']",
                "app.kubernetes.io/name": "metadata.labels['app.kubernetes.io/name']",
                "app.kubernetes.io/version": "metadata.labels['app.kubernetes.io/version']"
            }
        }
    
    def correct_failures(self, failures: List[Dict[str, Any]], 
                        max_corrections_per_file: int = 10) -> List[CorrectionResult]:
        """Apply corrections to YAML files based on failure analysis"""
        # Analyze failures first
        analyses = self.analyzer.analyze_batch_failures(failures)
        prioritized = self.analyzer.prioritize_fixes(analyses)
        
        logger.info(f"🔧 Starting correction of {len(prioritized)} failures...")
        
        results = []
        file_correction_count = {}
        
        for analysis in prioritized:
            # Skip if too many corrections already applied to this file
            service_files = self._get_service_files(analysis.service)
            if not service_files:
                continue
                
            applied_to_service = sum(1 for r in results if r.file_path in [str(f) for f in service_files])
            if applied_to_service >= max_corrections_per_file:
                logger.warning(f"⚠️  Skipping {analysis.check_id}: too many corrections for service {analysis.service}")
                continue
            
            # Apply correction
            correction_result = self._apply_correction(analysis)
            if correction_result:
                results.append(correction_result)
                self.applied_corrections.append(correction_result)
                
                if correction_result.applied:
                    logger.info(f"✅ Applied correction for {analysis.check_id}: {correction_result.correction_type}")
                else:
                    logger.warning(f"⚠️  Failed to apply correction for {analysis.check_id}: {correction_result.error}")
        
        logger.info(f"🎯 Correction complete. Applied {len([r for r in results if r.applied])}/{len(results)} corrections")
        return results
    
    def _apply_correction(self, analysis: FailureAnalysis) -> Optional[CorrectionResult]:
        """Apply a single correction based on failure analysis"""
        service_files = self._get_service_files(analysis.service)
        if not service_files:
            return CorrectionResult(
                file_path="",
                check_id=analysis.check_id,
                applied=False,
                correction_type="file_not_found",
                original_value=None,
                corrected_value=None,
                confidence=0.0,
                error=f"No YAML files found for service {analysis.service}"
            )
        
        # Try to find and correct the specific check
        for yaml_file in service_files:
            try:
                correction = self._correct_yaml_file(yaml_file, analysis)
                if correction and correction.applied:
                    return correction
            except Exception as e:
                logger.error(f"❌ Error correcting {yaml_file}: {e}")
                
        # If no successful correction, return failure result
        return CorrectionResult(
            file_path=str(service_files[0]) if service_files else "",
            check_id=analysis.check_id,
            applied=False,
            correction_type="correction_failed",
            original_value=None,
            corrected_value=None,
            confidence=analysis.fix_confidence,
            error="Could not apply correction to any YAML file"
        )
    
    def _correct_yaml_file(self, yaml_file: Path, analysis: FailureAnalysis) -> Optional[CorrectionResult]:
        """Apply correction to a specific YAML file"""
        try:
            # Load YAML content
            with open(yaml_file, 'r') as f:
                content = yaml.safe_load(f)
            
            if not content or not isinstance(content, dict):
                return None
            
            # Create backup
            backup_path = self._create_backup(yaml_file)
            
            # Apply correction based on failure category
            original_content = yaml.dump(content, default_flow_style=False)
            corrected = False
            correction_type = "unknown"
            original_value = None
            corrected_value = None
            
            if analysis.category == FailureCategory.FIELD_PATH_ERROR:
                corrected, correction_type, original_value, corrected_value = self._fix_field_path(
                    content, analysis
                )
            elif analysis.category == FailureCategory.OPERATOR_ERROR:
                corrected, correction_type, original_value, corrected_value = self._fix_operator(
                    content, analysis
                )
            elif analysis.category == FailureCategory.VALUE_TYPE_ERROR:
                corrected, correction_type, original_value, corrected_value = self._fix_value_type(
                    content, analysis
                )
            elif analysis.category == FailureCategory.API_SCHEMA_MISMATCH:
                corrected, correction_type, original_value, corrected_value = self._fix_api_schema(
                    content, analysis
                )
            
            # Save corrected content if changes were made
            if corrected:
                with open(yaml_file, 'w') as f:
                    yaml.dump(content, f, default_flow_style=False, sort_keys=False)
            
            return CorrectionResult(
                file_path=str(yaml_file),
                check_id=analysis.check_id,
                applied=corrected,
                correction_type=correction_type,
                original_value=original_value,
                corrected_value=corrected_value,
                confidence=analysis.fix_confidence,
                backup_created=backup_path is not None
            )
            
        except Exception as e:
            return CorrectionResult(
                file_path=str(yaml_file),
                check_id=analysis.check_id,
                applied=False,
                correction_type="error",
                original_value=None,
                corrected_value=None,
                confidence=0.0,
                error=str(e)
            )
    
    def _fix_field_path(self, content: Dict, analysis: FailureAnalysis) -> Tuple[bool, str, Any, Any]:
        """Fix field path errors in YAML content"""
        if not analysis.field_path:
            return False, "no_field_path", None, None
        
        # Look for the field path in correction patterns
        field_fixes = self.correction_patterns["field_path_fixes"]
        if analysis.field_path in field_fixes:
            corrected_path = field_fixes[analysis.field_path]
            
            # Find and update the field in YAML content
            checks = content.get("checks", [])
            for check in checks:
                if check.get("check_id") == analysis.check_id:
                    # Update field paths in calls
                    calls = check.get("calls", [])
                    for call in calls:
                        fields = call.get("fields", [])
                        for field in fields:
                            if field.get("path") == analysis.field_path:
                                old_path = field["path"]
                                field["path"] = corrected_path
                                return True, f"field_path_correction:{old_path}->{corrected_path}", old_path, corrected_path
        
        return False, "field_path_not_found", None, None
    
    def _fix_operator(self, content: Dict, analysis: FailureAnalysis) -> Tuple[bool, str, Any, Any]:
        """Fix operator errors in YAML content"""
        operator_fixes = self.correction_patterns["operator_fixes"]
        
        checks = content.get("checks", [])
        for check in checks:
            if check.get("check_id") == analysis.check_id:
                calls = check.get("calls", [])
                for call in calls:
                    fields = call.get("fields", [])
                    for field in fields:
                        current_op = field.get("operator")
                        if current_op in operator_fixes:
                            old_op = current_op
                            new_op = operator_fixes[current_op]
                            field["operator"] = new_op
                            return True, f"operator_correction:{old_op}->{new_op}", old_op, new_op
        
        return False, "operator_not_found", None, None
    
    def _fix_value_type(self, content: Dict, analysis: FailureAnalysis) -> Tuple[bool, str, Any, Any]:
        """Fix value type errors in YAML content"""
        type_fixes = self.correction_patterns["type_fixes"]
        
        checks = content.get("checks", [])
        for check in checks:
            if check.get("check_id") == analysis.check_id:
                calls = check.get("calls", [])
                for call in calls:
                    fields = call.get("fields", [])
                    for field in fields:
                        expected = field.get("expected")
                        if expected is not None:
                            # String to boolean conversion
                            if isinstance(expected, str) and expected.lower() in type_fixes["string_to_bool"]:
                                old_val = expected
                                new_val = type_fixes["string_to_bool"][expected.lower()]
                                field["expected"] = new_val
                                return True, f"type_correction:string_to_bool", old_val, new_val
                            
                            # String to int conversion
                            elif isinstance(expected, str) and expected.isdigit():
                                old_val = expected
                                new_val = int(expected)
                                field["expected"] = new_val
                                return True, f"type_correction:string_to_int", old_val, new_val
        
        return False, "type_correction_not_applicable", None, None
    
    def _fix_api_schema(self, content: Dict, analysis: FailureAnalysis) -> Tuple[bool, str, Any, Any]:
        """Fix API schema mismatch errors"""
        # Common K8s API schema fixes
        k8s_fixes = self.correction_patterns["k8s_specific"]
        
        checks = content.get("checks", [])
        for check in checks:
            if check.get("check_id") == analysis.check_id:
                calls = check.get("calls", [])
                for call in calls:
                    fields = call.get("fields", [])
                    for field in fields:
                        path = field.get("path", "")
                        
                        # Check for common schema mismatches
                        for wrong_field, correct_field in k8s_fixes.items():
                            if wrong_field in path:
                                old_path = path
                                new_path = path.replace(wrong_field, correct_field)
                                field["path"] = new_path
                                return True, f"schema_correction:{wrong_field}->{correct_field}", old_path, new_path
        
        return False, "schema_correction_not_found", None, None
    
    def _get_service_files(self, service: str) -> List[Path]:
        """Get YAML files for a service"""
        service_dir = self.services_dir / service
        if not service_dir.exists():
            return []
        
        yaml_files = []
        for file_path in service_dir.rglob("*.yaml"):
            yaml_files.append(file_path)
        
        return yaml_files
    
    def _create_backup(self, yaml_file: Path) -> Optional[Path]:
        """Create backup of YAML file before modification"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"{yaml_file.stem}_{timestamp}.yaml"
            backup_path = self.backup_dir / yaml_file.parent.name / backup_name
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Copy original file
            import shutil
            shutil.copy2(yaml_file, backup_path)
            
            return backup_path
            
        except Exception as e:
            logger.error(f"❌ Failed to create backup for {yaml_file}: {e}")
            return None
    
    def rollback_corrections(self, correction_results: List[CorrectionResult]) -> int:
        """Rollback applied corrections using backups"""
        rollback_count = 0
        
        for result in correction_results:
            if result.applied and result.backup_created:
                try:
                    # Find backup file
                    yaml_file = Path(result.file_path)
                    backup_pattern = f"{yaml_file.stem}_*{yaml_file.suffix}"
                    backup_dir = self.backup_dir / yaml_file.parent.name
                    
                    backup_files = list(backup_dir.glob(backup_pattern))
                    if backup_files:
                        # Use most recent backup
                        latest_backup = max(backup_files, key=lambda p: p.stat().st_mtime)
                        
                        # Restore from backup
                        import shutil
                        shutil.copy2(latest_backup, yaml_file)
                        rollback_count += 1
                        logger.info(f"🔄 Rolled back {result.check_id}")
                        
                except Exception as e:
                    logger.error(f"❌ Failed to rollback {result.check_id}: {e}")
        
        logger.info(f"🔄 Rollback complete. Restored {rollback_count} files")
        return rollback_count
    
    def generate_correction_report(self, correction_results: List[CorrectionResult]) -> Dict[str, Any]:
        """Generate comprehensive correction report"""
        total_corrections = len(correction_results)
        applied_corrections = [r for r in correction_results if r.applied]
        failed_corrections = [r for r in correction_results if not r.applied]
        
        # Group by correction type
        by_type = {}
        for result in applied_corrections:
            correction_type = result.correction_type
            by_type[correction_type] = by_type.get(correction_type, 0) + 1
        
        # Group by confidence
        high_confidence = [r for r in applied_corrections if r.confidence >= 0.7]
        medium_confidence = [r for r in applied_corrections if 0.4 <= r.confidence < 0.7]
        low_confidence = [r for r in applied_corrections if r.confidence < 0.4]
        
        return {
            "summary": {
                "total_corrections": total_corrections,
                "applied": len(applied_corrections),
                "failed": len(failed_corrections),
                "success_rate": round(len(applied_corrections) / total_corrections * 100, 2) if total_corrections > 0 else 0
            },
            "by_type": by_type,
            "by_confidence": {
                "high": len(high_confidence),
                "medium": len(medium_confidence), 
                "low": len(low_confidence)
            },
            "high_confidence_corrections": [
                {
                    "check_id": r.check_id,
                    "type": r.correction_type,
                    "confidence": r.confidence,
                    "file": str(Path(r.file_path).name) if r.file_path else "unknown"
                }
                for r in high_confidence
            ],
            "failed_corrections": [
                {
                    "check_id": r.check_id,
                    "error": r.error,
                    "file": str(Path(r.file_path).name) if r.file_path else "unknown"
                }
                for r in failed_corrections
            ],
            "timestamp": datetime.now().isoformat()
        }


def main():
    """CLI interface for smart YAML correction"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Smart YAML Corrector for K8s compliance checks")
    parser.add_argument("failures_file", help="JSON file containing failure data")
    parser.add_argument("--services-dir", help="Directory containing service YAML files")
    parser.add_argument("--backup-dir", help="Directory for YAML backups")
    parser.add_argument("--max-per-file", type=int, default=10, help="Max corrections per file")
    parser.add_argument("--output", help="Output file for correction report")
    parser.add_argument("--rollback", action="store_true", help="Rollback previous corrections")
    
    args = parser.parse_args()
    
    # Create corrector
    corrector = SmartYAMLCorrector(
        services_dir=args.services_dir,
        backup_dir=args.backup_dir
    )
    
    if args.rollback:
        # Load previous correction results and rollback
        if os.path.exists("correction_results.json"):
            with open("correction_results.json", 'r') as f:
                prev_results = json.load(f)
                results = [CorrectionResult(**r) for r in prev_results.get("corrections", [])]
                rollback_count = corrector.rollback_corrections(results)
                print(f"Rolled back {rollback_count} corrections")
        else:
            print("No previous corrections found to rollback")
        return
    
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
    
    # Apply corrections
    correction_results = corrector.correct_failures(failures, max_corrections_per_file=args.max_per_file)
    
    # Generate report
    report = corrector.generate_correction_report(correction_results)
    report["corrections"] = [result.__dict__ for result in correction_results]
    
    # Save report
    output_file = args.output or "correction_report.json"
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    # Also save correction results for potential rollback
    with open("correction_results.json", 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"Correction complete. Report saved to: {output_file}")
    print(f"Applied {report['summary']['applied']}/{report['summary']['total_corrections']} corrections")


if __name__ == "__main__":
    main()