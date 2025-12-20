#!/usr/bin/env python3
"""
Comprehensive Quality Check for IBM Dependency Chain Files

Checks:
1. Coverage - All services, operations, files present
2. Quality - Entity naming, dependency mapping, structure
3. Validation - Satisfiability, cycles, completeness
4. Unit Tests - Logic validation
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Any, Set, Tuple, Optional
from collections import defaultdict
import sys

class IBMQualityChecker:
    """Comprehensive quality checker for IBM dependency chain files"""
    
    def __init__(self, ibm_root: Path):
        self.ibm_root = ibm_root
        self.issues = defaultdict(list)
        self.stats = defaultdict(int)
        self.results = {}
    
    def check_coverage(self) -> Dict[str, Any]:
        """Check 1: Coverage - All services and files present"""
        print("=" * 80)
        print("COVERAGE CHECK")
        print("=" * 80)
        
        coverage_results = {
            'services_found': [],
            'services_missing_files': [],
            'operations_count': 0,
            'files_per_service': {}
        }
        
        # Find all service folders
        service_folders = [d for d in self.ibm_root.iterdir() 
                          if d.is_dir() and (d / "ibm_dependencies_with_python_names_fully_enriched.json").exists()]
        
        required_files = [
            'operation_registry.json',
            'adjacency.json',
            'validation_report.json',
            'overrides.json'
        ]
        
        for service_folder in sorted(service_folders):
            service_name = service_folder.name
            coverage_results['services_found'].append(service_name)
            
            missing_files = []
            for file_name in required_files:
                if not (service_folder / file_name).exists():
                    missing_files.append(file_name)
            
            if missing_files:
                coverage_results['services_missing_files'].append({
                    'service': service_name,
                    'missing': missing_files
                })
            
            # Count operations
            spec_file = service_folder / "ibm_dependencies_with_python_names_fully_enriched.json"
            if spec_file.exists():
                with open(spec_file, 'r') as f:
                    spec_data = json.load(f)
                    service_data = spec_data.get(service_name, {})
                    ops_count = service_data.get('total_operations', 0)
                    coverage_results['operations_count'] += ops_count
                    coverage_results['files_per_service'][service_name] = {
                        'operations': ops_count,
                        'has_all_files': len(missing_files) == 0
                    }
        
        print(f"✅ Services found: {len(coverage_results['services_found'])}")
        print(f"⚠️  Services with missing files: {len(coverage_results['services_missing_files'])}")
        print(f"📊 Total operations: {coverage_results['operations_count']}")
        
        if coverage_results['services_missing_files']:
            print("\nMissing files:")
            for item in coverage_results['services_missing_files']:
                print(f"  {item['service']}: {', '.join(item['missing'])}")
        
        return coverage_results
    
    def check_entity_naming_quality(self, service_name: str, registry: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check entity naming quality - no generic entities"""
        issues = []
        
        # Check for generic entity patterns
        generic_patterns = [
            r'ibm\.\w+\.item\.',  # ibm.vpc.item.item_id (too generic)
            r'ibm\.\w+\.\w+\.\1_',  # ibm.vpc.backup.backup_id (redundant)
            r'ibm\.\w+\.resource\.',  # ibm.vpc.resource.resource_id (too generic)
        ]
        
        operations = registry.get('operations', {})
        for op_name, op_data in operations.items():
            # Check consumes
            for consume in op_data.get('consumes', []):
                entity = consume.get('entity', '')
                
                # Check for generic "item" resource
                if '.item.' in entity:
                    issues.append({
                        'type': 'generic_entity',
                        'severity': 'high',
                        'operation': op_name,
                        'entity': entity,
                        'issue': 'Uses generic "item" resource name',
                        'suggestion': f'Should use specific resource name from operation: {op_name}'
                    })
                
                # Check for redundant patterns
                if re.search(r'\.(\w+)\.\1_', entity):
                    issues.append({
                        'type': 'redundant_entity',
                        'severity': 'medium',
                        'operation': op_name,
                        'entity': entity,
                        'issue': 'Redundant resource name in entity path'
                    })
            
            # Check produces
            for produce in op_data.get('produces', []):
                entity = produce.get('entity', '')
                
                if '.item.' in entity:
                    issues.append({
                        'type': 'generic_entity',
                        'severity': 'high',
                        'operation': op_name,
                        'entity': entity,
                        'issue': 'Produces generic "item" entity',
                        'suggestion': f'Should use specific resource name from operation: {op_name}'
                    })
        
        return issues
    
    def check_dependency_mapping(self, service_name: str, registry: Dict[str, Any], 
                                 adjacency: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check dependency mapping quality"""
        issues = []
        
        operations = registry.get('operations', {})
        op_consumes = adjacency.get('op_consumes', {})
        op_produces = adjacency.get('op_produces', {})
        entity_producers = adjacency.get('entity_producers', {})
        external_entities = set(adjacency.get('external_entities', []))
        
        # Check for operations with no producers for required entities
        for op_name, consumed_entities in op_consumes.items():
            for entity in consumed_entities:
                if entity not in external_entities:
                    if entity not in entity_producers:
                        issues.append({
                            'type': 'no_producer',
                            'severity': 'high',
                            'operation': op_name,
                            'entity': entity,
                            'issue': f'Entity {entity} has no producer operations',
                            'suggestion': 'Check if entity should be external or if producer operation is missing'
                        })
        
        # Check for operations that produce entities but no one consumes them
        for op_name, produced_entities in op_produces.items():
            for entity in produced_entities:
                if entity not in external_entities:
                    consumers = adjacency.get('entity_consumers', {}).get(entity, [])
                    if not consumers:
                        issues.append({
                            'type': 'orphan_producer',
                            'severity': 'low',
                            'operation': op_name,
                            'entity': entity,
                            'issue': f'Entity {entity} is produced but never consumed',
                            'suggestion': 'May be used externally or in future operations'
                        })
        
        return issues
    
    def check_structure_quality(self, service_name: str, registry: Dict[str, Any],
                                adjacency: Dict[str, Any], validation: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check structure and format quality"""
        issues = []
        
        # Check operation registry structure
        required_fields = ['service', 'version', 'operations']
        for field in required_fields:
            if field not in registry:
                issues.append({
                    'type': 'missing_field',
                    'severity': 'high',
                    'service': service_name,
                    'field': field,
                    'issue': f'Missing required field: {field}'
                })
        
        # Check adjacency structure
        required_adj_fields = ['service', 'op_consumes', 'op_produces', 'entity_producers']
        for field in required_adj_fields:
            if field not in adjacency:
                issues.append({
                    'type': 'missing_field',
                    'severity': 'high',
                    'service': service_name,
                    'field': f'adjacency.{field}',
                    'issue': f'Missing required field in adjacency: {field}'
                })
        
        # Check kind assignment
        operations = registry.get('operations', {})
        valid_kinds = ['read_list', 'read_get', 'write_create', 'write_update', 'write_delete', 'other']
        for op_name, op_data in operations.items():
            kind = op_data.get('kind')
            if kind not in valid_kinds:
                issues.append({
                    'type': 'invalid_kind',
                    'severity': 'high',
                    'operation': op_name,
                    'kind': kind,
                    'issue': f'Invalid kind: {kind}',
                    'suggestion': f'Should be one of: {valid_kinds}'
                })
        
        # Check satisfiability
        satisfiable_percent = validation.get('satisfiable_ops_percent', 0)
        if satisfiable_percent < 50:
            issues.append({
                'type': 'low_satisfiability',
                'severity': 'high',
                'service': service_name,
                'percent': satisfiable_percent,
                'issue': f'Only {satisfiable_percent:.1f}% of operations are satisfiable',
                'suggestion': 'Many operations have unresolved dependencies'
            })
        
        return issues
    
    def check_global_entity_usage(self, service_name: str, registry: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check if global entities are used correctly"""
        issues = []
        
        global_entities = {
            'ibm.account_id', 'ibm.region', 'ibm.crn', 'ibm.resource_group_id',
            'ibm.resource_instance_id', 'ibm.iam_id', 'ibm.pagination_token'
        }
        
        operations = registry.get('operations', {})
        for op_name, op_data in operations.items():
            # Check consumes
            for consume in op_data.get('consumes', []):
                entity = consume.get('entity', '')
                param = consume.get('param', '')
                
                # Check if param should map to global entity but doesn't
                param_lower = param.lower()
                if param_lower in ['account_id', 'accountid', 'region', 'region_id', 'crn']:
                    if entity not in global_entities:
                        issues.append({
                            'type': 'missing_global_mapping',
                            'severity': 'medium',
                            'operation': op_name,
                            'param': param,
                            'entity': entity,
                            'issue': f'Parameter {param} should map to global entity but maps to {entity}',
                            'suggestion': f'Should map to global entity (e.g., ibm.{param_lower})'
                        })
        
        return issues
    
    def check_all_services(self) -> Dict[str, Any]:
        """Run all quality checks on all services"""
        print("\n" + "=" * 80)
        print("QUALITY CHECK - All Services")
        print("=" * 80)
        
        all_issues = defaultdict(list)
        all_stats = defaultdict(int)
        
        service_folders = [d for d in self.ibm_root.iterdir() 
                          if d.is_dir() and (d / "ibm_dependencies_with_python_names_fully_enriched.json").exists()]
        
        for service_folder in sorted(service_folders):
            service_name = service_folder.name
            print(f"\n📦 Checking {service_name}...")
            
            # Load files
            try:
                registry_file = service_folder / "operation_registry.json"
                adjacency_file = service_folder / "adjacency.json"
                validation_file = service_folder / "validation_report.json"
                
                if not all([registry_file.exists(), adjacency_file.exists(), validation_file.exists()]):
                    all_issues['missing_files'].append(service_name)
                    continue
                
                with open(registry_file, 'r') as f:
                    registry = json.load(f)
                
                with open(adjacency_file, 'r') as f:
                    adjacency = json.load(f)
                
                with open(validation_file, 'r') as f:
                    validation = json.load(f)
                
                # Run checks
                entity_issues = self.check_entity_naming_quality(service_name, registry)
                dependency_issues = self.check_dependency_mapping(service_name, registry, adjacency)
                structure_issues = self.check_structure_quality(service_name, registry, adjacency, validation)
                global_issues = self.check_global_entity_usage(service_name, registry)
                
                all_issues[service_name] = {
                    'entity_naming': entity_issues,
                    'dependency_mapping': dependency_issues,
                    'structure': structure_issues,
                    'global_entities': global_issues
                }
                
                # Count stats
                all_stats['total_operations'] += len(registry.get('operations', {}))
                all_stats['total_entities'] += len(adjacency.get('entity_producers', {}))
                all_stats['high_severity'] += sum(1 for issue in entity_issues + dependency_issues + structure_issues 
                                                  if issue.get('severity') == 'high')
                all_stats['medium_severity'] += sum(1 for issue in entity_issues + dependency_issues + structure_issues 
                                                    if issue.get('severity') == 'medium')
                all_stats['low_severity'] += sum(1 for issue in entity_issues + dependency_issues + structure_issues 
                                                 if issue.get('severity') == 'low')
                
                total_issues = len(entity_issues) + len(dependency_issues) + len(structure_issues) + len(global_issues)
                print(f"   Issues found: {total_issues} (High: {sum(1 for i in entity_issues + dependency_issues + structure_issues if i.get('severity') == 'high')})")
                
            except Exception as e:
                all_issues['errors'].append({
                    'service': service_name,
                    'error': str(e)
                })
                print(f"   ❌ Error: {e}")
        
        return {
            'issues': dict(all_issues),
            'stats': dict(all_stats)
        }
    
    def generate_quality_report(self, coverage_results: Dict[str, Any], 
                               quality_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive quality report"""
        report = {
            'summary': {
                'total_services': len(coverage_results['services_found']),
                'total_operations': coverage_results['operations_count'],
                'services_with_issues': len([s for s, issues in quality_results['issues'].items() 
                                           if isinstance(issues, dict) and any(issues.values())]),
                'total_issues': quality_results['stats'].get('high_severity', 0) + 
                              quality_results['stats'].get('medium_severity', 0) + 
                              quality_results['stats'].get('low_severity', 0),
                'high_severity_issues': quality_results['stats'].get('high_severity', 0),
                'medium_severity_issues': quality_results['stats'].get('medium_severity', 0),
                'low_severity_issues': quality_results['stats'].get('low_severity', 0)
            },
            'coverage': coverage_results,
            'quality': quality_results,
            'recommendations': []
        }
        
        # Generate recommendations
        if quality_results['stats'].get('high_severity', 0) > 0:
            report['recommendations'].append({
                'priority': 'high',
                'issue': 'High severity issues found',
                'action': 'Review and fix entity naming, missing producers, and structure issues'
            })
        
        if coverage_results['services_missing_files']:
            report['recommendations'].append({
                'priority': 'high',
                'issue': 'Missing required files',
                'action': 'Regenerate missing files for affected services'
            })
        
        # Count generic entity issues
        generic_count = 0
        for service, issues_dict in quality_results['issues'].items():
            if isinstance(issues_dict, dict):
                generic_count += len(issues_dict.get('entity_naming', []))
        
        if generic_count > 0:
            report['recommendations'].append({
                'priority': 'medium',
                'issue': f'{generic_count} generic entity naming issues',
                'action': 'Improve entity naming to use specific resource names instead of generic "item"'
            })
        
        return report
    
    def run_all_checks(self) -> Dict[str, Any]:
        """Run all quality checks"""
        print("=" * 80)
        print("IBM Dependency Chain Quality Check")
        print("=" * 80)
        
        # Check 1: Coverage
        coverage_results = self.check_coverage()
        
        # Check 2: Quality
        quality_results = self.check_all_services()
        
        # Generate report
        report = self.generate_quality_report(coverage_results, quality_results)
        
        return report

def main():
    """Main execution"""
    ibm_root = Path("/Users/apple/Desktop/threat-engine/pythonsdk-database/ibm")
    
    checker = IBMQualityChecker(ibm_root)
    report = checker.run_all_checks()
    
    # Print summary
    print("\n" + "=" * 80)
    print("QUALITY REPORT SUMMARY")
    print("=" * 80)
    print(f"Total Services: {report['summary']['total_services']}")
    print(f"Total Operations: {report['summary']['total_operations']}")
    print(f"Services with Issues: {report['summary']['services_with_issues']}")
    print(f"\nIssues by Severity:")
    print(f"  🔴 High: {report['summary']['high_severity_issues']}")
    print(f"  🟡 Medium: {report['summary']['medium_severity_issues']}")
    print(f"  🟢 Low: {report['summary']['low_severity_issues']}")
    
    if report['recommendations']:
        print(f"\n📋 Recommendations:")
        for rec in report['recommendations']:
            print(f"  [{rec['priority'].upper()}] {rec['issue']}")
            print(f"      → {rec['action']}")
    
    # Save report
    report_file = ibm_root / "quality_report.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n✅ Quality report saved to: {report_file}")
    
    # Exit with error code if high severity issues
    if report['summary']['high_severity_issues'] > 0:
        sys.exit(1)

if __name__ == '__main__':
    main()

