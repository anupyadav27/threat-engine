#!/usr/bin/env python3
"""
Field Quality Tests - Deep validation of entity naming and field quality
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Any
from collections import defaultdict

class FieldQualityChecker:
    """Comprehensive field quality checker"""
    
    def __init__(self, ibm_root: Path):
        self.ibm_root = ibm_root
        self.issues = defaultdict(list)
        self.stats = defaultdict(int)
    
    def check_entity_naming_quality(self) -> Dict[str, Any]:
        """Check entity naming quality across all services"""
        print("=" * 80)
        print("FIELD QUALITY: Entity Naming")
        print("=" * 80)
        
        main_db = self.ibm_root / "ibm_dependencies_with_python_names_fully_enriched.json"
        with open(main_db, 'r') as f:
            main_data = json.load(f)
        
        results = {
            'generic_item_entities': [],
            'invalid_format_entities': [],
            'redundant_entities': [],
            'total_entities': 0,
            'valid_entities': 0
        }
        
        # Patterns to check
        generic_pattern = re.compile(r'\.item\.|\.item$')
        # Valid patterns: ibm.<service>.<resource>.<field> OR ibm.<global_entity>
        valid_pattern = re.compile(r'^ibm\.\w+\.\w+\.\w+$|^ibm\.(crn|account_id|region|resource_group_id|pagination_token|iam_id|resource_instance_id)$')
        redundant_pattern = re.compile(r'ibm\.\w+\.(\w+)\.\1_')
        
        for service_name in main_data.keys():
            registry_file = self.ibm_root / service_name / "operation_registry.json"
            if not registry_file.exists():
                continue
            
            with open(registry_file, 'r') as f:
                registry = json.load(f)
            
            for op_name, op_data in registry.get('operations', {}).items():
                # Check produces
                for produce in op_data.get('produces', []):
                    entity = produce.get('entity', '')
                    results['total_entities'] += 1
                    
                    if generic_pattern.search(entity):
                        results['generic_item_entities'].append({
                            'service': service_name,
                            'operation': op_name,
                            'entity': entity
                        })
                    elif not valid_pattern.match(entity):
                        results['invalid_format_entities'].append({
                            'service': service_name,
                            'operation': op_name,
                            'entity': entity
                        })
                    elif redundant_pattern.search(entity):
                        results['redundant_entities'].append({
                            'service': service_name,
                            'operation': op_name,
                            'entity': entity
                        })
                    else:
                        results['valid_entities'] += 1
                
                # Check consumes
                for consume in op_data.get('consumes', []):
                    entity = consume.get('entity', '')
                    results['total_entities'] += 1
                    
                    if generic_pattern.search(entity):
                        results['generic_item_entities'].append({
                            'service': service_name,
                            'operation': op_name,
                            'entity': entity
                        })
                    elif not valid_pattern.match(entity):
                        results['invalid_format_entities'].append({
                            'service': service_name,
                            'operation': op_name,
                            'entity': entity
                        })
                    else:
                        results['valid_entities'] += 1
        
        print(f"Total Entities: {results['total_entities']}")
        print(f"Valid Entities: {results['valid_entities']} ({results['valid_entities']/results['total_entities']*100:.1f}%)")
        print(f"Generic 'item' entities: {len(results['generic_item_entities'])}")
        print(f"Invalid format entities: {len(results['invalid_format_entities'])}")
        print(f"Redundant entities: {len(results['redundant_entities'])}")
        
        return results
    
    def check_field_completeness(self) -> Dict[str, Any]:
        """Check field completeness in operations"""
        print("\n" + "=" * 80)
        print("FIELD QUALITY: Completeness")
        print("=" * 80)
        
        main_db = self.ibm_root / "ibm_dependencies_with_python_names_fully_enriched.json"
        with open(main_db, 'r') as f:
            main_data = json.load(f)
        
        results = {
            'missing_kind': [],
            'missing_side_effect': [],
            'missing_entity_in_consumes': [],
            'missing_entity_in_produces': [],
            'missing_path_in_produces': [],
            'missing_param_in_consumes': []
        }
        
        for service_name in main_data.keys():
            registry_file = self.ibm_root / service_name / "operation_registry.json"
            if not registry_file.exists():
                continue
            
            with open(registry_file, 'r') as f:
                registry = json.load(f)
            
            for op_name, op_data in registry.get('operations', {}).items():
                if 'kind' not in op_data or not op_data['kind']:
                    results['missing_kind'].append(f"{service_name}.{op_name}")
                
                if 'side_effect' not in op_data:
                    results['missing_side_effect'].append(f"{service_name}.{op_name}")
                
                for consume in op_data.get('consumes', []):
                    if 'entity' not in consume:
                        results['missing_entity_in_consumes'].append(f"{service_name}.{op_name}")
                    if 'param' not in consume:
                        results['missing_param_in_consumes'].append(f"{service_name}.{op_name}")
                
                for produce in op_data.get('produces', []):
                    if 'entity' not in produce:
                        results['missing_entity_in_produces'].append(f"{service_name}.{op_name}")
                    if 'path' not in produce:
                        results['missing_path_in_produces'].append(f"{service_name}.{op_name}")
        
        print(f"Operations missing 'kind': {len(results['missing_kind'])}")
        print(f"Operations missing 'side_effect': {len(results['missing_side_effect'])}")
        print(f"Consumes missing 'entity': {len(results['missing_entity_in_consumes'])}")
        print(f"Consumes missing 'param': {len(results['missing_param_in_consumes'])}")
        print(f"Produces missing 'entity': {len(results['missing_entity_in_produces'])}")
        print(f"Produces missing 'path': {len(results['missing_path_in_produces'])}")
        
        return results
    
    def check_structure_quality(self) -> Dict[str, Any]:
        """Check structure quality of JSON files"""
        print("\n" + "=" * 80)
        print("FIELD QUALITY: Structure")
        print("=" * 80)
        
        main_db = self.ibm_root / "ibm_dependencies_with_python_names_fully_enriched.json"
        with open(main_db, 'r') as f:
            main_data = json.load(f)
        
        results = {
            'invalid_json': [],
            'missing_required_fields': [],
            'type_mismatches': []
        }
        
        required_registry_fields = ['service', 'version', 'operations']
        required_adjacency_fields = ['service', 'op_consumes', 'op_produces', 'entity_producers']
        
        for service_name in main_data.keys():
            # Check operation_registry.json
            registry_file = self.ibm_root / service_name / "operation_registry.json"
            if registry_file.exists():
                try:
                    with open(registry_file, 'r') as f:
                        registry = json.load(f)
                    
                    for field in required_registry_fields:
                        if field not in registry:
                            results['missing_required_fields'].append(
                                f"{service_name}/operation_registry.json: missing '{field}'"
                            )
                    
                    if 'operations' in registry:
                        if not isinstance(registry['operations'], dict):
                            results['type_mismatches'].append(
                                f"{service_name}/operation_registry.json: 'operations' should be dict"
                            )
                
                except json.JSONDecodeError as e:
                    results['invalid_json'].append(f"{service_name}/operation_registry.json: {e}")
            
            # Check adjacency.json
            adjacency_file = self.ibm_root / service_name / "adjacency.json"
            if adjacency_file.exists():
                try:
                    with open(adjacency_file, 'r') as f:
                        adjacency = json.load(f)
                    
                    for field in required_adjacency_fields:
                        if field not in adjacency:
                            results['missing_required_fields'].append(
                                f"{service_name}/adjacency.json: missing '{field}'"
                            )
                
                except json.JSONDecodeError as e:
                    results['invalid_json'].append(f"{service_name}/adjacency.json: {e}")
        
        print(f"Invalid JSON files: {len(results['invalid_json'])}")
        print(f"Missing required fields: {len(results['missing_required_fields'])}")
        print(f"Type mismatches: {len(results['type_mismatches'])}")
        
        return results
    
    def run_all_checks(self) -> Dict[str, Any]:
        """Run all field quality checks"""
        results = {
            'entity_naming': self.check_entity_naming_quality(),
            'completeness': self.check_field_completeness(),
            'structure': self.check_structure_quality()
        }
        
        # Calculate overall quality score
        total_issues = (
            len(results['entity_naming']['generic_item_entities']) +
            len(results['entity_naming']['invalid_format_entities']) +
            len(results['completeness']['missing_kind']) +
            len(results['completeness']['missing_side_effect']) +
            len(results['structure']['invalid_json']) +
            len(results['structure']['missing_required_fields'])
        )
        
        results['overall'] = {
            'total_issues': total_issues,
            'quality_score': max(0, 100 - (total_issues * 0.1))  # Penalty per issue
        }
        
        return results

if __name__ == '__main__':
    ibm_root = Path(__file__).parent.parent
    checker = FieldQualityChecker(ibm_root)
    results = checker.run_all_checks()
    
    print("\n" + "=" * 80)
    print("OVERALL QUALITY SCORE")
    print("=" * 80)
    print(f"Total Issues: {results['overall']['total_issues']}")
    print(f"Quality Score: {results['overall']['quality_score']:.1f}/100")
    
    # Save results
    output_file = ibm_root / "field_quality_report.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n✅ Report saved to: {output_file}")

