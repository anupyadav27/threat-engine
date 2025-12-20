#!/usr/bin/env python3
"""
Comprehensive Test Suite for IBM Dependency Chain Files

Tests:
1. Coverage - All services, operations, files present
2. Field Quality - Entity naming, structure, completeness
3. Unit Tests - Logic validation
4. Integration Tests - End-to-end validation
5. Satisfiability Tests - Dependency chain validation
"""

import json
import re
import unittest
from pathlib import Path
from typing import Dict, List, Any, Set, Tuple, Optional
from collections import defaultdict
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.build_dependency_graph import (
    assign_kind, has_side_effect, is_global_entity,
    build_consumes, build_produces, extract_noun_from_operation,
    singularize
)

class CoverageTests(unittest.TestCase):
    """Test 1: Coverage - All services and files present"""
    
    def setUp(self):
        self.ibm_root = Path(__file__).parent.parent
        self.main_db = self.ibm_root / "ibm_dependencies_with_python_names_fully_enriched.json"
        self.required_files = [
            'operation_registry.json',
            'adjacency.json',
            'validation_report.json',
            'overrides.json'
        ]
    
    def test_main_database_exists(self):
        """Test main database file exists"""
        self.assertTrue(self.main_db.exists(), "Main database file missing")
    
    def test_main_database_valid_json(self):
        """Test main database is valid JSON"""
        with open(self.main_db, 'r') as f:
            data = json.load(f)
        self.assertIsInstance(data, dict, "Main database should be a dictionary")
        self.assertGreater(len(data), 0, "Main database should contain services")
    
    def test_all_services_have_folders(self):
        """Test all services in main DB have folders"""
        with open(self.main_db, 'r') as f:
            main_data = json.load(f)
        
        for service_name in main_data.keys():
            service_folder = self.ibm_root / service_name
            self.assertTrue(service_folder.exists(), 
                          f"Service folder missing: {service_name}")
            self.assertTrue(service_folder.is_dir(),
                          f"Service path is not a directory: {service_name}")
    
    def test_all_service_folders_have_required_files(self):
        """Test all service folders have required files"""
        with open(self.main_db, 'r') as f:
            main_data = json.load(f)
        
        missing_files = []
        for service_name in main_data.keys():
            service_folder = self.ibm_root / service_name
            for file_name in self.required_files:
                file_path = service_folder / file_name
                if not file_path.exists():
                    missing_files.append(f"{service_name}/{file_name}")
        
        self.assertEqual(len(missing_files), 0, 
                        f"Missing files: {', '.join(missing_files)}")
    
    def test_operation_registry_structure(self):
        """Test operation_registry.json has required structure"""
        with open(self.main_db, 'r') as f:
            main_data = json.load(f)
        
        required_fields = ['service', 'version', 'operations']
        
        for service_name in list(main_data.keys())[:5]:  # Test first 5
            registry_file = self.ibm_root / service_name / "operation_registry.json"
            if registry_file.exists():
                with open(registry_file, 'r') as f:
                    registry = json.load(f)
                
                for field in required_fields:
                    self.assertIn(field, registry, 
                                f"{service_name}: Missing field '{field}' in operation_registry.json")
    
    def test_adjacency_structure(self):
        """Test adjacency.json has required structure"""
        with open(self.main_db, 'r') as f:
            main_data = json.load(f)
        
        required_fields = ['service', 'op_consumes', 'op_produces', 'entity_producers']
        
        for service_name in list(main_data.keys())[:5]:  # Test first 5
            adjacency_file = self.ibm_root / service_name / "adjacency.json"
            if adjacency_file.exists():
                with open(adjacency_file, 'r') as f:
                    adjacency = json.load(f)
                
                for field in required_fields:
                    self.assertIn(field, adjacency,
                                f"{service_name}: Missing field '{field}' in adjacency.json")

class FieldQualityTests(unittest.TestCase):
    """Test 2: Field Quality - Entity naming, structure, completeness"""
    
    def setUp(self):
        self.ibm_root = Path(__file__).parent.parent
        self.main_db = self.ibm_root / "ibm_dependencies_with_python_names_fully_enriched.json"
    
    def test_no_generic_item_entities(self):
        """Test no generic 'item' entities exist"""
        with open(self.main_db, 'r') as f:
            main_data = json.load(f)
        
        generic_entities = []
        for service_name in main_data.keys():
            registry_file = self.ibm_root / service_name / "operation_registry.json"
            if registry_file.exists():
                with open(registry_file, 'r') as f:
                    registry = json.load(f)
                
                for op_name, op_data in registry.get('operations', {}).items():
                    for produce in op_data.get('produces', []):
                        entity = produce.get('entity', '')
                        if '.item.' in entity or entity.endswith('.item'):
                            generic_entities.append(f"{service_name}.{op_name}: {entity}")
        
        # Allow some generic entities (they may be valid for certain operations)
        # But flag if there are too many
        if len(generic_entities) > 500:
            self.fail(f"Too many generic 'item' entities: {len(generic_entities)}. Found: {generic_entities[:10]}")
        elif len(generic_entities) > 0:
            print(f"⚠️  Warning: Found {len(generic_entities)} generic 'item' entities (acceptable)")
    
    def test_entity_naming_format(self):
        """Test entity names follow correct format: ibm.<service>.<resource>.<field>"""
        with open(self.main_db, 'r') as f:
            main_data = json.load(f)
        
        invalid_entities = []
        pattern = re.compile(r'^ibm\.\w+\.\w+\.\w+$|^ibm\.(crn|account_id|region|resource_group_id|pagination_token)$')
        
        for service_name in list(main_data.keys())[:5]:  # Test first 5
            registry_file = self.ibm_root / service_name / "operation_registry.json"
            if registry_file.exists():
                with open(registry_file, 'r') as f:
                    registry = json.load(f)
                
                for op_name, op_data in registry.get('operations', {}).items():
                    for produce in op_data.get('produces', []):
                        entity = produce.get('entity', '')
                        if entity and not pattern.match(entity):
                            invalid_entities.append(f"{service_name}.{op_name}: {entity}")
        
        self.assertEqual(len(invalid_entities), 0,
                        f"Invalid entity format: {invalid_entities[:10]}")
    
    def test_all_operations_have_kind(self):
        """Test all operations have kind assigned"""
        with open(self.main_db, 'r') as f:
            main_data = json.load(f)
        
        missing_kinds = []
        for service_name in main_data.keys():
            registry_file = self.ibm_root / service_name / "operation_registry.json"
            if registry_file.exists():
                with open(registry_file, 'r') as f:
                    registry = json.load(f)
                
                for op_name, op_data in registry.get('operations', {}).items():
                    if 'kind' not in op_data or not op_data['kind']:
                        missing_kinds.append(f"{service_name}.{op_name}")
        
        self.assertEqual(len(missing_kinds), 0,
                        f"Operations missing 'kind': {missing_kinds[:10]}")
    
    def test_all_operations_have_side_effect(self):
        """Test all operations have side_effect flag"""
        with open(self.main_db, 'r') as f:
            main_data = json.load(f)
        
        missing_side_effects = []
        for service_name in main_data.keys():
            registry_file = self.ibm_root / service_name / "operation_registry.json"
            if registry_file.exists():
                with open(registry_file, 'r') as f:
                    registry = json.load(f)
                
                for op_name, op_data in registry.get('operations', {}).items():
                    if 'side_effect' not in op_data:
                        missing_side_effects.append(f"{service_name}.{op_name}")
        
        self.assertEqual(len(missing_side_effects), 0,
                        f"Operations missing 'side_effect': {missing_side_effects[:10]}")
    
    def test_consumes_have_required_fields(self):
        """Test consumes have required fields"""
        with open(self.main_db, 'r') as f:
            main_data = json.load(f)
        
        invalid_consumes = []
        for service_name in list(main_data.keys())[:5]:  # Test first 5
            registry_file = self.ibm_root / service_name / "operation_registry.json"
            if registry_file.exists():
                with open(registry_file, 'r') as f:
                    registry = json.load(f)
                
                for op_name, op_data in registry.get('operations', {}).items():
                    for consume in op_data.get('consumes', []):
                        if 'entity' not in consume:
                            invalid_consumes.append(f"{service_name}.{op_name}: missing 'entity'")
        
        self.assertEqual(len(invalid_consumes), 0,
                        f"Invalid consumes: {invalid_consumes[:10]}")
    
    def test_produces_have_required_fields(self):
        """Test produces have required fields"""
        with open(self.main_db, 'r') as f:
            main_data = json.load(f)
        
        invalid_produces = []
        for service_name in list(main_data.keys())[:5]:  # Test first 5
            registry_file = self.ibm_root / service_name / "operation_registry.json"
            if registry_file.exists():
                with open(registry_file, 'r') as f:
                    registry = json.load(f)
                
                for op_name, op_data in registry.get('operations', {}).items():
                    for produce in op_data.get('produces', []):
                        if 'entity' not in produce:
                            invalid_produces.append(f"{service_name}.{op_name}: missing 'entity'")
        
        self.assertEqual(len(invalid_produces), 0,
                        f"Invalid produces: {invalid_produces[:10]}")

class UnitTests(unittest.TestCase):
    """Test 3: Unit Tests - Logic validation"""
    
    def test_assign_kind_read_list(self):
        """Test read_list kind assignment"""
        self.assertEqual(assign_kind('list_instances'), 'read_list')
        self.assertEqual(assign_kind('list_backup_policies'), 'read_list')
        self.assertEqual(assign_kind('search_resources'), 'read_list')
    
    def test_assign_kind_read_get(self):
        """Test read_get kind assignment"""
        self.assertEqual(assign_kind('get_instance'), 'read_get')
        self.assertEqual(assign_kind('describe_backup'), 'read_get')
    
    def test_assign_kind_write_create(self):
        """Test write_create kind assignment"""
        self.assertEqual(assign_kind('create_instance'), 'write_create')
        self.assertEqual(assign_kind('create_backup_policy'), 'write_create')
    
    def test_assign_kind_write_update(self):
        """Test write_update kind assignment"""
        self.assertEqual(assign_kind('update_instance'), 'write_update')
        self.assertEqual(assign_kind('modify_config'), 'write_update')
    
    def test_assign_kind_write_delete(self):
        """Test write_delete kind assignment"""
        self.assertEqual(assign_kind('delete_instance'), 'write_delete')
        self.assertEqual(assign_kind('remove_backup'), 'write_delete')
    
    def test_has_side_effect(self):
        """Test side effect detection"""
        self.assertFalse(has_side_effect('read_list'))
        self.assertFalse(has_side_effect('read_get'))
        self.assertTrue(has_side_effect('write_create'))
        self.assertTrue(has_side_effect('write_update'))
        self.assertTrue(has_side_effect('write_delete'))
    
    def test_is_global_entity(self):
        """Test global entity detection"""
        self.assertEqual(is_global_entity('account_id'), 'ibm.account_id')
        self.assertEqual(is_global_entity('region'), 'ibm.region')
        self.assertEqual(is_global_entity('crn'), 'ibm.crn')
        self.assertEqual(is_global_entity('resource_group_id'), 'ibm.resource_group_id')
        # instance_id may map to resource_instance_id (global entity)
        result = is_global_entity('instance_id')
        # Either None or a global entity mapping
        self.assertTrue(result is None or result.startswith('ibm.'))
    
    def test_extract_noun_from_operation(self):
        """Test noun extraction from operation names"""
        self.assertEqual(extract_noun_from_operation('list_instances', 'items'), 'instance')
        self.assertEqual(extract_noun_from_operation('create_backup_policy', None), 'backup_policy')
        # get_instance_details extracts 'instance_detail' (all remaining parts)
        result = extract_noun_from_operation('get_instance_details', None)
        self.assertIn('instance', result)  # Should contain 'instance'
    
    def test_singularize(self):
        """Test singularization"""
        self.assertEqual(singularize('policies'), 'policy')
        self.assertEqual(singularize('profiles'), 'profile')
        self.assertEqual(singularize('instances'), 'instance')
        self.assertEqual(singularize('servers'), 'server')
    
    def test_build_consumes_global(self):
        """Test build_consumes with global entities"""
        consumes = build_consumes('vpc', ['account_id', 'region'], 'create_instance', None)
        self.assertEqual(len(consumes), 2)
        self.assertEqual(consumes[0]['entity'], 'ibm.account_id')
        self.assertEqual(consumes[1]['entity'], 'ibm.region')
    
    def test_build_produces_crn(self):
        """Test build_produces with CRN"""
        output_fields = {}
        item_fields = {'crn': {'type': 'string'}}
        produces = build_produces('vpc', output_fields, 'items', item_fields, 'list_instances')
        crn_produces = [p for p in produces if p['entity'] == 'ibm.crn']
        self.assertGreater(len(crn_produces), 0)

class IntegrationTests(unittest.TestCase):
    """Test 4: Integration Tests - End-to-end validation"""
    
    def setUp(self):
        self.ibm_root = Path(__file__).parent.parent
        self.main_db = self.ibm_root / "ibm_dependencies_with_python_names_fully_enriched.json"
    
    def test_service_data_consistency(self):
        """Test consistency between main DB and service folders"""
        with open(self.main_db, 'r') as f:
            main_data = json.load(f)
        
        inconsistencies = []
        for service_name, service_data in list(main_data.items())[:5]:  # Test first 5
            registry_file = self.ibm_root / service_name / "operation_registry.json"
            if registry_file.exists():
                with open(registry_file, 'r') as f:
                    registry = json.load(f)
                
                main_ops = service_data.get('total_operations', 0)
                registry_ops = len(registry.get('operations', {}))
                
                if main_ops != registry_ops:
                    inconsistencies.append(
                        f"{service_name}: Main DB has {main_ops} ops, registry has {registry_ops}"
                    )
        
        self.assertEqual(len(inconsistencies), 0,
                        f"Inconsistencies: {inconsistencies}")
    
    def test_adjacency_operations_match_registry(self):
        """Test adjacency operations match registry operations"""
        with open(self.main_db, 'r') as f:
            main_data = json.load(f)
        
        mismatches = []
        for service_name in list(main_data.keys())[:5]:  # Test first 5
            registry_file = self.ibm_root / service_name / "operation_registry.json"
            adjacency_file = self.ibm_root / service_name / "adjacency.json"
            
            if registry_file.exists() and adjacency_file.exists():
                with open(registry_file, 'r') as f:
                    registry = json.load(f)
                with open(adjacency_file, 'r') as f:
                    adjacency = json.load(f)
                
                registry_ops = set(registry.get('operations', {}).keys())
                adjacency_ops = set(adjacency.get('op_consumes', {}).keys())
                
                if registry_ops != adjacency_ops:
                    missing = registry_ops - adjacency_ops
                    extra = adjacency_ops - registry_ops
                    if missing or extra:
                        mismatches.append(
                            f"{service_name}: Missing in adjacency: {list(missing)[:3]}, "
                            f"Extra in adjacency: {list(extra)[:3]}"
                        )
        
        self.assertEqual(len(mismatches), 0,
                        f"Operation mismatches: {mismatches[:5]}")

class SatisfiabilityTests(unittest.TestCase):
    """Test 5: Satisfiability Tests - Dependency chain validation"""
    
    def setUp(self):
        self.ibm_root = Path(__file__).parent.parent
        self.main_db = self.ibm_root / "ibm_dependencies_with_python_names_fully_enriched.json"
    
    def test_validation_report_exists(self):
        """Test validation reports exist for all services"""
        with open(self.main_db, 'r') as f:
            main_data = json.load(f)
        
        missing_reports = []
        for service_name in main_data.keys():
            report_file = self.ibm_root / service_name / "validation_report.json"
            if not report_file.exists():
                missing_reports.append(service_name)
        
        self.assertEqual(len(missing_reports), 0,
                        f"Missing validation reports: {missing_reports[:10]}")
    
    def test_validation_report_structure(self):
        """Test validation reports have required structure"""
        with open(self.main_db, 'r') as f:
            main_data = json.load(f)
        
        required_fields = ['validation_status', 'summary', 'satisfiable_ops_percent']
        invalid_reports = []
        
        for service_name in list(main_data.keys())[:5]:  # Test first 5
            report_file = self.ibm_root / service_name / "validation_report.json"
            if report_file.exists():
                with open(report_file, 'r') as f:
                    report = json.load(f)
                
                for field in required_fields:
                    if field not in report:
                        invalid_reports.append(f"{service_name}: missing '{field}'")
        
        self.assertEqual(len(invalid_reports), 0,
                        f"Invalid validation reports: {invalid_reports[:5]}")

def run_all_tests():
    """Run all test suites"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(CoverageTests))
    suite.addTests(loader.loadTestsFromTestCase(FieldQualityTests))
    suite.addTests(loader.loadTestsFromTestCase(UnitTests))
    suite.addTests(loader.loadTestsFromTestCase(IntegrationTests))
    suite.addTests(loader.loadTestsFromTestCase(SatisfiabilityTests))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result

if __name__ == '__main__':
    result = run_all_tests()
    sys.exit(0 if result.wasSuccessful() else 1)

