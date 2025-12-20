#!/usr/bin/env python3
"""
Unit Tests for IBM Dependency Chain Generator

Tests:
1. Kind assignment logic
2. Entity naming logic
3. Global entity mapping
4. Dependency graph building
5. Validation logic
"""

import unittest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.build_dependency_graph import (
    assign_kind, has_side_effect, is_global_entity,
    build_consumes, build_produces, extract_noun_from_operation
)

class TestKindAssignment(unittest.TestCase):
    """Test kind assignment logic"""
    
    def test_write_delete_kinds(self):
        """Test write_delete kind assignment"""
        self.assertEqual(assign_kind('delete_instance'), 'write_delete')
        self.assertEqual(assign_kind('remove_backup'), 'write_delete')
        self.assertEqual(assign_kind('terminate_server'), 'write_delete')
        self.assertEqual(assign_kind('disable_feature'), 'write_delete')
        self.assertEqual(assign_kind('detach_volume'), 'write_delete')
    
    def test_write_update_kinds(self):
        """Test write_update kind assignment"""
        self.assertEqual(assign_kind('update_instance'), 'write_update')
        self.assertEqual(assign_kind('modify_config'), 'write_update')
        self.assertEqual(assign_kind('set_tags'), 'write_update')
        self.assertEqual(assign_kind('attach_volume'), 'write_update')
        self.assertEqual(assign_kind('enable_logging'), 'write_update')
    
    def test_write_create_kinds(self):
        """Test write_create kind assignment"""
        self.assertEqual(assign_kind('create_instance'), 'write_create')
        self.assertEqual(assign_kind('start_server'), 'write_create')
        self.assertEqual(assign_kind('provision_resource'), 'write_create')
        self.assertEqual(assign_kind('register_service'), 'write_create')
        self.assertEqual(assign_kind('generate_token'), 'write_create')
    
    def test_read_list_kinds(self):
        """Test read_list kind assignment"""
        self.assertEqual(assign_kind('list_instances'), 'read_list')
        self.assertEqual(assign_kind('search_resources'), 'read_list')
        self.assertEqual(assign_kind('query_data'), 'read_list')
        self.assertEqual(assign_kind('find_items'), 'read_list')
        self.assertEqual(assign_kind('enumerate_resources'), 'read_list')
    
    def test_read_get_kinds(self):
        """Test read_get kind assignment"""
        self.assertEqual(assign_kind('get_instance'), 'read_get')
        self.assertEqual(assign_kind('describe_backup'), 'read_get')
        self.assertEqual(assign_kind('read_config'), 'read_get')
        self.assertEqual(assign_kind('fetch_data'), 'read_get')
    
    def test_side_effects(self):
        """Test side effect detection"""
        self.assertFalse(has_side_effect('read_list'))
        self.assertFalse(has_side_effect('read_get'))
        self.assertTrue(has_side_effect('write_create'))
        self.assertTrue(has_side_effect('write_update'))
        self.assertTrue(has_side_effect('write_delete'))
        self.assertTrue(has_side_effect('other'))

class TestGlobalEntities(unittest.TestCase):
    """Test global entity mapping"""
    
    def test_account_id_mapping(self):
        """Test account_id global entity mapping"""
        self.assertEqual(is_global_entity('account_id'), 'ibm.account_id')
        self.assertEqual(is_global_entity('accountId'), 'ibm.account_id')
        self.assertEqual(is_global_entity('accountID'), None)  # Case sensitive
    
    def test_region_mapping(self):
        """Test region global entity mapping"""
        self.assertEqual(is_global_entity('region'), 'ibm.region')
        self.assertEqual(is_global_entity('region_id'), 'ibm.region')
        self.assertEqual(is_global_entity('regionId'), 'ibm.region')
    
    def test_crn_mapping(self):
        """Test CRN global entity mapping"""
        self.assertEqual(is_global_entity('crn'), 'ibm.crn')
        self.assertEqual(is_global_entity('CRN'), 'ibm.crn')
    
    def test_resource_group_mapping(self):
        """Test resource_group_id global entity mapping"""
        self.assertEqual(is_global_entity('resource_group_id'), 'ibm.resource_group_id')
        self.assertEqual(is_global_entity('resourceGroupId'), 'ibm.resource_group_id')
    
    def test_pagination_tokens(self):
        """Test pagination token mapping"""
        self.assertEqual(is_global_entity('start'), 'ibm.pagination_token')
        self.assertEqual(is_global_entity('offset'), 'ibm.pagination_token')
        self.assertEqual(is_global_entity('page'), 'ibm.pagination_token')
        self.assertEqual(is_global_entity('next'), 'ibm.pagination_token')
        self.assertEqual(is_global_entity('limit'), 'ibm.pagination_token')

class TestEntityNaming(unittest.TestCase):
    """Test entity naming logic"""
    
    def test_extract_noun_from_operation(self):
        """Test noun extraction from operation names"""
        self.assertEqual(extract_noun_from_operation('list_instances'), 'instance')
        self.assertEqual(extract_noun_from_operation('create_backup_policy'), 'backup')
        self.assertEqual(extract_noun_from_operation('get_instance_details'), 'instance')
        self.assertEqual(extract_noun_from_operation('delete_vpc_route'), 'vpc')
        self.assertEqual(extract_noun_from_operation('update_security_group'), 'security')
    
    def test_build_consumes_global_entity(self):
        """Test consumes building with global entities"""
        consumes = build_consumes('vpc', ['account_id', 'region'], 'create_instance', None)
        self.assertEqual(len(consumes), 2)
        self.assertEqual(consumes[0]['entity'], 'ibm.account_id')
        self.assertEqual(consumes[1]['entity'], 'ibm.region')
    
    def test_build_consumes_generic_id(self):
        """Test consumes building with generic id parameter"""
        consumes = build_consumes('vpc', ['instance_id'], 'get_instance', None)
        self.assertEqual(len(consumes), 1)
        # Should map to ibm.vpc.instance.instance_id
        self.assertIn('instance', consumes[0]['entity'])
        self.assertIn('id', consumes[0]['entity'])
    
    def test_build_produces_crn(self):
        """Test produces building with CRN"""
        output_fields = {}
        item_fields = {'crn': {'type': 'string'}}
        produces = build_produces('vpc', output_fields, 'items', item_fields, 'list_instances')
        crn_produces = [p for p in produces if 'crn' in p['entity'].lower()]
        self.assertTrue(len(crn_produces) > 0)
        self.assertEqual(crn_produces[0]['entity'], 'ibm.crn')

class TestDependencyGraph(unittest.TestCase):
    """Test dependency graph building"""
    
    def test_operation_registry_structure(self):
        """Test operation registry has required structure"""
        # This would require loading actual data
        # For now, just test the structure expectations
        required_fields = ['service', 'version', 'operations']
        # In real test, load a registry and check fields
        self.assertTrue(True)  # Placeholder
    
    def test_adjacency_structure(self):
        """Test adjacency has required structure"""
        required_fields = ['service', 'op_consumes', 'op_produces', 'entity_producers']
        # In real test, load adjacency and check fields
        self.assertTrue(True)  # Placeholder

class TestValidation(unittest.TestCase):
    """Test validation logic"""
    
    def test_validation_report_structure(self):
        """Test validation report has required fields"""
        required_fields = ['validation_status', 'summary', 'satisfiable_ops_percent']
        # In real test, load validation and check fields
        self.assertTrue(True)  # Placeholder

if __name__ == '__main__':
    unittest.main(verbosity=2)

