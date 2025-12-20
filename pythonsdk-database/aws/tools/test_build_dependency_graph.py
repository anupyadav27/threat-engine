#!/usr/bin/env python3
"""
Unit tests for build_dependency_graph.py
Tests key scenarios for entity normalization, aliasing, and kind assignment.
"""

import json
import sys
from pathlib import Path

# Add tools directory to path
sys.path.insert(0, str(Path(__file__).parent))

from build_dependency_graph import (
    normalize_produces_entity,
    normalize_consumes_entity,
    assign_kind,
    extract_meaningful_parent,
    generate_safe_aliases
)

def test_normalize_produces_entity_analyzer_arn():
    """Test: GetAnalyzer.analyzer.arn becomes analyzer_arn (no generic accessanalyzer.arn)"""
    service = "accessanalyzer"
    path = "analyzer.arn"
    operation = "GetAnalyzer"
    
    entity = normalize_produces_entity(service, path, operation)
    
    assert entity == "accessanalyzer.analyzer_arn", f"Expected 'accessanalyzer.analyzer_arn', got '{entity}'"
    assert entity != "accessanalyzer.arn", "Should not create generic accessanalyzer.arn"
    print("✓ Test 1 passed: GetAnalyzer.analyzer.arn -> analyzer_arn")

def test_normalize_produces_entity_certificate_status():
    """Test: CertificateSummaryList[].Status and Certificate.Status map to correctly prefixed entities"""
    service = "acm"
    
    # ListCertificates case
    path1 = "CertificateSummaryList[].Status"
    entity1 = normalize_produces_entity(service, path1, "ListCertificates")
    
    # DescribeCertificate case
    path2 = "Certificate.Status"
    entity2 = normalize_produces_entity(service, path2, "DescribeCertificate")
    
    # Both should map to certificate_status (not certificate_summary_list_status)
    assert "certificate_status" in entity1, f"Expected certificate_status in '{entity1}'"
    assert "certificate_status" in entity2, f"Expected certificate_status in '{entity2}'"
    print("✓ Test 2 passed: Certificate status entities correctly prefixed")

def test_normalize_consumes_entity_alternate_contact_type():
    """Test: GetAlternateContact AlternateContactType consume maps correctly"""
    service = "account"
    param = "AlternateContactType"
    operation = "GetAlternateContact"
    
    entity = normalize_consumes_entity(service, param, operation)
    
    assert entity == "account.alternate_contact_type", f"Expected 'account.alternate_contact_type', got '{entity}'"
    print("✓ Test 3 passed: AlternateContactType consume -> alternate_contact_type")

def test_extract_meaningful_parent():
    """Test: extract_meaningful_parent finds nearest meaningful parent"""
    # Test cases
    test_cases = [
        ("analyzer.arn", "analyzer"),
        ("accessPreview.id", "accessPreview"),
        ("CertificateSummaryList[].Status", "CertificateSummaryList"),
        ("Certificate.Status", "Certificate"),
        ("resource.analyzer.arn", "analyzer"),  # Should skip generic "resource"
    ]
    
    for path, expected_parent in test_cases:
        parent = extract_meaningful_parent(path)
        assert parent == expected_parent, f"Path '{path}': expected '{expected_parent}', got '{parent}'"
    
    print("✓ Test 4 passed: extract_meaningful_parent works correctly")

def test_assign_kind():
    """Test: Kind assignment follows single clean rule"""
    test_cases = [
        ("ListAnalyzers", "read_list"),
        ("GetAnalyzer", "read_get"),
        ("DescribeCertificate", "read_get"),
        ("CreateAnalyzer", "write_create"),
        ("UpdateAnalyzer", "write_update"),
        ("DeleteAnalyzer", "write_delete"),
        ("AttachPolicy", "write_apply"),
        ("TagResource", "write_apply"),
        ("UnknownOperation", "other"),
    ]
    
    for operation, expected_kind in test_cases:
        kind = assign_kind(operation)
        assert kind == expected_kind, f"Operation '{operation}': expected '{expected_kind}', got '{kind}'"
    
    print("✓ Test 5 passed: Kind assignment works correctly")

def test_safe_aliases_same_field_input_output():
    """Test: Safe alias heuristics - same field name appears as input and output"""
    service = "account"
    operations = {
        "GetAlternateContact": {
            "consumes": [
                {"entity": "account.alternate_contact_type", "param": "AlternateContactType"}
            ],
            "produces": [
                {"entity": "account.alternate_contact_alternate_contact_type", "path": "AlternateContact.AlternateContactType"}
            ]
        }
    }
    
    aliases = generate_safe_aliases(operations, service)
    
    # Should alias the redundant prefix version to the shorter one
    assert "account.alternate_contact_alternate_contact_type" in aliases, "Should create alias for redundant prefix"
    assert aliases["account.alternate_contact_alternate_contact_type"] == "account.alternate_contact_type", \
        "Should alias to the shorter canonical form"
    
    print("✓ Test 6 passed: Safe aliases detect redundant prefix patterns")

def test_no_generic_entities():
    """Test: No generic entities (service.arn, service.id, service.name, service.status) are created"""
    service = "test"
    
    # Test produces
    test_paths = [
        ("analyzer.arn", "GetAnalyzer"),
        ("accessPreview.id", "GetAccessPreview"),
        ("certificate.status", "DescribeCertificate"),
        ("resource.name", "GetResource"),
    ]
    
    for path, operation in test_paths:
        entity = normalize_produces_entity(service, path, operation)
        assert entity != f"{service}.arn", f"Should not create generic {service}.arn for path '{path}'"
        assert entity != f"{service}.id", f"Should not create generic {service}.id for path '{path}'"
        assert entity != f"{service}.name", f"Should not create generic {service}.name for path '{path}'"
        assert entity != f"{service}.status", f"Should not create generic {service}.status for path '{path}'"
        assert "_" in entity.replace(f"{service}.", ""), f"Entity '{entity}' should have parent prefix"
    
    # Test consumes
    test_params = [
        ("Name", "PutAlternateContact"),
        ("id", "GetFinding"),
        ("arn", "GetAnalyzer"),
        ("status", "UpdateFindings"),
    ]
    
    for param, operation in test_params:
        entity = normalize_consumes_entity(service, param, operation)
        assert entity != f"{service}.arn", f"Should not create generic {service}.arn for param '{param}'"
        assert entity != f"{service}.id", f"Should not create generic {service}.id for param '{param}'"
        assert entity != f"{service}.name", f"Should not create generic {service}.name for param '{param}'"
        assert entity != f"{service}.status", f"Should not create generic {service}.status for param '{param}'"
    
    print("✓ Test 7 passed: No generic entities created")

def run_all_tests():
    """Run all unit tests"""
    print("Running unit tests for build_dependency_graph.py\n")
    
    try:
        test_normalize_produces_entity_analyzer_arn()
        test_normalize_produces_entity_certificate_status()
        test_normalize_consumes_entity_alternate_contact_type()
        test_extract_meaningful_parent()
        test_assign_kind()
        test_safe_aliases_same_field_input_output()
        test_no_generic_entities()
        
        print("\n✅ All tests passed!")
        return 0
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        return 1
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(run_all_tests())

