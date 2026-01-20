#!/usr/bin/env python3
"""
Test integration with real configScan output.

This script tests:
1. Reading configScan findings
2. Enriching findings with data_security context
3. Mapping findings to modules
"""

import sys
from pathlib import Path

# Add to path
sys.path.insert(0, str(Path(__file__).parent))

from data_security_engine.input.configscan_reader import ConfigScanReader
from data_security_engine.input.rule_db_reader import RuleDBReader
from data_security_engine.enricher.finding_enricher import FindingEnricher
from data_security_engine.mapper.rule_to_module_mapper import RuleToModuleMapper


def test_configscan_reading():
    """Test reading configScan output."""
    print("=" * 60)
    print("Test 1: Reading ConfigScan Output")
    print("=" * 60)
    
    reader = ConfigScanReader()
    
    # Try to find available scan IDs
    # Use the latest scan we know about
    csp = "aws"
    scan_id = "full_scan_all"
    
    try:
        # Get data-related findings
        findings = reader.filter_data_related_findings(csp, scan_id, services=["s3"])
        print(f"✓ Found {len(findings)} S3 findings")
        
        if findings:
            sample = findings[0]
            print(f"  Sample finding: {sample.get('rule_id')} - {sample.get('status')}")
            return True, findings[:10]  # Return first 10 for testing
        else:
            print("  No findings found - scan may not exist or have no S3 findings")
            return False, []
    except Exception as e:
        print(f"  Error: {e}")
        return False, []


def test_finding_enrichment(findings):
    """Test enriching findings."""
    print("\n" + "=" * 60)
    print("Test 2: Enriching Findings with Data Security Context")
    print("=" * 60)
    
    if not findings:
        print("  Skipping - no findings to enrich")
        return
    
    enricher = FindingEnricher()
    
    try:
        enriched = enricher.enrich_findings(findings)
        print(f"✓ Enriched {len(enriched)} findings")
        
        # Count data security relevant findings
        relevant = sum(1 for f in enriched if f.get("is_data_security_relevant"))
        print(f"  Data security relevant: {relevant}/{len(enriched)}")
        
        # Show sample enriched finding
        if enriched:
            sample = enriched[0]
            if sample.get("is_data_security_relevant"):
                print(f"\n  Sample enriched finding:")
                print(f"    Rule ID: {sample.get('rule_id')}")
                print(f"    Modules: {sample.get('data_security_modules')}")
                context = sample.get("data_security_context")
                if context:
                    print(f"    Priority: {context.get('priority')}")
                    print(f"    Categories: {context.get('categories')}")
        
        return enriched
    except Exception as e:
        print(f"  Error: {e}")
        import traceback
        traceback.print_exc()
        return None


def test_module_mapping(enriched_findings):
    """Test module mapping."""
    print("\n" + "=" * 60)
    print("Test 3: Module Mapping Statistics")
    print("=" * 60)
    
    if not enriched_findings:
        print("  Skipping - no enriched findings")
        return
    
    mapper = RuleToModuleMapper()
    
    try:
        grouped = mapper.group_findings_by_module(enriched_findings)
        stats = mapper.get_module_statistics(enriched_findings)
        
        print(f"✓ Module distribution:")
        for module, count in sorted(stats.items(), key=lambda x: -x[1]):
            print(f"  {module}: {count}")
        
        return stats
    except Exception as e:
        print(f"  Error: {e}")
        import traceback
        traceback.print_exc()
        return None


def test_rule_db_reader():
    """Test rule database reader."""
    print("\n" + "=" * 60)
    print("Test 4: Rule Database Reader")
    print("=" * 60)
    
    reader = RuleDBReader()
    
    try:
        # Test reading a specific rule
        rule_id = "aws.s3.bucket.encryption_at_rest_enabled"
        metadata = reader.read_metadata("s3", rule_id)
        
        if metadata:
            data_security = metadata.get("data_security")
            if data_security:
                print(f"✓ Rule {rule_id} has data_security section")
                print(f"  Modules: {data_security.get('modules')}")
                print(f"  Priority: {data_security.get('priority')}")
            else:
                print(f"  Rule {rule_id} does not have data_security section")
        else:
            print(f"  Rule {rule_id} not found")
        
        # Get statistics
        s3_rules = reader.get_all_data_security_rules("s3")
        rds_rules = reader.get_all_data_security_rules("rds")
        
        print(f"\n✓ Data security rules:")
        print(f"  S3: {len(s3_rules)}")
        print(f"  RDS: {len(rds_rules)}")
        
        return True
    except Exception as e:
        print(f"  Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run integration tests."""
    print("Data Security Engine - Integration Test")
    print("=" * 60)
    
    # Test 1: Reading configScan output
    success, findings = test_configscan_reading()
    
    # Test 2: Enriching findings
    enriched_findings = None
    if success:
        enriched_findings = test_finding_enrichment(findings)
    
    # Test 3: Module mapping
    if enriched_findings:
        test_module_mapping(enriched_findings)
    
    # Test 4: Rule DB reader
    test_rule_db_reader()
    
    print("\n" + "=" * 60)
    print("Integration Test Complete")
    print("=" * 60)


if __name__ == "__main__":
    main()

