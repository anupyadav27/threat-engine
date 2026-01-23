"""
Quick test to verify threat rule generation works
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from generate_comprehensive_threat_rules import ComprehensiveThreatRuleGenerator

def test_generator():
    """Test rule generation with a small subset"""
    print("Testing threat rule generator...")
    
    service_list = Path(__file__).parent.parent.parent / "configScan_engines" / "aws-configScan-engine" / "config" / "service_list.json"
    relation_types = Path(__file__).parent.parent.parent / "inventory-engine" / "inventory_engine" / "config" / "relation_types.json"
    
    if not service_list.exists():
        print(f"❌ Service list not found: {service_list}")
        return False
    
    if not relation_types.exists():
        print(f"⚠️  Relation types not found: {relation_types}")
        relation_types = None
    
    try:
        generator = ComprehensiveThreatRuleGenerator(
            service_list_path=str(service_list),
            relation_types_path=str(relation_types) if relation_types else None
        )
        
        print(f"✅ Loaded {len(generator.services)} services")
        print(f"✅ Loaded {len(generator.relation_types)} relation types")
        print(f"✅ Loaded {len(generator.mitre_techniques)} MITRE techniques")
        
        # Test generating rules for first 5 services
        test_services = generator.services[:5]
        print(f"\n📝 Testing rule generation for {len(test_services)} services...")
        
        total_rules = 0
        for service in test_services:
            service_name = service.get("name", "unknown")
            rules = generator.generate_rules_for_service(service)
            total_rules += len(rules)
            print(f"  {service_name}: {len(rules)} rules")
        
        print(f"\n✅ Generated {total_rules} test rules successfully!")
        print(f"✅ Generator is working correctly")
        
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_generator()
    sys.exit(0 if success else 1)
