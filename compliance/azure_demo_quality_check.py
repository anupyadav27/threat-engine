#!/usr/bin/env python3
"""
Azure Quality Demo - Process 3 rules for immediate review
"""

import sys
import yaml
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from agentic_quality_system import CSPAgenticSystem

def main():
    print("="*80)
    print("🎯 Azure Agentic Enhancement - DEMO (3 rules)")
    print("="*80)
    
    # Load Azure rules
    azure_path = Path("/Users/apple/Desktop/threat-engine/compliance/azure/rule_ids_ENRICHED.yaml")
    
    with open(azure_path) as f:
        data = yaml.safe_load(f)
    
    rules = data.get('rules', [])[:3]  # Just first 3 rules
    
    print(f"\n📂 Processing {len(rules)} sample Azure rules for quality review\n")
    
    # Initialize system
    print("🤖 Initializing Claude Sonnet 4.5 multi-agent system...")
    system = CSPAgenticSystem('azure')
    print("✅ 5 agents initialized\n")
    
    # Process each rule and show before/after
    improved_rules = []
    
    for idx, rule in enumerate(rules, 1):
        print(f"\n{'='*80}")
        print(f"RULE {idx}/3: {rule.get('rule_id', 'N/A')}")
        print(f"{'='*80}")
        
        print("\n📥 BEFORE Enhancement:")
        print(f"  Title: {rule.get('title', '')[:80]}...")
        print(f"  Description: {rule.get('description', '')[:100]}...")
        print(f"  References: {len(rule.get('references', []))} URLs")
        
        print("\n🤖 Processing through 5 agents...")
        improved = system.process_rule(rule)
        improved_rules.append(improved)
        
        print("\n📤 AFTER Enhancement:")
        print(f"  Title: {improved.get('title', '')[:80]}...")
        print(f"  Description: {improved.get('description', '')[:150]}...")
        print(f"  References: {len(improved.get('references', []))} URLs")
        print(f"  QA Score: {improved.get('qa_score', 0)}/10")
        print(f"  Quality Grade: {improved.get('quality_grade', 'N/A')}")
        
        print(f"\n✅ Rule {idx} complete!")
    
    # Show detailed comparison
    print("\n" + "="*80)
    print("📊 DETAILED QUALITY COMPARISON")
    print("="*80)
    
    for idx, (original, improved) in enumerate(zip(rules, improved_rules), 1):
        print(f"\n--- Rule {idx}: {improved.get('rule_id', 'N/A')} ---")
        
        print(f"\n✏️  TITLE:")
        print(f"  Before: {original.get('title', '')}")
        print(f"  After:  {improved.get('title', '')}")
        
        print(f"\n📝 DESCRIPTION:")
        print(f"  Before: {original.get('description', '')[:200]}...")
        print(f"  After:  {improved.get('description', '')[:200]}...")
        
        print(f"\n🔗 REFERENCES:")
        print(f"  Before ({len(original.get('references', []))}):")
        for ref in original.get('references', [])[:3]:
            print(f"    • {ref}")
        print(f"  After ({len(improved.get('references', []))}):")
        for ref in improved.get('references', [])[:5]:
            print(f"    • {ref}")
        
        print(f"\n📊 QUALITY:")
        print(f"  QA Score: {improved.get('qa_score', 0)}/10")
        print(f"  Grade: {improved.get('quality_grade', 'N/A')}")
    
    # Summary
    avg_score = sum(r.get('qa_score', 0) for r in improved_rules) / len(improved_rules)
    
    print("\n" + "="*80)
    print("📊 DEMO SUMMARY")
    print("="*80)
    print(f"Rules Processed: {len(improved_rules)}")
    print(f"Average QA Score: {avg_score:.1f}/10")
    print(f"All Grades: {[r.get('quality_grade', 'N/A') for r in improved_rules]}")
    print("="*80)
    
    print("\n🎉 Demo Complete!")
    print(f"\n💡 If quality looks good, proceed with full Azure enhancement")
    print(f"   (Process will take ~2.5 hours for all 1,739 rules)")

if __name__ == '__main__':
    main()

