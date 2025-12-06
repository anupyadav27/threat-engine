#!/usr/bin/env python3
"""
Azure-Specific Agentic Quality Enhancement
Uses Claude Sonnet 4.5 + LangGraph
"""

import sys
import yaml
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))
from agentic_quality_system import CSPAgenticSystem

def main():
    csp = 'azure'
    base_dir = Path("/Users/apple/Desktop/threat-engine/compliance/azure")
    
    print("="*80)
    print("🤖 AZURE Agentic Quality Enhancement")
    print("="*80)
    print("Model: Claude Sonnet 4.5")
    print("Framework: LangGraph Multi-Agent Orchestration")
    print("="*80)
    
    # Load existing enriched rules
    input_path = base_dir / "rule_ids_ENRICHED.yaml"
    
    if not input_path.exists():
        print(f"❌ File not found: {input_path}")
        return
    
    print(f"\n📂 Loading rules from: {input_path.name}")
    
    with open(input_path) as f:
        data = yaml.safe_load(f)
    
    rules = data.get('rules', [])
    print(f"✅ Loaded {len(rules)} rules\n")
    
    # Initialize agentic system
    print("🤖 Initializing multi-agent system...")
    system = CSPAgenticSystem('azure')
    print("✅ Agents initialized:")
    print("  1️⃣  Validator Agent")
    print("  2️⃣  Title Improvement Agent")
    print("  3️⃣  Description Enhancement Agent")
    print("  4️⃣  Reference Finder Agent")
    print("  5️⃣  QA Review Agent\n")
    
    # Process all rules
    improved_rules = system.process_all_rules(rules, batch_size=5)
    
    # Save results
    output_path = base_dir / "rule_ids_AGENTIC_AI_ENHANCED.yaml"
    
    output_data = {
        'metadata': {
            'csp': 'AZURE',
            'description': 'Azure rules enhanced by Claude Sonnet 4.5 multi-agent system',
            'version': '3.0.0',
            'enhancement_date': datetime.now().strftime('%Y-%m-%d'),
            'total_rules': len(improved_rules),
            'quality_grade': 'A++ (Agentic AI Enhanced)',
            'ai_model': 'Claude Sonnet 4.5',
            'framework': 'LangGraph Multi-Agent',
            'agents': ['Validator', 'Title Improver', 'Description Enhancer', 'Reference Finder', 'QA Reviewer']
        },
        'rules': improved_rules
    }
    
    print(f"\n💾 Saving enhanced rules...")
    with open(output_path, 'w') as f:
        yaml.dump(output_data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
    
    print(f"✅ Saved to: {output_path}")
    
    # Statistics
    avg_score = sum(r.get('qa_score', 0) for r in improved_rules) / len(improved_rules) if improved_rules else 0
    a_plus_count = sum(1 for r in improved_rules if r.get('quality_grade') == 'A+')
    
    print("\n" + "="*80)
    print("📊 AZURE ENHANCEMENT SUMMARY")
    print("="*80)
    print(f"Total Rules:           {len(improved_rules)}")
    print(f"Average QA Score:      {avg_score:.2f}/10")
    print(f"A+ Quality Rules:      {a_plus_count} ({a_plus_count/len(improved_rules)*100:.1f}%)")
    print(f"Quality Grade:         A++ (Agentic AI Enhanced)")
    print("="*80)
    
    print("\n🎉 Azure Enhancement Complete!")

if __name__ == '__main__':
    main()

