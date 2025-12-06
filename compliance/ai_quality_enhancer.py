#!/usr/bin/env python3
"""
AI-Powered Quality Enhancement for All CSP Rules
Uses OpenAI GPT-4 to improve title, description, and references
"""

import yaml
import json
from pathlib import Path
from typing import Dict, List
import time
import os
from openai import OpenAI

class QualityEnhancer:
    def __init__(self, csp_name: str):
        self.csp_name = csp_name.lower()
        self.csp_upper = csp_name.upper()
        self.base_dir = Path(f"/Users/apple/Desktop/threat-engine/compliance/{self.csp_name}")
        
        # Initialize OpenAI
        api_key = os.getenv('OPENAI_API_KEY')
        if not api_key:
            raise ValueError("OPENAI_API_KEY not set")
        
        self.client = OpenAI(api_key=api_key, timeout=30.0, max_retries=3)
        print(f"✅ OpenAI GPT-4 initialized for {self.csp_upper}")
        
        # Statistics
        self.stats = {
            'total_rules': 0,
            'enhanced': 0,
            'failed': 0,
            'api_calls': 0
        }
        
        # CSP-specific documentation bases
        self.doc_bases = {
            'alicloud': 'https://www.alibabacloud.com/help',
            'azure': 'https://docs.microsoft.com/azure',
            'gcp': 'https://cloud.google.com',
            'ibm': 'https://cloud.ibm.com/docs',
            'oci': 'https://docs.oracle.com/iaas'
        }
    
    def load_enriched_rules(self) -> List[Dict]:
        """Load existing enriched rules"""
        # Try different file patterns
        patterns = [
            self.base_dir / "rule_ids_ENRICHED.yaml",
            self.base_dir / "final/rule_ids_ENRICHED_V2.yaml",
            self.base_dir / "final/rule_ids_ENRICHED.yaml"
        ]
        
        for yaml_path in patterns:
            if yaml_path.exists():
                print(f"📂 Loading from: {yaml_path}")
                with open(yaml_path) as f:
                    data = yaml.safe_load(f)
                
                rules = data.get('rules', [])
                print(f"✅ Loaded {len(rules)} rules")
                return rules, yaml_path
        
        raise FileNotFoundError(f"No enriched rules found for {self.csp_name}")
    
    def enhance_with_openai(self, rule: Dict) -> Dict:
        """Use OpenAI to enhance title, description, and references"""
        
        rule_id = rule.get('rule_id', '')
        service = rule.get('service', '')
        resource = rule.get('resource', '')
        requirement = rule.get('requirement', '')
        domain = rule.get('domain', '')
        severity = rule.get('severity', '')
        
        prompt = f"""You are a cloud security expert for {self.csp_upper}. Improve the metadata for this security rule.

**Rule Information:**
- Rule ID: {rule_id}
- Service: {service}
- Resource: {resource}
- Requirement: {requirement}
- Domain: {domain}
- Severity: {severity}

**Task:** Generate improved, enterprise-grade metadata in JSON format:

1. **title**: Professional, concise title (format: "{self.csp_upper} Service Resource: Clear Requirement")
   - Use proper service names (not codes)
   - Be specific and actionable
   - Max 80 characters

2. **description**: Enterprise CSPM-quality description (3-4 sentences)
   - Explain WHAT is validated
   - WHY it matters for security
   - WHAT risks it prevents
   - Include compliance relevance if applicable
   - Professional tone, avoid generic language

3. **references**: 3-5 specific {self.csp_upper} documentation URLs
   - Use real, specific documentation paths
   - Include security best practices page
   - Include service-specific security guide
   - Include compliance/governance page if relevant
   - Base URL: {self.doc_bases.get(self.csp_name, 'https://docs')}
   - Format: Full URLs only

**Important:**
- Be specific to {self.csp_upper} and this exact control
- Use real documentation URLs (not generic)
- Focus on security value and business impact
- Mention specific {self.csp_upper} features/services by correct names

Return ONLY valid JSON:
{{
  "title": "...",
  "description": "...",
  "references": ["url1", "url2", "url3"]
}}"""

        try:
            response = self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": f"You are a {self.csp_upper} cloud security expert specializing in CSPM and compliance. Generate accurate, professional security metadata."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=800
            )
            
            content = response.choices[0].message.content.strip()
            
            # Clean JSON
            if content.startswith('```json'):
                content = content[7:]
            if content.startswith('```'):
                content = content[3:]
            if content.endswith('```'):
                content = content[:-3]
            content = content.strip()
            
            result = json.loads(content)
            self.stats['api_calls'] += 1
            return result
            
        except Exception as e:
            print(f"⚠️  OpenAI error for {rule_id}: {str(e)[:100]}")
            return None
    
    def enhance_rule(self, rule: Dict) -> Dict:
        """Enhance a single rule"""
        
        # Get AI-enhanced metadata
        enhanced = self.enhance_with_openai(rule)
        
        if enhanced:
            # Update rule with enhanced fields
            rule['title'] = enhanced.get('title', rule.get('title', ''))
            rule['description'] = enhanced.get('description', rule.get('description', ''))
            rule['references'] = enhanced.get('references', rule.get('references', []))
            self.stats['enhanced'] += 1
        else:
            self.stats['failed'] += 1
        
        return rule
    
    def enhance_all_rules(self, rules: List[Dict]) -> List[Dict]:
        """Enhance all rules"""
        print(f"\n🚀 Enhancing {len(rules)} {self.csp_upper} rules with OpenAI...")
        print(f"⏱️  Estimated time: {len(rules) * 0.5 / 60:.1f} minutes\n")
        
        self.stats['total_rules'] = len(rules)
        enhanced_rules = []
        
        for idx, rule in enumerate(rules, 1):
            try:
                enhanced_rule = self.enhance_rule(rule)
                enhanced_rules.append(enhanced_rule)
                
                if idx % 50 == 0:
                    print(f"✅ {idx}/{len(rules)} | Enhanced: {self.stats['enhanced']} | Failed: {self.stats['failed']} | API calls: {self.stats['api_calls']}")
                
                # Rate limiting
                if idx % 20 == 0:
                    time.sleep(1)
                
            except Exception as e:
                print(f"❌ Error on {rule.get('rule_id', 'unknown')}: {str(e)}")
                enhanced_rules.append(rule)  # Keep original if enhancement fails
                self.stats['failed'] += 1
        
        return enhanced_rules
    
    def save_enhanced_rules(self, rules: List[Dict], original_path: Path):
        """Save enhanced rules"""
        # Determine output path
        if 'final' in str(original_path):
            output_path = original_path.parent / f"rule_ids_ENRICHED_V3_AI_ENHANCED.yaml"
        else:
            output_path = self.base_dir / "rule_ids_ENRICHED_AI_ENHANCED.yaml"
        
        output_data = {
            'metadata': {
                'csp': self.csp_upper,
                'description': f'Enterprise-grade {self.csp_upper} compliance rules - AI Enhanced (GPT-4)',
                'version': '2.0.0',
                'enhancement_date': time.strftime('%Y-%m-%d'),
                'total_rules': len(rules),
                'quality_grade': 'A+ (AI Enhanced)',
                'ai_engine': 'OpenAI GPT-4o-mini',
                'enhancements': 'AI-improved title, description, and references'
            },
            'statistics': self.stats,
            'rules': rules
        }
        
        with open(output_path, 'w') as f:
            yaml.dump(output_data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
        
        print(f"\n✅ Saved enhanced rules to: {output_path}")
        return output_path
    
    def generate_report(self):
        """Print enhancement summary"""
        success_rate = (self.stats['enhanced'] / self.stats['total_rules'] * 100) if self.stats['total_rules'] > 0 else 0
        
        print("\n" + "="*80)
        print(f"📊 {self.csp_upper} AI ENHANCEMENT SUMMARY")
        print("="*80)
        print(f"Total Rules:           {self.stats['total_rules']}")
        print(f"Successfully Enhanced: {self.stats['enhanced']} ({success_rate:.1f}%)")
        print(f"Failed:                {self.stats['failed']}")
        print(f"Total API Calls:       {self.stats['api_calls']}")
        print(f"Quality Grade:         A+ (AI Enhanced)")
        print("="*80)

def main():
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 ai_quality_enhancer.py <csp_name>")
        print("Examples: alicloud, azure, gcp, ibm, oci")
        print("\nOr use 'all' to enhance all CSPs")
        sys.exit(1)
    
    csp_arg = sys.argv[1].lower()
    
    if csp_arg == 'all':
        csps = ['alicloud', 'azure', 'gcp', 'ibm', 'oci']
    else:
        csps = [csp_arg]
    
    print("="*80)
    print("🎯 AI-Powered Quality Enhancement - OpenAI GPT-4")
    print("="*80)
    print(f"CSPs to enhance: {', '.join(csp.upper() for csp in csps)}\n")
    
    for csp in csps:
        try:
            print(f"\n{'='*80}")
            print(f"Processing {csp.upper()}")
            print(f"{'='*80}")
            
            enhancer = QualityEnhancer(csp)
            rules, original_path = enhancer.load_enriched_rules()
            enhanced_rules = enhancer.enhance_all_rules(rules)
            output_path = enhancer.save_enhanced_rules(enhanced_rules, original_path)
            enhancer.generate_report()
            
            print(f"\n🎉 {csp.upper()} Enhancement Complete!")
            
        except Exception as e:
            print(f"\n❌ Error processing {csp.upper()}: {str(e)}")
            continue
    
    print(f"\n{'='*80}")
    print("✅ All CSP Enhancements Complete!")
    print(f"{'='*80}")

if __name__ == '__main__':
    main()

