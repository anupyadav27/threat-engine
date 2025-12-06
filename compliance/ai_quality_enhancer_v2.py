#!/usr/bin/env python3
"""
AI Quality Enhancer V2 - Improved Error Handling
Processes Azure, GCP, IBM, OCI (skips AliCloud)
Batch processing with robust retry logic
"""

import yaml
import json
from pathlib import Path
from typing import Dict, List, Optional
import time
import os
from openai import OpenAI
import sys

class ImprovedQualityEnhancer:
    def __init__(self, csp_name: str):
        self.csp_name = csp_name.lower()
        self.csp_upper = csp_name.upper()
        self.base_dir = Path(f"/Users/apple/Desktop/threat-engine/compliance/{self.csp_name}")
        
        # Initialize OpenAI with longer timeout
        api_key = os.getenv('OPENAI_API_KEY')
        if not api_key:
            raise ValueError("OPENAI_API_KEY not set")
        
        self.client = OpenAI(api_key=api_key, timeout=60.0, max_retries=2)
        print(f"✅ OpenAI initialized for {self.csp_upper}")
        
        self.stats = {
            'total_rules': 0,
            'enhanced': 0,
            'failed': 0,
            'connection_errors': 0,
            'api_calls': 0
        }
        
        self.doc_bases = {
            'azure': 'https://docs.microsoft.com/azure',
            'gcp': 'https://cloud.google.com',
            'ibm': 'https://cloud.ibm.com/docs',
            'oci': 'https://docs.oracle.com/iaas'
        }
        
        # Batch settings
        self.batch_size = 10
        self.pause_after_batch = 2
        self.max_connection_errors = 50
    
    def load_enriched_rules(self) -> tuple:
        """Load existing enriched rules"""
        yaml_path = self.base_dir / "rule_ids_ENRICHED.yaml"
        
        if not yaml_path.exists():
            raise FileNotFoundError(f"No enriched rules found at {yaml_path}")
        
        print(f"📂 Loading from: {yaml_path}")
        with open(yaml_path) as f:
            data = yaml.safe_load(f)
        
        rules = data.get('rules', [])
        print(f"✅ Loaded {len(rules)} rules")
        return rules, yaml_path
    
    def enhance_with_openai(self, rule: Dict, retry_count: int = 0) -> Optional[Dict]:
        """Enhanced with better error handling and retry logic"""
        
        if retry_count > 1 or self.stats['connection_errors'] > self.max_connection_errors:
            return None
        
        rule_id = rule.get('rule_id', '')
        service = rule.get('service', '')
        resource = rule.get('resource', '')
        requirement = rule.get('requirement', '')
        severity = rule.get('severity', '')
        
        # Shorter, more focused prompt
        prompt = f"""Improve metadata for {self.csp_upper} security rule:

Service: {service}
Resource: {resource}  
Requirement: {requirement}
Severity: {severity}

Generate JSON with:
1. title: Professional title (max 80 chars, use proper service names)
2. description: 2-3 sentences explaining what it validates, why it matters, security risks
3. references: 3 specific {self.csp_upper} doc URLs (base: {self.doc_bases.get(self.csp_name)})

JSON only:
{{
  "title": "...",
  "description": "...",
  "references": ["url1", "url2", "url3"]
}}"""

        try:
            response = self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": f"{self.csp_upper} security expert. Return only JSON."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=600
            )
            
            content = response.choices[0].message.content.strip()
            
            # Clean JSON
            content = content.replace('```json', '').replace('```', '').strip()
            result = json.loads(content)
            
            self.stats['api_calls'] += 1
            return result
            
        except Exception as e:
            error_str = str(e).lower()
            
            if 'connection' in error_str or 'timeout' in error_str:
                self.stats['connection_errors'] += 1
                
                if retry_count < 1 and self.stats['connection_errors'] < self.max_connection_errors:
                    time.sleep(3)  # Wait before retry
                    return self.enhance_with_openai(rule, retry_count + 1)
            
            return None
    
    def enhance_batch(self, rules_batch: List[Dict]) -> List[Dict]:
        """Process a batch of rules"""
        enhanced_batch = []
        
        for rule in rules_batch:
            enhanced_data = self.enhance_with_openai(rule)
            
            if enhanced_data:
                rule['title'] = enhanced_data.get('title', rule.get('title', ''))
                rule['description'] = enhanced_data.get('description', rule.get('description', ''))
                rule['references'] = enhanced_data.get('references', rule.get('references', []))
                self.stats['enhanced'] += 1
            else:
                self.stats['failed'] += 1
            
            enhanced_batch.append(rule)
        
        return enhanced_batch
    
    def enhance_all_rules(self, rules: List[Dict]) -> List[Dict]:
        """Process all rules in batches"""
        print(f"\n🚀 Enhancing {len(rules)} {self.csp_upper} rules...")
        print(f"📦 Batch size: {self.batch_size}, Pause: {self.pause_after_batch}s\n")
        
        self.stats['total_rules'] = len(rules)
        enhanced_rules = []
        
        for i in range(0, len(rules), self.batch_size):
            batch = rules[i:i + self.batch_size]
            batch_num = i // self.batch_size + 1
            total_batches = (len(rules) + self.batch_size - 1) // self.batch_size
            
            enhanced_batch = self.enhance_batch(batch)
            enhanced_rules.extend(enhanced_batch)
            
            # Progress update
            progress = i + len(batch)
            success_rate = (self.stats['enhanced'] / progress * 100) if progress > 0 else 0
            
            print(f"✅ Batch {batch_num}/{total_batches} | "
                  f"Progress: {progress}/{len(rules)} | "
                  f"Enhanced: {self.stats['enhanced']} ({success_rate:.1f}%) | "
                  f"Failed: {self.stats['failed']} | "
                  f"Conn Errors: {self.stats['connection_errors']}")
            
            # Check if too many connection errors
            if self.stats['connection_errors'] > self.max_connection_errors:
                print(f"\n⚠️  Too many connection errors ({self.stats['connection_errors']}). Stopping.")
                # Keep remaining rules with original content
                enhanced_rules.extend(rules[progress:])
                self.stats['failed'] += len(rules) - progress
                break
            
            # Pause between batches
            if i + self.batch_size < len(rules):
                time.sleep(self.pause_after_batch)
        
        return enhanced_rules
    
    def save_enhanced_rules(self, rules: List[Dict]) -> Path:
        """Save enhanced rules"""
        output_path = self.base_dir / "rule_ids_ENRICHED_AI_ENHANCED.yaml"
        
        output_data = {
            'metadata': {
                'csp': self.csp_upper,
                'description': f'Enterprise-grade {self.csp_upper} rules - AI Enhanced',
                'version': '2.0.0',
                'enhancement_date': time.strftime('%Y-%m-%d'),
                'total_rules': len(rules),
                'quality_grade': 'A+ (AI Enhanced)',
                'ai_engine': 'OpenAI GPT-4o-mini'
            },
            'statistics': self.stats,
            'rules': rules
        }
        
        with open(output_path, 'w') as f:
            yaml.dump(output_data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
        
        print(f"\n✅ Saved to: {output_path}")
        return output_path
    
    def generate_report(self):
        """Print summary"""
        success_rate = (self.stats['enhanced'] / self.stats['total_rules'] * 100) if self.stats['total_rules'] > 0 else 0
        
        print("\n" + "="*80)
        print(f"📊 {self.csp_upper} ENHANCEMENT SUMMARY")
        print("="*80)
        print(f"Total Rules:           {self.stats['total_rules']}")
        print(f"Successfully Enhanced: {self.stats['enhanced']} ({success_rate:.1f}%)")
        print(f"Failed:                {self.stats['failed']}")
        print(f"Connection Errors:     {self.stats['connection_errors']}")
        print(f"Total API Calls:       {self.stats['api_calls']}")
        print(f"Quality Grade:         {'A+' if success_rate > 90 else 'A' if success_rate > 70 else 'B+'}")
        print("="*80)

def main():
    # Only process these CSPs (skip alicloud)
    csps_to_process = ['azure', 'gcp', 'ibm', 'oci']
    
    print("="*80)
    print("🎯 AI Quality Enhancement V2 - Improved Error Handling")
    print("="*80)
    print(f"CSPs: {', '.join(csp.upper() for csp in csps_to_process)}")
    print("Skipping: ALICLOUD (already done)")
    print("="*80)
    
    for csp in csps_to_process:
        try:
            print(f"\n{'='*80}")
            print(f"Processing {csp.upper()}")
            print(f"{'='*80}")
            
            enhancer = ImprovedQualityEnhancer(csp)
            rules, original_path = enhancer.load_enriched_rules()
            enhanced_rules = enhancer.enhance_all_rules(rules)
            enhancer.save_enhanced_rules(enhanced_rules)
            enhancer.generate_report()
            
            print(f"\n🎉 {csp.upper()} Complete!")
            
        except Exception as e:
            print(f"\n❌ Error processing {csp.upper()}: {str(e)}")
            continue
    
    print(f"\n{'='*80}")
    print("✅ All CSP Enhancements Complete!")
    print(f"{'='*80}")

if __name__ == '__main__':
    main()

