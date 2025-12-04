#!/usr/bin/env python3
"""
Batch generate all 57 remaining Azure services with tracking and logging
Uses quality-controlled agentic system
"""

import os
import sys
import json
import yaml
import csv
from pathlib import Path
from datetime import datetime
import logging
from typing import Dict, List, Tuple
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('agentic_generation.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Import the quality-controlled generator
from agentic_service_generator_quality_controlled import (
    generate_service_with_quality_control,
    QualityValidator
)

# Service tiers for prioritization
TIER_1_SERVICES = ['compute', 'network', 'storage', 'monitor', 'security']
TIER_2_SERVICES = ['keyvault', 'sql', 'aks', 'webapp', 'function', 'cosmosdb', 
                    'backup', 'policy', 'rbac', 'dns']

class ProgressTracker:
    """Track progress across all services"""
    
    def __init__(self, total_services: int):
        self.total = total_services
        self.completed = 0
        self.failed = 0
        self.skipped = 0
        self.start_time = datetime.now()
        self.service_results = {}
    
    def update(self, service: str, success: bool, quality_score: int, errors: List[str]):
        """Update progress for a service"""
        self.service_results[service] = {
            'success': success,
            'quality_score': quality_score,
            'errors': errors,
            'timestamp': datetime.now().isoformat()
        }
        
        if success:
            self.completed += 1
        else:
            self.failed += 1
    
    def skip(self, service: str, reason: str):
        """Mark service as skipped"""
        self.service_results[service] = {
            'skipped': True,
            'reason': reason,
            'timestamp': datetime.now().isoformat()
        }
        self.skipped += 1
    
    def print_progress(self):
        """Print current progress"""
        elapsed = (datetime.now() - self.start_time).total_seconds()
        progress_pct = ((self.completed + self.failed + self.skipped) / self.total) * 100
        
        print(f"\n{'='*80}")
        print(f" PROGRESS: {progress_pct:.1f}% ({self.completed + self.failed + self.skipped}/{self.total})")
        print(f"{'='*80}")
        print(f"   ✅ Completed: {self.completed}")
        print(f"   ❌ Failed: {self.failed}")
        print(f"   ⏭️  Skipped: {self.skipped}")
        print(f"   ⏱️  Elapsed: {elapsed/60:.1f} minutes")
        
        if self.completed > 0:
            avg_time = elapsed / (self.completed + self.failed)
            remaining = (self.total - self.completed - self.failed - self.skipped) * avg_time
            print(f"   📊 ETA: {remaining/60:.1f} minutes")
    
    def save_report(self, filename: str = 'generation_report.json'):
        """Save final report"""
        report = {
            'summary': {
                'total_services': self.total,
                'completed': self.completed,
                'failed': self.failed,
                'skipped': self.skipped,
                'success_rate': (self.completed / (self.completed + self.failed)) * 100 if (self.completed + self.failed) > 0 else 0,
                'duration_minutes': (datetime.now() - self.start_time).total_seconds() / 60
            },
            'services': self.service_results,
            'generated_at': datetime.now().isoformat()
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        return filename


def load_all_services() -> List[Tuple[str, int]]:
    """Load all services with rule counts"""
    mapping_file = Path('AZURE_SERVICE_PACKAGE_MAPPING.csv')
    
    services = []
    with open(mapping_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            service_name = row['service']
            rule_count = int(row['rules'])
            
            # Skip AAD (already done)
            if service_name == 'aad':
                continue
            
            services.append((service_name, rule_count))
    
    return services


def prioritize_services(services: List[Tuple[str, int]]) -> List[Tuple[str, int, int]]:
    """Prioritize services by tier"""
    prioritized = []
    
    for service, rule_count in services:
        if service in TIER_1_SERVICES:
            tier = 1
        elif service in TIER_2_SERVICES:
            tier = 2
        else:
            tier = 3
        
        prioritized.append((service, rule_count, tier))
    
    # Sort by tier, then by rule count (descending)
    return sorted(prioritized, key=lambda x: (x[2], -x[1]))


def batch_generate_all_services(
    max_concurrent: int = 1,
    tier_filter: int = None
):
    """
    Generate all services with tracking
    
    Args:
        max_concurrent: Number of concurrent generations (1 for safety)
        tier_filter: Only generate services in this tier (1, 2, or 3)
    """
    
    logger.info("="*80)
    logger.info(" BATCH GENERATION - ALL AZURE SERVICES")
    logger.info("="*80)
    
    # Load and prioritize services
    all_services = load_all_services()
    prioritized = prioritize_services(all_services)
    
    # Filter by tier if specified
    if tier_filter:
        prioritized = [s for s in prioritized if s[2] == tier_filter]
        logger.info(f"Filtering to Tier {tier_filter} only")
    
    logger.info(f"\nTotal services to generate: {len(prioritized)}")
    logger.info(f"Tier 1: {len([s for s in prioritized if s[2] == 1])} services")
    logger.info(f"Tier 2: {len([s for s in prioritized if s[2] == 2])} services")
    logger.info(f"Tier 3: {len([s for s in prioritized if s[2] == 3])} services")
    
    # Initialize tracker
    tracker = ProgressTracker(len(prioritized))
    
    # Process each service
    for service_name, rule_count, tier in prioritized:
        logger.info(f"\n{'='*80}")
        logger.info(f" SERVICE: {service_name.upper()} (Tier {tier}, {rule_count} rules)")
        logger.info(f"{'='*80}")
        
        try:
            # Check if metadata exists
            metadata_dir = Path('services') / service_name / 'metadata'
            if not metadata_dir.exists() or not list(metadata_dir.glob('*.yaml')):
                logger.warning(f"No metadata for {service_name}, skipping")
                tracker.skip(service_name, "No metadata files")
                continue
            
            # Generate with quality control
            success, rules = generate_service_with_quality_control(service_name)
            
            # Get quality score from last generation
            if success:
                # Simple quality score
                service_data = rules.get(service_name, {})
                quality_score = len(service_data.get('checks', [])) * 10
                tracker.update(service_name, True, quality_score, [])
                logger.info(f"✅ {service_name}: SUCCESS (quality: {quality_score})")
            else:
                tracker.update(service_name, False, 0, ["Generation failed"])
                logger.error(f"❌ {service_name}: FAILED")
            
            # Print progress
            tracker.print_progress()
            
            # Small delay to avoid rate limits
            time.sleep(2)
            
        except Exception as e:
            logger.error(f"❌ {service_name}: Exception - {e}")
            tracker.update(service_name, False, 0, [str(e)])
    
    # Final report
    logger.info(f"\n{'='*80}")
    logger.info(" BATCH GENERATION COMPLETE")
    logger.info(f"{'='*80}")
    
    tracker.print_progress()
    
    # Save report
    report_file = tracker.save_report('batch_generation_report.json')
    logger.info(f"\n📊 Report saved: {report_file}")
    
    # Summary
    print(f"\n{'='*80}")
    print(" FINAL SUMMARY")
    print(f"{'='*80}")
    print(f"   Total: {tracker.total} services")
    print(f"   ✅ Completed: {tracker.completed}")
    print(f"   ❌ Failed: {tracker.failed}")
    print(f"   ⏭️  Skipped: {tracker.skipped}")
    print(f"   Success rate: {(tracker.completed/(tracker.completed+tracker.failed))*100:.1f}%" if (tracker.completed+tracker.failed) > 0 else "N/A")
    print(f"   Duration: {(datetime.now()-tracker.start_time).total_seconds()/60:.1f} minutes")
    
    return tracker.completed, tracker.failed


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Batch generate all Azure services with quality control')
    parser.add_argument('--tier', type=int, choices=[1, 2, 3], help='Only generate services in this tier')
    parser.add_argument('--service', type=str, help='Generate single service')
    args = parser.parse_args()
    
    # Check API key
    if not os.getenv('ANTHROPIC_API_KEY'):
        print("❌ Please set ANTHROPIC_API_KEY environment variable")
        print("   export ANTHROPIC_API_KEY='your-key'")
        return 1
    
    print("╔" + "═"*78 + "╗")
    print("║" + " "*15 + "QUALITY-CONTROLLED BATCH GENERATION" + " "*28 + "║")
    print("╚" + "═"*78 + "╝")
    
    if args.service:
        # Single service
        logger.info(f"Generating single service: {args.service}")
        success, _ = generate_service_with_quality_control(args.service)
        return 0 if success else 1
    else:
        # Batch generation
        completed, failed = batch_generate_all_services(tier_filter=args.tier)
        
        if completed > 0:
            print(f"\n🎉 Successfully generated {completed} services!")
            print(f"\nNext: Test generated services")
            print(f"  python3 batch_test_services.py")
            return 0
        else:
            print(f"\n❌ No services generated successfully")
            return 1


if __name__ == "__main__":
    sys.exit(main())

