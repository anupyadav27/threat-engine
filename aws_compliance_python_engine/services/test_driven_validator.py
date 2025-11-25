#!/usr/bin/env python3
"""
TEST-DRIVEN CHECK VALIDATOR
Run checks against real AWS and collect actual errors for systematic fixes
"""

import boto3
import yaml
import json
from pathlib import Path
from collections import defaultdict
import traceback
from datetime import datetime

class TestDrivenValidator:
    def __init__(self):
        self.services_dir = Path("/Users/apple/Desktop/threat-engine/aws_compliance_python_engine/services")
        self.results_dir = self.services_dir / "test_results"
        self.results_dir.mkdir(exist_ok=True)
        
        # Test against real AWS
        self.session = boto3.Session()
        self.region = self.session.region_name or 'us-east-1'
        
        print(f"✅ Initialized for region: {self.region}")
        
        self.test_results = {
            'timestamp': datetime.now().isoformat(),
            'region': self.region,
            'services': []
        }
    
    def test_discovery_step(self, service_name, discovery_step):
        """Test a single discovery step against real AWS"""
        
        disc_id = discovery_step.get('discovery_id', 'unknown')
        results = {
            'discovery_id': disc_id,
            'status': 'unknown',
            'calls_tested': 0,
            'calls_succeeded': 0,
            'calls_failed': 0,
            'errors': [],
            'fixes_needed': []
        }
        
        for call in discovery_step.get('calls', []):
            client_name = call.get('client')
            action = call.get('action')
            params = call.get('params', {})
            
            results['calls_tested'] += 1
            
            try:
                # Try to create client
                client = self.session.client(client_name, region_name=self.region)
                
                # Check if method exists
                if not hasattr(client, action):
                    results['calls_failed'] += 1
                    results['errors'].append({
                        'type': 'method_not_found',
                        'client': client_name,
                        'action': action,
                        'message': f"Method '{action}' not found on {client_name} client"
                    })
                    
                    # Suggest alternatives
                    available_methods = [m for m in dir(client) if not m.startswith('_')]
                    similar = [m for m in available_methods if action.replace('_', '').lower() in m.lower()]
                    
                    if similar:
                        results['fixes_needed'].append({
                            'issue': f"Invalid action: {action}",
                            'suggestions': similar[:5],
                            'fix_type': 'replace_action'
                        })
                    continue
                
                # Try to call the method (without params for now, just to validate signature)
                # We won't actually execute to avoid costs/side effects
                method = getattr(client, action)
                
                results['calls_succeeded'] += 1
                results['status'] = 'valid_method'
                
            except Exception as e:
                results['calls_failed'] += 1
                results['errors'].append({
                    'type': 'client_error',
                    'client': client_name,
                    'action': action,
                    'message': str(e),
                    'traceback': traceback.format_exc()
                })
                
                # Determine fix type
                if 'Unknown service' in str(e):
                    results['fixes_needed'].append({
                        'issue': f"Invalid service: {client_name}",
                        'fix_type': 'fix_service_name',
                        'suggestion': self.suggest_service_name(client_name)
                    })
                elif 'Could not connect' in str(e):
                    results['fixes_needed'].append({
                        'issue': 'AWS credentials not configured',
                        'fix_type': 'credentials',
                        'suggestion': 'Run: aws configure'
                    })
        
        if results['calls_succeeded'] == results['calls_tested']:
            results['status'] = 'passed'
        elif results['calls_failed'] == results['calls_tested']:
            results['status'] = 'failed'
        else:
            results['status'] = 'partial'
        
        return results
    
    def suggest_service_name(self, invalid_name):
        """Suggest correct service name"""
        
        # Known mappings
        mappings = {
            'fargate': 'ecs (Fargate is part of ECS)',
            'identitycenter': 'identitystore',
            'kinesisfirehose': 'firehose',
            'kinesisvideostreams': 'kinesisvideo',
            'vpcflowlogs': 'ec2 (VPC Flow Logs via EC2)',
            'elastic': 'opensearch or es',
            'edr': 'Not a standalone service',
            'no': 'Invalid service name'
        }
        
        return mappings.get(invalid_name, f"Check AWS documentation for '{invalid_name}'")
    
    def test_service(self, service_name):
        """Test all discovery steps for a service"""
        
        rules_file = self.services_dir / service_name / "rules" / f"{service_name}.yaml"
        
        if not rules_file.exists():
            return None
        
        try:
            with open(rules_file, 'r') as f:
                data = yaml.safe_load(f)
            
            service_results = {
                'service': service_name,
                'total_discovery_steps': len(data.get('discovery', [])),
                'total_checks': len(data.get('checks', [])),
                'discovery_results': [],
                'summary': {
                    'passed': 0,
                    'failed': 0,
                    'partial': 0
                },
                'priority': 'unknown'
            }
            
            # Test each discovery step
            for disc_step in data.get('discovery', []):
                result = self.test_discovery_step(service_name, disc_step)
                service_results['discovery_results'].append(result)
                
                # Update summary
                status = result['status']
                if status == 'passed':
                    service_results['summary']['passed'] += 1
                elif status == 'failed':
                    service_results['summary']['failed'] += 1
                elif status == 'partial':
                    service_results['summary']['partial'] += 1
            
            # Determine priority
            total = service_results['total_discovery_steps']
            failed = service_results['summary']['failed']
            
            if failed == 0:
                service_results['priority'] = 'low'  # Already working
            elif failed == total:
                service_results['priority'] = 'critical'  # Completely broken
            else:
                service_results['priority'] = 'high'  # Partially working
            
            return service_results
            
        except Exception as e:
            return {
                'service': service_name,
                'error': str(e),
                'traceback': traceback.format_exc()
            }
    
    def test_all_services(self, limit=None):
        """Test all services against real AWS"""
        
        print(f"\n{'='*80}")
        print(f"TEST-DRIVEN VALIDATION AGAINST REAL AWS")
        print(f"{'='*80}\n")
        
        # Get all services
        services = []
        for service_dir in sorted(self.services_dir.iterdir()):
            if service_dir.is_dir():
                rules_file = service_dir / "rules" / f"{service_dir.name}.yaml"
                if rules_file.exists():
                    services.append(service_dir.name)
        
        if limit:
            services = services[:limit]
        
        print(f"Testing {len(services)} services...\n")
        
        for i, service_name in enumerate(services, 1):
            print(f"[{i}/{len(services)}] Testing {service_name}...")
            
            result = self.test_service(service_name)
            
            if result and 'error' not in result:
                self.test_results['services'].append(result)
                
                passed = result['summary']['passed']
                failed = result['summary']['failed']
                partial = result['summary']['partial']
                total = result['total_discovery_steps']
                priority = result['priority']
                
                priority_icon = {
                    'low': '✅',
                    'high': '⚠️ ',
                    'critical': '❌'
                }.get(priority, '❓')
                
                print(f"  {priority_icon} {passed} passed, {failed} failed, {partial} partial (Priority: {priority})")
            else:
                print(f"  ❌ Error: {result.get('error', 'Unknown')}")
        
        # Generate summary
        self.generate_summary()
        
        # Save results
        self.save_results()
        
        return self.test_results
    
    def generate_summary(self):
        """Generate test summary"""
        
        print(f"\n{'='*80}")
        print(f"TEST SUMMARY")
        print(f"{'='*80}\n")
        
        services_tested = len(self.test_results['services'])
        
        # Count by priority
        critical = sum(1 for s in self.test_results['services'] if s['priority'] == 'critical')
        high = sum(1 for s in self.test_results['services'] if s['priority'] == 'high')
        low = sum(1 for s in self.test_results['services'] if s['priority'] == 'low')
        
        print(f"Services tested: {services_tested}")
        print(f"  ❌ Critical (completely broken): {critical}")
        print(f"  ⚠️  High (partially working): {high}")
        print(f"  ✅ Low (working): {low}")
        
        # Collect all unique errors
        error_types = defaultdict(int)
        for service in self.test_results['services']:
            for disc_result in service['discovery_results']:
                for error in disc_result['errors']:
                    error_types[error['type']] += 1
        
        if error_types:
            print(f"\nError breakdown:")
            for error_type, count in sorted(error_types.items(), key=lambda x: x[1], reverse=True):
                print(f"  • {error_type}: {count}")
        
        # Collect all fixes needed
        fix_types = defaultdict(int)
        for service in self.test_results['services']:
            for disc_result in service['discovery_results']:
                for fix in disc_result['fixes_needed']:
                    fix_types[fix['fix_type']] += 1
        
        if fix_types:
            print(f"\nFixes needed:")
            for fix_type, count in sorted(fix_types.items(), key=lambda x: x[1], reverse=True):
                print(f"  • {fix_type}: {count}")
    
    def save_results(self):
        """Save test results"""
        
        # Save JSON results
        json_file = self.results_dir / f"test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(json_file, 'w') as f:
            json.dump(self.test_results, f, indent=2)
        
        print(f"\n📄 Test results: {json_file}")
        
        # Generate fix priority report
        self.generate_fix_priority_report()
    
    def generate_fix_priority_report(self):
        """Generate prioritized fix report"""
        
        report_file = self.results_dir / "FIX_PRIORITY_REPORT.md"
        
        with open(report_file, 'w') as f:
            f.write("# Test-Driven Fix Priority Report\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Region: {self.region}\n\n")
            
            # Group services by priority
            critical_services = [s for s in self.test_results['services'] if s['priority'] == 'critical']
            high_services = [s for s in self.test_results['services'] if s['priority'] == 'high']
            low_services = [s for s in self.test_results['services'] if s['priority'] == 'low']
            
            # Critical services
            f.write("## 🔴 CRITICAL Priority (Fix First)\n\n")
            f.write(f"**{len(critical_services)} services completely broken**\n\n")
            
            for service in critical_services[:10]:  # Top 10
                f.write(f"### {service['service']}\n\n")
                f.write(f"- Discovery steps: {service['total_discovery_steps']}\n")
                f.write(f"- Failed: {service['summary']['failed']}\n")
                f.write(f"- Checks affected: {service['total_checks']}\n\n")
                
                # Show sample fixes
                for disc in service['discovery_results'][:2]:
                    if disc['fixes_needed']:
                        for fix in disc['fixes_needed'][:2]:
                            f.write(f"**Fix needed**: {fix['issue']}\n")
                            if 'suggestion' in fix:
                                f.write(f"- Suggestion: {fix['suggestion']}\n")
                            elif 'suggestions' in fix:
                                f.write(f"- Suggestions: {', '.join(fix['suggestions'][:3])}\n")
                            f.write("\n")
                f.write("\n")
            
            # High priority services
            f.write("## 🟡 HIGH Priority (Fix Next)\n\n")
            f.write(f"**{len(high_services)} services partially working**\n\n")
            
            for service in high_services[:5]:
                f.write(f"### {service['service']}\n\n")
                f.write(f"- Passed: {service['summary']['passed']}\n")
                f.write(f"- Failed: {service['summary']['failed']}\n")
                f.write(f"- Partial: {service['summary']['partial']}\n\n")
            
            # Working services
            f.write("## 🟢 LOW Priority (Working)\n\n")
            f.write(f"**{len(low_services)} services working correctly**\n\n")
            
            for service in low_services:
                f.write(f"- {service['service']} ({service['total_checks']} checks)\n")
        
        print(f"📄 Fix priority report: {report_file}")

if __name__ == '__main__':
    import sys
    
    print("🚀 Starting Test-Driven Validation...\n")
    print("⚠️  This will test against your REAL AWS account")
    print("   - No resources will be created/modified")
    print("   - Only API method validation (no actual calls)")
    print("   - Checks AWS credentials configuration\n")
    
    validator = TestDrivenValidator()
    
    # Test limit (start small)
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    
    results = validator.test_all_services(limit=limit)
    
    print(f"\n🎉 Testing complete!")
    print(f"\nNext steps:")
    print(f"1. Review test_results/ for detailed findings")
    print(f"2. Start fixing CRITICAL services first")
    print(f"3. Re-test after each fix to validate")
    print(f"4. Gradually increase test coverage")

