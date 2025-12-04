#!/usr/bin/env python3
"""
Autonomous Agentic Testing System
1. Run test scan
2. Analyze results (PASS/FAIL/ERROR)
3. Use AI to fix errors
4. Re-test improved version
5. Iterate until quality threshold met
6. Delete test resources automatically
"""

import os
import sys
import json
import subprocess
import yaml
from pathlib import Path
from datetime import datetime
import anthropic

class AutonomousTestingAgent:
    """Autonomous agent that tests, analyzes, and improves services"""
    
    def __init__(self, api_key: str, subscription_id: str):
        self.claude = anthropic.Anthropic(api_key=api_key)
        self.subscription_id = subscription_id
        self.test_rg = 'rg-agentic-test-DELETE'
        self.iteration_limit = 3
        self.quality_threshold = 0.90  # 90% checks must work
    
    def create_test_environment(self):
        """Create minimal test resources"""
        print("\n🔧 Creating test environment...")
        
        cmd = f"az group create --name {self.test_rg} --location eastus"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"   ✅ Test resource group created: {self.test_rg}")
            return True
        else:
            print(f"   ❌ Failed: {result.stderr[:200]}")
            return False
    
    def run_service_scan(self, service_name: str) -> dict:
        """Run compliance scan for a service"""
        print(f"\n📊 Scanning {service_name}...")
        
        cmd = (
            f"cd /Users/apple/Desktop/threat-engine && "
            f"source azure_compliance_python_engine/venv/bin/activate && "
            f"export AZURE_SUBSCRIPTION_ID='{self.subscription_id}' && "
            f"python3 -m azure_compliance_python_engine.engine.targeted_scan "
            f"--services {service_name} --save-report 2>&1"
        )
        
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=180
            )
            
            # Parse output - look for JSON in output
            output = result.stdout
            
            # Try to extract JSON from output
            try:
                # Find JSON array in output
                import re
                json_match = re.search(r'\[\s*\{.*\}\s*\]', output, re.DOTALL)
                if json_match:
                    output_data = json.loads(json_match.group(0))
                    if output_data and len(output_data) > 0:
                        return self._analyze_scan_results(output_data[0], service_name)
            except:
                pass
            
            # If no JSON, check reporting folder
            latest_report = self._get_latest_report()
            if latest_report:
                return self._analyze_report_files(latest_report, service_name)
            
            return {'error': 'No valid output', 'passed': 0, 'failed': 0, 'errors': 0}
            
        except subprocess.TimeoutExpired:
            return {'error': 'Timeout', 'passed': 0, 'failed': 0, 'errors': 0}
        except Exception as e:
            return {'error': str(e), 'passed': 0, 'failed': 0, 'errors': 0}
    
    def _get_latest_report(self):
        """Get latest report folder"""
        # Use absolute path to azure_compliance_python_engine/reporting
        base_dir = Path(__file__).parent
        reporting_dir = base_dir / 'reporting'
        if not reporting_dir.exists():
            return None
        
        reports = sorted(reporting_dir.glob('reporting_*'), key=lambda x: x.stat().st_mtime, reverse=True)
        return reports[0] if reports else None
    
    def _analyze_report_files(self, report_folder: Path, service_name: str) -> dict:
        """Analyze results from report files"""
        try:
            # Check for subscription folder (Azure format)
            sub_folders = list(report_folder.glob('subscription_*'))
            if sub_folders:
                # Look for service checks file - Azure format: default_tenant_SERVICE_checks.json or *_SERVICE_checks.json
                checks_files = list(sub_folders[0].glob(f'*{service_name}_checks.json'))
                if checks_files:
                    with open(checks_files[0], 'r') as f:
                        checks = json.load(f)
                    
                    passed = len([c for c in checks if c.get('result') == 'PASS'])
                    failed = len([c for c in checks if c.get('result') == 'FAIL'])
                    errors = len([c for c in checks if c.get('result') == 'ERROR'])
                    total = len(checks)
                    
                    quality_score = (passed / total) if total > 0 else 0
                    
                    return {
                        'service': service_name,
                        'total': total,
                        'passed': passed,
                        'failed': failed,
                        'errors': errors,
                        'quality_score': quality_score,
                        'meets_threshold': quality_score >= self.quality_threshold,
                        'error_details': [
                            {'check_id': c.get('check_id'), 'error': c.get('error', '')}
                            for c in checks if c.get('result') == 'ERROR'
                        ][:10]
                    }
        except:
            pass
        
        return {'error': 'Could not parse report', 'passed': 0, 'failed': 0, 'errors': 0}
    
    def _analyze_scan_results(self, scan_output: dict, service_name: str) -> dict:
        """Analyze scan results"""
        checks = scan_output.get('checks', [])
        
        passed = len([c for c in checks if c.get('result') == 'PASS'])
        failed = len([c for c in checks if c.get('result') == 'FAIL'])
        errors = len([c for c in checks if c.get('result') == 'ERROR'])
        total = len(checks)
        
        # Extract error details
        error_details = []
        for check in checks:
            if check.get('result') == 'ERROR':
                error_details.append({
                    'check_id': check.get('check_id', ''),
                    'error': check.get('error', '')[:200]
                })
        
        quality_score = (passed / total) if total > 0 else 0
        
        return {
            'service': service_name,
            'total': total,
            'passed': passed,
            'failed': failed,
            'errors': errors,
            'quality_score': quality_score,
            'error_details': error_details[:10],  # First 10 errors
            'meets_threshold': quality_score >= self.quality_threshold
        }
    
    def ai_fix_errors(self, service_name: str, test_results: dict) -> bool:
        """Use Claude to fix errors in service rules"""
        
        if not test_results.get('error_details'):
            return False  # No errors to fix
        
        print(f"\n🤖 AI analyzing and fixing errors for {service_name}...")
        
        # Load current rules
        base_dir = Path(__file__).parent
        rules_file = base_dir / 'services' / service_name / f'{service_name}_rules.yaml'
        with open(rules_file, 'r') as f:
            current_rules = yaml.safe_load(f)
        
        # Create fix prompt
        error_summary = "\n".join([
            f"- {e['check_id']}: {e['error']}"
            for e in test_results['error_details']
        ])
        
        prompt = f"""You are an Azure SDK expert. Fix the errors in this service's rules.

SERVICE: {service_name}
ERRORS FOUND ({len(test_results['error_details'])}):
{error_summary}

CURRENT RULES (relevant sections):
{yaml.dump(current_rules, default_flow_style=False)[:3000]}

FIX THE ERRORS:
1. Correct API endpoint paths
2. Fix field paths
3. Ensure operators are valid
4. Remove invalid endpoints

Return ONLY the corrected YAML (same structure, just fixed).
Focus on fixing the specific errors listed above.
"""
        
        try:
            response = self.claude.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=8000,
                temperature=0.1,
                messages=[{"role": "user", "content": prompt}]
            )
            
            fixed_yaml = response.content[0].text.strip()
            
            # Extract YAML
            if '```yaml' in fixed_yaml:
                fixed_yaml = fixed_yaml.split('```yaml')[1].split('```')[0].strip()
            elif '```' in fixed_yaml:
                fixed_yaml = fixed_yaml.split('```')[1].split('```')[0].strip()
            
            # Parse and save
            fixed_data = yaml.safe_load(fixed_yaml)
            
            with open(rules_file, 'w') as f:
                yaml.dump(fixed_data, f, default_flow_style=False, sort_keys=False, width=120)
            
            print(f"   ✅ AI fixed {len(test_results['error_details'])} errors")
            return True
            
        except Exception as e:
            print(f"   ❌ AI fix failed: {e}")
            return False
    
    def test_and_improve_service(self, service_name: str) -> dict:
        """
        Autonomous test-fix-iterate loop for a service
        
        Returns final test results
        """
        print(f"\n{'='*80}")
        print(f" AUTONOMOUS TESTING: {service_name.upper()}")
        print(f"{'='*80}")
        
        for iteration in range(1, self.iteration_limit + 1):
            print(f"\n🔄 Iteration {iteration}/{self.iteration_limit}")
            
            # Run scan
            results = self.run_service_scan(service_name)
            
            # Show results
            print(f"   Results: {results.get('passed', 0)} PASS, "
                  f"{results.get('failed', 0)} FAIL, "
                  f"{results.get('errors', 0)} ERROR")
            print(f"   Quality: {results.get('quality_score', 0)*100:.1f}%")
            
            # Check if meets threshold
            if results.get('meets_threshold'):
                print(f"   ✅ Quality threshold met ({self.quality_threshold*100}%)")
                return results
            
            # If errors, try to fix
            if results.get('errors', 0) > 0 and iteration < self.iteration_limit:
                print(f"   🔧 Attempting AI fix...")
                if self.ai_fix_errors(service_name, results):
                    print(f"   ↻ Re-testing with fixes...")
                    continue
                else:
                    print(f"   ⚠️  AI fix unsuccessful, keeping current version")
                    break
            else:
                break
        
        return results
    
    def cleanup_test_environment(self):
        """Delete all test resources"""
        print(f"\n{'='*80}")
        print(" 🔴 CLEANUP - DELETING TEST RESOURCES")
        print(f"{'='*80}")
        
        cmd = f"az group delete --name {self.test_rg} --yes --no-wait"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"✅ Cleanup initiated for {self.test_rg}")
            print("   Resources will be deleted in background")
            return True
        else:
            print(f"❌ Cleanup failed: {result.stderr[:200]}")
            print(f"\n⚠️  MANUAL CLEANUP REQUIRED:")
            print(f"   az group delete --name {self.test_rg} --yes")
            return False
    
    def test_all_services(self, services: list):
        """Test all services with autonomous improvement"""
        
        print("\n╔" + "═"*78 + "╗")
        print("║" + " "*20 + "AUTONOMOUS SERVICE TESTING" + " "*32 + "║")
        print("╚" + "═"*78 + "╝")
        
        print(f"\nServices to test: {len(services)}")
        print(f"Quality threshold: {self.quality_threshold*100}%")
        print(f"Max iterations: {self.iteration_limit}\n")
        
        all_results = {}
        
        try:
            # Setup
            if not self.create_test_environment():
                return {}
            
            # Test each service
            for i, service in enumerate(services, 1):
                print(f"\n[{i}/{len(services)}] Testing {service}...")
                
                results = self.test_and_improve_service(service)
                all_results[service] = results
                
                # Progress summary
                if i % 5 == 0:
                    passed_svcs = len([r for r in all_results.values() if r.get('meets_threshold')])
                    print(f"\n📊 Progress: {i}/{len(services)} tested, {passed_svcs} meeting quality")
        
        finally:
            # CRITICAL: Always cleanup
            self.cleanup_test_environment()
        
        return all_results
    
    def generate_report(self, results: dict, output_file: str = 'autonomous_test_report.json'):
        """Generate comprehensive test report"""
        
        report = {
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'subscription_id': self.subscription_id,
                'total_services': len(results)
            },
            'summary': {
                'meeting_threshold': len([r for r in results.values() if r.get('meets_threshold')]),
                'total_passed': sum(r.get('passed', 0) for r in results.values()),
                'total_failed': sum(r.get('failed', 0) for r in results.values()),
                'total_errors': sum(r.get('errors', 0) for r in results.values()),
            },
            'services': results
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        return report


def main():
    # Check requirements
    api_key = os.getenv('ANTHROPIC_API_KEY')
    subscription_id = os.getenv('AZURE_SUBSCRIPTION_ID')
    
    if not api_key or not subscription_id:
        print("❌ Set ANTHROPIC_API_KEY and AZURE_SUBSCRIPTION_ID")
        return 1
    
    # Get services to test
    services_to_test = []
    base_dir = Path(__file__).parent
    services_dir = base_dir / 'services'
    for service_dir in services_dir.iterdir():
        if service_dir.is_dir():
            rules_file = service_dir / f'{service_dir.name}_rules.yaml'
            if rules_file.exists():
                services_to_test.append(service_dir.name)
    
    print(f"Found {len(services_to_test)} services with rules to test")
    
    # Auto-confirm for autonomous operation
    print("\n⚠️  Autonomous mode - will:")
    print("   1. Create test resources in Azure")
    print("   2. Run compliance scans")
    print("   3. Use AI to fix errors")
    print("   4. Iterate until quality met")
    print("   5. AUTO-DELETE all test resources")
    print("\n✅ Starting autonomous testing...")
    
    # Run autonomous testing
    agent = AutonomousTestingAgent(api_key, subscription_id)
    
    # Test all services
    test_services = services_to_test  # Test all available services
    
    results = agent.test_all_services(test_services)
    
    # Generate report
    report = agent.generate_report(results)
    
    print("\n" + "="*80)
    print(" AUTONOMOUS TESTING COMPLETE")
    print("="*80)
    print(f"   Services tested: {len(results)}")
    print(f"   Meeting threshold: {report['summary']['meeting_threshold']}")
    print(f"   Total passed: {report['summary']['total_passed']}")
    print(f"   Total errors: {report['summary']['total_errors']}")
    print(f"\n📄 Report: autonomous_test_report.json")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

