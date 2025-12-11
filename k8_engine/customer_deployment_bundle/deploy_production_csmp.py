#!/usr/bin/env python3
'''
Customer Deployment Script for Production-Ready CSMP Services
Deploy optimized services: software, storage
'''

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from enhanced_k8s_tester import EnhancedK8sTester

def deploy_production_services(kubeconfig_path=None):
    '''Deploy production-ready CSMP services'''
    
    tester = EnhancedK8sTester()
    
    if not tester.connect_to_cluster(kubeconfig=kubeconfig_path):
        print("❌ Could not connect to K8s cluster")
        return False
    
    production_services = ['software', 'storage']
    
    print(f"🚀 Deploying {len(production_services)} production-ready CSMP services...")
    
    results = {}
    for service in production_services:
        print(f"🧪 Validating {service}...")
        result = tester.test_service(service)
        results[service] = result
        
        if 'error' not in result:
            rate = result.get('success_rate', 0)
            print(f"   ✅ {service}: {result.get('passed', 0)}/{result.get('total_checks', 0)} ({rate:.1f}%)")
        else:
            print(f"   ❌ {service}: {result['error']}")
    
    return results

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--kubeconfig", help="Path to kubeconfig")
    args = parser.parse_args()
    
    deploy_production_services(args.kubeconfig)
