#!/usr/bin/env python3
"""
Batch process services to generate relationships using OpenAI

Processes services one at a time and collects results for review.
"""

import json
import subprocess
import sys
from pathlib import Path
from typing import List

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = PROJECT_ROOT / "inventory-engine" / "inventory_engine" / "config"
SCRIPT_PATH = PROJECT_ROOT / "inventory-engine" / "scripts" / "generate_relationships_with_openai.py"

# High-priority services for CSPM (start with these)
PRIORITY_SERVICES = [
    "eks",           # EKS clusters, nodegroups
    "backup",        # Backup vaults, plans
    "cloudwatch",    # Log groups, alarms
    "config",        # Config rules, recorders
    "autoscaling",   # Auto scaling groups
    "batch",         # Batch compute
    "appsync",       # GraphQL APIs
    "athena",        # Query service
    "cognito",       # User pools
    "codebuild",     # CI/CD
]

def get_services_without_relations() -> List[str]:
    """Get list of services without relations from relationship index."""
    index_file = CONFIG_DIR / "aws_relationship_index.json"
    if not index_file.exists():
        return []
    
    with open(index_file, "r") as f:
        data = json.load(f)
    
    return data.get("metadata", {}).get("services_without_relations", [])

def process_service(service_name: str, api_key: str, model: str = "gpt-4o") -> bool:
    """Process a single service."""
    print(f"\n{'='*60}")
    print(f"Processing: {service_name}")
    print(f"{'='*60}")
    
    cmd = [
        sys.executable,
        str(SCRIPT_PATH),
        service_name,
        "--model", model,
        "--api-key", api_key
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode == 0:
            print(f"✓ Success: {service_name}")
            return True
        else:
            print(f"✗ Failed: {service_name}")
            print(result.stderr)
            return False
    except subprocess.TimeoutExpired:
        print(f"✗ Timeout: {service_name}")
        return False
    except Exception as e:
        print(f"✗ Error: {service_name} - {e}")
        return False

def main():
    if len(sys.argv) < 2:
        print("Usage: python batch_generate_relationships.py <api_key> [--model gpt-4o] [--priority-only]")
        sys.exit(1)
    
    api_key = sys.argv[1]
    model = "gpt-4o"
    priority_only = False
    
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == "--model" and i + 1 < len(sys.argv):
            model = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == "--priority-only":
            priority_only = True
            i += 1
        else:
            i += 1
    
    if priority_only:
        services = PRIORITY_SERVICES
        print(f"Processing {len(services)} priority services...")
    else:
        all_services = get_services_without_relations()
        # Start with priority services, then add others
        priority_set = set(PRIORITY_SERVICES)
        services = PRIORITY_SERVICES + [s for s in all_services if s not in priority_set]
        print(f"Processing {len(services)} services (priority first)...")
    
    results = {"success": [], "failed": []}
    
    for service in services:
        success = process_service(service, api_key, model)
        if success:
            results["success"].append(service)
        else:
            results["failed"].append(service)
    
    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    print(f"Success: {len(results['success'])}")
    print(f"Failed: {len(results['failed'])}")
    
    if results["failed"]:
        print(f"\nFailed services: {', '.join(results['failed'])}")
    
    # Save summary
    summary_file = CONFIG_DIR / "generation_summary.json"
    with open(summary_file, "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\nSummary saved to: {summary_file}")

if __name__ == "__main__":
    main()
