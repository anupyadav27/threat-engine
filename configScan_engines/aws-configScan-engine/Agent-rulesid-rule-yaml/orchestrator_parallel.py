"""
Parallel Orchestrator for All Services

Processes ALL services in PARALLEL batches:
- Each batch runs independently
- No shared state between batches
- Much faster than sequential

Output: Each batch saves to its own folder
"""

import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed
import time


BATCH_SIZE = 5
MAX_PARALLEL_BATCHES = 5  # Run 5 batches at once


def get_all_services_with_metadata():
    """Get list of all services that have metadata files"""
    services = set()
    
    services_dir = Path('../services')
    for service_dir in services_dir.iterdir():
        if service_dir.is_dir():
            metadata_dir = service_dir / 'metadata'
            if metadata_dir.exists():
                yaml_files = list(metadata_dir.glob('*.yaml'))
                if yaml_files:
                    services.add(service_dir.name)
    
    return sorted(list(services))


def process_single_batch(batch_num: int, services: list, api_key: str):
    """
    Process a single batch in isolation.
    Each batch has its own working directory to avoid conflicts.
    
    Returns:
        Batch result dict
    """
    batch_dir = f'batch_{batch_num}_work'
    os.makedirs(batch_dir, exist_ok=True)
    
    print(f"[Batch {batch_num}] Starting: {', '.join(services)}")
    
    batch_start = datetime.now()
    
    try:
        # Create agent1 script for this batch
        agent1_code = f"""
SERVICES_TO_PROCESS = {services}

# Import rest of agent1 code
"""
        
        # Read template agent1
        with open('agent1_requirements_generator.py') as f:
            original_agent1 = f.read()
        
        # Replace SERVICES_TO_PROCESS
        import re
        pattern = r"SERVICES_TO_PROCESS = \[.*?\]"
        batch_agent1 = re.sub(pattern, f"SERVICES_TO_PROCESS = {services}", original_agent1)
        
        # Write batch-specific agent1
        batch_agent1_file = f'{batch_dir}/agent1.py'
        with open(batch_agent1_file, 'w') as f:
            f.write(batch_agent1)
        
        # Create batch output dir
        batch_output = f'{batch_dir}/output'
        os.makedirs(batch_output, exist_ok=True)
        
        env = os.environ.copy()
        env['OPENAI_API_KEY'] = api_key
        
        # Run Agent 1
        print(f"[Batch {batch_num}] Running Agent 1...")
        result1 = subprocess.run(
            f'cd {batch_dir} && python3 agent1.py',
            shell=True,
            capture_output=True,
            text=True,
            timeout=600,
            env=env,
            cwd=os.getcwd()
        )
        
        if result1.returncode != 0:
            raise Exception(f"Agent 1 failed: {result1.stderr[:200]}")
        
        print(f"[Batch {batch_num}] Agent 1 ✅")
        
        # Copy other agents and run
        for agent_file in ['agent2_function_validator.py', 'agent3_field_validator.py', 
                          'agent4_yaml_generator.py', 'boto3_dependencies_with_python_names.json']:
            subprocess.run(f'cp {agent_file} {batch_dir}/', shell=True)
        
        # Run Agent 2
        print(f"[Batch {batch_num}] Running Agent 2...")
        subprocess.run(
            f'cd {batch_dir} && python3 agent2_function_validator.py',
            shell=True,
            timeout=120
        )
        
        # Run Agent 3
        print(f"[Batch {batch_num}] Running Agent 3...")
        subprocess.run(
            f'cd {batch_dir} && python3 agent3_field_validator.py',
            shell=True,
            timeout=120
        )
        
        # Run Agent 4
        print(f"[Batch {batch_num}] Running Agent 4...")
        subprocess.run(
            f'cd {batch_dir} && python3 agent4_yaml_generator.py',
            shell=True,
            timeout=60
        )
        
        # Load results
        with open(f'{batch_dir}/output/requirements_validated.json') as f:
            validated = json.load(f)
        
        total_rules = sum(len(rules) for rules in validated.values())
        validated_rules = sum(1 for svc in validated.values() for r in svc if r.get('all_fields_valid'))
        
        # Archive results
        archive_dir = f'output_batch_{batch_num}'
        os.makedirs(archive_dir, exist_ok=True)
        subprocess.run(f'cp -r {batch_dir}/output/* {archive_dir}/', shell=True)
        
        # Cleanup work dir
        subprocess.run(f'rm -rf {batch_dir}', shell=True)
        
        batch_end = datetime.now()
        duration = (batch_end - batch_start).total_seconds()
        
        result = {
            'batch_number': batch_num,
            'services': services,
            'timestamp': batch_start.isoformat(),
            'duration_seconds': duration,
            'stats': {
                'total_rules': total_rules,
                'validated_rules': validated_rules,
                'validation_rate': f"{validated_rules/total_rules*100:.1f}%" if total_rules > 0 else "0%"
            },
            'status': 'success'
        }
        
        print(f"[Batch {batch_num}] ✅ Complete: {validated_rules}/{total_rules} validated")
        
        return result
        
    except Exception as e:
        print(f"[Batch {batch_num}] ❌ Failed: {e}")
        return {
            'batch_number': batch_num,
            'services': services,
            'error': str(e),
            'status': 'failed'
        }


def main():
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        print("❌ OPENAI_API_KEY not set")
        sys.exit(1)
    
    print("=" * 80)
    print("PARALLEL ORCHESTRATOR")
    print("=" * 80)
    print(f"Batch size: {BATCH_SIZE}")
    print(f"Max parallel: {MAX_PARALLEL_BATCHES}")
    print()
    
    # Get all services
    all_services = get_all_services_with_metadata()
    total_services = len(all_services)
    
    print(f"Total services: {total_services}")
    print(f"Total batches: {(total_services + BATCH_SIZE - 1) // BATCH_SIZE}")
    print()
    
    # Create batches
    batches = []
    batch_num = 1
    for i in range(0, total_services, BATCH_SIZE):
        batch = all_services[i:i+BATCH_SIZE]
        batches.append((batch_num, batch))
        batch_num += 1
    
    # Process batches in parallel
    batch_results = []
    
    with ProcessPoolExecutor(max_workers=MAX_PARALLEL_BATCHES) as executor:
        # Submit all batches
        future_to_batch = {
            executor.submit(process_single_batch, batch_num, services, api_key): batch_num
            for batch_num, services in batches
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_batch):
            batch_num = future_to_batch[future]
            try:
                result = future.result()
                batch_results.append(result)
                
                completed = len(batch_results)
                total = len(batches)
                print(f"\n{'=' * 60}")
                print(f"Progress: {completed}/{total} batches complete ({completed/total*100:.1f}%)")
                print(f"{'=' * 60}\n")
                
            except Exception as e:
                print(f"[Batch {batch_num}] Exception: {e}")
                batch_results.append({
                    'batch_number': batch_num,
                    'status': 'exception',
                    'error': str(e)
                })
    
    # Save orchestrator log
    batch_results.sort(key=lambda x: x['batch_number'])
    
    total_rules = sum(b.get('stats', {}).get('total_rules', 0) for b in batch_results if b.get('status') == 'success')
    total_validated = sum(b.get('stats', {}).get('validated_rules', 0) for b in batch_results if b.get('status') == 'success')
    successful = sum(1 for b in batch_results if b.get('status') == 'success')
    
    orchestrator_log = {
        'run_date': datetime.now().isoformat(),
        'total_services': total_services,
        'total_batches': len(batches),
        'parallel_workers': MAX_PARALLEL_BATCHES,
        'batches': batch_results,
        'summary': {
            'total_rules_processed': total_rules,
            'total_validated': total_validated,
            'validation_rate': f"{total_validated/total_rules*100:.1f}%" if total_rules > 0 else "0%",
            'successful_batches': successful,
            'failed_batches': len(batches) - successful
        }
    }
    
    with open('orchestrator_parallel_log.json', 'w') as f:
        json.dump(orchestrator_log, f, indent=2)
    
    print("\n" + "=" * 80)
    print("PARALLEL ORCHESTRATOR COMPLETE")
    print("=" * 80)
    print(f"\nServices: {total_services}")
    print(f"Batches: {len(batches)}")
    print(f"Successful: {successful}")
    print(f"\nRules: {total_rules}")
    print(f"Validated: {total_validated} ({total_validated/total_rules*100:.1f}%)" if total_rules > 0 else "N/A")
    print(f"\n✅ Log: orchestrator_parallel_log.json")


if __name__ == '__main__':
    main()

