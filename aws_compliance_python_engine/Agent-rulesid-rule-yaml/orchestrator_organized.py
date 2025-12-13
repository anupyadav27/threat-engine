"""
Organized Parallel Orchestrator

All outputs under orchestrator_output/ with clear structure.
Agents coordinate via run_metadata.json.

Structure:
orchestrator_output/
├── run_metadata.json (current state)
├── batch_001/ (results per batch)
├── batch_002/
...
└── summary/ (final merged results)
"""

import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed
import shutil


BATCH_SIZE = 1  # Test with 1 service per batch
MAX_PARALLEL_BATCHES = 5  # Run 5 batches in parallel
ORCHESTRATOR_DIR = 'orchestrator_output'


def setup_orchestrator_structure():
    """Create organized folder structure"""
    os.makedirs(ORCHESTRATOR_DIR, exist_ok=True)
    os.makedirs(f'{ORCHESTRATOR_DIR}/summary', exist_ok=True)
    
    # Initialize run metadata
    run_metadata = {
        'run_id': datetime.now().strftime('%Y%m%d_%H%M%S'),
        'start_time': datetime.now().isoformat(),
        'status': 'initializing',
        'current_batch': 0,
        'total_batches': 0
    }
    
    with open(f'{ORCHESTRATOR_DIR}/run_metadata.json', 'w') as f:
        json.dump(run_metadata, f, indent=2)
    
    return run_metadata['run_id']


def update_run_metadata(updates: dict):
    """Update run metadata file"""
    metadata_file = f'{ORCHESTRATOR_DIR}/run_metadata.json'
    
    with open(metadata_file) as f:
        metadata = json.load(f)
    
    metadata.update(updates)
    metadata['last_updated'] = datetime.now().isoformat()
    
    with open(metadata_file, 'w') as f:
        json.dump(metadata, f, indent=2)


def get_all_services_with_metadata():
    """Get all services with metadata YAML files"""
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


def process_single_batch(batch_num: int, services: list, api_key: str, run_id: str):
    """
    Process one batch - runs from main directory to access metadata files.
    Saves to orchestrator_output/batch_XXX/
    """
    batch_dir_name = f'batch_{batch_num:03d}'
    batch_output_dir = f'{ORCHESTRATOR_DIR}/{batch_dir_name}'
    
    print(f"\n[Batch {batch_num}] Starting: {', '.join(services)}")
    
    batch_start = datetime.now()
    
    try:
        # Create batch directory
        os.makedirs(batch_output_dir, exist_ok=True)
        
        # Save services list
        with open(f'{batch_output_dir}/services.txt', 'w') as f:
            f.write('\n'.join(services))
        
        # Update agent1 for this batch directly
        with open('agent1_requirements_generator.py') as f:
            agent1_original = f.read()
        
        import re
        agent1_batch = re.sub(
            r"SERVICES_TO_PROCESS = \[.*?\]",
            f"SERVICES_TO_PROCESS = {services}",
            agent1_original,
            flags=re.DOTALL
        )
        
        # Save modified agent1 temporarily
        with open('agent1_requirements_generator.py', 'w') as f:
            f.write(agent1_batch)
        
        env = os.environ.copy()
        env['OPENAI_API_KEY'] = api_key
        
        # Run agents from MAIN directory (can access ../services/)
        print(f"[Batch {batch_num}] Running agents...")
        
        # Agent 1
        result1 = subprocess.run(
            'python3 agent1_requirements_generator.py',
            shell=True,
            env=env,
            timeout=600,
            capture_output=True,
            text=True
        )
        
        if result1.returncode != 0:
            print(f"[Batch {batch_num}] Agent 1 error: {result1.stderr[:200]}")
        
        # Agent 2
        subprocess.run(
            'python3 agent2_function_validator.py',
            shell=True,
            timeout=120,
            capture_output=True
        )
        
        # Agent 3
        subprocess.run(
            'python3 agent3_field_validator.py',
            shell=True,
            timeout=120,
            capture_output=True
        )
        
        # Agent 4
        subprocess.run(
            'python3 agent4_yaml_generator.py',
            shell=True,
            timeout=60,
            capture_output=True
        )
        
        # Restore original agent1
        with open('agent1_requirements_generator.py', 'w') as f:
            f.write(agent1_original)
        
        # Copy results to batch output directory
        if os.path.exists('output/requirements_validated.json'):
            shutil.copy('output/requirements_validated.json', batch_output_dir)
        
        # Copy generated YAML files
        for service in services:
            yaml_file = f'output/{service}_generated.yaml'
            if os.path.exists(yaml_file):
                shutil.copy(yaml_file, batch_output_dir)
        
        # Load results for stats
        stats = {'total_rules': 0, 'validated_rules': 0}
        
        if os.path.exists(f'{batch_output_dir}/requirements_validated.json'):
            with open(f'{batch_output_dir}/requirements_validated.json') as f:
                validated = json.load(f)
            
            stats['total_rules'] = sum(len(rules) for rules in validated.values())
            stats['validated_rules'] = sum(
                1 for svc in validated.values() 
                for r in svc if r.get('all_fields_valid')
            )
        
        batch_end = datetime.now()
        duration = (batch_end - batch_start).total_seconds()
        
        result = {
            'batch_number': batch_num,
            'batch_dir': batch_dir_name,
            'services': services,
            'timestamp': batch_start.isoformat(),
            'duration_seconds': duration,
            'stats': stats,
            'status': 'success'
        }
        
        print(f"[Batch {batch_num}] ✅ {stats['validated_rules']}/{stats['total_rules']} validated ({duration:.1f}s)")
        
        return result
        
    except Exception as e:
        print(f"[Batch {batch_num}] ❌ Error: {e}")
        return {
            'batch_number': batch_num,
            'batch_dir': batch_dir_name,
            'services': services,
            'error': str(e),
            'status': 'failed'
        }


def create_summary(batch_results: list):
    """
    Create summary by merging all batch results.
    """
    print("\nCreating summary...")
    
    summary_dir = f'{ORCHESTRATOR_DIR}/summary'
    
    # Merge all requirements
    all_requirements = {}
    all_yamls_dir = f'{summary_dir}/all_generated_yamls'
    os.makedirs(all_yamls_dir, exist_ok=True)
    
    for batch in batch_results:
        if batch['status'] != 'success':
            continue
        
        batch_dir = f"{ORCHESTRATOR_DIR}/{batch['batch_dir']}"
        
        # Merge requirements
        req_file = f'{batch_dir}/requirements_validated.json'
        if os.path.exists(req_file):
            with open(req_file) as f:
                batch_reqs = json.load(f)
            all_requirements.update(batch_reqs)
        
        # Copy YAML files to summary
        for service in batch['services']:
            yaml_file = f'{batch_dir}/{service}_generated.yaml'
            if os.path.exists(yaml_file):
                shutil.copy(yaml_file, all_yamls_dir)
    
    # Save merged requirements
    with open(f'{summary_dir}/all_validated_requirements.json', 'w') as f:
        json.dump(all_requirements, f, indent=2)
    
    # Create summary stats
    total_rules = sum(len(rules) for rules in all_requirements.values())
    total_validated = sum(
        1 for svc in all_requirements.values()
        for r in svc if r.get('all_fields_valid')
    )
    
    summary_stats = {
        'total_services': len(all_requirements),
        'total_rules': total_rules,
        'total_validated': total_validated,
        'validation_rate': f"{total_validated/total_rules*100:.1f}%" if total_rules > 0 else "0%",
        'successful_batches': sum(1 for b in batch_results if b['status'] == 'success'),
        'failed_batches': sum(1 for b in batch_results if b['status'] == 'failed')
    }
    
    with open(f'{summary_dir}/orchestrator_final_report.json', 'w') as f:
        json.dump({
            'summary': summary_stats,
            'batches': batch_results
        }, f, indent=2)
    
    print(f"✅ Summary created in {summary_dir}/")
    
    return summary_stats


def main():
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        print("❌ OPENAI_API_KEY not set")
        sys.exit(1)
    
    print("=" * 80)
    print("ORGANIZED PARALLEL ORCHESTRATOR")
    print("=" * 80)
    print(f"Output: {ORCHESTRATOR_DIR}/")
    print(f"Batch size: {BATCH_SIZE}")
    print(f"Parallel workers: {MAX_PARALLEL_BATCHES}")
    print()
    
    # Setup structure
    run_id = setup_orchestrator_structure()
    
    # Get all services
    all_services = get_all_services_with_metadata()
    
    # TEST MODE: Only process first 5 services
    all_services = all_services[:5]
    total_services = len(all_services)
    
    # Create batches
    batches = []
    batch_num = 1
    for i in range(0, total_services, BATCH_SIZE):
        batch = all_services[i:i+BATCH_SIZE]
        batches.append((batch_num, batch))
        batch_num += 1
    
    total_batches = len(batches)
    
    update_run_metadata({
        'total_batches': total_batches,
        'total_services': total_services,
        'status': 'processing'
    })
    
    print(f"Services: {total_services}")
    print(f"Batches: {total_batches}")
    print()
    
    # Process batches in parallel
    batch_results = []
    
    with ProcessPoolExecutor(max_workers=MAX_PARALLEL_BATCHES) as executor:
        future_to_batch = {
            executor.submit(process_single_batch, batch_num, services, api_key, run_id): batch_num
            for batch_num, services in batches
        }
        
        for future in as_completed(future_to_batch):
            batch_num = future_to_batch[future]
            try:
                result = future.result()
                batch_results.append(result)
                
                # Update progress
                completed = len(batch_results)
                update_run_metadata({
                    'current_batch': batch_num,
                    'completed_batches': completed,
                    'progress': f"{completed}/{total_batches}"
                })
                
                print(f"Progress: {completed}/{total_batches} batches ({completed/total_batches*100:.1f}%)")
                
            except Exception as e:
                print(f"[Batch {batch_num}] Exception: {e}")
                batch_results.append({
                    'batch_number': batch_num,
                    'status': 'exception',
                    'error': str(e)
                })
    
    # Create summary
    summary_stats = create_summary(batch_results)
    
    # Update final metadata
    update_run_metadata({
        'status': 'complete',
        'end_time': datetime.now().isoformat(),
        'summary': summary_stats
    })
    
    # Print final report
    print("\n" + "=" * 80)
    print("ORCHESTRATOR COMPLETE")
    print("=" * 80)
    print(f"\nServices: {summary_stats['total_services']}")
    print(f"Rules: {summary_stats['total_rules']}")
    print(f"Validated: {summary_stats['total_validated']} ({summary_stats['validation_rate']})")
    print(f"Successful batches: {summary_stats['successful_batches']}/{total_batches}")
    
    print(f"\n📁 All outputs in: {ORCHESTRATOR_DIR}/")
    print(f"📊 Summary: {ORCHESTRATOR_DIR}/summary/")
    print(f"📄 Final report: {ORCHESTRATOR_DIR}/summary/orchestrator_final_report.json")


if __name__ == '__main__':
    main()

