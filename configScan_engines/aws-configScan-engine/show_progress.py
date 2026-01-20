#!/usr/bin/env python3
"""Show real-time scan progress from latest folder"""
import os
import re
import glob
from datetime import datetime
from collections import defaultdict

def analyze_log(log_file):
    """Analyze scan log file"""
    if not os.path.exists(log_file):
        return None
    
    stats = {
        'total_lines': 0,
        'discoveries': 0,
        'completed': 0,
        'tasks_completed': 0,
        'sagemaker_errors': 0,
        'warnings': 0,
        'start_time': None,
        'last_time': None,
        'services': set(),
        'recent_lines': []
    }
    
    with open(log_file, 'r') as f:
        lines = f.readlines()
        stats['total_lines'] = len(lines)
        
        for line in lines:
            # Extract timestamp
            time_match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
            if time_match:
                timestamp = time_match.group(1)
                if not stats['start_time']:
                    stats['start_time'] = timestamp
                stats['last_time'] = timestamp
            
            # Count discoveries
            if 'Processing discovery:' in line:
                stats['discoveries'] += 1
                # Extract service
                match = re.search(r'aws\.(\w+)\.', line)
                if match:
                    stats['services'].add(match.group(1))
            
            # Count completed
            if 'Completed discovery' in line:
                stats['completed'] += 1
            
            # Count task completions
            if '✓' in line and '/' in line:
                stats['tasks_completed'] += 1
            
            # Count errors
            if 'ValidationException' in line and 'maxResults' in line:
                stats['sagemaker_errors'] += 1
            
            if 'WARNING' in line:
                stats['warnings'] += 1
    
    # Get recent lines
    stats['recent_lines'] = [l.strip() for l in lines[-10:] if l.strip()]
    
    return stats

def main():
    latest_dir = "engines-output/aws-configScan-engine/output/latest"
    log_file = os.path.join(latest_dir, "logs", "scan.log")
    
    print("="*80)
    print("SCAN PROGRESS MONITOR - LATEST FOLDER")
    print("="*80)
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    if not os.path.exists(log_file):
        print("⏳ Log file not found. Waiting for scan to start...")
        return
    
    stats = analyze_log(log_file)
    if not stats:
        print("⏳ Could not analyze log file")
        return
    
    print(f"📁 Scan: latest/")
    print(f"📝 Log: {stats['total_lines']:,} lines")
    
    if stats['start_time']:
        print(f"⏰ Started: {stats['start_time']}")
    if stats['last_time']:
        print(f"🕐 Last Activity: {stats['last_time']}")
    
    print()
    print("📊 Progress:")
    print(f"   Discoveries: {stats['discoveries']} processed, {stats['completed']} completed")
    print(f"   Tasks completed: {stats['tasks_completed']}")
    print(f"   Services: {', '.join(sorted(stats['services']))}")
    print(f"   Warnings: {stats['warnings']}")
    print(f"   SageMaker errors: {stats['sagemaker_errors']} (should be 0)")
    
    # Check output files
    results = glob.glob(os.path.join(latest_dir, "results_*.ndjson"))
    inventory = glob.glob(os.path.join(latest_dir, "inventory_*.ndjson"))
    
    print()
    print("📦 Output Files:")
    print(f"   Results: {len(results)} files")
    print(f"   Inventory: {len(inventory)} files")
    
    if results:
        print()
        print("   Sample results files:")
        for f in sorted(results)[:5]:
            name = os.path.basename(f)
            size = os.path.getsize(f)
            mtime = datetime.fromtimestamp(os.path.getmtime(f))
            print(f"      - {name}")
            print(f"        Size: {size:,} bytes, Updated: {mtime.strftime('%H:%M:%S')}")
    
    if inventory:
        print()
        print("   Sample inventory files:")
        for f in sorted(inventory)[:5]:
            name = os.path.basename(f)
            size = os.path.getsize(f)
            mtime = datetime.fromtimestamp(os.path.getmtime(f))
            print(f"      - {name}")
            print(f"        Size: {size:,} bytes, Updated: {mtime.strftime('%H:%M:%S')}")
    
    print()
    print("📝 Recent Activity:")
    for line in stats['recent_lines'][-5:]:
        if len(line) > 120:
            line = line[:120] + "..."
        print(f"   {line}")
    
    # Check if running
    import subprocess
    try:
        result = subprocess.run(['pgrep', '-f', 'test_performance'], 
                              capture_output=True, text=True)
        if result.stdout.strip():
            print()
            print("✅ Scan is RUNNING")
        else:
            print()
            print("⚠️  Scan process NOT running (may have completed)")
    except:
        pass
    
    print()
    print("="*80)
    print("💡 Run this script again to see updates")
    print("="*80)

if __name__ == '__main__':
    main()

