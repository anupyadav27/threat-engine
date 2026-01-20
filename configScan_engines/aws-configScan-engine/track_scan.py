#!/usr/bin/env python3
"""Real-time scan tracking and monitoring"""
import os
import time
import glob
from datetime import datetime
from collections import defaultdict

def find_latest_scan():
    """Find the most recent test_performance scan folder"""
    output_dir = "engines-output/aws-configScan-engine/output"
    if not os.path.exists(output_dir):
        return None
    
    folders = glob.glob(os.path.join(output_dir, "test_performance_*"))
    if not folders:
        return None
    
    # Sort by modification time
    folders.sort(key=os.path.getmtime, reverse=True)
    return folders[0]

def analyze_scan(scan_folder):
    """Analyze scan progress and performance"""
    log_file = os.path.join(scan_folder, "logs", "scan.log")
    error_file = os.path.join(scan_folder, "logs", "errors.log")
    
    if not os.path.exists(log_file):
        return None
    
    stats = {
        'scan_name': os.path.basename(scan_folder),
        'discoveries': defaultdict(int),
        'completed': 0,
        'errors': 0,
        'warnings': 0,
        'sagemaker_errors': 0,
        'start_time': None,
        'last_activity': None,
        'services': set(),
        'total_lines': 0
    }
    
    with open(log_file, 'r') as f:
        lines = f.readlines()
        stats['total_lines'] = len(lines)
        
        for line in lines:
            # Extract timestamp
            if 'INFO' in line or 'WARNING' in line or 'ERROR' in line:
                parts = line.split(' ', 2)
                if len(parts) >= 3:
                    try:
                        timestamp = ' '.join(parts[0:2])
                        if not stats['start_time']:
                            stats['start_time'] = timestamp
                        stats['last_activity'] = timestamp
                    except:
                        pass
            
            # Count discoveries
            if 'Processing discovery:' in line:
                disc = line.split('Processing discovery:')[-1].strip()
                stats['discoveries'][disc] += 1
                # Extract service
                if 'aws.' in disc:
                    service = disc.split('.')[1] if len(disc.split('.')) > 1 else 'unknown'
                    stats['services'].add(service)
            
            # Count completed
            if 'Completed discovery' in line:
                stats['completed'] += 1
            
            # Count errors
            if 'ERROR' in line:
                stats['errors'] += 1
            
            # Count warnings
            if 'WARNING' in line:
                stats['warnings'] += 1
                # Check for SageMaker MaxResults errors
                if 'ValidationException' in line and 'maxResults' in line.lower():
                    stats['sagemaker_errors'] += 1
    
    # Count output files
    results_files = glob.glob(os.path.join(scan_folder, "results_*.ndjson"))
    inventory_files = glob.glob(os.path.join(scan_folder, "inventory_*.ndjson"))
    stats['results_files'] = len(results_files)
    stats['inventory_files'] = len(inventory_files)
    
    # Calculate file sizes
    stats['results_size'] = sum(os.path.getsize(f) for f in results_files)
    stats['inventory_size'] = sum(os.path.getsize(f) for f in inventory_files)
    
    return stats

def print_status(stats):
    """Print formatted scan status"""
    if not stats:
        print("⏳ No scan found or scan not started yet")
        return
    
    print("="*80)
    print("SCAN PERFORMANCE TRACKER")
    print("="*80)
    print(f"📁 Scan: {stats['scan_name']}")
    print(f"⏰ Started: {stats['start_time'] or 'N/A'}")
    print(f"🕐 Last Activity: {stats['last_activity'] or 'N/A'}")
    print()
    
    print("📊 Progress:")
    print(f"   Total log entries: {stats['total_lines']:,}")
    print(f"   Discoveries processed: {len(stats['discoveries'])}")
    print(f"   Discoveries completed: {stats['completed']}")
    print(f"   Services: {', '.join(sorted(stats['services']))}")
    print()
    
    print("⚠️  Issues:")
    print(f"   Errors: {stats['errors']}")
    print(f"   Warnings: {stats['warnings']}")
    if stats['sagemaker_errors'] > 0:
        print(f"   ⚠️  SageMaker MaxResults errors: {stats['sagemaker_errors']} (should be 0)")
    else:
        print(f"   ✅ SageMaker MaxResults errors: 0 (fix working!)")
    print()
    
    print("📦 Output:")
    print(f"   Results files: {stats['results_files']}")
    print(f"   Inventory files: {stats['inventory_files']}")
    print(f"   Results size: {stats['results_size']:,} bytes ({stats['results_size']/1024/1024:.2f} MB)")
    print(f"   Inventory size: {stats['inventory_size']:,} bytes ({stats['inventory_size']/1024/1024:.2f} MB)")
    print()
    
    # Top discoveries by count
    if stats['discoveries']:
        print("🔍 Top discoveries:")
        sorted_discs = sorted(stats['discoveries'].items(), key=lambda x: x[1], reverse=True)
        for disc, count in sorted_discs[:5]:
            print(f"   {disc}: {count}")
    print()
    
    print("="*80)

def main():
    scan_folder = find_latest_scan()
    if not scan_folder:
        print("⏳ No test scan found. Waiting for scan to start...")
        return
    
    stats = analyze_scan(scan_folder)
    print_status(stats)
    
    # Check if scan is still running
    import subprocess
    try:
        result = subprocess.run(['pgrep', '-f', 'test_performance'], 
                              capture_output=True, text=True)
        if result.stdout.strip():
            print("✅ Scan is RUNNING")
        else:
            print("⚠️  Scan process NOT running (may have completed)")
    except:
        pass

if __name__ == '__main__':
    main()

