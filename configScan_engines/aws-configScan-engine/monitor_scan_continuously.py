#!/usr/bin/env python3
"""
Continuous scan monitor - checks progress every N seconds until completion.
"""

import time
import json
import sys
from pathlib import Path
from datetime import datetime
from utils.progress_monitor import ProgressMonitor

def find_latest_scan_id() -> str:
    """Find the latest scan ID from output directory."""
    output_dir = Path("/Users/apple/Desktop/threat-engine/engines-output/aws-configScan-engine/output/configscan/discoveries")
    if not output_dir.exists():
        return None
    
    # Find all scan folders
    scan_folders = sorted(
        [d for d in output_dir.iterdir() if d.is_dir()],
        key=lambda x: x.stat().st_mtime,
        reverse=True
    )
    
    if not scan_folders:
        return None
    
    # Extract scan ID from folder name (format: discovery_YYYYMMDD_HHMMSS)
    latest_folder = scan_folders[0]
    scan_id = latest_folder.name
    return scan_id

def monitor_until_complete(scan_id: str, interval: int = 30):
    """Monitor scan until completion."""
    monitor = ProgressMonitor(scan_id)
    
    print(f"🔍 Monitoring scan: {scan_id}")
    print(f"⏱️  Check interval: {interval} seconds")
    print(f"📊 Press Ctrl+C to stop monitoring\n")
    
    try:
        while True:
            # Clear screen for live update
            import os
            os.system('clear' if os.name != 'nt' else 'cls')
            
            print(f"\n{'='*80}")
            print(f"Scan Monitor - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"{'='*80}\n")
            
            # Display progress
            monitor.display_progress("discoveries")
            
            # Check if completed
            try:
                progress_file = monitor._get_progress_file_path("discoveries")
                if progress_file.exists():
                    with open(progress_file, 'r') as f:
                        progress = json.load(f)
                    
                    if progress.get('status') == 'completed':
                        print(f"\n{'='*80}")
                        print("✅ SCAN COMPLETED!")
                        print(f"{'='*80}\n")
                        monitor.display_summary("discoveries")
                        break
            except Exception as e:
                pass
            
            print(f"\n⏳ Next update in {interval} seconds... (Ctrl+C to stop)")
            time.sleep(interval)
            
    except KeyboardInterrupt:
        print(f"\n\n⚠️  Monitoring stopped by user")
        print(f"📊 Final status:")
        monitor.display_progress("discoveries")

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Monitor discovery scan continuously')
    parser.add_argument('--scan-id', type=str, help='Scan ID to monitor (auto-detect if not provided)')
    parser.add_argument('--interval', type=int, default=30, help='Check interval in seconds (default: 30)')
    args = parser.parse_args()
    
    scan_id = args.scan_id or find_latest_scan_id()
    
    if not scan_id:
        print("❌ No scan ID found. Please provide --scan-id or ensure scan is running.")
        sys.exit(1)
    
    monitor_until_complete(scan_id, args.interval)

if __name__ == '__main__':
    main()

