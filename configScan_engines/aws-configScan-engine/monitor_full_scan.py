#!/usr/bin/env python3
"""
Monitor Full Discovery Scan Progress
"""
import sys
import os
from pathlib import Path

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from utils.progress_monitor import ProgressMonitor

def find_latest_scan():
    """Find the latest scan ID"""
    output_dir = Path("/Users/apple/Desktop/threat-engine/engines-output/aws-configScan-engine/output")
    discoveries_dir = output_dir / "discoveries"
    
    # Check both old location (for backward compatibility) and new location
    if discoveries_dir.exists():
        scan_dirs = [d for d in discoveries_dir.iterdir() if d.is_dir() and d.name.startswith('discovery_')]
    elif output_dir.exists():
        # Fallback to old location for running scans
        scan_dirs = [d for d in output_dir.iterdir() if d.is_dir() and d.name.startswith('discovery_')]
    else:
        return None
    if not scan_dirs:
        return None
    
    # Get the most recent one
    latest = max(scan_dirs, key=lambda x: x.stat().st_mtime)
    return latest.name

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Monitor discovery scan progress')
    parser.add_argument('--scan-id', help='Scan ID to monitor (default: latest)')
    parser.add_argument('--live', action='store_true', help='Monitor live with auto-refresh')
    parser.add_argument('--interval', type=int, default=10, help='Refresh interval in seconds (default: 10)')
    
    args = parser.parse_args()
    
    scan_id = args.scan_id
    if not scan_id:
        scan_id = find_latest_scan()
        if not scan_id:
            print("❌ No scan found. Please provide --scan-id")
            sys.exit(1)
        print(f"📊 Monitoring latest scan: {scan_id}\n")
    
    monitor = ProgressMonitor(scan_id)
    
    if args.live:
        monitor.monitor_live('discovery', interval=args.interval)
    else:
        monitor.display_progress('discovery')
        print("\n")
        monitor.display_summary('discovery')

