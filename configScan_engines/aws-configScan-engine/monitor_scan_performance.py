#!/usr/bin/env python3
"""
Monitor scan performance and identify optimization opportunities.
Run this script periodically to watch for slow operations and errors.
"""

import re
from pathlib import Path
from collections import defaultdict
from datetime import datetime
import sys

def find_latest_scan_log():
    """Find the most recent scan log file."""
    output_dir = Path('engines-output/aws-configScan-engine/output')
    if not output_dir.exists():
        return None
    
    # Find all scan directories
    scan_dirs = [d for d in output_dir.iterdir() if d.is_dir() and 'full_scan' in d.name]
    if not scan_dirs:
        return None
    
    # Get most recent
    latest_scan = max(scan_dirs, key=lambda x: x.stat().st_mtime)
    log_file = latest_scan / 'logs' / 'scan.log'
    
    if log_file.exists():
        return log_file
    return None

def analyze_scan_performance(log_file):
    """Analyze scan log for performance issues."""
    print("="*80)
    print("SCAN PERFORMANCE MONITORING")
    print("="*80)
    print()
    
    with open(log_file, 'r') as f:
        lines = f.readlines()
    
    # Get scan start time
    start_time = None
    for line in lines[:100]:
        if '[SCAN-START]' in line:
            match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
            if match:
                start_time = datetime.strptime(match.group(1), '%Y-%m-%d %H:%M:%S')
                break
    
    # Get latest activity
    latest_time = None
    task_pattern = re.compile(r'\[(\d+)/7720\]')
    tasks_completed = 0
    
    for line in reversed(lines[-1000:]):
        match = task_pattern.search(line)
        if match:
            tasks_completed = int(match.group(1))
            time_match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
            if time_match:
                latest_time = datetime.strptime(time_match.group(1), '%Y-%m-%d %H:%M:%S')
            break
    
    now = datetime.now()
    
    # Progress
    print("📊 SCAN PROGRESS:")
    if start_time:
        elapsed = (now - start_time).total_seconds()
        print(f"   Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"   Elapsed: {elapsed/60:.1f} minutes ({elapsed/3600:.2f} hours)")
        
        if latest_time:
            activity_age = (now - latest_time).total_seconds()
            print(f"   Last activity: {latest_time.strftime('%H:%M:%S')} ({activity_age:.0f}s ago)")
            if activity_age > 300:  # 5 minutes
                print(f"   ⚠️  WARNING: No activity for {activity_age/60:.1f} minutes!")
    
    if tasks_completed > 0:
        progress_pct = (tasks_completed / 7720) * 100
        print(f"   Tasks: {tasks_completed:,} / 7,720 ({progress_pct:.1f}%)")
        
        if start_time and elapsed > 60:
            rate = tasks_completed / elapsed
            remaining = 7720 - tasks_completed
            eta = remaining / rate if rate > 0 else 0
            print(f"   Rate: {rate:.3f} tasks/sec ({rate*3600:.0f} tasks/hour)")
            print(f"   ETA: {eta/60:.0f} minutes ({eta/3600:.1f} hours)")
    
    print()
    
    # Analyze slow operations (last 5000 lines for recent activity)
    print("⏱️  SLOW OPERATIONS (Recent Activity - Last 5000 lines):")
    print()
    
    recent_lines = lines[-5000:]
    discovery_times = defaultdict(list)
    pattern = re.compile(r'Completed discovery (aws\.([^.]+)\.([^:]+)):\s+([0-9]+\.?[0-9]*)s')
    
    for line in recent_lines:
        match = pattern.search(line)
        if match:
            full_discovery = match.group(1)
            time = float(match.group(4))
            discovery_times[full_discovery].append(time)
    
    # Find slow operations
    slow_ops = []
    for discovery, times in discovery_times.items():
        if len(times) > 0:
            max_time = max(times)
            avg_time = sum(times) / len(times)
            count = len(times)
            
            # Flag if max > 60s or avg > 30s
            if max_time > 60 or avg_time > 30:
                slow_ops.append((discovery, avg_time, max_time, count))
    
    slow_ops.sort(key=lambda x: x[2], reverse=True)  # Sort by max time
    
    if slow_ops:
        print(f"{'Discovery':<65} {'Avg':<10} {'Max':<10} {'Count':<8} {'Status':<15}")
        print("-" * 110)
        
        # Known optimizations
        optimized = {
            'describe_snapshots': '✅ Fixed (OwnerIds)',
            'describe_images': '✅ Fixed (Owners)',
            'list_device_fleets': '✅ Fixed (MaxResults)',
            'list_edge_packaging_jobs': '✅ Fixed (MaxResults)',
            'list_flow_definitions': '✅ Fixed (MaxResults)',
            'list_assessment_templates': '✅ Fixed (MaxResults)',
            'list_findings': '✅ Fixed (MaxResults)',
        }
        
        for discovery, avg, max_t, count in slow_ops[:20]:
            status = '⚠️  Needs optimization'
            for key, msg in optimized.items():
                if key in discovery:
                    status = msg
                    break
            
            print(f"{discovery:<65} {avg:>6.1f}s    {max_t:>6.1f}s    {count:<8} {status:<15}")
    else:
        print("   ✅ No slow operations found in recent activity")
    
    print()
    
    # Analyze errors
    print("🔍 ERROR ANALYSIS (Recent Activity):")
    print()
    
    error_types = defaultdict(int)
    error_details = []
    
    for line in recent_lines:
        if 'ERROR' in line or 'Exception' in line or 'Failed' in line:
            # Categorize errors
            if 'timeout' in line.lower():
                error_types['Timeout'] += 1
            elif 'throttl' in line.lower():
                error_types['Throttling'] += 1
            elif 'accessdenied' in line.lower():
                error_types['AccessDenied'] += 1
            elif 'parametervalidation' in line.lower() or 'parameter validation' in line.lower():
                error_types['ParameterValidation'] += 1
            elif 'connection' in line.lower() or 'could not connect' in line.lower():
                error_types['Connection'] += 1
            elif 'exception' in line.lower():
                error_types['Exception'] += 1
            else:
                error_types['Other'] += 1
            
            # Keep unique error details
            if len(error_details) < 20:
                error_details.append(line.strip())
    
    if error_types:
        print("   Error Summary:")
        for err_type, count in sorted(error_types.items(), key=lambda x: x[1], reverse=True):
            status = "✅ Expected" if err_type in ['ParameterValidation', 'AccessDenied'] else "⚠️  Review"
            print(f"      {err_type:<25} {count:>5}  {status}")
        
        # Show recent unique errors
        print()
        print("   Recent Unique Errors (last 5):")
        seen = set()
        unique_errors = []
        for err in reversed(error_details):
            # Extract error message
            if 'Failed' in err:
                match = re.search(r'Failed ([^:]+):', err)
                if match:
                    key = match.group(1)
                    if key not in seen:
                        seen.add(key)
                        unique_errors.append(err)
                        if len(unique_errors) >= 5:
                            break
        
        for err in unique_errors:
            if len(err) > 150:
                err = err[:147] + "..."
            print(f"      {err}")
    else:
        print("   ✅ No errors found in recent activity")
    
    print()
    
    # Check for operations that might need MaxResults
    print("🔎 POTENTIAL OPTIMIZATION OPPORTUNITIES:")
    print()
    
    # Check for list operations without MaxResults in recent slow operations
    list_ops_needing_optimization = []
    for discovery, avg, max_t, count in slow_ops:
        if 'list_' in discovery.lower() and max_t > 10:
            # Check if it's already optimized (would have MaxResults in YAML)
            # We can't check YAML here, but flag for review
            if 'describe_snapshots' not in discovery and 'describe_images' not in discovery:
                list_ops_needing_optimization.append((discovery, max_t))
    
    if list_ops_needing_optimization:
        print("   Operations that might need MaxResults:")
        for discovery, max_t in list_ops_needing_optimization[:10]:
            print(f"      {discovery:<65} Max: {max_t:>6.1f}s")
    else:
        print("   ✅ No obvious optimization opportunities found")
    
    print()
    print("="*80)
    print()
    print("💡 RECOMMENDATIONS:")
    print()
    
    # Generate recommendations
    recommendations = []
    
    if slow_ops:
        critical = [op for op in slow_ops if op[2] > 300]  # > 5 minutes
        if critical:
            recommendations.append(f"   ⚠️  {len(critical)} operations taking > 5 minutes - CRITICAL!")
            for discovery, avg, max_t, count in critical[:5]:
                recommendations.append(f"      - {discovery}: {max_t:.0f}s max")
    
    if error_types.get('Throttling', 0) > 10:
        recommendations.append(f"   ⚠️  High throttling errors ({error_types['Throttling']}) - consider rate limiting")
    
    if error_types.get('Timeout', 0) > 5:
        recommendations.append(f"   ⚠️  Timeout errors ({error_types['Timeout']}) - check slow operations")
    
    if not recommendations:
        recommendations.append("   ✅ Scan performing well - no immediate optimizations needed")
    
    for rec in recommendations:
        print(rec)
    
    print()
    print("="*80)

if __name__ == '__main__':
    log_file = find_latest_scan_log()
    
    if not log_file:
        print("❌ No scan log found")
        print("   Looking in: engines-output/aws-configScan-engine/output/*/logs/scan.log")
        sys.exit(1)
    
    print(f"📁 Monitoring: {log_file}")
    print()
    
    analyze_scan_performance(log_file)

