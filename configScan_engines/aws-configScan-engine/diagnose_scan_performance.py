#!/usr/bin/env python3
"""
Diagnostic script to analyze scan performance and identify bottlenecks.
Analyzes scan logs to provide insights on:
- Actual task count vs expected
- Slow discoveries
- Retry overhead
- Worker utilization
"""
import os
import re
import json
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Tuple
import sys

def analyze_scan_logs(log_file: str) -> Dict:
    """Analyze scan logs for performance bottlenecks"""
    
    if not os.path.exists(log_file):
        return {"error": f"Log file not found: {log_file}"}
    
    with open(log_file, 'r') as f:
        lines = f.readlines()
    
    results = {
        "scan_start": None,
        "scan_end": None,
        "total_tasks": None,
        "tasks_completed": 0,
        "discoveries_by_service": defaultdict(int),
        "slow_discoveries": [],
        "error_patterns": defaultdict(int),
        "retry_events": 0,
        "service_avg_times": defaultdict(list),
        "task_progress": []
    }
    
    # Extract scan metadata
    for line in lines[:100]:
        if 'SCAN-START' in line:
            match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
            if match:
                results["scan_start"] = match.group(1)
        
        if 'Total tasks:' in line:
            match = re.search(r'Total tasks:\s*(\d+)', line)
            if match:
                results["total_tasks"] = int(match.group(1))
        
        if 'Regional tasks:' in line:
            match = re.search(r'Regional tasks:\s*(\d+)', line)
            if match:
                results["regional_tasks"] = int(match.group(1))
        
        if 'Global tasks:' in line:
            match = re.search(r'Global tasks:\s*(\d+)', line)
            if match:
                results["global_tasks"] = int(match.group(1))
        
        if 'Max concurrent workers:' in line:
            match = re.search(r'Max concurrent workers:\s*(\d+)', line)
            if match:
                results["max_workers"] = int(match.group(1))
    
    # Analyze discoveries and timing
    for line in lines:
        # Track task completion
        if '/]' in line and 'tasks/sec' in line:
            match = re.search(r'\[(\d+)/(\d+)\]', line)
            if match:
                completed, total = int(match.group(1)), int(match.group(2))
                if not results["total_tasks"]:
                    results["total_tasks"] = total
                results["tasks_completed"] = max(results["tasks_completed"], completed)
                
                # Extract timestamp for rate calculation
                match_time = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
                if match_time:
                    rate_match = re.search(r'\(([\d.]+)\s+tasks/sec\)', line)
                    if rate_match:
                        rate = float(rate_match.group(1))
                        results["task_progress"].append({
                            "time": match_time.group(1),
                            "completed": completed,
                            "rate": rate
                        })
        
        # Track discovery completion
        if 'Completed discovery' in line:
            match = re.search(r'aws\.(\w+)\.([^\s:]+)', line)
            if match:
                service = match.group(1)
                discovery = match.group(2)
                results["discoveries_by_service"][service] += 1
                
                # Extract timing
                time_match = re.search(r':\s*([\d.]+)s', line)
                if time_match:
                    elapsed = float(time_match.group(1))
                    results["service_avg_times"][service].append(elapsed)
                    
                    if elapsed > 30.0:  # Slow discoveries
                        results["slow_discoveries"].append({
                            "service": service,
                            "discovery": discovery,
                            "time": elapsed
                        })
        
        # Track retries
        if 'Retrying after error' in line:
            results["retry_events"] += 1
        
        # Track errors
        if 'WARNING' in line or 'ERROR' in line:
            if 'Failed' in line:
                match = re.search(r'Failed\s+(\w+):', line)
                if match:
                    operation = match.group(1)
                    results["error_patterns"][operation] += 1
    
    # Calculate statistics
    results["slow_discoveries"].sort(key=lambda x: -x["time"])
    results["top_slow_discoveries"] = results["slow_discoveries"][:20]
    
    # Service average times
    results["service_statistics"] = {}
    for service, times in results["service_avg_times"].items():
        if times:
            results["service_statistics"][service] = {
                "avg": sum(times) / len(times),
                "max": max(times),
                "count": len(times)
            }
    
    return results


def print_diagnostic_report(results: Dict):
    """Print formatted diagnostic report"""
    
    print("="*80)
    print("SCAN PERFORMANCE DIAGNOSTIC REPORT")
    print("="*80)
    
    if "error" in results:
        print(f"❌ Error: {results['error']}")
        return
    
    # Scan metadata
    print("\n📊 SCAN METADATA:")
    if results.get("scan_start"):
        print(f"  Start: {results['scan_start']}")
    if results.get("total_tasks"):
        print(f"  Total tasks: {results['total_tasks']:,}")
        print(f"  Completed: {results['tasks_completed']:,} ({results['tasks_completed']/results['total_tasks']*100:.1f}%)")
    if results.get("max_workers"):
        print(f"  Max workers: {results['max_workers']}")
    if results.get("regional_tasks"):
        print(f"  Regional tasks: {results['regional_tasks']:,}")
    if results.get("global_tasks"):
        print(f"  Global tasks: {results['global_tasks']:,}")
    
    # Performance analysis
    print("\n⚡ PERFORMANCE ANALYSIS:")
    if results.get("task_progress"):
        latest = results["task_progress"][-1] if results["task_progress"] else None
        if latest:
            print(f"  Current rate: {latest['rate']:.2f} tasks/sec")
            if results.get("total_tasks") and results.get("tasks_completed"):
                remaining = results["total_tasks"] - results["tasks_completed"]
                if latest['rate'] > 0:
                    eta_seconds = remaining / latest['rate']
                    eta_hours = eta_seconds / 3600
                    print(f"  ETA: {eta_hours:.1f} hours ({remaining:,} tasks remaining)")
    
    # Slow discoveries
    print("\n🐌 SLOW DISCOVERIES (>30s):")
    if results.get("top_slow_discoveries"):
        for item in results["top_slow_discoveries"][:15]:
            print(f"  {item['service']:20} {item['discovery']:40} {item['time']:6.1f}s")
    else:
        print("  None found")
    
    # Service statistics
    print("\n📈 SERVICE STATISTICS (Top 15 by avg time):")
    if results.get("service_statistics"):
        sorted_services = sorted(
            results["service_statistics"].items(),
            key=lambda x: -x[1]["avg"]
        )[:15]
        for service, stats in sorted_services:
            print(f"  {service:20} avg: {stats['avg']:6.1f}s | max: {stats['max']:6.1f}s | count: {stats['count']:5}")
    
    # Error patterns
    print("\n⚠️  ERROR PATTERNS (Top 10):")
    if results.get("error_patterns"):
        sorted_errors = sorted(
            results["error_patterns"].items(),
            key=lambda x: -x[1]
        )[:10]
        for operation, count in sorted_errors:
            print(f"  {operation:40} {count:5} occurrences")
    
    # Retry overhead
    print(f"\n🔄 RETRY OVERHEAD:")
    print(f"  Retry events: {results.get('retry_events', 0)}")
    
    # Recommendations
    print("\n💡 RECOMMENDATIONS:")
    recommendations = []
    
    if results.get("max_workers", 0) < 50:
        recommendations.append(f"  ⚡ Increase max_total_workers from {results.get('max_workers', 20)} to 50-100")
    
    if results.get("slow_discoveries"):
        slow_count = len([s for s in results["slow_discoveries"] if s["time"] > 60])
        if slow_count > 0:
            recommendations.append(f"  🐌 {slow_count} very slow discoveries (>60s) - consider excluding or optimizing")
    
    if results.get("retry_events", 0) > 100:
        recommendations.append("  🔄 High retry count - review expected error handling")
    
    if not recommendations:
        recommendations.append("  ✅ No obvious optimizations needed")
    
    for rec in recommendations:
        print(rec)
    
    print("\n" + "="*80)


if __name__ == "__main__":
    # Default to latest scan log
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        # Find latest scan log
        base_dir = "engines-output/aws-configScan-engine/output"
        discoveries_dir = os.path.join(base_dir, "discoveries")
        latest_scan = None
        latest_time = 0
        
        # Check both discoveries subdirectory (new) and root (old for backward compatibility)
        search_dirs = []
        if os.path.exists(discoveries_dir):
            search_dirs.append(discoveries_dir)
        if os.path.exists(base_dir):
            search_dirs.append(base_dir)
        
        for search_dir in search_dirs:
            for item in os.listdir(search_dir):
                scan_dir = os.path.join(search_dir, item)
                log_path = os.path.join(scan_dir, "logs", "scan.log")
                if os.path.exists(log_path):
                    mtime = os.path.getmtime(log_path)
                    if mtime > latest_time:
                        latest_time = mtime
                        latest_scan = log_path
        
        if latest_scan:
            log_file = latest_scan
            print(f"Using latest scan log: {log_file}\n")
        else:
            print("Error: No scan log found. Please specify log file path.")
            sys.exit(1)
    
    results = analyze_scan_logs(log_file)
    print_diagnostic_report(results)


