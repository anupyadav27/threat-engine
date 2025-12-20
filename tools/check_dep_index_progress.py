#!/usr/bin/env python3
"""
Progress tracker for dependency index builds.

Shows current status, progress, and file creation count.
"""

import re
import subprocess
from pathlib import Path
from datetime import datetime
import time

def get_file_count(root_path: Path) -> int:
    """Count dependency_index.json files."""
    try:
        result = subprocess.run(
            ['find', str(root_path), '-maxdepth', '2', '-name', 'dependency_index.json', '-type', 'f'],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            return len([f for f in result.stdout.strip().split('\n') if f])
        return 0
    except:
        return 0

def get_log_progress(log_file: Path) -> dict:
    """Extract progress from log file."""
    progress = {
        'current_service': 0,
        'total_services': 411,
        'success': 0,
        'failed': 0,
        'last_service_name': None,
        'last_status': None
    }
    
    if not log_file.exists():
        return progress
    
    try:
        with open(log_file, 'r') as f:
            content = f.read()
        
        # Find last progress line
        matches = re.findall(r'\[(\d+)/(\d+)\] Processing: (\w+)', content)
        if matches:
            last_match = matches[-1]
            progress['current_service'] = int(last_match[0])
            progress['total_services'] = int(last_match[1])
            progress['last_service_name'] = last_match[2]
        
        # Count successes and failures
        progress['success'] = len(re.findall(r'✓ Success', content))
        progress['failed'] = len(re.findall(r'✗ Failed', content))
        
        # Get last status line
        lines = content.split('\n')
        for line in reversed(lines[-20:]):
            if '✓ Success' in line or '✗ Failed' in line:
                progress['last_status'] = line.strip()
                break
        
    except Exception as e:
        progress['error'] = str(e)
    
    return progress

def get_process_info() -> dict:
    """Get process information."""
    try:
        result = subprocess.run(
            ['ps', 'aux'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        for line in result.stdout.split('\n'):
            if 'build_all_dependency_indexes' in line and 'grep' not in line:
                parts = line.split()
                if len(parts) >= 11:
                    return {
                        'pid': parts[1],
                        'cpu': parts[2],
                        'mem': parts[3],
                        'runtime': parts[9] if len(parts) > 9 else 'N/A'
                    }
    except:
        pass
    
    return {'running': False}

def format_progress_bar(current: int, total: int, width: int = 50) -> str:
    """Create a progress bar."""
    if total == 0:
        return '[' + ' ' * width + ']'
    
    filled = int((current / total) * width)
    bar = '[' + '=' * filled + ' ' * (width - filled) + ']'
    percent = (current / total) * 100
    return f"{bar} {percent:.1f}%"

def main():
    root_path = Path('pythonsdk-database/aws')
    log_file = Path('/tmp/dep_index_build.log')
    
    print("=" * 70)
    print("DEPENDENCY INDEX BUILD PROGRESS TRACKER")
    print("=" * 70)
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # Check if process is running
    process_info = get_process_info()
    if process_info.get('running') is False:
        print("⚠️  Build process is NOT running")
        print()
    else:
        print("✓ Build process is RUNNING")
        print(f"  PID: {process_info.get('pid', 'N/A')}")
        print(f"  CPU: {process_info.get('cpu', 'N/A')}%")
        print(f"  Memory: {process_info.get('mem', 'N/A')}%")
        print(f"  Runtime: {process_info.get('runtime', 'N/A')}")
        print()
    
    # Get progress from log
    progress = get_log_progress(log_file)
    
    print("PROGRESS:")
    print(f"  Services: {progress['current_service']}/{progress['total_services']}")
    print(f"  {format_progress_bar(progress['current_service'], progress['total_services'])}")
    print(f"  Success: {progress['success']}")
    print(f"  Failed: {progress['failed']}")
    if progress['last_service_name']:
        print(f"  Current: {progress['last_service_name']}")
    print()
    
    # Count files
    file_count = get_file_count(root_path)
    print("FILES CREATED:")
    print(f"  dependency_index.json files: {file_count}/{progress['total_services']}")
    print(f"  {format_progress_bar(file_count, progress['total_services'])}")
    print()
    
    # Estimate time remaining
    if progress['current_service'] > 0 and process_info.get('running') is not False:
        elapsed_minutes = 0
        try:
            # Try to parse runtime from ps output (format: HH:MM or MM:SS)
            runtime_str = process_info.get('runtime', '')
            if ':' in runtime_str:
                parts = runtime_str.split(':')
                if len(parts) == 2:
                    elapsed_minutes = int(parts[0]) * 60 + int(parts[1])
                elif len(parts) == 3:
                    elapsed_minutes = int(parts[0]) * 3600 + int(parts[1]) * 60 + int(parts[2])
        except:
            pass
        
        if elapsed_minutes > 0 and progress['current_service'] > 0:
            avg_time_per_service = elapsed_minutes / progress['current_service']
            remaining_services = progress['total_services'] - progress['current_service']
            remaining_minutes = avg_time_per_service * remaining_services
            
            hours = int(remaining_minutes // 60)
            minutes = int(remaining_minutes % 60)
            print("ESTIMATED TIME REMAINING:")
            print(f"  {hours}h {minutes}m ({remaining_minutes:.0f} minutes)")
            print()
    
    # Last status
    if progress.get('last_status'):
        print("LAST STATUS:")
        print(f"  {progress['last_status']}")
        print()
    
    # Show recent services if available
    if log_file.exists():
        try:
            with open(log_file, 'r') as f:
                lines = f.readlines()
            
            recent_services = []
            for line in reversed(lines[-50:]):
                match = re.search(r'\[(\d+)/\d+\] Processing: (\w+)', line)
                if match:
                    recent_services.append((int(match.group(1)), match.group(2)))
                    if len(recent_services) >= 5:
                        break
            
            if recent_services:
                print("RECENT SERVICES:")
                for num, name in reversed(recent_services):
                    print(f"  [{num}] {name}")
        except:
            pass
    
    print("=" * 70)
    print()
    print("To monitor continuously, run:")
    print("  watch -n 10 python3 tools/check_dep_index_progress.py")
    print("Or:")
    print("  tail -f /tmp/dep_index_build.log")

if __name__ == '__main__':
    main()

