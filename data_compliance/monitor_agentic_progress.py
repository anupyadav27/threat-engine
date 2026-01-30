#!/usr/bin/env python3
"""
Real-time monitoring dashboard for agentic AI enhancements
"""

import time
from pathlib import Path
import subprocess
import os

def check_process_running(csp):
    """Check if enhancement process is running for CSP"""
    try:
        result = subprocess.run(['pgrep', '-f', f'universal_agentic_enhancer.py {csp}'], 
                              capture_output=True, text=True)
        return bool(result.stdout.strip())
    except:
        return False

def get_file_size(file_path):
    """Get file size in MB"""
    try:
        size = os.path.getsize(file_path)
        return f"{size / (1024*1024):.1f} MB"
    except:
        return "N/A"

def count_log_lines(log_path):
    """Count lines in log file"""
    try:
        with open(log_path) as f:
            return sum(1 for _ in f)
    except:
        return 0

def monitor_all_csps():
    """Monitor all CSP enhancements"""
    base_dir = Path("/Users/apple/Desktop/threat-engine/compliance")
    
    csps = {
        'azure': {'rules': 1739, 'status': '🔄'},
        'gcp': {'rules': 1576, 'status': '🔄'},
        'ibm': {'rules': 1504, 'status': '🔄'},
        'oci': {'rules': 1914, 'status': '🔄'}
    }
    
    print("\n" + "="*80)
    print("🤖 AGENTIC AI ENHANCEMENT - LIVE MONITORING DASHBOARD")
    print("="*80)
    print()
    
    while True:
        os.system('clear' if os.name != 'nt' else 'cls')
        
        print("╔" + "═"*78 + "╗")
        print("║" + " "*20 + "AGENTIC AI ENHANCEMENT - LIVE STATUS" + " "*22 + "║")
        print("╚" + "═"*78 + "╝")
        print()
        
        print(f"{'CSP':<10} {'Rules':<8} {'Status':<10} {'Output File':<25} {'Log Lines':<12}")
        print("─"*80)
        
        all_complete = True
        
        for csp, info in csps.items():
            # Check if process running
            is_running = check_process_running(csp)
            
            # Check output file
            output_patterns = [
                base_dir / csp / "rule_ids_AGENTIC_AI_ENHANCED.yaml",
                base_dir / csp / "final/rule_ids_AGENTIC_AI_ENHANCED_V3.yaml"
            ]
            
            file_size = "N/A"
            for output_path in output_patterns:
                if output_path.exists():
                    file_size = get_file_size(output_path)
                    break
            
            # Check log file
            log_path = base_dir / f"{csp}_agentic_enhancement.log"
            log_lines = count_log_lines(log_path)
            
            # Determine status
            if file_size != "N/A" and not is_running:
                status = "✅ Complete"
            elif is_running:
                status = "🔄 Running"
                all_complete = False
            else:
                status = "⏳ Queued"
                all_complete = False
            
            print(f"{csp.upper():<10} {info['rules']:<8} {status:<10} {file_size:<25} {log_lines:<12}")
        
        print("─"*80)
        print(f"Total: {sum(info['rules'] for info in csps.values())} rules")
        print()
        
        if all_complete:
            print("✅ All CSPs Complete!")
            break
        
        print(f"🕐 Last updated: {time.strftime('%H:%M:%S')}")
        print("Press Ctrl+C to stop monitoring (processes will continue)")
        
        time.sleep(30)  # Update every 30 seconds

if __name__ == '__main__':
    try:
        monitor_all_csps()
    except KeyboardInterrupt:
        print("\n\n📊 Monitoring stopped. Processes continue in background.")
        print("Check logs: tail -f {csp}_agentic_enhancement.log")

