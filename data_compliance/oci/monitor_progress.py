#!/usr/bin/env python3
"""
Real-time monitoring for OCI rule enhancement progress
"""
import json
import time
import os
from datetime import datetime

PROGRESS_FILE = 'enhancement_progress_oci.json'
TOTAL_RULES = 1914

def clear_screen():
    os.system('clear' if os.name != 'nt' else 'cls')

def display_progress():
    while True:
        try:
            if not os.path.exists(PROGRESS_FILE):
                print("\n✅ Enhancement Complete! Progress file removed.\n")
                break
            
            with open(PROGRESS_FILE, 'r') as f:
                data = json.load(f)
            
            enhanced = data['enhanced_count']
            failed = len(data.get('failed_rules', []))
            remaining = TOTAL_RULES - enhanced
            percent = (enhanced / TOTAL_RULES) * 100
            
            clear_screen()
            print('═' * 70)
            print('🔄 OCI RULE ENHANCEMENT - LIVE MONITORING')
            print('═' * 70)
            print()
            print(f'  ✅ Enhanced:      {enhanced:,} / {TOTAL_RULES:,} rules ({percent:.2f}%)')
            print(f'  ❌ Failed:        {failed}')
            print(f'  ⏳ Remaining:     {remaining:,} rules')
            print()
            
            # Progress bar
            bar_length = 50
            filled = int(bar_length * enhanced / TOTAL_RULES)
            bar = '█' * filled + '░' * (bar_length - filled)
            print(f'  [{bar}] {percent:.1f}%')
            print()
            
            # Time estimates
            if enhanced > 0:
                est_mins = (remaining * 0.8) / 60
                est_hours = est_mins / 60
                
                if est_hours >= 1:
                    print(f'  ⏱️  Est. Time Remaining: ~{est_hours:.1f} hours')
                else:
                    print(f'  ⏱️  Est. Time Remaining: ~{est_mins:.0f} minutes')
            
            print()
            print(f'  🕐 Last Updated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
            print('═' * 70)
            print()
            print('  Press Ctrl+C to stop monitoring...')
            print('  (Enhancement continues in background)')
            
            time.sleep(15)  # Update every 15 seconds
            
        except KeyboardInterrupt:
            print("\n\n⚠️  Monitoring stopped by user")
            print("💡 Enhancement continues in background")
            print(f"📊 Last status: {enhanced}/{TOTAL_RULES} rules enhanced\n")
            break
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(5)

if __name__ == "__main__":
    display_progress()

