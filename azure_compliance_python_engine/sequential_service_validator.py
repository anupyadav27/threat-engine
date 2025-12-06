#!/usr/bin/env python3
"""
Sequential Service Validator for Azure Compliance Engine

Tracks validation progress across all 58 Azure services.
Processes one service at a time, marking complete before moving to next.
"""

import json
import os
import sys
from pathlib import Path
from datetime import datetime

MANIFEST_FILE = Path(__file__).parent / 'all_services_manifest.json'
STATUS_FILE = Path(__file__).parent / 'service_validation_status.json'

def load_manifest():
    """Load the services manifest."""
    if not MANIFEST_FILE.exists():
        print(f"❌ Manifest file not found: {MANIFEST_FILE}")
        print("   Run the manifest generator first!")
        sys.exit(1)
    
    with open(MANIFEST_FILE, 'r') as f:
        return json.load(f)

def load_status():
    """Load validation status."""
    if STATUS_FILE.exists():
        with open(STATUS_FILE, 'r') as f:
            return json.load(f)
    return {
        'validated': [],
        'in_progress': None,
        'started_at': datetime.now().isoformat(),
        'last_updated': datetime.now().isoformat()
    }

def save_status(status):
    """Save validation status."""
    status['last_updated'] = datetime.now().isoformat()
    with open(STATUS_FILE, 'w') as f:
        json.dump(status, f, indent=2)

def get_next_service(manifest, status):
    """Get the next service to validate."""
    validated = set(status.get('validated', []))
    
    for service in manifest:
        if service['service'] not in validated:
            return service
    
    return None

def mark_done(service_name, status):
    """Mark a service as validated."""
    validated = status.get('validated', [])
    if service_name not in validated:
        validated.append(service_name)
        status['validated'] = validated
        status['in_progress'] = None
        save_status(status)
        print(f"✅ Marked {service_name} as validated")
    else:
        print(f"ℹ️  {service_name} already marked as validated")

def show_status(manifest, status):
    """Show current validation status."""
    validated = set(status.get('validated', []))
    total = len(manifest)
    done = len(validated)
    remaining = total - done
    progress = (done / total * 100) if total > 0 else 0
    
    print("\n" + "="*70)
    print("📊 VALIDATION STATUS")
    print("="*70)
    print(f"Total Services: {total}")
    print(f"✅ Validated: {done}")
    print(f"⏳ Remaining: {remaining}")
    print(f"Progress: {progress:.1f}%")
    print(f"Started: {status.get('started_at', 'Unknown')}")
    print(f"Last Updated: {status.get('last_updated', 'Unknown')}")
    print("="*70)
    
    if status.get('in_progress'):
        print(f"\n🔄 Currently Working On: {status['in_progress']}")
    
    next_service = get_next_service(manifest, status)
    if next_service:
        print(f"\n➡️  Next Service: {next_service['service']}")
        print(f"   File: {next_service['file_path']}")
        print(f"   Checks: {next_service['check_count']}")
        print(f"   Scope: {next_service['scope']}")
    else:
        print("\n🎉 All services validated!")
    
    print()

def show_list(manifest, status):
    """Show list of all services with status."""
    validated = set(status.get('validated', []))
    
    print("\n" + "="*80)
    print("📋 ALL SERVICES")
    print("="*80)
    print(f"{'Status':<12} {'Service':<25} {'Checks':<8} {'Scope':<15} {'File'}")
    print("-"*80)
    
    for service in manifest:
        name = service['service']
        checks = service['check_count']
        scope = service['scope']
        file_path = service['file_path']
        
        if name in validated:
            status_icon = "✅ VALIDATED"
        elif status.get('in_progress') == name:
            status_icon = "🔄 IN PROGRESS"
        else:
            status_icon = "⏳ PENDING"
        
        print(f"{status_icon:<12} {name:<25} {checks:<8} {scope:<15} {file_path}")
    
    print("="*80)
    print()

def start_validation(manifest, status):
    """Start or continue validation."""
    next_service = get_next_service(manifest, status)
    
    if not next_service:
        print("🎉 All services have been validated!")
        return
    
    service_name = next_service['service']
    file_path = next_service['file_path']
    
    print("\n" + "="*70)
    print("🚀 START VALIDATION")
    print("="*70)
    print(f"\n📁 Service: {service_name}")
    print(f"📄 File: {file_path}")
    print(f"🔍 Checks: {next_service['check_count']}")
    print(f"🔎 Discoveries: {next_service['discovery_count']}")
    print(f"📍 Scope: {next_service['scope']}")
    print("\n" + "-"*70)
    print("📝 INSTRUCTIONS:")
    print("-"*70)
    print(f"1. Open the service file:")
    print(f"   cursor {file_path}")
    print()
    print(f"2. Read the validation instructions at the TOP of the file")
    print(f"   (Look for the '🤖 CURSOR AI' section)")
    print()
    print(f"3. Follow the inline instructions to:")
    print(f"   - Run the engine for this service")
    print(f"   - Fix any issues in discovery/checks")
    print(f"   - Verify all checks work (PASS/FAIL, not ERROR)")
    print(f"   - Update validation tracking at bottom of file")
    print()
    print(f"4. When complete, mark as done:")
    print(f"   python sequential_service_validator.py --mark-done {service_name}")
    print()
    print(f"5. Move to next service:")
    print(f"   python sequential_service_validator.py --next")
    print()
    print("="*70)
    print()
    
    # Mark as in progress
    status['in_progress'] = service_name
    save_status(status)

def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python sequential_service_validator.py --start      # Start/continue validation")
        print("  python sequential_service_validator.py --status     # Show status")
        print("  python sequential_service_validator.py --list        # List all services")
        print("  python sequential_service_validator.py --next        # Show next service")
        print("  python sequential_service_validator.py --mark-done <service>  # Mark service complete")
        sys.exit(1)
    
    manifest = load_manifest()
    status = load_status()
    
    command = sys.argv[1]
    
    if command == '--start':
        start_validation(manifest, status)
    elif command == '--status':
        show_status(manifest, status)
    elif command == '--list':
        show_list(manifest, status)
    elif command == '--next':
        next_service = get_next_service(manifest, status)
        if next_service:
            print(f"\n➡️  Next: {next_service['service']}")
            print(f"   File: {next_service['file_path']}")
            print(f"   Checks: {next_service['check_count']}")
        else:
            print("\n🎉 All services validated!")
    elif command == '--mark-done':
        if len(sys.argv) < 3:
            print("❌ Please specify service name: --mark-done <service>")
            sys.exit(1)
        service_name = sys.argv[2]
        mark_done(service_name, status)
        show_status(manifest, status)
    else:
        print(f"❌ Unknown command: {command}")
        sys.exit(1)

if __name__ == '__main__':
    main()

