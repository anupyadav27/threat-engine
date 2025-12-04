#!/usr/bin/env python3
"""
Execute redistribution with Azure expert corrections
1. Move rule files to correct service folders
2. Update rule_id in metadata YAML files
3. Update azure_consolidated_rules_with_mapping.csv
4. Update rule_ids_ENRICHED_AI_ENHANCED.yaml
"""

import csv
import yaml
import shutil
import json
from pathlib import Path
from datetime import datetime
from collections import defaultdict

def load_expert_csv(csv_file):
    """Load the Azure expert reviewed CSV"""
    rules_map = {}
    with open(csv_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            old_rule_id = row['rule_id']
            new_rule_id = row['normalized_rule_id']
            target_service = row['suggested_service']
            current_service = row['current_service']
            
            rules_map[old_rule_id] = {
                'new_rule_id': new_rule_id,
                'target_service': target_service,
                'current_service': current_service,
                'file': row.get('file', ''),
                'corrected': row.get('azure_expert_corrected', 'NO')
            }
    
    return rules_map


def move_and_update_rule_file(old_rule_id, rule_info, services_dir, stats):
    """Move rule file and update its content"""
    current_service = rule_info['current_service']
    target_service = rule_info['target_service']
    new_rule_id = rule_info['new_rule_id']
    
    # Find source file (handle long names)
    source_dir = services_dir / current_service / 'metadata'
    
    if not source_dir.exists():
        stats['missing_source_dir'].append(current_service)
        return False
    
    # Try to find the file (might be truncated)
    source_files = list(source_dir.glob(f"{old_rule_id[:180]}*.yaml"))
    
    if not source_files:
        stats['file_not_found'].append(old_rule_id)
        return False
    
    source_file = source_files[0]
    
    # Create target directory
    target_dir = services_dir / target_service / 'metadata'
    target_dir.mkdir(parents=True, exist_ok=True)
    
    # Create new filename (handle long names)
    new_filename = new_rule_id
    if len(new_filename) > 200:
        import hashlib
        hash_suffix = hashlib.md5(new_filename.encode()).hexdigest()[:8]
        new_filename = new_filename[:180] + f"__{hash_suffix}"
    
    target_file = target_dir / f"{new_filename}.yaml"
    
    # Read, update, and write YAML
    try:
        with open(source_file, 'r') as f:
            rule_data = yaml.safe_load(f)
        
        # Update rule_id in the YAML
        rule_data['rule_id'] = new_rule_id
        
        # Update service field
        rule_data['service'] = target_service
        
        # Write to new location
        with open(target_file, 'w') as f:
            yaml.dump(rule_data, f, default_flow_style=False, sort_keys=False)
        
        # Remove old file if different location
        if source_file != target_file:
            source_file.unlink()
        
        stats['moved'] += 1
        return True
        
    except Exception as e:
        stats['errors'].append({'file': str(source_file), 'error': str(e)})
        return False


def update_csv_file(csv_file, rules_map, output_file):
    """Update rule IDs in the CSV file"""
    
    rows = []
    stats = {'updated': 0, 'not_found': 0, 'total': 0}
    
    with open(csv_file, 'r') as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        
        for row in reader:
            stats['total'] += 1
            old_rule_id = row.get('rule_id', row.get('Rule ID', ''))
            
            if old_rule_id in rules_map:
                # Update rule_id
                new_rule_id = rules_map[old_rule_id]['new_rule_id']
                
                # Update in all possible column names
                if 'rule_id' in row:
                    row['rule_id'] = new_rule_id
                if 'Rule ID' in row:
                    row['Rule ID'] = new_rule_id
                
                stats['updated'] += 1
            else:
                stats['not_found'] += 1
            
            rows.append(row)
    
    # Write updated CSV
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    
    return stats


def update_rule_ids_yaml(yaml_file, rules_map, output_file):
    """Update rule IDs in the rule_ids_ENRICHED_AI_ENHANCED.yaml"""
    
    stats = {'updated': 0, 'not_found': 0, 'total': 0}
    
    with open(yaml_file, 'r') as f:
        data = yaml.safe_load(f)
    
    if 'rules' in data:
        for rule in data['rules']:
            stats['total'] += 1
            old_rule_id = rule.get('rule_id', '')
            
            if old_rule_id in rules_map:
                new_rule_id = rules_map[old_rule_id]['new_rule_id']
                target_service = rules_map[old_rule_id]['target_service']
                
                # Update rule_id and service
                rule['rule_id'] = new_rule_id
                rule['service'] = target_service
                
                stats['updated'] += 1
            else:
                stats['not_found'] += 1
    
    # Write updated YAML
    with open(output_file, 'w') as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)
    
    return stats


def cleanup_empty_services(services_dir, source_services):
    """Remove empty source service folders"""
    removed = []
    
    for service in source_services:
        service_dir = services_dir / service
        metadata_dir = service_dir / 'metadata'
        
        if metadata_dir.exists():
            remaining = list(metadata_dir.glob('*.yaml'))
            if len(remaining) == 0:
                shutil.rmtree(service_dir)
                removed.append(service)
    
    return removed


def update_service_rules_yaml(services_dir, target_services):
    """Update rules/*.yaml files with new counts"""
    
    for service in target_services:
        service_dir = services_dir / service
        metadata_dir = service_dir / 'metadata'
        rules_dir = service_dir / 'rules'
        
        if not metadata_dir.exists():
            continue
        
        # Count rules
        rule_count = len(list(metadata_dir.glob('*.yaml')))
        
        # Update rules YAML
        rules_file = rules_dir / f"{service}.yaml"
        
        if rules_file.exists():
            with open(rules_file, 'r') as f:
                rules_yaml = yaml.safe_load(f)
        else:
            rules_yaml = {
                'version': '1.0',
                'provider': 'azure',
                'service': service
            }
        
        rules_yaml['total_rules'] = rule_count
        rules_yaml['last_updated'] = datetime.now().isoformat()
        
        rules_dir.mkdir(parents=True, exist_ok=True)
        with open(rules_file, 'w') as f:
            yaml.dump(rules_yaml, f, default_flow_style=False, sort_keys=False)


def main():
    import sys
    
    print("=" * 80)
    print(" EXECUTING REDISTRIBUTION WITH AZURE EXPERT CORRECTIONS")
    print("=" * 80)
    
    script_dir = Path(__file__).parent
    services_dir = script_dir / 'services'
    
    # Input files
    expert_csv = script_dir / 'redistribution_mapping_azure_expert.csv'
    consolidated_csv = script_dir / 'azure_consolidated_rules_with_mapping.csv'
    rule_ids_yaml = script_dir / 'rule_ids_ENRICHED_AI_ENHANCED.yaml'
    
    # Output files
    consolidated_csv_updated = script_dir / 'azure_consolidated_rules_with_mapping_UPDATED.csv'
    rule_ids_yaml_updated = script_dir / 'rule_ids_ENRICHED_AI_ENHANCED_UPDATED.yaml'
    
    if not expert_csv.exists():
        print(f"❌ Error: {expert_csv} not found")
        return 1
    
    # Load expert mappings
    print(f"\n📄 Loading Azure expert mappings...")
    rules_map = load_expert_csv(expert_csv)
    print(f"✓ Loaded {len(rules_map)} rule mappings")
    
    # Stats
    stats = {
        'moved': 0,
        'errors': [],
        'file_not_found': [],
        'missing_source_dir': [],
        'by_service': defaultdict(int)
    }
    
    # Move and update rule files
    print(f"\n📦 Moving and updating rule files...")
    for old_rule_id, rule_info in rules_map.items():
        success = move_and_update_rule_file(old_rule_id, rule_info, services_dir, stats)
        if success:
            stats['by_service'][rule_info['target_service']] += 1
    
    print(f"✓ Moved and updated: {stats['moved']} files")
    
    # Update CSV file
    if consolidated_csv.exists():
        print(f"\n📊 Updating {consolidated_csv.name}...")
        csv_stats = update_csv_file(consolidated_csv, rules_map, consolidated_csv_updated)
        print(f"✓ Updated: {csv_stats['updated']}/{csv_stats['total']} rules")
    else:
        print(f"⚠️  {consolidated_csv.name} not found, skipping")
    
    # Update rule_ids YAML
    if rule_ids_yaml.exists():
        print(f"\n📋 Updating {rule_ids_yaml.name}...")
        yaml_stats = update_rule_ids_yaml(rule_ids_yaml, rules_map, rule_ids_yaml_updated)
        print(f"✓ Updated: {yaml_stats['updated']}/{yaml_stats['total']} rules")
    else:
        print(f"⚠️  {rule_ids_yaml.name} not found, skipping")
    
    # Update service rules YAML files
    print(f"\n📁 Updating service rules files...")
    target_services = set(r['target_service'] for r in rules_map.values())
    update_service_rules_yaml(services_dir, target_services)
    print(f"✓ Updated {len(target_services)} service rule files")
    
    # Cleanup empty source services
    print(f"\n🧹 Cleaning up empty source services...")
    source_services = ['azure', 'active', 'managed']
    removed = cleanup_empty_services(services_dir, source_services)
    if removed:
        print(f"✓ Removed empty services: {', '.join(removed)}")
    else:
        print(f"⚠️  Some source services still have rules")
    
    # Summary
    print("\n" + "=" * 80)
    print(" SUMMARY")
    print("=" * 80)
    print(f"Rule files moved:         {stats['moved']}")
    print(f"File not found:           {len(stats['file_not_found'])}")
    print(f"Errors:                   {len(stats['errors'])}")
    
    if consolidated_csv.exists():
        print(f"\nCSV file updated:         {csv_stats['updated']}/{csv_stats['total']} rules")
    
    if rule_ids_yaml.exists():
        print(f"YAML file updated:        {yaml_stats['updated']}/{yaml_stats['total']} rules")
    
    print(f"\n📊 Rules by target service:")
    for service, count in sorted(stats['by_service'].items(), key=lambda x: x[1], reverse=True):
        print(f"  {service:20s}: {count:3d} rules")
    
    # Errors
    if stats['errors']:
        print(f"\n⚠️  {len(stats['errors'])} errors occurred:")
        for error in stats['errors'][:5]:
            print(f"  - {error['file']}: {error['error']}")
        if len(stats['errors']) > 5:
            print(f"  ... and {len(stats['errors']) - 5} more")
    
    if stats['file_not_found']:
        print(f"\n⚠️  {len(stats['file_not_found'])} files not found (may have been already moved):")
        for rule_id in stats['file_not_found'][:5]:
            print(f"  - {rule_id[:80]}...")
        if len(stats['file_not_found']) > 5:
            print(f"  ... and {len(stats['file_not_found']) - 5} more")
    
    # Output files
    print(f"\n📄 Output files created:")
    if consolidated_csv_updated.exists():
        print(f"  ✓ {consolidated_csv_updated.name}")
    if rule_ids_yaml_updated.exists():
        print(f"  ✓ {rule_ids_yaml_updated.name}")
    
    print("\n" + "=" * 80)
    print(" ✅ REDISTRIBUTION COMPLETE")
    print("=" * 80)
    print(f"\n💡 Next steps:")
    print(f"  1. Review updated files")
    print(f"  2. Backup originals if needed:")
    print(f"     mv azure_consolidated_rules_with_mapping.csv azure_consolidated_rules_with_mapping_OLD.csv")
    print(f"     mv azure_consolidated_rules_with_mapping_UPDATED.csv azure_consolidated_rules_with_mapping.csv")
    print(f"  3. Same for rule_ids_ENRICHED_AI_ENHANCED.yaml")
    
    # Generate execution report
    report = {
        'timestamp': datetime.now().isoformat(),
        'stats': {
            'moved': stats['moved'],
            'errors': len(stats['errors']),
            'file_not_found': len(stats['file_not_found']),
            'by_service': dict(stats['by_service'])
        },
        'csv_updated': csv_stats if consolidated_csv.exists() else {},
        'yaml_updated': yaml_stats if rule_ids_yaml.exists() else {},
        'removed_services': removed
    }
    
    report_file = script_dir / 'redistribution_final_report.json'
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n📊 Detailed report: {report_file}")
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())

