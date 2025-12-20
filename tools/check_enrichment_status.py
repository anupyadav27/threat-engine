#!/usr/bin/env python3
"""Check enrichment status across all services"""

import json
from pathlib import Path
from collections import defaultdict

def check_enrichment_status(root_path: Path):
    """Check how many services have been enriched"""
    
    stats = {
        'total_services': 0,
        'enriched_services': 0,
        'total_enum_fields': 0,
        'services_with_enums': 0,
        'top_services': []
    }
    
    service_stats = []
    
    for service_dir in sorted(root_path.iterdir()):
        if not service_dir.is_dir():
            continue
        
        enriched_file = service_dir / "boto3_dependencies_with_python_names_fully_enriched.json"
        if not enriched_file.exists():
            continue
        
        stats['total_services'] += 1
        
        try:
            with open(enriched_file) as f:
                data = json.load(f)
            
            service_name = service_dir.name
            enum_count = 0
            
            if service_name in data:
                for op_type in ['independent', 'dependent']:
                    if op_type in data[service_name]:
                        for op in data[service_name][op_type]:
                            for field_type in ['output_fields', 'item_fields']:
                                if field_type in op and isinstance(op[field_type], dict):
                                    for field_name, field_data in op[field_type].items():
                                        if 'possible_values' in field_data:
                                            enum_count += 1
            
            if enum_count > 0:
                stats['enriched_services'] += 1
                stats['total_enum_fields'] += enum_count
                service_stats.append({
                    'service': service_name,
                    'enum_fields': enum_count
                })
        
        except Exception as e:
            pass
    
    # Sort by enum count
    service_stats.sort(key=lambda x: x['enum_fields'], reverse=True)
    stats['top_services'] = service_stats[:20]
    
    return stats

if __name__ == '__main__':
    root_path = Path('pythonsdk-database/aws')
    stats = check_enrichment_status(root_path)
    
    print(f"\n{'='*70}")
    print(f"ENRICHMENT STATUS")
    print(f"{'='*70}")
    print(f"Total services: {stats['total_services']}")
    print(f"Services with enums: {stats['enriched_services']}")
    print(f"Total enum fields: {stats['total_enum_fields']}")
    print(f"Average enums per service: {stats['total_enum_fields'] / max(stats['enriched_services'], 1):.1f}")
    
    print(f"\nTop 20 services by enum count:")
    for i, svc in enumerate(stats['top_services'], 1):
        print(f"  {i:2}. {svc['service']:30} {svc['enum_fields']:4} enum fields")

