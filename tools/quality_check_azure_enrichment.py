#!/usr/bin/env python3
"""
Quality check for Azure enum enrichment - validates enum values by checking Azure SDK models.
"""

import json
import importlib
import inspect
from pathlib import Path
from typing import Dict, List, Any, Optional
from collections import defaultdict

class AzureEnrichmentQualityChecker:
    """Validate Azure enum enrichment quality"""
    
    def __init__(self):
        self.stats = {
            'services_checked': 0,
            'fields_validated': 0,
            'fields_correct': 0,
            'fields_incorrect': 0,
            'fields_missing': 0,
            'errors': []
        }
    
    def extract_enum_from_model(self, model_class) -> Optional[List[str]]:
        """Extract enum values from an Azure SDK model class"""
        if model_class is None:
            return None
        
        try:
            if inspect.isclass(model_class) and hasattr(model_class, '__members__'):
                members = model_class.__members__
                if members:
                    values = []
                    for name, member in members.items():
                        if hasattr(member, 'value'):
                            values.append(str(member.value))
                        else:
                            values.append(name)
                    return sorted(list(set(values)))
        except Exception:
            pass
        
        return None
    
    def find_enum_class(self, module_name: str, field_name: str) -> Optional[type]:
        """Find enum class for a field"""
        try:
            enum_patterns = [
                f"{field_name}Type",
                f"{field_name}Types",
                f"{field_name}Enum",
                f"{field_name}State",
                f"{field_name}Status",
                f"{field_name}ProvisioningState",
            ]
            
            if '.models' in module_name:
                models_module_name = module_name.replace('.models', '.models')
            else:
                models_module_name = f"{module_name}.models"
            
            try:
                models_module = importlib.import_module(models_module_name)
                
                for pattern in enum_patterns:
                    if hasattr(models_module, pattern):
                        enum_class = getattr(models_module, pattern)
                        if inspect.isclass(enum_class) and hasattr(enum_class, '__members__'):
                            return enum_class
            except Exception:
                pass
            
        except Exception:
            pass
        
        return None
    
    def validate_field_enum(self, module_name: str, field_name: str, 
                           enriched_values: List[str]) -> Dict[str, Any]:
        """Validate enum values for a field"""
        
        result = {
            'correct': False,
            'actual': None,
            'match': False
        }
        
        try:
            enum_class = self.find_enum_class(module_name, field_name)
            if enum_class:
                actual_values = self.extract_enum_from_model(enum_class)
                if actual_values:
                    result['actual'] = actual_values
                    # Check if enriched values match (order may differ)
                    if sorted(enriched_values) == sorted(actual_values):
                        result['correct'] = True
                        result['match'] = True
                    else:
                        # Check if enriched is a subset (common enums)
                        if set(enriched_values).issubset(set(actual_values)):
                            result['correct'] = True
                            result['match'] = 'subset'
        
        except Exception as e:
            pass
        
        return result
    
    def check_service(self, service_path: Path, sample_ops: int = 3) -> Dict[str, Any]:
        """Check a single service"""
        
        enriched_file = service_path / "azure_dependencies_with_python_names_fully_enriched.json"
        
        if not enriched_file.exists():
            return {'error': 'File not found'}
        
        try:
            with open(enriched_file) as f:
                data = json.load(f)
            
            service_name = service_path.name
            module_name = data.get(service_name, {}).get('module', '')
            
            results = {
                'service': service_name,
                'correct': 0,
                'incorrect': 0,
                'total': 0
            }
            
            # Check operations_by_category
            if service_name in data and 'operations_by_category' in data[service_name]:
                for category, category_data in data[service_name]['operations_by_category'].items():
                    for op_type in ['independent', 'dependent']:
                        if op_type in category_data:
                            for op_data in category_data[op_type][:sample_ops]:
                                if 'item_fields' in op_data and isinstance(op_data['item_fields'], dict):
                                    for field_name, field_data in op_data['item_fields'].items():
                                        if 'possible_values' in field_data:
                                            enriched_values = field_data['possible_values']
                                            validation = self.validate_field_enum(
                                                module_name, field_name, enriched_values
                                            )
                                            results['total'] += 1
                                            if validation['correct']:
                                                results['correct'] += 1
                                            else:
                                                results['incorrect'] += 1
            
            self.stats['services_checked'] += 1
            self.stats['fields_validated'] += results['total']
            self.stats['fields_correct'] += results['correct']
            self.stats['fields_incorrect'] += results['incorrect']
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def check_sample_services(self, root_path: Path, sample_size: int = 20):
        """Check a sample of services"""
        
        print(f"\n{'='*70}")
        print(f"QUALITY CHECK: AZURE ENUM ENRICHMENT VALIDATION")
        print(f"{'='*70}\n")
        
        service_dirs = []
        for service_dir in root_path.iterdir():
            if service_dir.is_dir():
                enriched_file = service_dir / "azure_dependencies_with_python_names_fully_enriched.json"
                if enriched_file.exists():
                    service_dirs.append(service_dir)
        
        # Sample services
        priority_services = ['compute', 'storage', 'network', 'sql', 'web', 'keyvault']
        sample_services = []
        
        for svc in priority_services:
            svc_path = root_path / svc
            if svc_path in service_dirs:
                sample_services.append(svc_path)
        
        remaining = [s for s in service_dirs if s not in sample_services]
        sample_services.extend(remaining[:sample_size - len(sample_services)])
        
        print(f"Checking {len(sample_services)} services...\n")
        
        for i, service_path in enumerate(sample_services, 1):
            service_name = service_path.name
            print(f"[{i}/{len(sample_services)}] {service_name}...", end=" ")
            
            result = self.check_service(service_path)
            
            if 'error' in result:
                print(f"❌ {result['error']}")
            else:
                total = result['total']
                if total > 0:
                    accuracy = (result['correct'] / total * 100) if total > 0 else 0
                    print(f"✓ {result['correct']}/{total} validated ({accuracy:.1f}%)")
                else:
                    print("✓ (no enum fields to validate)")
        
        # Print summary
        print(f"\n{'='*70}")
        print(f"QUALITY CHECK SUMMARY")
        print(f"{'='*70}")
        print(f"Services checked: {self.stats['services_checked']}")
        print(f"Fields validated: {self.stats['fields_validated']}")
        print(f"Fields correct: {self.stats['fields_correct']}")
        print(f"Fields incorrect: {self.stats['fields_incorrect']}")
        
        if self.stats['fields_validated'] > 0:
            accuracy = (self.stats['fields_correct'] / self.stats['fields_validated'] * 100)
            print(f"\nOverall Accuracy: {accuracy:.1f}%")


def main():
    """CLI entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Quality check Azure enum enrichment'
    )
    parser.add_argument(
        '--root',
        default='pythonsdk-database/azure',
        help='Root path for services'
    )
    parser.add_argument(
        '--sample',
        type=int,
        default=20,
        help='Number of services to sample (default: 20)'
    )
    
    args = parser.parse_args()
    
    root_path = Path(args.root)
    checker = AzureEnrichmentQualityChecker()
    checker.check_sample_services(root_path, args.sample)


if __name__ == '__main__':
    main()

