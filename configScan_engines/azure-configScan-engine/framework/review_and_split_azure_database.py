#!/usr/bin/env python3
"""
Review Azure SDK database data quality and ensure all services are split into folders
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Any, Set
from collections import defaultdict

class AzureDatabaseReviewer:
    """Review and validate Azure SDK database"""
    
    def __init__(self, database_file: str, output_dir: str):
        self.database_file = Path(database_file)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.issues = []
        self.stats = defaultdict(int)
        
    def load_database(self) -> Dict[str, Any]:
        """Load the main database file"""
        print(f"Loading database from: {self.database_file}")
        with open(self.database_file, 'r') as f:
            return json.load(f)
    
    def review_service(self, service_name: str, service_data: Dict[str, Any]) -> List[str]:
        """Review a single service for data quality issues"""
        issues = []
        
        # Check required fields
        required_fields = ['service', 'module', 'total_operations']
        for field in required_fields:
            if field not in service_data:
                issues.append(f"Missing required field: {field}")
        
        # Check operations structure
        if 'operations_by_category' not in service_data and 'independent' not in service_data:
            issues.append("Missing operations structure")
        
        # Review operations
        all_ops = []
        if 'operations_by_category' in service_data:
            for category, cat_data in service_data['operations_by_category'].items():
                if 'independent' in cat_data:
                    all_ops.extend(cat_data['independent'])
                if 'dependent' in cat_data:
                    all_ops.extend(cat_data['dependent'])
        else:
            if 'independent' in service_data:
                all_ops.extend(service_data['independent'])
            if 'dependent' in service_data:
                all_ops.extend(service_data['dependent'])
        
        # Review each operation
        for op in all_ops:
            op_issues = self.review_operation(op)
            if op_issues:
                issues.extend([f"Operation {op.get('operation', 'unknown')}: {issue}" for issue in op_issues])
        
        # Check operation count matches
        if 'total_operations' in service_data:
            expected_count = len(all_ops)
            actual_count = service_data['total_operations']
            if expected_count != actual_count:
                issues.append(f"Operation count mismatch: expected {expected_count}, got {actual_count}")
        
        return issues
    
    def review_operation(self, operation: Dict[str, Any]) -> List[str]:
        """Review a single operation for data quality"""
        issues = []
        
        # Check required fields
        required = ['operation', 'python_method', 'yaml_action']
        for field in required:
            if field not in operation:
                issues.append(f"Missing field: {field}")
        
        # Check item_fields structure
        if 'item_fields' in operation:
            item_fields = operation['item_fields']
            if isinstance(item_fields, dict) and item_fields:
                for field_name, field_data in item_fields.items():
                    if not isinstance(field_data, dict):
                        issues.append(f"item_field '{field_name}' is not a dict")
                    else:
                        # Check field has required properties
                        if 'type' not in field_data:
                            issues.append(f"item_field '{field_name}' missing 'type'")
                        if 'compliance_category' not in field_data:
                            issues.append(f"item_field '{field_name}' missing 'compliance_category'")
                        if 'operators' not in field_data:
                            issues.append(f"item_field '{field_name}' missing 'operators'")
                        if 'description' not in field_data:
                            issues.append(f"item_field '{field_name}' missing 'description'")
        
        return issues
    
    def review_all_services(self, database: Dict[str, Any]) -> Dict[str, List[str]]:
        """Review all services in the database"""
        print("\n" + "=" * 80)
        print("Reviewing Data Quality")
        print("=" * 80)
        
        all_issues = {}
        
        for service_name, service_data in database.items():
            issues = self.review_service(service_name, service_data)
            if issues:
                all_issues[service_name] = issues
                self.stats['services_with_issues'] += 1
            else:
                self.stats['services_clean'] += 1
            
            self.stats['total_services'] += 1
            self.stats['total_operations'] += service_data.get('total_operations', 0)
        
        return all_issues
    
    def split_services_to_folders(self, database: Dict[str, Any]) -> Dict[str, bool]:
        """Split each service into its own folder"""
        print("\n" + "=" * 80)
        print("Splitting Services into Folders")
        print("=" * 80)
        
        results = {}
        
        for service_name, service_data in database.items():
            service_dir = self.output_dir / service_name
            service_dir.mkdir(exist_ok=True)
            
            service_file = service_dir / "azure_dependencies_with_python_names_fully_enriched.json"
            
            # Create service-specific JSON
            service_json = {service_name: service_data}
            
            try:
                with open(service_file, 'w') as f:
                    json.dump(service_json, f, indent=2)
                results[service_name] = True
                self.stats['folders_created'] += 1
            except Exception as e:
                print(f"  ✗ Error creating file for {service_name}: {e}")
                results[service_name] = False
        
        return results
    
    def generate_quality_report(self, issues: Dict[str, List[str]]):
        """Generate a data quality report"""
        report_file = self.output_dir / "data_quality_report.json"
        
        report = {
            "summary": {
                "total_services": self.stats['total_services'],
                "services_clean": self.stats['services_clean'],
                "services_with_issues": self.stats['services_with_issues'],
                "total_operations": self.stats['total_operations'],
                "folders_created": self.stats['folders_created']
            },
            "issues": issues
        }
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n✅ Quality report saved to: {report_file}")
        
        # Print summary
        print("\n" + "=" * 80)
        print("DATA QUALITY SUMMARY")
        print("=" * 80)
        print(f"Total Services: {self.stats['total_services']}")
        print(f"Clean Services: {self.stats['services_clean']}")
        print(f"Services with Issues: {self.stats['services_with_issues']}")
        print(f"Total Operations: {self.stats['total_operations']:,}")
        print(f"Folders Created: {self.stats['folders_created']}")
        
        if issues:
            print(f"\n⚠️  {len(issues)} services have issues:")
            for svc, svc_issues in list(issues.items())[:10]:
                print(f"  - {svc}: {len(svc_issues)} issues")
                for issue in svc_issues[:3]:
                    print(f"    • {issue}")
        else:
            print("\n✅ All services passed quality checks!")
    
    def run(self):
        """Run the complete review and split process"""
        print("=" * 80)
        print("Azure SDK Database Review and Split")
        print("=" * 80)
        
        # Load database
        database = self.load_database()
        print(f"✅ Loaded {len(database)} services")
        
        # Review data quality
        issues = self.review_all_services(database)
        
        # Split services to folders
        split_results = self.split_services_to_folders(database)
        
        # Generate report
        self.generate_quality_report(issues)
        
        print("\n" + "=" * 80)
        print("✅ Review and Split Complete!")
        print("=" * 80)


def main():
    """Main execution"""
    # Find the correct path
    possible_paths = [
        Path(__file__).parent.parent.parent.parent / "pythonsdk-database" / "azure" / "azure_dependencies_with_python_names_fully_enriched.json",
        Path("/Users/apple/Desktop/threat-engine/pythonsdk-database/azure/azure_dependencies_with_python_names_fully_enriched.json"),
    ]
    
    database_file = None
    for path in possible_paths:
        if path.exists():
            database_file = path
            break
    
    if not database_file:
        # Try to find it
        base_dir = Path("/Users/apple/Desktop/threat-engine")
        database_file = base_dir / "pythonsdk-database" / "azure" / "azure_dependencies_with_python_names_fully_enriched.json"
    
    output_dir = database_file.parent
    
    reviewer = AzureDatabaseReviewer(database_file, output_dir)
    reviewer.run()


if __name__ == '__main__':
    main()

