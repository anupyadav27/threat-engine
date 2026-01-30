"""
Consolidated CSV Loader

Loads comprehensive compliance mappings from aws_consolidated_rules_with_final_checks.csv
which contains rich framework structure information including:
- Framework sections/categories
- Control descriptions
- Multiple rule_ids per control
- Service mappings
- Total checks count
"""

import csv
from pathlib import Path
from typing import Dict, List, Optional, Any
from collections import defaultdict
from ..mapper.framework_loader import FrameworkControl


class ConsolidatedCSVLoader:
    """Loads comprehensive compliance mappings from consolidated CSV."""
    
    def __init__(self, csv_path: Optional[Path] = None):
        """
        Initialize consolidated CSV loader.
        
        Args:
            csv_path: Path to consolidated CSV file
                     Default: compliance-database/aws/aws_consolidated_rules_with_final_checks.csv
        """
        if csv_path is None:
            from engine_common.storage_paths import get_project_root
            root = get_project_root()
            csv_path = root / "data_compliance" / "aws" / "aws_consolidated_rules_with_final_checks.csv"
        
        self.csv_path = Path(csv_path)
        self._mappings_cache: Dict[str, List[FrameworkControl]] = {}
        self._framework_structure_cache: Dict[str, Dict[str, Any]] = {}
        self._control_details_cache: Dict[str, Dict[str, Any]] = {}
    
    def load_all_mappings(self, csp: str = "aws") -> Dict[str, List[FrameworkControl]]:
        """
        Load all rule-to-framework mappings from consolidated CSV.
        
        Args:
            csp: Cloud service provider
        
        Returns:
            Dictionary mapping rule_id to list of FrameworkControl objects
        """
        cache_key = f"{csp}_consolidated"
        if cache_key in self._mappings_cache:
            return self._mappings_cache[cache_key]
        
        if not self.csv_path.exists():
            return {}
        
        mappings: Dict[str, List[FrameworkControl]] = {}
        
        with open(self.csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Get rule_ids from final_aws_check column
                rule_ids_str = row.get('final_aws_check', '')
                if not rule_ids_str:
                    continue
                
                # Parse multiple rule_ids (semicolon-separated)
                rule_ids = [r.strip() for r in rule_ids_str.split(';') if r.strip()]
                
                # Get framework information
                framework = row.get('compliance_framework', '')
                framework_version = row.get('framework_version', '')
                control_id = row.get('requirement_id', '')
                control_title = row.get('requirement_name', '')
                control_category = row.get('section', '')
                control_description = row.get('requirement_description', '')
                
                if not framework or not control_id:
                    continue
                
                # Create FrameworkControl
                control = FrameworkControl(
                    framework=framework,
                    framework_version=framework_version if framework_version else None,
                    control_id=control_id,
                    control_title=control_title,
                    control_category=control_category if control_category else None,
                    control_description=control_description if control_description else None
                )
                
                # Map each rule_id to this control
                for rule_id in rule_ids:
                    if rule_id:
                        if rule_id not in mappings:
                            mappings[rule_id] = []
                        mappings[rule_id].append(control)
        
        self._mappings_cache[cache_key] = mappings
        return mappings
    
    def get_framework_structure(self, framework: str) -> Dict[str, Any]:
        """
        Get framework structure (sections, categories, controls) from CSV.
        
        Args:
            framework: Framework name
        
        Returns:
            Framework structure with sections, categories, and controls
        """
        cache_key = f"structure_{framework}"
        if cache_key in self._framework_structure_cache:
            return self._framework_structure_cache[cache_key]
        
        if not self.csv_path.exists():
            return {}
        
        structure = {
            'framework': framework,
            'sections': defaultdict(list),
            'categories': defaultdict(list),
            'controls': {},
            'services': set()
        }
        
        with open(self.csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                row_framework = row.get('compliance_framework', '')
                if row_framework != framework:
                    continue
                
                control_id = row.get('requirement_id', '')
                control_title = row.get('requirement_name', '')
                section = row.get('section', '')
                service = row.get('service', '')
                framework_version = row.get('framework_version', '')
                total_checks = row.get('total_checks', '0')
                
                if not control_id:
                    continue
                
                # Store control details
                control_key = f"{framework}_{control_id}"
                structure['controls'][control_key] = {
                    'control_id': control_id,
                    'control_title': control_title,
                    'section': section,
                    'service': service,
                    'framework_version': framework_version,
                    'total_checks': int(total_checks) if total_checks.isdigit() else 0
                }
                
                # Group by section
                if section:
                    structure['sections'][section].append(control_id)
                
                # Group by service
                if service:
                    structure['services'].add(service)
        
        # Convert sets to lists for JSON serialization
        structure['services'] = sorted(list(structure['services']))
        structure['sections'] = dict(structure['sections'])
        
        self._framework_structure_cache[cache_key] = structure
        return structure
    
    def get_control_details(self, framework: str, control_id: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a specific control.
        
        Args:
            framework: Framework name
            control_id: Control ID
        
        Returns:
            Control details dictionary or None
        """
        control_key = f"{framework}_{control_id}"
        
        if control_key in self._control_details_cache:
            return self._control_details_cache[control_key]
        
        if not self.csv_path.exists():
            return None
        
        with open(self.csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                row_framework = row.get('compliance_framework', '')
                row_control_id = row.get('requirement_id', '')
                
                if row_framework == framework and row_control_id == control_id:
                    details = {
                        'framework': framework,
                        'framework_id': row.get('framework_id', ''),
                        'framework_version': row.get('framework_version', ''),
                        'control_id': control_id,
                        'control_title': row.get('requirement_name', ''),
                        'control_description': row.get('requirement_description', ''),
                        'section': row.get('section', ''),
                        'service': row.get('service', ''),
                        'total_checks': int(row.get('total_checks', '0')) if row.get('total_checks', '0').isdigit() else 0,
                        'automation_type': row.get('automation_type', ''),
                        'rule_ids': [r.strip() for r in row.get('final_aws_check', '').split(';') if r.strip()]
                    }
                    self._control_details_cache[control_key] = details
                    return details
        
        return None
    
    def get_frameworks_list(self) -> List[str]:
        """
        Get list of all frameworks in the CSV.
        
        Returns:
            List of unique framework names
        """
        if not self.csv_path.exists():
            return []
        
        frameworks = set()
        with open(self.csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                framework = row.get('compliance_framework', '')
                if framework:
                    frameworks.add(framework)
        
        return sorted(list(frameworks))
    
    def get_framework_controls(self, framework: str) -> List[Dict[str, Any]]:
        """
        Get all controls for a framework.
        
        Args:
            framework: Framework name
        
        Returns:
            List of control dictionaries
        """
        controls = []
        
        if not self.csv_path.exists():
            return controls
        
        with open(self.csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                row_framework = row.get('compliance_framework', '')
                if row_framework != framework:
                    continue
                
                control_id = row.get('requirement_id', '')
                if not control_id:
                    continue
                
                controls.append({
                    'control_id': control_id,
                    'control_title': row.get('requirement_name', ''),
                    'control_description': row.get('requirement_description', ''),
                    'section': row.get('section', ''),
                    'service': row.get('service', ''),
                    'framework_version': row.get('framework_version', ''),
                    'total_checks': int(row.get('total_checks', '0')) if row.get('total_checks', '0').isdigit() else 0
                })
        
        return controls
