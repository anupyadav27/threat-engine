"""
Framework Loader

Loads compliance framework definitions and mappings from CSV/YAML files.
"""

import os
import csv
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass


@dataclass
class FrameworkControl:
    """Represents a compliance framework control."""
    framework: str
    framework_version: Optional[str]
    control_id: str
    control_title: str
    control_category: Optional[str] = None
    control_description: Optional[str] = None


@dataclass
class RuleMapping:
    """Maps a rule_id to compliance framework controls."""
    rule_id: str
    csp: str
    controls: List[FrameworkControl]


class FrameworkLoader:
    """Loads compliance framework definitions and rule mappings."""
    
    def __init__(self, data_dir: Optional[str] = None):
        """
        Initialize framework loader.
        
        Args:
            data_dir: Base directory for framework data (default: ../data/)
        """
        if data_dir is None:
            # Default to data/ directory relative to this file
            base_dir = Path(__file__).parent.parent.parent
            data_dir = str(base_dir / "data")
        
        self.data_dir = Path(data_dir)
        self.frameworks_dir = self.data_dir / "frameworks"
        self.mappings_dir = self.data_dir / "mappings"
        
        # Cache for loaded frameworks
        self._frameworks_cache: Dict[str, List[FrameworkControl]] = {}
        self._rule_mappings_cache: Dict[str, List[RuleMapping]] = {}
    
    def load_framework_from_csv(self, framework_name: str, version: Optional[str] = None) -> List[FrameworkControl]:
        """
        Load framework controls from CSV file.
        
        CSV format:
        control_id,control_title,control_category,control_description
        
        Args:
            framework_name: Name of framework (e.g., "CIS AWS Foundations Benchmark")
            version: Framework version (e.g., "2.0")
        
        Returns:
            List of FrameworkControl objects
        """
        cache_key = f"{framework_name}_{version or 'latest'}"
        if cache_key in self._frameworks_cache:
            return self._frameworks_cache[cache_key]
        
        # Construct filename
        filename = framework_name.lower().replace(" ", "_")
        if version:
            filename = f"{filename}_v{version}"
        filename = f"{filename}.csv"
        
        csv_path = self.frameworks_dir / filename
        
        if not csv_path.exists():
            raise FileNotFoundError(f"Framework file not found: {csv_path}")
        
        controls = []
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                control = FrameworkControl(
                    framework=framework_name,
                    framework_version=version,
                    control_id=row.get('control_id', ''),
                    control_title=row.get('control_title', ''),
                    control_category=row.get('control_category'),
                    control_description=row.get('control_description')
                )
                controls.append(control)
        
        self._frameworks_cache[cache_key] = controls
        return controls
    
    def load_rule_mappings_from_csv(self, csp: str) -> Dict[str, List[FrameworkControl]]:
        """
        Load rule-to-framework mappings from CSV.
        
        CSV format:
        rule_id,framework,framework_version,control_id,control_title,control_category
        
        Args:
            csp: Cloud service provider (aws, azure, gcp, etc.)
        
        Returns:
            Dictionary mapping rule_id to list of FrameworkControl objects
        """
        cache_key = f"{csp}_mappings"
        if cache_key in self._rule_mappings_cache:
            return self._rule_mappings_cache[cache_key]
        
        # Try CSP-specific mapping file
        csv_path = self.mappings_dir / f"{csp}_rule_to_framework.csv"
        
        if not csv_path.exists():
            # Try generic consolidated file
            csv_path = self.data_dir.parent / "compliance" / csp / f"{csp}_consolidated_rules_with_final_checks.csv"
        
        if not csv_path.exists():
            # Try compliance-database directory (actual location)
            workspace_root = Path("/Users/apple/Desktop/threat-engine")
            csv_path = workspace_root / "compliance-database" / csp / f"{csp}_consolidated_rules_with_final_checks.csv"
        
        if not csv_path.exists():
            # Return empty dict if no mappings found
            return {}
        
        mappings: Dict[str, List[FrameworkControl]] = {}
        
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                rule_id = row.get('final_aws_check') or row.get('rule_id') or row.get('aws_checks', '')
                if not rule_id:
                    continue
                
                # Parse multiple rule_ids if semicolon-separated
                rule_ids = [r.strip() for r in rule_id.split(';')]
                
                framework = row.get('compliance_framework', '')
                framework_version = row.get('framework_version')
                control_id = row.get('requirement_id') or row.get('framework_id', '')
                control_title = row.get('requirement_name', '')
                control_category = row.get('section', '')
                
                if not framework or not control_id:
                    continue
                
                control = FrameworkControl(
                    framework=framework,
                    framework_version=framework_version,
                    control_id=control_id,
                    control_title=control_title,
                    control_category=control_category
                )
                
                # Map each rule_id to this control
                for rid in rule_ids:
                    if rid:
                        if rid not in mappings:
                            mappings[rid] = []
                        mappings[rid].append(control)
        
        self._rule_mappings_cache[cache_key] = mappings
        return mappings
    
    def load_rule_mappings_from_yaml(self, csp: str) -> Dict[str, List[FrameworkControl]]:
        """
        Load rule-to-framework mappings from YAML file.
        
        YAML format:
        rule_ids:
          - rule_id: aws.accessanalyzer.resource.access_analyzer_enabled
            compliance:
              - framework: CIS AWS Foundations Benchmark
                version: 2.0
                control_id: 2.1.1
                control_title: Ensure IAM Access Analyzer is enabled
        
        Args:
            csp: Cloud service provider
        
        Returns:
            Dictionary mapping rule_id to list of FrameworkControl objects
        """
        cache_key = f"{csp}_yaml_mappings"
        if cache_key in self._rule_mappings_cache:
            return self._rule_mappings_cache[cache_key]
        
        # Try CSP-specific YAML file
        yaml_path = self.mappings_dir / f"{csp}_rule_to_framework.yaml"
        
        if not yaml_path.exists():
            # Try in compliance directory
            yaml_path = self.data_dir.parent / "compliance" / csp / f"rule_ids_BEDROCK_VALIDATED.yaml"
        
        if not yaml_path.exists():
            return {}
        
        mappings: Dict[str, List[FrameworkControl]] = {}
        
        with open(yaml_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        rule_ids = data.get('rule_ids', [])
        
        for rule_data in rule_ids:
            rule_id = rule_data.get('rule_id')
            if not rule_id:
                continue
            
            compliance_list = rule_data.get('compliance', [])
            
            for comp in compliance_list:
                if isinstance(comp, str):
                    # Handle string format like "iso27001_2022_multi_cloud_A.8.3_0085"
                    # Parse if needed, or skip
                    continue
                
                framework = comp.get('framework') or comp.get('framework_name', '')
                framework_version = comp.get('version') or comp.get('framework_version')
                control_id = comp.get('control_id') or comp.get('requirement_id', '')
                control_title = comp.get('control_title') or comp.get('requirement_name', '')
                control_category = comp.get('control_category') or comp.get('category', '')
                
                if not framework or not control_id:
                    continue
                
                control = FrameworkControl(
                    framework=framework,
                    framework_version=framework_version,
                    control_id=control_id,
                    control_title=control_title,
                    control_category=control_category
                )
                
                if rule_id not in mappings:
                    mappings[rule_id] = []
                mappings[rule_id].append(control)
        
        self._rule_mappings_cache[cache_key] = mappings
        return mappings
    
    def load_rule_mappings_from_metadata(self, csp: str) -> Dict[str, List[FrameworkControl]]:
        """
        Load rule-to-framework mappings from rule metadata files.
        
        Uses MetadataLoader to load compliance mappings from rule_db metadata files.
        
        Args:
            csp: Cloud service provider
        
        Returns:
            Dictionary mapping rule_id to list of FrameworkControl objects
        """
        try:
            from ..loader.metadata_loader import MetadataLoader
            metadata_loader = MetadataLoader()
            return metadata_loader.load_all_metadata_mappings(csp)
        except Exception as e:
            print(f"Error loading metadata mappings: {e}")
            return {}
    
    def get_rule_mappings(self, csp: str, use_metadata: bool = False) -> Dict[str, List[FrameworkControl]]:
        """
        Get rule-to-framework mappings for a CSP.
        Tries CSV first, then YAML, then metadata files if use_metadata=True.
        
        Args:
            csp: Cloud service provider
            use_metadata: If True, also try loading from rule metadata files
        
        Returns:
            Dictionary mapping rule_id to list of FrameworkControl objects
        """
        # Try CSV first
        csv_mappings = self.load_rule_mappings_from_csv(csp)
        if csv_mappings:
            return csv_mappings
        
        # Fall back to YAML
        yaml_mappings = self.load_rule_mappings_from_yaml(csp)
        if yaml_mappings:
            return yaml_mappings
        
        # If use_metadata and no other mappings found, try metadata files
        if use_metadata:
            metadata_mappings = self.load_rule_mappings_from_metadata(csp)
            if metadata_mappings:
                return metadata_mappings
        
        return {}

