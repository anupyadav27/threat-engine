"""
Metadata Loader

Loads check metadata (titles, severity, descriptions) from separate YAML files.
This keeps the main rule YAML files clean with just logic.

Structure:
  - services/{service}/rules/{service}.yaml - Logic only (discoveries, checks)
  - metadata/checks/{service}_metadata.yaml - Metadata (titles, severity, remediation)
"""

import os
import yaml
from typing import Dict, Optional


class MetadataLoader:
    """Loads and merges check metadata with rule logic"""
    
    def __init__(self, metadata_dir: str = None):
        if metadata_dir is None:
            # Default to metadata/checks/ directory
            current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            metadata_dir = os.path.join(current_dir, 'metadata', 'checks')
        
        self.metadata_dir = metadata_dir
        self._metadata_cache = {}
    
    def load_metadata(self, service_name: str) -> Dict:
        """Load metadata for a service"""
        if service_name in self._metadata_cache:
            return self._metadata_cache[service_name]
        
        metadata_file = os.path.join(self.metadata_dir, f'{service_name}_metadata.yaml')
        
        if not os.path.exists(metadata_file):
            # No metadata file, return empty
            return {}
        
        with open(metadata_file, 'r') as f:
            metadata = yaml.safe_load(f)
        
        self._metadata_cache[service_name] = metadata
        return metadata
    
    def enrich_checks(self, service_name: str, checks: list) -> list:
        """
        Enrich check list with metadata
        
        Args:
            service_name: Service name (e.g., 'account', 'accessanalyzer')
            checks: List of checks from rule YAML (has rule_id, conditions)
        
        Returns:
            List of checks with metadata added (title, severity, description, etc.)
        """
        metadata = self.load_metadata(service_name)
        
        if not metadata or 'checks' not in metadata:
            # No metadata, return as-is
            return checks
        
        enriched_checks = []
        
        for check in checks:
            rule_id = check.get('rule_id')
            
            if not rule_id:
                # No rule_id, can't enrich
                enriched_checks.append(check)
                continue
            
            # Get metadata for this rule_id
            check_metadata = metadata['checks'].get(rule_id, {})
            
            # Merge: metadata + original check (original takes precedence)
            enriched_check = {
                'title': check_metadata.get('title', rule_id),
                'description': check_metadata.get('description', ''),
                'severity': check_metadata.get('severity', 'medium'),
                'category': check_metadata.get('category', 'general'),
                'frameworks': check_metadata.get('frameworks', []),
                'remediation': check_metadata.get('remediation', ''),
                'references': check_metadata.get('references', []),
                **check  # Original check data (rule_id, conditions, etc.)
            }
            
            enriched_checks.append(enriched_check)
        
        return enriched_checks
    
    def get_check_metadata(self, service_name: str, rule_id: str) -> Dict:
        """Get metadata for a specific check"""
        metadata = self.load_metadata(service_name)
        
        if not metadata or 'checks' not in metadata:
            return {}
        
        return metadata['checks'].get(rule_id, {})


# Global instance
_loader = None

def get_metadata_loader() -> MetadataLoader:
    """Get global metadata loader instance"""
    global _loader
    if _loader is None:
        _loader = MetadataLoader()
    return _loader


def load_service_rules_with_metadata(service_name: str, rules_path: str) -> Dict:
    """
    Load service rules and enrich with metadata
    
    Args:
        service_name: Service name
        rules_path: Path to rules YAML file
    
    Returns:
        Dict with enriched rules (checks have metadata)
    """
    # Load rules YAML
    with open(rules_path, 'r') as f:
        rules = yaml.safe_load(f)
    
    # Enrich checks with metadata
    if 'checks' in rules:
        loader = get_metadata_loader()
        rules['checks'] = loader.enrich_checks(service_name, rules['checks'])
    
    return rules


if __name__ == '__main__':
    # Test the metadata loader
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 metadata_loader.py <service_name>")
        print("\nExample:")
        print("  python3 metadata_loader.py account")
        sys.exit(1)
    
    service = sys.argv[1]
    
    loader = get_metadata_loader()
    
    print(f"Loading metadata for service: {service}")
    metadata = loader.load_metadata(service)
    
    if metadata:
        print(f"\nFound {len(metadata.get('checks', {}))} checks with metadata:")
        for rule_id, data in metadata.get('checks', {}).items():
            print(f"\n  {rule_id}:")
            print(f"    Title: {data.get('title')}")
            print(f"    Severity: {data.get('severity')}")
            print(f"    Frameworks: {', '.join(data.get('frameworks', []))}")
    else:
        print(f"No metadata found for {service}")
