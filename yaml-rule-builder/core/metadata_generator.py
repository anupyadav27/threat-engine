"""
Metadata file generator for custom rules
"""

import yaml
from pathlib import Path
from typing import Dict, Optional
from datetime import datetime

class MetadataGenerator:
    """Generates metadata YAML files for custom rules"""
    
    def __init__(self, service_name: str, config):
        self.service_name = service_name
        self.config = config
        self.metadata_dir = self.config.output_dir / service_name / "metadata"
    
    def generate_metadata(
        self,
        rule_id: str,
        title: str,
        description: str,
        remediation: str,
        field_name: str,
        operator: str,
        value: any
    ) -> Path:
        """
        Generate metadata file for a custom rule
        
        Args:
            rule_id: Rule identifier
            title: Rule title
            description: Rule description
            remediation: Remediation steps
            field_name: Field being checked
            operator: Operator used
            value: Expected value
        
        Returns:
            Path to created metadata file
        """
        # Create metadata directory if it doesn't exist
        self.metadata_dir.mkdir(parents=True, exist_ok=True)
        
        # Extract resource from rule_id
        # Format: aws.service.resource.rule_name
        parts = rule_id.split(".")
        resource = parts[2] if len(parts) > 2 else "resource"
        requirement = title.replace(f"{self.service_name.upper()} {resource}: ", "")
        
        # Build metadata structure
        metadata = {
            "rule_id": rule_id,
            "service": self.service_name,
            "resource": resource,
            "requirement": requirement,
            "title": f"{self.service_name.upper()} {resource}: {title}",
            "scope": f"{self.service_name}.{resource}.configuration",
            "domain": "configuration_and_change_management",
            "subcategory": "configuration_baseline",
            "rationale": f"Ensures {self.service_name} {resource} has {field_name} {operator} {value} properly configured for security compliance.",
            "severity": "medium",
            "assertion_id": f"security.configuration.{self.service_name}_{resource}_{field_name}_{operator}",
            "source": "user_created",  # Mark as user-created
            "custom": True,  # Custom field to mark user-created rules
            "created_at": datetime.now().isoformat(),
            "created_by": "yaml_rule_builder",
            "compliance": [],  # Empty - user can add later
            "description": description,
            "references": [
                f"https://docs.aws.amazon.com/{self.service_name}/latest/userguide/"
            ],
            "remediation": remediation
        }
        
        # Save metadata file
        metadata_file = self.metadata_dir / f"{rule_id}.yaml"
        with open(metadata_file, 'w') as f:
            yaml.dump(metadata, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
        
        return metadata_file

