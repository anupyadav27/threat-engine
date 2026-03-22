"""
Metadata file generator for custom rules
"""

import yaml
from pathlib import Path
from typing import Dict, Optional
from datetime import datetime, timezone

class MetadataGenerator:
    """Generates metadata YAML files for custom rules with provider awareness"""
    
    def __init__(self, service_name: str, provider: str, config):
        """
        Initialize metadata generator
        
        Args:
            service_name: Service name (e.g., 'iam')
            provider: Provider name (e.g., 'aws', 'azure') - REQUIRED
            config: Config instance
        """
        if not provider:
            raise ValueError("provider is required for metadata generation")
        
        self.service_name = service_name
        self.provider = provider
        self.config = config
        self.provider_adapter = config.get_provider_adapter(provider)
        self.metadata_dir = self.config.get_metadata_path(service_name, provider)
    
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
        # Format: {provider}.service.resource.rule_name
        parts = rule_id.split(".")
        resource = parts[2] if len(parts) > 2 else "resource"
        requirement = title.replace(f"{self.service_name.upper()} {resource}: ", "")
        
        # Get provider-specific documentation URL
        docs_url = self.provider_adapter.get_documentation_url(self.service_name)
        
        # Build metadata structure
        value_str = "" if value is None else str(value)
        rationale_value_part = "" if value is None else f" {value_str}"
        created_at = datetime.now(timezone.utc).isoformat() + "Z"

        assertion_id = (
            f"security.configuration."
            f"{self.service_name}_{resource}_{field_name}_{operator}"
        ).lower()

        metadata = {
            "rule_id": rule_id,
            "provider": self.provider,  # NEW: Include provider
            "service": self.service_name,
            "resource": resource,
            "requirement": requirement,
            "title": f"{self.service_name.upper()} {resource}: {title}",
            "scope": f"{self.service_name}.{resource}.configuration",
            "domain": "configuration_and_change_management",
            "subcategory": "configuration_baseline",
            "rationale": (
                f"Ensures {self.service_name} {resource} has "
                f"{field_name} {operator}{rationale_value_part} properly configured for security compliance."
            ),
            "severity": "medium",
            "assertion_id": assertion_id,
            "source": "user_generated",  # Mark as user-generated
            "metadata_source": "user_generated",
            "generated_by": "yaml_rule_builder",
            "custom": True,  # Custom field to mark user-created rules
            "created_at": created_at,
            "created_by": "yaml_rule_builder",
            "compliance": [],  # Empty - user can add later
            "description": description,
            "references": [
                docs_url  # Provider-specific documentation URL
            ],
            "remediation": remediation
        }
        
        # Save metadata file
        metadata_file = self.metadata_dir / f"{rule_id}.yaml"
        with open(metadata_file, 'w') as f:
            yaml.dump(metadata, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
        
        return metadata_file

