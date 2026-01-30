"""
AWS Provider Adapter Implementation
"""

from pathlib import Path
from ..plugin_base import CSPProvider


class AWSProvider(CSPProvider):
    """AWS (Amazon Web Services) provider adapter"""
    
    @property
    def provider_name(self) -> str:
        return "aws"
    
    @property
    def display_name(self) -> str:
        return "Amazon Web Services"
    
    def get_sdk_module_pattern(self) -> str:
        return "boto3.client"
    
    def format_discovery_id(self, service: str, method: str) -> str:
        """Format: aws.service.method"""
        return f"aws.{service}.{method}"
    
    def format_rule_id_prefix(self) -> str:
        return "aws."
    
    def get_dependencies_file_name(self) -> str:
        return "boto3_dependencies_with_python_names_fully_enriched.json"
    
    def get_database_path(self, base_path: Path) -> Path:
        """Path: pythonsdk-database/aws"""
        return base_path / "aws"
    
    def get_output_path(self, base_path: Path, service: str) -> Path:
        """Path: aws_compliance_python_engine/services/{service}/rules"""
        return base_path / "aws_compliance_python_engine" / "services" / service / "rules"
    
    def get_metadata_path(self, base_path: Path, service: str) -> Path:
        """Path: aws_compliance_python_engine/services/{service}/metadata"""
        return base_path / "aws_compliance_python_engine" / "services" / service / "metadata"
    
    def validate_rule_id(self, rule_id: str) -> bool:
        """Validate rule ID starts with 'aws.' and has at least 4 parts"""
        parts = rule_id.split(".")
        return len(parts) >= 4 and rule_id.startswith("aws.")
    
    def get_documentation_url(self, service: str) -> str:
        """Generate AWS documentation URL"""
        return f"https://docs.aws.amazon.com/{service}/latest/userguide/"

