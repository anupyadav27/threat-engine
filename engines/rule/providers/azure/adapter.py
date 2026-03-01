"""
Azure Provider Adapter Implementation
"""

from pathlib import Path
from ..plugin_base import CSPProvider


class AzureProvider(CSPProvider):
    """Azure (Microsoft Azure) provider adapter"""
    
    @property
    def provider_name(self) -> str:
        return "azure"
    
    @property
    def display_name(self) -> str:
        return "Microsoft Azure"
    
    def get_sdk_module_pattern(self) -> str:
        return "azure.mgmt.{service}.{Service}ManagementClient"
    
    def format_discovery_id(self, service: str, method: str) -> str:
        """Format: azure.service.method"""
        return f"azure.{service}.{method}"
    
    def format_rule_id_prefix(self) -> str:
        return "azure."
    
    def get_dependencies_file_name(self) -> str:
        return "azure_dependencies_with_python_names_fully_enriched.json"
    
    def get_database_path(self, base_path: Path) -> Path:
        """Path: pythonsdk-database/azure"""
        return base_path / "azure"
    
    def get_output_path(self, base_path: Path, service: str) -> Path:
        """Path: azure_compliance_python_engine/services/{service}/rules"""
        return base_path / "azure_compliance_python_engine" / "services" / service / "rules"
    
    def get_metadata_path(self, base_path: Path, service: str) -> Path:
        """Path: azure_compliance_python_engine/services/{service}/metadata"""
        return base_path / "azure_compliance_python_engine" / "services" / service / "metadata"
    
    def validate_rule_id(self, rule_id: str) -> bool:
        """Validate rule ID starts with 'azure.' and has at least 4 parts"""
        parts = rule_id.split(".")
        return len(parts) >= 4 and rule_id.startswith("azure.")
    
    def get_documentation_url(self, service: str) -> str:
        """Generate Azure documentation URL"""
        # Azure docs typically use service names like 'compute', 'storage', etc.
        service_clean = service.replace('_', '-').lower()
        return f"https://learn.microsoft.com/en-us/azure/{service_clean}/"

