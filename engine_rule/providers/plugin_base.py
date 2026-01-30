"""
Abstract base class for CSP provider adapters
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional


class CSPProvider(ABC):
    """Base class for all CSP providers"""
    
    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Provider identifier: 'aws', 'azure', 'gcp', etc."""
        pass
    
    @property
    @abstractmethod
    def display_name(self) -> str:
        """Human-readable name: 'Amazon Web Services'"""
        pass
    
    @abstractmethod
    def get_sdk_module_pattern(self) -> str:
        """
        SDK module pattern for YAML generation
        Examples:
        - AWS: 'boto3.client'
        - Azure: 'azure.mgmt.{service}.{Service}ManagementClient'
        - GCP: 'googleapiclient.discovery.build'
        """
        pass
    
    @abstractmethod
    def format_discovery_id(self, service: str, method: str) -> str:
        """
        Format discovery_id for this provider
        Examples:
        - AWS: 'aws.service.method'
        - Azure: 'azure.service.method'
        - GCP: 'gcp.service.method'
        """
        pass
    
    @abstractmethod
    def format_rule_id_prefix(self) -> str:
        """
        Rule ID prefix for this provider
        Examples:
        - AWS: 'aws.'
        - Azure: 'azure.'
        - GCP: 'gcp.'
        """
        pass
    
    @abstractmethod
    def get_dependencies_file_name(self) -> str:
        """
        Name of the dependencies file for this provider
        Examples:
        - AWS: 'boto3_dependencies_with_python_names_fully_enriched.json'
        - Azure: 'azure_dependencies_with_python_names_fully_enriched.json'
        - GCP: 'gcp_dependencies_with_python_names_fully_enriched.json'
        """
        pass
    
    @abstractmethod
    def get_database_path(self, base_path: Path) -> Path:
        """
        Path to provider's database directory
        Examples:
        - AWS: base_path / 'aws'
        - Azure: base_path / 'azure'
        """
        pass
    
    @abstractmethod
    def get_output_path(self, base_path: Path, service: str) -> Path:
        """
        Path to provider's output directory for rules
        Examples:
        - AWS: base_path / 'aws_compliance_python_engine' / 'services' / service / 'rules'
        - Azure: base_path / 'azure_compliance_python_engine' / 'services' / service / 'rules'
        """
        pass
    
    @abstractmethod
    def get_metadata_path(self, base_path: Path, service: str) -> Path:
        """
        Path to provider's metadata directory
        Examples:
        - AWS: base_path / 'aws_compliance_python_engine' / 'services' / service / 'metadata'
        """
        pass
    
    @abstractmethod
    def validate_rule_id(self, rule_id: str) -> bool:
        """
        Validate rule ID format for this provider
        Must start with provider prefix (e.g., 'aws.' for AWS)
        """
        pass
    
    @abstractmethod
    def get_documentation_url(self, service: str) -> str:
        """
        Generate documentation URL for service
        Examples:
        - AWS: 'https://docs.aws.amazon.com/{service}/latest/userguide/'
        - Azure: 'https://learn.microsoft.com/en-us/azure/{service}/'
        """
        pass

