"""
Configuration management for YAML Rule Builder
"""

from pathlib import Path
from typing import Optional
import os

class Config:
    """Configuration settings"""
    
    def __init__(self, pythonsdk_base: Optional[Path] = None):
        # Default paths
        self.project_root = Path(__file__).parent.parent
        self.pythonsdk_base = pythonsdk_base or (self.project_root / "pythonsdk-database" / "aws")
        self.output_dir = self.project_root / "aws_compliance_python_engine" / "services"
        
        # Validate paths
        if not self.pythonsdk_base.exists():
            raise FileNotFoundError(f"PythonSDK base directory not found: {self.pythonsdk_base}")
    
    def get_service_path(self, service_name: str) -> Path:
        """Get path to service directory"""
        return self.pythonsdk_base / service_name
    
    def get_output_path(self, service_name: str) -> Path:
        """Get output path for generated YAML"""
        return self.output_dir / service_name / "rules"
    
    def validate_service(self, service_name: str) -> bool:
        """Check if service exists"""
        service_path = self.get_service_path(service_name)
        required_files = [
            "direct_vars.json",
            "dependency_index.json",
            "boto3_dependencies_with_python_names_fully_enriched.json"
        ]
        return all((service_path / f).exists() for f in required_files)

