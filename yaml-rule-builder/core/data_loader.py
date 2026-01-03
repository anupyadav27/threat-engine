"""
Data loader for JSON files
"""

import json
from pathlib import Path
from typing import Dict, Optional
try:
    from ..config import Config
except ImportError:
    from config import Config

class DataLoader:
    """Loads and caches JSON data files"""
    
    def __init__(self, config: Config):
        self.config = config
        self._cache: Dict[str, Dict] = {}
    
    def load_service_data(self, service_name: str) -> Dict:
        """Load all required JSON files for a service"""
        if service_name in self._cache:
            return self._cache[service_name]
        
        service_path = self.config.get_service_path(service_name)
        
        if not service_path.exists():
            raise FileNotFoundError(f"Service directory not found: {service_path}")
        
        data = {
            "direct_vars": self._load_json(service_path / "direct_vars.json"),
            "dependency_index": self._load_json(service_path / "dependency_index.json"),
            "boto3_deps": self._load_json(
                service_path / "boto3_dependencies_with_python_names_fully_enriched.json"
            )
        }
        
        # Validate required keys - try service name as key
        service_key = service_name
        if service_key not in data["boto3_deps"]:
            # Try to find the key (case-insensitive or alternative naming)
            for key in data["boto3_deps"].keys():
                if key.lower() == service_name.lower():
                    service_key = key
                    break
        
        if service_key not in data["boto3_deps"]:
            raise ValueError(f"Service '{service_name}' not found in boto3_deps. Available: {list(data['boto3_deps'].keys())[:5]}")
        
        self._cache[service_name] = data
        return data
    
    def _load_json(self, file_path: Path) -> Dict:
        """Load JSON file"""
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def clear_cache(self):
        """Clear the cache"""
        self._cache.clear()

