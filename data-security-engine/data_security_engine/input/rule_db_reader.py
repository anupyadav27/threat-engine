"""
Read enriched metadata from rule database.

The rule database is located at:
engines-input/aws-configScan-engine/input/rule_db/default/services/
"""

import yaml
import json
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
import logging

logger = logging.getLogger(__name__)


class RuleDBReader:
    """Reads enriched metadata from the rule database."""
    
    def __init__(self, rule_db_path: Optional[str] = None):
        """
        Initialize rule database reader.
        
        Args:
            rule_db_path: Path to rule database root.
                        Default: engines-input/aws-configScan-engine/input/rule_db
        """
        if rule_db_path is None:
            # Default path relative to threat-engine root
            base_path = Path(__file__).parent.parent.parent.parent
            self.rule_db_path = base_path / "engines-input" / "aws-configScan-engine" / "input" / "rule_db"
        else:
            self.rule_db_path = Path(rule_db_path)
        
        if not self.rule_db_path.exists():
            raise ValueError(f"Rule database path does not exist: {self.rule_db_path}")
    
    def get_metadata_path(self, service: str, rule_id: str) -> Path:
        """Get path to metadata file for a rule."""
        metadata_dir = self.rule_db_path / "default" / "services" / service / "metadata"
        metadata_file = metadata_dir / f"{rule_id}.yaml"
        return metadata_file
    
    def read_metadata(self, service: str, rule_id: str) -> Optional[Dict[str, Any]]:
        """
        Read metadata for a specific rule.
        
        Args:
            service: Service name (e.g., 's3', 'rds')
            rule_id: Rule ID (e.g., 'aws.s3.bucket.encryption_at_rest_enabled')
            
        Returns:
            Metadata dictionary or None if not found
        """
        metadata_file = self.get_metadata_path(service, rule_id)
        
        if not metadata_file.exists():
            logger.warning(f"Metadata file not found: {metadata_file}")
            return None
        
        try:
            with open(metadata_file, 'r') as f:
                metadata = yaml.safe_load(f)
            return metadata
        except Exception as e:
            logger.error(f"Error reading metadata file {metadata_file}: {e}")
            return None
    
    def get_data_security_info(self, service: str, rule_id: str) -> Optional[Dict[str, Any]]:
        """
        Get data_security section from metadata for a rule.
        
        Args:
            service: Service name
            rule_id: Rule ID
            
        Returns:
            data_security dictionary or None
        """
        metadata = self.read_metadata(service, rule_id)
        if not metadata:
            return None
        
        return metadata.get("data_security")
    
    def is_data_security_relevant(self, service: str, rule_id: str) -> bool:
        """
        Check if a rule is relevant for data security.
        
        Args:
            service: Service name
            rule_id: Rule ID
            
        Returns:
            True if rule has data_security section
        """
        data_security = self.get_data_security_info(service, rule_id)
        return data_security is not None and data_security.get("applicable", False)
    
    def get_rules_by_module(self, service: str, module: str) -> List[str]:
        """
        Get all rule IDs for a service that belong to a specific data security module.
        
        Args:
            service: Service name
            module: Data security module (e.g., 'data_protection_encryption')
            
        Returns:
            List of rule IDs
        """
        metadata_dir = self.rule_db_path / "default" / "services" / service / "metadata"
        if not metadata_dir.exists():
            return []
        
        matching_rules = []
        
        for metadata_file in metadata_dir.glob("*.yaml"):
            try:
                with open(metadata_file, 'r') as f:
                    metadata = yaml.safe_load(f)
                
                data_security = metadata.get("data_security", {})
                if data_security.get("applicable") and module in data_security.get("modules", []):
                    rule_id = metadata.get("rule_id")
                    if rule_id:
                        matching_rules.append(rule_id)
            except Exception as e:
                logger.warning(f"Error reading {metadata_file}: {e}")
        
        return sorted(matching_rules)
    
    def list_services(self) -> List[str]:
        """List all services in the rule database."""
        services_dir = self.rule_db_path / "default" / "services"
        if not services_dir.exists():
            return []
        
        return sorted([d.name for d in services_dir.iterdir() if d.is_dir() and (d / "metadata").exists()])
    
    def get_all_data_security_rules(self, service: str) -> Dict[str, Dict[str, Any]]:
        """
        Get all data security relevant rules for a service.
        
        Args:
            service: Service name
            
        Returns:
            Dictionary mapping rule_id to data_security info
        """
        metadata_dir = self.rule_db_path / "default" / "services" / service / "metadata"
        if not metadata_dir.exists():
            return {}
        
        rules = {}
        
        for metadata_file in metadata_dir.glob("*.yaml"):
            try:
                with open(metadata_file, 'r') as f:
                    metadata = yaml.safe_load(f)
                
                rule_id = metadata.get("rule_id")
                data_security = metadata.get("data_security")
                
                if rule_id and data_security and data_security.get("applicable"):
                    rules[rule_id] = data_security
            except Exception as e:
                logger.warning(f"Error reading {metadata_file}: {e}")
        
        return rules
    
    def get_all_data_security_rule_ids(self, services: Optional[List[str]] = None) -> Set[str]:
        """
        Get set of all data security relevant rule IDs across services.
        
        This is used to pre-filter findings - only process findings with these rule IDs.
        
        Args:
            services: List of services to check (default: all services in rule_db)
            
        Returns:
            Set of rule IDs that are data security relevant
        """
        if services is None:
            services = self.list_services()
        
        rule_ids = set()
        
        for service in services:
            service_rules = self.get_all_data_security_rules(service)
            rule_ids.update(service_rules.keys())
        
        logger.info(f"Found {len(rule_ids)} data security relevant rule IDs across {len(services)} services")
        return rule_ids


# Convenience functions
def get_rule_metadata(service: str, rule_id: str, rule_db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Get metadata for a rule."""
    reader = RuleDBReader(rule_db_path)
    return reader.read_metadata(service, rule_id)


def get_data_security_modules(service: str, rule_id: str, rule_db_path: Optional[str] = None) -> List[str]:
    """Get data security modules for a rule."""
    reader = RuleDBReader(rule_db_path)
    data_security = reader.get_data_security_info(service, rule_id)
    if data_security:
        return data_security.get("modules", [])
    return []

