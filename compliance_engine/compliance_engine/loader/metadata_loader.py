"""
Metadata Loader

Loads rule metadata files from rule_db and extracts compliance mappings.
"""

import yaml
import re
from pathlib import Path
from typing import Dict, List, Optional, Any
from ..mapper.framework_loader import FrameworkControl


class MetadataLoader:
    """Loads rule metadata and extracts compliance mappings."""
    
    def __init__(self, rule_db_path: Optional[Path] = None):
        """
        Initialize metadata loader.
        
        Args:
            rule_db_path: Base path to rule_db
                         Default: engines-input/aws-configScan-engine/input/rule_db/default/services
        """
        if rule_db_path is None:
            workspace_root = Path("/Users/apple/Desktop/threat-engine")
            rule_db_path = workspace_root / "engines-input" / "aws-configScan-engine" / "input" / "rule_db" / "default" / "services"
        
        self.rule_db_path = Path(rule_db_path)
        self._metadata_cache: Dict[str, Dict[str, Any]] = {}
        self._compliance_cache: Dict[str, List[FrameworkControl]] = {}
    
    def load_metadata_file(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """
        Load metadata file for a rule_id.
        
        Args:
            rule_id: Rule ID (e.g., aws.s3.bucket.block_public_access_enabled)
        
        Returns:
            Metadata dictionary or None if not found
        """
        if rule_id in self._metadata_cache:
            return self._metadata_cache[rule_id]
        
        # Extract service from rule_id: aws.s3.bucket.* -> s3
        parts = rule_id.split('.')
        if len(parts) < 2:
            return None
        
        service = parts[1]
        metadata_filename = f"{rule_id}.yaml"
        metadata_path = self.rule_db_path / service / "metadata" / metadata_filename
        
        if not metadata_path.exists():
            return None
        
        try:
            with open(metadata_path, 'r', encoding='utf-8') as f:
                metadata = yaml.safe_load(f)
                self._metadata_cache[rule_id] = metadata
                return metadata
        except Exception as e:
            print(f"Error loading metadata for {rule_id}: {e}")
            return None
    
    def parse_compliance_string(self, compliance_str: str) -> Optional[FrameworkControl]:
        """
        Parse compliance string to FrameworkControl.
        
        Formats:
        - cisa_ce_v1_multi_cloud_Your_Systems-3_0008
        - hipaa_multi_cloud_164_308_a_1_ii_b_0002
        - nist_800_171_r2_multi_cloud_3_13_2_3.13.2_Employ_architectural_designs_softw_0008
        - iso27001_2022_multi_cloud_A.8.3_0085
        
        Args:
            compliance_str: Compliance string from metadata
        
        Returns:
            FrameworkControl object or None
        """
        if not compliance_str:
            return None
        
        # Parse framework name and version
        framework = None
        framework_version = None
        control_id = None
        control_title = None
        
        # Pattern matching for different frameworks
        parts = compliance_str.split('_multi_cloud_')
        if len(parts) < 2:
            return None
        
        framework_part = parts[0]
        control_part = parts[1]
        
        # Extract framework name and version
        if framework_part.startswith('cisa_ce_v'):
            # cisa_ce_v1 -> CISA CE v1
            version_match = re.search(r'v(\d+)', framework_part)
            framework = "CISA Cybersecurity Essentials"
            framework_version = version_match.group(1) if version_match else None
        elif framework_part.startswith('hipaa'):
            # hipaa -> HIPAA
            framework = "HIPAA"
        elif framework_part.startswith('nist_800_171_r'):
            # nist_800_171_r2 -> NIST 800-171 Rev 2
            version_match = re.search(r'r(\d+)', framework_part)
            framework = "NIST 800-171"
            framework_version = f"Rev {version_match.group(1)}" if version_match else None
        elif framework_part.startswith('iso27001'):
            # iso27001_2022 -> ISO 27001:2022
            version_match = re.search(r'(\d{4})', framework_part)
            framework = "ISO 27001"
            framework_version = version_match.group(1) if version_match else None
        elif framework_part.startswith('pci'):
            framework = "PCI DSS"
        elif framework_part.startswith('gdpr'):
            framework = "GDPR"
        elif framework_part.startswith('rbi_bank'):
            framework = "RBI Bank"
        elif framework_part.startswith('cis'):
            framework = "CIS"
        else:
            # Try to extract framework name
            framework = framework_part.replace('_', ' ').title()
        
        # Extract control_id and title from control_part
        # Format: section_control_id_title_0008
        # Or: 3.13.2_3.13.2_Employ_architectural_designs_softw_0008
        control_parts = control_part.split('_')
        
        if len(control_parts) >= 2:
            # Try to find control ID (usually first part or contains dots/numbers)
            for part in control_parts:
                if re.match(r'^[\d\.]+$', part) or re.match(r'^[A-Z]\.[\d\.]+$', part):
                    control_id = part
                    break
                elif re.match(r'^\d+$', part) and len(part) >= 3:
                    # Might be a numeric control ID
                    control_id = part
                    break
            
            # If no control_id found, use first part
            if not control_id:
                control_id = control_parts[0]
            
            # Title is the rest (excluding the trailing number)
            title_parts = []
            for part in control_parts:
                if part != control_id and not part.isdigit() or len(part) < 3:
                    title_parts.append(part)
            control_title = ' '.join(title_parts) if title_parts else control_id
        
        if not framework or not control_id:
            return None
        
        return FrameworkControl(
            framework=framework,
            framework_version=framework_version,
            control_id=control_id,
            control_title=control_title or control_id,
            control_category=None
        )
    
    def get_compliance_mappings(self, rule_id: str) -> List[FrameworkControl]:
        """
        Get compliance framework mappings for a rule_id from metadata.
        
        Args:
            rule_id: Rule ID
        
        Returns:
            List of FrameworkControl objects
        """
        if rule_id in self._compliance_cache:
            return self._compliance_cache[rule_id]
        
        metadata = self.load_metadata_file(rule_id)
        if not metadata:
            return []
        
        compliance_list = metadata.get('compliance', [])
        if not compliance_list:
            return []
        
        controls = []
        for compliance_str in compliance_list:
            if isinstance(compliance_str, str):
                control = self.parse_compliance_string(compliance_str)
                if control:
                    controls.append(control)
        
        self._compliance_cache[rule_id] = controls
        return controls
    
    def load_all_metadata_mappings(self, csp: str = "aws") -> Dict[str, List[FrameworkControl]]:
        """
        Load all rule metadata mappings for a CSP.
        
        Args:
            csp: Cloud service provider
        
        Returns:
            Dictionary mapping rule_id to list of FrameworkControl objects
        """
        mappings: Dict[str, List[FrameworkControl]] = {}
        
        if not self.rule_db_path.exists():
            return mappings
        
        # Iterate through all services
        for service_dir in self.rule_db_path.iterdir():
            if not service_dir.is_dir():
                continue
            
            metadata_dir = service_dir / "metadata"
            if not metadata_dir.exists():
                continue
            
            # Load all metadata files
            for metadata_file in metadata_dir.glob("*.yaml"):
                rule_id = metadata_file.stem  # filename without .yaml
                controls = self.get_compliance_mappings(rule_id)
                if controls:
                    mappings[rule_id] = controls
        
        return mappings
