"""
Database Rule Mapper

Maps rule_ids to compliance frameworks using rule_metadata.compliance_frameworks
from the check database. Replaces CSV file-based mapping with database-driven approach.
"""

import os
import psycopg2
from psycopg2.extras import RealDictCursor
from typing import Dict, List, Optional, Any
from dataclasses import dataclass


@dataclass
class FrameworkControl:
    """Represents a compliance framework control."""
    framework: str
    framework_version: Optional[str]
    control_id: str
    control_title: str
    control_category: Optional[str] = None
    control_description: Optional[str] = None


def _check_db_connection_string() -> str:
    """Build Check DB connection string."""
    host = os.getenv("CHECK_DB_HOST", "localhost")
    port = os.getenv("CHECK_DB_PORT", "5432")
    db = os.getenv("CHECK_DB_NAME", "threat_engine_check")
    user = os.getenv("CHECK_DB_USER", "check_user")
    pwd = os.getenv("CHECK_DB_PASSWORD", "check_password")
    return f"postgresql://{user}:{pwd}@{host}:{port}/{db}"


class DatabaseRuleMapper:
    """
    Maps rule_ids to compliance framework controls using rule_metadata table.
    
    Reads from: threat_engine_check.rule_metadata.compliance_frameworks (JSONB array)
    
    Example compliance_frameworks value:
    ["cis_aws_3.0_1.2.1", "pci_dss_v4_multi_cloud_10.2.1.3_0146"]
    """
    
    def __init__(self, db_url: Optional[str] = None):
        if db_url is None:
            db_url = _check_db_connection_string()
        self.db_url = db_url
        self._cache: Dict[str, List[FrameworkControl]] = {}
    
    def get_controls_for_rule(self, rule_id: str) -> List[FrameworkControl]:
        """
        Get compliance framework controls for a rule_id from database.
        
        Args:
            rule_id: Rule identifier
        
        Returns:
            List of FrameworkControl objects
        """
        # Check cache first
        if rule_id in self._cache:
            return self._cache[rule_id]
        
        controls = []
        
        try:
            conn = psycopg2.connect(self.db_url)
            
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT 
                        rule_id,
                        compliance_frameworks,
                        title,
                        description,
                        domain,
                        subcategory
                    FROM rule_metadata
                    WHERE rule_id = %s
                """, (rule_id,))
                row = cur.fetchone()
            
            conn.close()
            
            if not row or not row['compliance_frameworks']:
                self._cache[rule_id] = []
                return []
            
            # Parse compliance_frameworks JSONB array
            frameworks = row['compliance_frameworks']
            if not isinstance(frameworks, list):
                self._cache[rule_id] = []
                return []
            
            # Each framework ID format: "cis_aws_3.0_1.2.1" or "pci_dss_v4_multi_cloud_10.2.1.3_0146"
            for fw_id in frameworks:
                if not fw_id:
                    continue
                
                # Parse framework ID
                parts = fw_id.split('_')
                
                # Extract framework name and version
                if fw_id.startswith('cis_'):
                    # cis_aws_3.0_1.2.1
                    framework_name = 'CIS'
                    version = parts[2] if len(parts) > 2 else None
                    control_id = '_'.join(parts[3:]) if len(parts) > 3 else fw_id
                elif fw_id.startswith('pci_dss'):
                    # pci_dss_v4_multi_cloud_10.2.1.3_0146
                    framework_name = 'PCI-DSS'
                    version = parts[2] if len(parts) > 2 else None
                    control_id = '_'.join(parts[4:]) if len(parts) > 4 else fw_id
                elif fw_id.startswith('iso27001'):
                    # iso27001_2022_multi_cloud_A.8.14_0069
                    framework_name = 'ISO27001'
                    version = parts[1] if len(parts) > 1 else None
                    control_id = '_'.join(parts[3:]) if len(parts) > 3 else fw_id
                elif fw_id.startswith('soc2'):
                    # soc2_multi_cloud_a1_1_0024
                    framework_name = 'SOC2'
                    version = None
                    control_id = '_'.join(parts[2:]) if len(parts) > 2 else fw_id
                elif fw_id.startswith('nist'):
                    # nist_csf_multi_cloud_PR.AC-1_0012
                    framework_name = 'NIST-CSF'
                    version = None
                    control_id = '_'.join(parts[3:]) if len(parts) > 3 else fw_id
                elif fw_id.startswith('hipaa'):
                    framework_name = 'HIPAA'
                    version = None
                    control_id = '_'.join(parts[2:]) if len(parts) > 2 else fw_id
                else:
                    # Generic fallback
                    framework_name = parts[0].upper()
                    version = None
                    control_id = fw_id
                
                control = FrameworkControl(
                    framework=framework_name,
                    framework_version=version,
                    control_id=control_id,
                    control_title=row['title'] or control_id,
                    control_category=row['domain'] or row['subcategory'],
                    control_description=row['description']
                )
                controls.append(control)
            
            self._cache[rule_id] = controls
            
        except Exception:
            self._cache[rule_id] = []
        
        return controls
    
    def get_all_rule_mappings(self, csp: str = 'aws') -> Dict[str, List[FrameworkControl]]:
        """
        Load all rule-to-framework mappings for a CSP from database.
        
        Args:
            csp: Cloud service provider (aws, azure, gcp)
        
        Returns:
            Dictionary mapping rule_id → List[FrameworkControl]
        """
        mappings: Dict[str, List[FrameworkControl]] = {}
        
        try:
            conn = psycopg2.connect(self.db_url)
            
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT 
                        rule_id,
                        compliance_frameworks,
                        title,
                        description,
                        domain,
                        subcategory
                    FROM rule_metadata
                    WHERE provider = %s 
                      AND compliance_frameworks IS NOT NULL
                      AND jsonb_array_length(compliance_frameworks) > 0
                """, (csp,))
                
                rows = cur.fetchall()
            
            conn.close()
            
            # Process each rule
            for row in rows:
                rule_id = row['rule_id']
                controls = []
                
                frameworks = row['compliance_frameworks'] or []
                
                for fw_id in frameworks:
                    if not fw_id:
                        continue
                    
                    # Parse framework ID (same logic as above)
                    parts = fw_id.split('_')
                    
                    if fw_id.startswith('cis_'):
                        framework_name = 'CIS'
                        version = parts[2] if len(parts) > 2 else None
                        control_id = '_'.join(parts[3:]) if len(parts) > 3 else fw_id
                    elif fw_id.startswith('pci_dss'):
                        framework_name = 'PCI-DSS'
                        version = parts[2] if len(parts) > 2 else None
                        control_id = '_'.join(parts[4:]) if len(parts) > 4 else fw_id
                    elif fw_id.startswith('iso27001'):
                        framework_name = 'ISO27001'
                        version = parts[1] if len(parts) > 1 else None
                        control_id = '_'.join(parts[3:]) if len(parts) > 3 else fw_id
                    elif fw_id.startswith('soc2'):
                        framework_name = 'SOC2'
                        version = None
                        control_id = '_'.join(parts[2:]) if len(parts) > 2 else fw_id
                    elif fw_id.startswith('nist'):
                        framework_name = 'NIST-CSF'
                        version = None
                        control_id = '_'.join(parts[3:]) if len(parts) > 3 else fw_id
                    elif fw_id.startswith('hipaa'):
                        framework_name = 'HIPAA'
                        version = None
                        control_id = '_'.join(parts[2:]) if len(parts) > 2 else fw_id
                    else:
                        framework_name = parts[0].upper()
                        version = None
                        control_id = fw_id
                    
                    controls.append(FrameworkControl(
                        framework=framework_name,
                        framework_version=version,
                        control_id=control_id,
                        control_title=row['title'] or control_id,
                        control_category=row['domain'] or row['subcategory'],
                        control_description=row['description']
                    ))
                
                if controls:
                    mappings[rule_id] = controls
            
        except Exception as e:
            print(f"Failed to load rule mappings from database: {e}")
        
        return mappings
    
    def get_frameworks_covered(self, csp: str = 'aws') -> List[Dict[str, Any]]:
        """
        Get list of unique frameworks with rule counts.
        
        Returns:
            List of {framework, version, rule_count}
        """
        try:
            conn = psycopg2.connect(self.db_url)
            
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT 
                        jsonb_array_elements_text(compliance_frameworks) as framework_id,
                        COUNT(DISTINCT rule_id) as rule_count
                    FROM rule_metadata
                    WHERE provider = %s
                      AND compliance_frameworks IS NOT NULL
                      AND jsonb_array_length(compliance_frameworks) > 0
                    GROUP BY framework_id
                    ORDER BY rule_count DESC
                """, (csp,))
                
                rows = cur.fetchall()
            
            conn.close()
            
            # Group by framework name
            framework_summary = {}
            for row in rows:
                fw_id = row['framework_id']
                
                # Extract framework name
                if fw_id.startswith('cis_'):
                    fw_name = 'CIS'
                elif fw_id.startswith('pci_dss'):
                    fw_name = 'PCI-DSS'
                elif fw_id.startswith('iso27001'):
                    fw_name = 'ISO27001'
                elif fw_id.startswith('soc2'):
                    fw_name = 'SOC2'
                elif fw_id.startswith('nist'):
                    fw_name = 'NIST-CSF'
                elif fw_id.startswith('hipaa'):
                    fw_name = 'HIPAA'
                else:
                    fw_name = fw_id.split('_')[0].upper()
                
                if fw_name not in framework_summary:
                    framework_summary[fw_name] = 0
                framework_summary[fw_name] += row['rule_count']
            
            return [
                {'framework': k, 'rule_count': v}
                for k, v in sorted(framework_summary.items(), key=lambda x: x[1], reverse=True)
            ]
            
        except Exception:
            return []
