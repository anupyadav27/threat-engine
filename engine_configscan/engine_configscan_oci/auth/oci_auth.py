"""
OCI Authentication Module

Handles authentication and client creation for Oracle Cloud Infrastructure services.
Supports:
- API Key authentication (config file)
- Instance Principal authentication
- Resource Principal authentication
"""

import os
import logging
from typing import Optional
import oci
from oci.config import from_file, validate_config
from oci.signer import Signer

logger = logging.getLogger('oci-auth')


class OCIAuth:
    """
    OCI Authentication Manager
    
    Environment Variables:
    - OCI_CONFIG_FILE: Path to OCI config file (default: ~/.oci/config)
    - OCI_CONFIG_PROFILE: Config profile to use (default: DEFAULT)
    - OCI_REGION: Override region
    - OCI_USE_INSTANCE_PRINCIPAL: Use instance principal (true/false)
    """
    
    def __init__(
        self,
        config_file: Optional[str] = None,
        profile: Optional[str] = None,
        region: Optional[str] = None,
        use_instance_principal: bool = False
    ):
        """
        Initialize OCI authentication
        
        Args:
            config_file: Path to OCI config file
            profile: Config profile name
            region: Override region
            use_instance_principal: Use instance principal authentication
        """
        self.config_file = config_file or os.getenv('OCI_CONFIG_FILE', '~/.oci/config')
        self.profile = profile or os.getenv('OCI_CONFIG_PROFILE', 'DEFAULT')
        self.region = region or os.getenv('OCI_REGION')
        self.use_instance_principal = use_instance_principal or os.getenv('OCI_USE_INSTANCE_PRINCIPAL', '').lower() == 'true'
        
        self.config = None
        self.signer = None
        
        self._initialize()
        
    def _initialize(self):
        """Initialize authentication"""
        try:
            if self.use_instance_principal:
                # Use instance principal authentication
                self.signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
                self.config = {}
                if self.region:
                    self.config['region'] = self.region
                logger.info("Initialized OCI with instance principal")
            else:
                # Use config file authentication
                self.config = from_file(
                    file_location=os.path.expanduser(self.config_file),
                    profile_name=self.profile
                )
                
                # Override region if specified
                if self.region:
                    self.config['region'] = self.region
                
                # Validate config
                validate_config(self.config)
                
                logger.info(f"Initialized OCI auth for region: {self.config.get('region')}")
                
        except Exception as e:
            logger.error(f"Failed to initialize OCI auth: {e}")
            raise ValueError(f"OCI authentication failed: {e}")
    
    def get_config(self) -> dict:
        """
        Get OCI configuration
        
        Returns:
            OCI config dictionary
        """
        return self.config
    
    def get_signer(self) -> Optional[Signer]:
        """
        Get OCI signer (for instance principal)
        
        Returns:
            OCI signer or None
        """
        return self.signer
    
    def get_identity_client(self):
        """Get Identity service client"""
        if self.signer:
            return oci.identity.IdentityClient(config={}, signer=self.signer)
        return oci.identity.IdentityClient(self.config)
    
    def get_compute_client(self):
        """Get Compute service client"""
        if self.signer:
            return oci.core.ComputeClient(config={}, signer=self.signer)
        return oci.core.ComputeClient(self.config)
    
    def get_object_storage_client(self):
        """Get Object Storage service client"""
        if self.signer:
            return oci.object_storage.ObjectStorageClient(config={}, signer=self.signer)
        return oci.object_storage.ObjectStorageClient(self.config)
    
    def get_database_client(self):
        """Get Database service client"""
        if self.signer:
            return oci.database.DatabaseClient(config={}, signer=self.signer)
        return oci.database.DatabaseClient(self.config)
    
    def get_virtual_network_client(self):
        """Get Virtual Network service client"""
        if self.signer:
            return oci.core.VirtualNetworkClient(config={}, signer=self.signer)
        return oci.core.VirtualNetworkClient(self.config)
    
    def get_block_storage_client(self):
        """Get Block Storage service client"""
        if self.signer:
            return oci.core.BlockstorageClient(config={}, signer=self.signer)
        return oci.core.BlockstorageClient(self.config)
    
    def get_audit_client(self):
        """Get Audit service client"""
        if self.signer:
            return oci.audit.AuditClient(config={}, signer=self.signer)
        return oci.audit.AuditClient(self.config)
    
    def get_key_management_client(self, vault_endpoint: str):
        """Get Key Management service client"""
        if self.signer:
            return oci.key_management.KmsVaultClient(config={}, signer=self.signer, service_endpoint=vault_endpoint)
        return oci.key_management.KmsVaultClient(self.config, service_endpoint=vault_endpoint)
    
    def get_monitoring_client(self):
        """Get Monitoring service client"""
        if self.signer:
            return oci.monitoring.MonitoringClient(config={}, signer=self.signer)
        return oci.monitoring.MonitoringClient(self.config)
    
    def get_container_engine_client(self):
        """Get Container Engine (OKE) client"""
        if self.signer:
            return oci.container_engine.ContainerEngineClient(config={}, signer=self.signer)
        return oci.container_engine.ContainerEngineClient(self.config)
    
    def list_regions(self) -> list:
        """
        Get list of available OCI regions
        
        Returns:
            List of region names
        """
        try:
            identity = self.get_identity_client()
            regions = identity.list_regions().data
            return [r.name for r in regions]
        except Exception as e:
            logger.warning(f"Failed to list regions: {e}")
            # Return common regions as fallback
            return [
                'us-ashburn-1',
                'us-phoenix-1',
                'eu-frankfurt-1',
                'uk-london-1',
                'ap-tokyo-1',
                'ap-mumbai-1'
            ]
    
    def list_compartments(self, tenancy_id: Optional[str] = None) -> list:
        """
        List compartments in the tenancy
        
        Args:
            tenancy_id: Tenancy OCID (defaults to config tenancy)
            
        Returns:
            List of compartment objects
        """
        try:
            identity = self.get_identity_client()
            tid = tenancy_id or self.config.get('tenancy')
            
            compartments = []
            # Add root compartment
            compartments.append({
                'id': tid,
                'name': 'root',
                'description': 'Root compartment'
            })
            
            # List child compartments
            response = identity.list_compartments(
                compartment_id=tid,
                compartment_id_in_subtree=True
            )
            
            for comp in response.data:
                if comp.lifecycle_state == 'ACTIVE':
                    compartments.append({
                        'id': comp.id,
                        'name': comp.name,
                        'description': comp.description
                    })
            
            return compartments
            
        except Exception as e:
            logger.error(f"Failed to list compartments: {e}")
            return []
    
    def test_connection(self) -> bool:
        """
        Test OCI connection by making a simple API call
        
        Returns:
            True if connection successful, False otherwise
        """
        try:
            identity = self.get_identity_client()
            user = identity.get_user(self.config.get('user')).data
            logger.info(f"OCI connection test successful - User: {user.name}")
            return True
        except Exception as e:
            logger.error(f"OCI connection test failed: {e}")
            return False


def get_oci_auth(
    config_file: Optional[str] = None,
    profile: Optional[str] = None,
    region: Optional[str] = None
) -> OCIAuth:
    """
    Convenience function to get OCI authentication
    
    Args:
        config_file: Path to OCI config file
        profile: Config profile name
        region: Override region
        
    Returns:
        OCIAuth instance
    """
    return OCIAuth(config_file, profile, region)

