"""
IBM Cloud Authentication Module

Handles authentication for IBM Cloud services.
Supports:
- API Key authentication
- IAM Token authentication
"""

import os
import logging
from typing import Optional
from ibm_cloud_sdk_core.authenticators import IAMAuthenticator
from ibm_platform_services import IamIdentityV1, ResourceControllerV2
from ibm_vpc import VpcV1

logger = logging.getLogger('ibm-auth')


class IBMCloudAuth:
    """
    IBM Cloud Authentication Manager
    
    Environment Variables:
    - IBM_CLOUD_API_KEY: API key for authentication
    - IBM_CLOUD_REGION: Region (default: us-south)
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        region: Optional[str] = None
    ):
        """
        Initialize IBM Cloud authentication
        
        Args:
            api_key: IBM Cloud API key
            region: IBM Cloud region
        """
        self.api_key = api_key or os.getenv('IBM_CLOUD_API_KEY')
        self.region = region or os.getenv('IBM_CLOUD_REGION', 'us-south')
        
        if not self.api_key:
            raise ValueError(
                "IBM Cloud API key not found. Set IBM_CLOUD_API_KEY environment variable."
            )
        
        self.authenticator = IAMAuthenticator(self.api_key)
        logger.info(f"Initialized IBM Cloud auth for region: {self.region}")
    
    def get_authenticator(self) -> IAMAuthenticator:
        """Get IAM authenticator"""
        return self.authenticator
    
    def get_iam_identity_service(self) -> IamIdentityV1:
        """Get IAM Identity service"""
        service = IamIdentityV1(authenticator=self.authenticator)
        return service
    
    def get_resource_controller_service(self) -> ResourceControllerV2:
        """Get Resource Controller service"""
        service = ResourceControllerV2(authenticator=self.authenticator)
        return service
    
    def get_vpc_service(self) -> VpcV1:
        """Get VPC service"""
        service = VpcV1(authenticator=self.authenticator)
        service.set_service_url(f'https://{self.region}.iaas.cloud.ibm.com/v1')
        return service
    
    def list_regions(self) -> list:
        """Get list of IBM Cloud regions"""
        return [
            'us-south',      # Dallas
            'us-east',       # Washington DC
            'eu-gb',         # London
            'eu-de',         # Frankfurt
            'jp-tok',        # Tokyo
            'jp-osa',        # Osaka
            'au-syd',        # Sydney
            'ca-tor',        # Toronto
            'br-sao',        # São Paulo
        ]
    
    def test_connection(self) -> bool:
        """
        Test IBM Cloud connection
        
        Returns:
            True if successful
        """
        try:
            iam_service = self.get_iam_identity_service()
            api_keys = iam_service.list_api_keys().get_result()
            logger.info("IBM Cloud connection test successful")
            return True
        except Exception as e:
            logger.error(f"IBM Cloud connection test failed: {e}")
            return False


def get_ibm_auth(
    api_key: Optional[str] = None,
    region: Optional[str] = None
) -> IBMCloudAuth:
    """
    Convenience function to get IBM Cloud authentication
    
    Args:
        api_key: IBM Cloud API key
        region: IBM Cloud region
        
    Returns:
        IBMCloudAuth instance
    """
    return IBMCloudAuth(api_key, region)

