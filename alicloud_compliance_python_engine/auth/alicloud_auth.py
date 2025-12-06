"""
AliCloud Authentication Module

Handles authentication and client creation for Alibaba Cloud services.
Supports:
- AccessKey/SecretKey from environment variables
- RAM Role credentials
- STS temporary credentials
"""

import os
import logging
from typing import Optional, Dict, Any
from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.auth.credentials import (
    AccessKeyCredential,
    StsTokenCredential,
    RamRoleArnCredential
)
from aliyunsdkcore.acs_exception.exceptions import ClientException, ServerException

logger = logging.getLogger('alicloud-auth')


class AliCloudAuth:
    """
    AliCloud Authentication Manager
    
    Environment Variables:
    - ALIBABA_CLOUD_ACCESS_KEY_ID: Access Key ID
    - ALIBABA_CLOUD_ACCESS_KEY_SECRET: Access Key Secret
    - ALIBABA_CLOUD_REGION: Default region (default: cn-hangzhou)
    - ALIBABA_CLOUD_SECURITY_TOKEN: STS token (optional)
    - ALIBABA_CLOUD_ROLE_ARN: RAM role ARN for role assumption (optional)
    """
    
    def __init__(
        self,
        access_key_id: Optional[str] = None,
        access_key_secret: Optional[str] = None,
        region: Optional[str] = None,
        security_token: Optional[str] = None,
        role_arn: Optional[str] = None
    ):
        """
        Initialize AliCloud authentication
        
        Args:
            access_key_id: Access Key ID (defaults to env var)
            access_key_secret: Access Key Secret (defaults to env var)
            region: Region (defaults to cn-hangzhou)
            security_token: STS token (optional)
            role_arn: RAM role ARN for role assumption (optional)
        """
        self.access_key_id = access_key_id or os.getenv('ALIBABA_CLOUD_ACCESS_KEY_ID')
        self.access_key_secret = access_key_secret or os.getenv('ALIBABA_CLOUD_ACCESS_KEY_SECRET')
        self.region = region or os.getenv('ALIBABA_CLOUD_REGION', 'cn-hangzhou')
        self.security_token = security_token or os.getenv('ALIBABA_CLOUD_SECURITY_TOKEN')
        self.role_arn = role_arn or os.getenv('ALIBABA_CLOUD_ROLE_ARN')
        
        if not self.access_key_id or not self.access_key_secret:
            raise ValueError(
                "AliCloud credentials not found. Set ALIBABA_CLOUD_ACCESS_KEY_ID "
                "and ALIBABA_CLOUD_ACCESS_KEY_SECRET environment variables."
            )
        
        logger.info(f"Initialized AliCloud auth for region: {self.region}")
    
    def get_client(self, region: Optional[str] = None) -> AcsClient:
        """
        Create an AliCloud client for API calls
        
        Args:
            region: Region to use (defaults to instance region)
            
        Returns:
            AcsClient instance
        """
        target_region = region or self.region
        
        try:
            if self.security_token:
                # Use STS token credentials
                credential = StsTokenCredential(
                    self.access_key_id,
                    self.access_key_secret,
                    self.security_token
                )
                client = AcsClient(
                    region_id=target_region,
                    credential=credential
                )
            elif self.role_arn:
                # Assume RAM role
                credential = RamRoleArnCredential(
                    self.access_key_id,
                    self.access_key_secret,
                    self.role_arn,
                    "compliance-engine-session"
                )
                client = AcsClient(
                    region_id=target_region,
                    credential=credential
                )
            else:
                # Use access key credentials
                client = AcsClient(
                    ak=self.access_key_id,
                    secret=self.access_key_secret,
                    region_id=target_region
                )
            
            logger.debug(f"Created AliCloud client for region: {target_region}")
            return client
            
        except (ClientException, ServerException) as e:
            logger.error(f"Failed to create AliCloud client: {e}")
            raise
    
    def get_regions(self) -> list:
        """
        Get list of available AliCloud regions
        
        Returns:
            List of region IDs
        """
        # Common AliCloud regions
        return [
            'cn-hangzhou',     # China (Hangzhou)
            'cn-shanghai',     # China (Shanghai)
            'cn-beijing',      # China (Beijing)
            'cn-shenzhen',     # China (Shenzhen)
            'cn-qingdao',      # China (Qingdao)
            'cn-zhangjiakou',  # China (Zhangjiakou)
            'cn-huhehaote',    # China (Hohhot)
            'cn-hongkong',     # China (Hong Kong)
            'ap-southeast-1',  # Singapore
            'ap-southeast-2',  # Australia (Sydney)
            'ap-southeast-3',  # Malaysia (Kuala Lumpur)
            'ap-southeast-5',  # Indonesia (Jakarta)
            'ap-south-1',      # India (Mumbai)
            'ap-northeast-1',  # Japan (Tokyo)
            'us-west-1',       # US (Silicon Valley)
            'us-east-1',       # US (Virginia)
            'eu-central-1',    # Germany (Frankfurt)
            'eu-west-1',       # UK (London)
            'me-east-1',       # UAE (Dubai)
        ]
    
    def test_connection(self) -> bool:
        """
        Test AliCloud connection by making a simple API call
        
        Returns:
            True if connection successful, False otherwise
        """
        try:
            from aliyunsdkecs.request.v20140526 import DescribeRegionsRequest
            
            client = self.get_client()
            request = DescribeRegionsRequest.DescribeRegionsRequest()
            response = client.do_action_with_exception(request)
            
            logger.info("AliCloud connection test successful")
            return True
            
        except Exception as e:
            logger.error(f"AliCloud connection test failed: {e}")
            return False


def get_alicloud_client(region: Optional[str] = None) -> AcsClient:
    """
    Convenience function to get an AliCloud client
    
    Args:
        region: Region to use (defaults to env var or cn-hangzhou)
        
    Returns:
        AcsClient instance
    """
    auth = AliCloudAuth()
    return auth.get_client(region)


def get_all_regions() -> list:
    """
    Get list of all AliCloud regions
    
    Returns:
        List of region IDs
    """
    auth = AliCloudAuth()
    return auth.get_regions()

