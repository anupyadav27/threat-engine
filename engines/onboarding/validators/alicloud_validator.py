"""
AliCloud credential validator
"""
from typing import Dict, Any
from engine_onboarding.validators.base_validator import BaseValidator, ValidationResult

try:
    from alicloud_compliance_python_engine.auth.alicloud_auth import AliCloudAuth
    ALICLOUD_AVAILABLE = True
except ImportError:
    ALICLOUD_AVAILABLE = False


class AliCloudValidator(BaseValidator):
    """Validator for AliCloud credentials"""
    
    async def validate(self, credentials: Dict[str, Any]) -> ValidationResult:
        """
        Validate AliCloud credentials
        
        Supports:
        - alicloud_access_key: access_key_id, access_key_secret
        """
        if not ALICLOUD_AVAILABLE:
            return self._create_error_result(
                "AliCloud SDK not available",
                ["Install alicloud_compliance_python_engine dependencies"]
            )
        
        credential_type = credentials.get('credential_type')
        
        if credential_type == 'alicloud_access_key':
            return await self._validate_access_key(credentials)
        else:
            return self._create_error_result(
                f"Unsupported AliCloud credential type: {credential_type}",
                ["Supported types: alicloud_access_key"]
            )
    
    async def _validate_access_key(self, credentials: Dict[str, Any]) -> ValidationResult:
        """Validate AliCloud Access Key credentials"""
        try:
            access_key_id = credentials.get('access_key_id')
            access_key_secret = credentials.get('access_key_secret')
            
            if not access_key_id or not access_key_secret:
                return self._create_error_result(
                    "Missing required fields",
                    ["access_key_id and access_key_secret are required"]
                )
            
            # Create auth object
            auth = AliCloudAuth(
                access_key_id=access_key_id,
                access_key_secret=access_key_secret
            )
            
            # Test connection
            if auth.test_connection():
                return self._create_success_result(
                    "AliCloud access key validated successfully"
                )
            else:
                return self._create_error_result(
                    "Connection test failed",
                    ["Unable to connect to AliCloud with provided credentials"]
                )
            
        except Exception as e:
            return self._create_error_result(
                f"AliCloud Error: {str(e)}",
                [str(e)]
            )

