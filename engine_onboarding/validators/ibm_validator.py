"""
IBM credential validator
"""
from typing import Dict, Any
from engine_onboarding.validators.base_validator import BaseValidator, ValidationResult

try:
    from ibm_cloud_sdk_core.authenticators import IAMAuthenticator
    from ibm_platform_services import ResourceControllerV2
    IBM_AVAILABLE = True
except ImportError:
    IBM_AVAILABLE = False


class IBMValidator(BaseValidator):
    """Validator for IBM credentials"""
    
    async def validate(self, credentials: Dict[str, Any]) -> ValidationResult:
        """
        Validate IBM credentials
        
        Supports:
        - ibm_api_key: api_key
        """
        if not IBM_AVAILABLE:
            return self._create_error_result(
                "IBM SDK not available",
                ["Install ibm-cloud-sdk-core and ibm-platform-services"]
            )
        
        credential_type = credentials.get('credential_type')
        
        if credential_type == 'ibm_api_key':
            return await self._validate_api_key(credentials)
        else:
            return self._create_error_result(
                f"Unsupported IBM credential type: {credential_type}",
                ["Supported types: ibm_api_key"]
            )
    
    async def _validate_api_key(self, credentials: Dict[str, Any]) -> ValidationResult:
        """Validate IBM API Key credentials"""
        try:
            api_key = credentials.get('api_key')
            
            if not api_key:
                return self._create_error_result(
                    "Missing required field",
                    ["api_key is required"]
                )
            
            # Create authenticator
            authenticator = IAMAuthenticator(api_key=api_key)
            
            # Test by getting resource controller
            resource_controller = ResourceControllerV2(authenticator=authenticator)
            
            # Try to list resource groups (simple test)
            resource_groups = resource_controller.list_resource_groups()
            
            return self._create_success_result(
                "IBM API key validated successfully"
            )
            
        except Exception as e:
            return self._create_error_result(
                f"IBM Error: {str(e)}",
                [str(e)]
            )

