"""
OCI credential validator
"""
from typing import Dict, Any
from engine_onboarding.validators.base_validator import BaseValidator, ValidationResult

try:
    import oci
    OCI_AVAILABLE = True
except ImportError:
    OCI_AVAILABLE = False


class OCIValidator(BaseValidator):
    """Validator for OCI credentials"""
    
    async def validate(self, credentials: Dict[str, Any]) -> ValidationResult:
        """
        Validate OCI credentials
        
        Supports:
        - oci_user_principal: user_ocid, tenancy_ocid, fingerprint, private_key, region
        """
        if not OCI_AVAILABLE:
            return self._create_error_result(
                "OCI SDK not available",
                ["Install oci package"]
            )
        
        credential_type = credentials.get('credential_type')
        
        if credential_type == 'oci_user_principal':
            return await self._validate_user_principal(credentials)
        else:
            return self._create_error_result(
                f"Unsupported OCI credential type: {credential_type}",
                ["Supported types: oci_user_principal"]
            )
    
    async def _validate_user_principal(self, credentials: Dict[str, Any]) -> ValidationResult:
        """Validate OCI User Principal credentials"""
        try:
            user_ocid = credentials.get('user_ocid')
            tenancy_ocid = credentials.get('tenancy_ocid')
            fingerprint = credentials.get('fingerprint')
            private_key = credentials.get('private_key')
            region = credentials.get('region')
            
            if not all([user_ocid, tenancy_ocid, fingerprint, private_key, region]):
                return self._create_error_result(
                    "Missing required fields",
                    ["user_ocid, tenancy_ocid, fingerprint, private_key, and region are required"]
                )
            
            # Create config
            config = {
                "user": user_ocid,
                "key_file": None,
                "fingerprint": fingerprint,
                "tenancy": tenancy_ocid,
                "region": region
            }
            
            # Create signer with private key
            signer = oci.signer.Signer(
                config,
                private_key_content=private_key
            )
            
            # Test by getting identity
            identity_client = oci.identity.IdentityClient(config, signer=signer)
            user = identity_client.get_user(user_id=user_ocid)
            
            return self._create_success_result(
                "OCI user principal validated successfully",
                account_number=tenancy_ocid
            )
            
        except Exception as e:
            return self._create_error_result(
                f"OCI Error: {str(e)}",
                [str(e)]
            )

