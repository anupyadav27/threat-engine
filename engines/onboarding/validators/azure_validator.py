"""
Azure credential validator
"""
from typing import Dict, Any
from azure.identity import ClientSecretCredential
from azure.mgmt.subscription import SubscriptionClient
from azure.core.exceptions import AzureError
from engine_onboarding.validators.base_validator import BaseValidator, ValidationResult


class AzureValidator(BaseValidator):
    """Validator for Azure credentials"""
    
    async def validate(self, credentials: Dict[str, Any]) -> ValidationResult:
        """
        Validate Azure credentials
        
        Supports:
        - azure_service_principal: client_id, client_secret, tenant_id, subscription_id
        """
        credential_type = credentials.get('credential_type')
        
        if credential_type == 'azure_service_principal':
            return await self._validate_service_principal(credentials)
        else:
            return self._create_error_result(
                f"Unsupported Azure credential type: {credential_type}",
                ["Supported types: azure_service_principal"]
            )
    
    async def _validate_service_principal(self, credentials: Dict[str, Any]) -> ValidationResult:
        """Validate Azure Service Principal credentials"""
        try:
            client_id = credentials.get('client_id')
            client_secret = credentials.get('client_secret')
            tenant_id = credentials.get('tenant_id')
            subscription_id = credentials.get('subscription_id')
            
            if not all([client_id, client_secret, tenant_id, subscription_id]):
                return self._create_error_result(
                    "Missing required fields",
                    ["client_id, client_secret, tenant_id, and subscription_id are required"]
                )
            
            # Create credential
            credential = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret
            )
            
            # Test credentials by getting subscription
            subscription_client = SubscriptionClient(credential)
            subscription = subscription_client.subscriptions.get(subscription_id)
            
            return self._create_success_result(
                "Service principal validated successfully",
                account_number=subscription_id
            )
            
        except AzureError as e:
            return self._create_error_result(
                f"Azure Error: {str(e)}",
                [str(e)]
            )
        except Exception as e:
            return self._create_error_result(
                f"Validation failed: {str(e)}",
                [str(e)]
            )

