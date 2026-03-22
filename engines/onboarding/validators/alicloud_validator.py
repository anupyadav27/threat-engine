"""
AliCloud credential validator
Uses aliyun-python-sdk-core (already in requirements) to call STS GetCallerIdentity.
"""
import json
from typing import Dict, Any
from engine_onboarding.validators.base_validator import BaseValidator, ValidationResult

try:
    from aliyunsdkcore.client import AcsClient
    from aliyunsdkcore.request import CommonRequest
    from aliyunsdkcore.acs_exception.exceptions import ClientException, ServerException
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
                ["Install aliyun-python-sdk-core"]
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
        """Validate AliCloud Access Key via STS GetCallerIdentity"""
        try:
            access_key_id = credentials.get('access_key_id')
            access_key_secret = credentials.get('access_key_secret')

            if not access_key_id or not access_key_secret:
                return self._create_error_result(
                    "Missing required fields",
                    ["access_key_id and access_key_secret are required"]
                )

            # AcsClient accepts any region; cn-hangzhou is the global STS endpoint
            client = AcsClient(
                ak=access_key_id,
                secret=access_key_secret,
                region_id='cn-hangzhou',
            )

            request = CommonRequest()
            request.set_accept_format('json')
            request.set_domain('sts.aliyuncs.com')
            request.set_method('POST')
            request.set_version('2015-04-01')
            request.set_action_name('GetCallerIdentity')

            response_bytes = client.do_action_with_exception(request)
            result = json.loads(response_bytes)

            account_id = result.get('AccountId')

            return self._create_success_result(
                "AliCloud access key validated successfully",
                account_number=account_id,
            )

        except ServerException as e:
            # InvalidAccessKeyId / SignatureDoesNotMatch → bad credentials
            return self._create_error_result(
                f"AliCloud Error ({e.get_error_code()}): {e.get_error_msg()}",
                [str(e)]
            )
        except ClientException as e:
            return self._create_error_result(
                f"AliCloud Client Error: {e.get_error_msg()}",
                [str(e)]
            )
        except Exception as e:
            return self._create_error_result(
                f"Validation failed: {str(e)}",
                [str(e)]
            )
