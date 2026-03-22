"""
AWS credential validator
"""
import uuid
import boto3
from botocore.exceptions import ClientError
from typing import Dict, Any
from engine_onboarding.validators.base_validator import BaseValidator, ValidationResult
from engine_onboarding.config import settings


class AWSValidator(BaseValidator):
    """Validator for AWS credentials"""

    async def validate(self, credentials: Dict[str, Any]) -> ValidationResult:
        """
        Validate AWS credentials

        Supports:
        - aws_access_key: access_key_id, secret_access_key
          (also accepts aws_access_key_id / aws_secret_access_key)
        - aws_iam_role: role_arn, external_id, account_number
        """
        credential_type = credentials.get('credential_type')

        if credential_type in ('aws_access_key', 'access_key'):
            return await self._validate_access_key(credentials)
        elif credential_type == 'aws_iam_role':
            return await self._validate_iam_role(credentials)
        else:
            return self._create_error_result(
                f"Unsupported AWS credential type: {credential_type}",
                ["Supported types: aws_access_key, aws_iam_role"]
            )

    async def _validate_access_key(self, credentials: Dict[str, Any]) -> ValidationResult:
        """Validate AWS access key credentials.

        Accepts either naming convention:
          - access_key_id / secret_access_key  (internal)
          - aws_access_key_id / aws_secret_access_key  (boto3/AWS standard)
        """
        try:
            # Accept both naming conventions
            access_key_id = (
                credentials.get('access_key_id')
                or credentials.get('aws_access_key_id')
            )
            secret_access_key = (
                credentials.get('secret_access_key')
                or credentials.get('aws_secret_access_key')
            )

            if not access_key_id or not secret_access_key:
                return self._create_error_result(
                    "Missing required fields",
                    ["Provide access_key_id + secret_access_key "
                     "(or aws_access_key_id + aws_secret_access_key)"]
                )

            session = boto3.Session(
                aws_access_key_id=access_key_id,
                aws_secret_access_key=secret_access_key,
            )

            sts = session.client('sts')
            identity = sts.get_caller_identity()
            account_number = identity.get('Account')

            # Verify basic read permission
            ec2 = session.client('ec2', region_name='us-east-1')
            ec2.describe_regions()

            return self._create_success_result(
                "Access key validated successfully",
                account_number=account_number,
            )

        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            return self._create_error_result(
                f"AWS Error ({error_code}): {error_message}",
                [str(e)],
            )
        except Exception as e:
            return self._create_error_result(
                f"Validation failed: {str(e)}",
                [str(e)],
            )

    async def _validate_iam_role(self, credentials: Dict[str, Any]) -> ValidationResult:
        """Validate AWS IAM role credentials"""
        try:
            role_arn = credentials.get('role_arn')
            external_id = credentials.get('external_id')
            account_number = credentials.get('account_number')

            if not all([role_arn, external_id, account_number]):
                return self._create_error_result(
                    "Missing required fields",
                    ["role_arn, external_id, and account_number are required"]
                )

            if not role_arn.startswith('arn:aws:iam::') or ':role/' not in role_arn:
                return self._create_error_result(
                    "Invalid Role ARN format",
                    ["Role ARN must be: arn:aws:iam::ACCOUNT_ID:role/ROLE_NAME"]
                )

            role_account_id = role_arn.split(':')[4]
            if role_account_id != account_number:
                return self._create_error_result(
                    "Account ID mismatch",
                    [f"Role ARN account ({role_account_id}) != provided account ({account_number})"]
                )

            sts_client = boto3.client('sts')
            assume_role_response = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=f'threat-engine-validation-{uuid.uuid4().hex[:8]}',
                ExternalId=external_id,
                DurationSeconds=900,
            )

            temp_creds = assume_role_response['Credentials']
            temp_session = boto3.Session(
                aws_access_key_id=temp_creds['AccessKeyId'],
                aws_secret_access_key=temp_creds['SecretAccessKey'],
                aws_session_token=temp_creds['SessionToken'],
            )

            caller_identity = temp_session.client('sts').get_caller_identity()
            verified_account_id = caller_identity['Account']

            if verified_account_id != account_number:
                return self._create_error_result(
                    "Account verification failed",
                    [f"Role returned account {verified_account_id}, expected {account_number}"]
                )

            ec2_client = temp_session.client('ec2', region_name='us-east-1')
            ec2_client.describe_regions()

            return self._create_success_result(
                "IAM role validated successfully",
                account_number=verified_account_id,
            )

        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            if error_code == 'AccessDenied':
                return self._create_error_result(
                    "Access denied - check role permissions",
                    [f"Cannot assume role: {error_message}"]
                )
            elif error_code == 'InvalidClientTokenId':
                return self._create_error_result(
                    "Invalid credentials",
                    [f"Invalid External ID or role config: {error_message}"]
                )
            return self._create_error_result(
                f"AWS Error ({error_code}): {error_message}",
                [str(e)],
            )
        except Exception as e:
            return self._create_error_result(
                f"Validation failed: {str(e)}",
                [str(e)],
            )
