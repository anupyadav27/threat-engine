"""AWS CIEM provider — parsers, readers, and session creation."""

import logging
from typing import Any, Dict, Optional, Type

from .base import BaseCIEMProvider

logger = logging.getLogger(__name__)


class AWSCIEMProvider(BaseCIEMProvider):
    def get_parsers(self) -> Dict[str, Type]:
        from ciem_engine.parser.cloudtrail_parser import CloudTrailParser
        from ciem_engine.parser.vpc_flow_parser import VPCFlowParser
        from ciem_engine.parser.alb_parser import ALBParser
        from ciem_engine.parser.waf_parser import WAFParser
        from ciem_engine.parser.cloudfront_parser import CloudFrontParser
        from ciem_engine.parser.s3_access_parser import S3AccessParser
        from ciem_engine.parser.dns_parser import DNSParser
        from ciem_engine.parser.rds_audit_parser import RDSAuditParser
        from ciem_engine.parser.eks_audit_parser import EKSAuditParser
        from ciem_engine.parser.lambda_parser import LambdaParser
        from ciem_engine.parser.guardduty_parser import GuardDutyParser

        return {
            "cloudtrail": CloudTrailParser,
            "vpc_flow": VPCFlowParser,
            "alb": ALBParser,
            "waf": WAFParser,
            "cloudfront": CloudFrontParser,
            "s3_access": S3AccessParser,
            "dns": DNSParser,
            "rds_audit": RDSAuditParser,
            "eks_audit": EKSAuditParser,
            "eks_authenticator": EKSAuditParser,
            "lambda": LambdaParser,
            "guardduty": GuardDutyParser,
        }

    def get_readers(self) -> Dict[str, Type]:
        from ciem_engine.reader.aws_s3_reader import AWSS3Reader
        from ciem_engine.reader.aws_cloudwatch_reader import AWSCloudWatchReader

        return {
            "s3": AWSS3Reader,
            "cloudwatch": AWSCloudWatchReader,
        }

    def create_session(
        self,
        region: str,
        account_id: str,
        credentials: Optional[dict] = None,
    ) -> Optional[Any]:
        import boto3

        creds = credentials or {}
        cred_type = creds.get("credential_type", "")

        if cred_type in ("access_key", "aws_access_key", "access_key_id"):
            return boto3.Session(
                aws_access_key_id=creds.get("aws_access_key_id", creds.get("access_key_id", "")),
                aws_secret_access_key=creds.get("aws_secret_access_key", creds.get("secret_access_key", "")),
                region_name=region,
            )

        if cred_type in ("iam_role", "aws_iam_role", "role"):
            role_arn = creds.get("role_arn", "")
            if role_arn:
                sts = boto3.client("sts", region_name=region)
                assumed = sts.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName="CIEMLogScanner",
                )
                c = assumed["Credentials"]
                return boto3.Session(
                    aws_access_key_id=c["AccessKeyId"],
                    aws_secret_access_key=c["SecretAccessKey"],
                    aws_session_token=c["SessionToken"],
                    region_name=region,
                )

        # Fallback: instance profile / env vars
        return boto3.Session(region_name=region)
