"""K8s CIEM provider — EKS audit logs via AWS CloudWatch/S3."""

import logging
from typing import Any, Dict, Optional, Type

from .base import BaseCIEMProvider

logger = logging.getLogger(__name__)


class K8sCIEMProvider(BaseCIEMProvider):
    """K8s uses EKS audit logs delivered via CloudWatch or S3 — same readers as AWS."""

    def get_parsers(self) -> Dict[str, Type]:
        from cdr_engine.parser.eks_audit_parser import EKSAuditParser

        return {
            "eks_audit": EKSAuditParser,
            "k8s_audit": EKSAuditParser,   # alias for log_sources configured as k8s_audit
            "eks_authenticator": EKSAuditParser,
        }

    def get_readers(self) -> Dict[str, Type]:
        from cdr_engine.reader.aws_s3_reader import AWSS3Reader
        from cdr_engine.reader.aws_cloudwatch_reader import AWSCloudWatchReader

        return {
            "s3": AWSS3Reader,
            "cloudwatch": AWSCloudWatchReader,
        }

    def create_session(self, region: str, account_id: str, credentials: Optional[Dict] = None) -> Optional[Any]:
        import boto3

        return boto3.Session(region_name=region)
