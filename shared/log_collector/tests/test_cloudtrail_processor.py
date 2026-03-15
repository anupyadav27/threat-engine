"""
Unit Tests — CloudTrail Processor
Task 0.2.12 [Seq 24 | QA]

Tests: parse JSON, extract fields, skip malformed, normalize events.
"""

import gzip
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from shared.log_collector.processors.cloudtrail_processor import (
    CloudTrailProcessor,
    _is_ip_address,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
SAMPLE_CLOUDTRAIL = {
    "Records": [
        {
            "eventVersion": "1.08",
            "eventTime": "2024-01-15T10:30:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateAccessKey",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "203.0.113.50",
            "userAgent": "aws-cli/2.0",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AIDAEXAMPLE",
                "arn": "arn:aws:iam::123456789012:user/admin",
                "accountId": "123456789012",
                "userName": "admin",
            },
            "requestParameters": {"userName": "new-user"},
            "responseElements": {"accessKey": {"accessKeyId": "AKIAEXAMPLE"}},
            "resources": [
                {
                    "type": "AWS::IAM::AccessKey",
                    "ARN": "arn:aws:iam::123456789012:user/new-user",
                }
            ],
        },
        {
            "eventVersion": "1.08",
            "eventTime": "2024-01-15T10:31:00Z",
            "eventSource": "ec2.amazonaws.com",
            "eventName": "AuthorizeSecurityGroupIngress",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "10.0.0.5",
            "userAgent": "console.amazonaws.com",
            "userIdentity": {"type": "AssumedRole"},
            "errorCode": "UnauthorizedOperation",
            "errorMessage": "You are not authorized to perform this operation.",
        },
    ]
}


# ---------------------------------------------------------------------------
# _is_ip_address tests
# ---------------------------------------------------------------------------
class TestIsIPAddress:
    def test_valid_ipv4(self):
        assert _is_ip_address("10.0.0.1") is True
        assert _is_ip_address("203.0.113.50") is True

    def test_valid_ipv6(self):
        assert _is_ip_address("::1") is True
        assert _is_ip_address("2001:db8::1") is True

    def test_service_name(self):
        assert _is_ip_address("iam.amazonaws.com") is False
        assert _is_ip_address("console.amazonaws.com") is False

    def test_empty_string(self):
        assert _is_ip_address("") is False


# ---------------------------------------------------------------------------
# CloudTrailProcessor tests
# ---------------------------------------------------------------------------
class TestCloudTrailProcessor:
    @pytest.fixture
    def mock_pool(self):
        pool = AsyncMock()
        conn = AsyncMock()
        pool.acquire.return_value.__aenter__ = AsyncMock(return_value=conn)
        pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)
        return pool

    @pytest.fixture
    def mock_s3_with_data(self):
        s3 = MagicMock()
        data = json.dumps(SAMPLE_CLOUDTRAIL).encode("utf-8")
        compressed = gzip.compress(data)
        s3.get_object.return_value = {"Body": MagicMock(read=MagicMock(return_value=compressed))}
        return s3

    @pytest.mark.asyncio
    async def test_process_valid_file(self, mock_pool, mock_s3_with_data):
        processor = CloudTrailProcessor(pool=mock_pool, s3_client=mock_s3_with_data)
        result = await processor.process(
            bucket="cloudtrail-bucket",
            key="AWSLogs/123/CloudTrail/us-east-1/2024/01/15/ct.json.gz",
        )

        assert result["rows_inserted"] == 2
        assert result["rows_skipped"] == 0

    @pytest.mark.asyncio
    async def test_process_empty_records(self, mock_pool):
        s3 = MagicMock()
        data = json.dumps({"Records": []}).encode("utf-8")
        compressed = gzip.compress(data)
        s3.get_object.return_value = {"Body": MagicMock(read=MagicMock(return_value=compressed))}

        processor = CloudTrailProcessor(pool=mock_pool, s3_client=s3)
        result = await processor.process(bucket="b", key="k.json.gz")

        assert result["rows_inserted"] == 0

    @pytest.mark.asyncio
    async def test_process_invalid_json(self, mock_pool):
        s3 = MagicMock()
        compressed = gzip.compress(b"not valid json")
        s3.get_object.return_value = {"Body": MagicMock(read=MagicMock(return_value=compressed))}

        processor = CloudTrailProcessor(pool=mock_pool, s3_client=s3)
        result = await processor.process(bucket="b", key="k.json.gz")

        assert result["rows_inserted"] == 0
        assert result["rows_skipped"] == 1

    def test_normalize_event_extracts_fields(self, mock_pool):
        processor = CloudTrailProcessor(pool=mock_pool)
        event = SAMPLE_CLOUDTRAIL["Records"][0]
        row = processor._normalize_event(event, "cust-1", "tenant-1", "s3://b/k")

        assert row[0] == "cloudtrail"       # source_type
        assert row[1] == "cust-1"           # customer_id
        assert row[4] == "CreateAccessKey"  # event_name
        assert row[5] == "iam.amazonaws.com"  # event_source
        assert row[7] == "AWS::IAM::AccessKey"  # resource_type
        assert row[13] == "203.0.113.50"    # source_ip (valid IP)

    def test_normalize_event_error_fields(self, mock_pool):
        processor = CloudTrailProcessor(pool=mock_pool)
        event = SAMPLE_CLOUDTRAIL["Records"][1]
        row = processor._normalize_event(event, None, None, "s3://b/k")

        assert row[4] == "AuthorizeSecurityGroupIngress"
        assert row[11] == "UnauthorizedOperation"  # error_code
        assert "not authorized" in row[12]          # error_message

    def test_normalize_event_service_ip_filtered(self, mock_pool):
        """Source IP that's a service name should be stored as None."""
        processor = CloudTrailProcessor(pool=mock_pool)
        event = {
            "eventTime": "2024-01-15T10:00:00Z",
            "eventName": "DescribeInstances",
            "eventSource": "ec2.amazonaws.com",
            "sourceIPAddress": "ec2.amazonaws.com",  # Service name, not IP
            "userIdentity": {},
        }
        row = processor._normalize_event(event, None, None, "s3://b/k")
        assert row[13] is None  # source_ip should be None
