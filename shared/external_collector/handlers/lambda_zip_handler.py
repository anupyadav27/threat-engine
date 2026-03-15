"""
Serverless Function Code Downloader — Task 0.3.11 [Seq 35 | BD]

Downloads and extracts serverless function deployment packages to locate
manifest files (package.json, requirements.txt, go.mod) for dependency
analysis by engine_supplychain.

Currently supports:
  - AWS Lambda (ZIP from S3 via STS assume_role)

Multi-CSP roadmap (extend this handler):
  - Azure Functions: Download from Azure Blob Storage (deployment package ZIP)
  - GCP Cloud Functions: Download from GCS (source archive)
  - OCI Functions: Download from OCI Object Storage

Input:  {provider, account_id, function_name, code_location}
Output: List of manifest {filename, content} extracted from the ZIP

Dependencies:
  - STS assume_role permission (IRSA) for AWS
  - Task 0.3.1 (package_metadata table)
"""

import asyncio
import io
import json
import logging
import zipfile
from typing import Any, Dict, List, Optional

import asyncpg
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger("external_collector.handlers.lambda_zip")

# Manifest files to look for inside Lambda ZIPs
MANIFEST_FILES = {
    "package.json",
    "package-lock.json",
    "requirements.txt",
    "Pipfile",
    "Pipfile.lock",
    "go.mod",
    "go.sum",
    "pom.xml",
    "build.gradle",
    "Gemfile",
    "Gemfile.lock",
    "Cargo.toml",
    "Cargo.lock",
    "composer.json",
    "composer.lock",
}

# Max ZIP size to process (100 MB)
MAX_ZIP_SIZE = 100 * 1024 * 1024


class LambdaZIPHandler:
    """Downloads and extracts Lambda deployment ZIPs for dependency scanning.

    Args:
        pool: asyncpg connection pool for threat_engine_external.
        sts_client: Optional boto3 STS client (for testing).
    """

    def __init__(
        self,
        pool: asyncpg.Pool,
        sts_client: Optional[Any] = None,
    ) -> None:
        self._pool = pool
        self._sts = sts_client or boto3.client("sts")

    def _get_s3_client(self, account_id: str, role_name: str = "ThreatEngineLambdaReadRole") -> Any:
        """Assume role in target account and return S3 client.

        Args:
            account_id: AWS account ID.
            role_name: IAM role to assume.

        Returns:
            boto3 S3 client with assumed role credentials.
        """
        role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

        try:
            response = self._sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName="threat-engine-lambda-scan",
                DurationSeconds=900,
            )
            creds = response["Credentials"]
            return boto3.client(
                "s3",
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
            )
        except ClientError as exc:
            logger.error("Failed to assume role %s: %s", role_arn, exc)
            raise

    def download_and_extract(
        self,
        s3_client: Any,
        bucket: str,
        key: str,
    ) -> List[Dict[str, str]]:
        """Download ZIP from S3 and extract manifest files.

        Args:
            s3_client: boto3 S3 client.
            bucket: S3 bucket name.
            key: S3 object key.

        Returns:
            List of {filename, content} dicts.
        """
        # Check object size first
        try:
            head = s3_client.head_object(Bucket=bucket, Key=key)
            size = head.get("ContentLength", 0)
            if size > MAX_ZIP_SIZE:
                logger.warning(
                    "Lambda ZIP too large (%d bytes > %d), skipping: s3://%s/%s",
                    size, MAX_ZIP_SIZE, bucket, key,
                )
                return []
        except ClientError as exc:
            logger.error("Failed to head s3://%s/%s: %s", bucket, key, exc)
            return []

        # Download into memory
        try:
            response = s3_client.get_object(Bucket=bucket, Key=key)
            zip_data = response["Body"].read()
        except ClientError as exc:
            logger.error("Failed to download s3://%s/%s: %s", bucket, key, exc)
            return []

        # Extract manifest files
        manifests: List[Dict[str, str]] = []
        try:
            with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
                for entry in zf.namelist():
                    # Check if the filename (without path) matches a manifest
                    basename = entry.rsplit("/", 1)[-1] if "/" in entry else entry
                    if basename in MANIFEST_FILES:
                        try:
                            content = zf.read(entry).decode("utf-8", errors="replace")
                            manifests.append({
                                "filename": basename,
                                "path_in_zip": entry,
                                "content": content,
                            })
                        except Exception as exc:
                            logger.warning("Error reading %s from ZIP: %s", entry, exc)
        except zipfile.BadZipFile:
            logger.error("Bad ZIP file: s3://%s/%s", bucket, key)
        except Exception as exc:
            logger.error("ZIP extraction error for s3://%s/%s: %s", bucket, key, exc)

        return manifests

    async def process_lambda_function(
        self,
        account_id: str,
        function_name: str,
        code_s3_bucket: str,
        code_s3_key: str,
    ) -> Dict[str, Any]:
        """Download Lambda ZIP and extract manifest files.

        Args:
            account_id: AWS account ID.
            function_name: Lambda function name.
            code_s3_bucket: S3 bucket containing the ZIP.
            code_s3_key: S3 key for the ZIP.

        Returns:
            Dict with manifests_found, manifests list, error.
        """
        try:
            s3_client = await asyncio.get_event_loop().run_in_executor(
                None, self._get_s3_client, account_id
            )

            manifests = await asyncio.get_event_loop().run_in_executor(
                None,
                self.download_and_extract,
                s3_client,
                code_s3_bucket,
                code_s3_key,
            )

            # Store manifests
            for manifest in manifests:
                await self._store_manifest(
                    function_name=function_name,
                    account_id=account_id,
                    filename=manifest["filename"],
                    content=manifest["content"],
                )

            logger.info(
                "Lambda %s/%s: %d manifests found",
                account_id, function_name, len(manifests),
            )

            return {
                "manifests_found": len(manifests),
                "manifests": [m["filename"] for m in manifests],
                "error": None,
            }

        except Exception as exc:
            error_msg = str(exc)
            logger.error(
                "Lambda ZIP processing error for %s/%s: %s",
                account_id, function_name, error_msg,
            )
            return {
                "manifests_found": 0,
                "manifests": [],
                "error": error_msg,
            }

    async def _store_manifest(
        self,
        function_name: str,
        account_id: str,
        filename: str,
        content: str,
    ) -> None:
        """Store manifest in package_metadata table."""
        sql = """
            INSERT INTO package_metadata (
                package_name, registry, version, metadata, refreshed_at
            ) VALUES ($1, $2, $3, $4::jsonb, NOW())
            ON CONFLICT (package_name, registry, version)
            DO UPDATE SET
                metadata = EXCLUDED.metadata,
                refreshed_at = NOW()
        """
        metadata = json.dumps({
            "source": "lambda_zip",
            "account_id": account_id,
            "function_name": function_name,
            "manifest_file": filename,
            "file_content": content,
        })
        async with self._pool.acquire() as conn:
            await conn.execute(
                sql,
                f"lambda:{account_id}/{function_name}/{filename}",
                "lambda",
                "latest",
                metadata,
            )
