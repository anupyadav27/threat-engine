"""
Set up the cspm-vulnerability-agent S3 bucket:
  1. Verify bucket exists and is private.
  2. Apply lifecycle rule: delete downloads/* after 1 day.
  3. Check that the agent binary exists at the expected key.
  4. Print upload instructions if binary is missing.

Usage:
    python scripts/setup_vul_agent_s3.py [--upload-binary PATH]

Examples:
    # Check bucket + apply lifecycle rule
    python scripts/setup_vul_agent_s3.py

    # Also upload a pre-built binary
    python scripts/setup_vul_agent_s3.py --upload-binary dist/vul-agent
"""

import argparse
import json
import sys

import boto3
from botocore.exceptions import ClientError

BUCKET     = "cspm-vulnerability-agent"
REGION     = "ap-south-1"
BINARY_KEY = "vul-agent/v1.0.0/linux/vul-agent"


def get_s3():
    return boto3.client("s3", region_name=REGION)


def verify_bucket_private(s3):
    print(f"[check] Verifying bucket '{BUCKET}' public-access block ...")
    try:
        acl = s3.get_public_access_block(Bucket=BUCKET)
        cfg = acl["PublicAccessBlockConfiguration"]
        all_blocked = all([
            cfg.get("BlockPublicAcls"),
            cfg.get("IgnorePublicAcls"),
            cfg.get("BlockPublicPolicy"),
            cfg.get("RestrictPublicBuckets"),
        ])
        if all_blocked:
            print("  [ok] All public access is blocked.")
        else:
            print("  [WARN] Public access is NOT fully blocked. Applying block ...")
            s3.put_public_access_block(
                Bucket=BUCKET,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            )
            print("  [ok] Public access block applied.")
    except ClientError as e:
        print(f"  [ERROR] {e}")
        sys.exit(1)


def apply_lifecycle_rule(s3):
    print(f"[check] Applying lifecycle rule: downloads/* → expire after 1 day ...")
    rule = {
        "Rules": [
            {
                "ID": "expire-temp-agent-downloads",
                "Status": "Enabled",
                "Filter": {"Prefix": "downloads/"},
                "Expiration": {"Days": 1},
            }
        ]
    }
    try:
        s3.put_bucket_lifecycle_configuration(
            Bucket=BUCKET,
            LifecycleConfiguration=rule,
        )
        print("  [ok] Lifecycle rule applied.")
    except ClientError as e:
        print(f"  [ERROR] {e}")
        sys.exit(1)


def check_binary(s3):
    print(f"[check] Looking for agent binary at s3://{BUCKET}/{BINARY_KEY} ...")
    try:
        head = s3.head_object(Bucket=BUCKET, Key=BINARY_KEY)
        size_mb = head["ContentLength"] / 1024 / 1024
        print(f"  [ok] Binary exists ({size_mb:.1f} MB).")
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "404":
            print(f"  [MISSING] Binary not found.")
            print()
            print("  To upload the binary, run:")
            print(f"    python scripts/setup_vul_agent_s3.py --upload-binary /path/to/vul-agent")
            print()
            print("  Or with AWS CLI:")
            print(f"    aws s3 cp ./dist/vul-agent s3://{BUCKET}/{BINARY_KEY} --region {REGION}")
            return False
        print(f"  [ERROR] {e}")
        sys.exit(1)


def upload_binary(s3, local_path: str):
    print(f"[upload] Uploading {local_path} → s3://{BUCKET}/{BINARY_KEY} ...")
    try:
        s3.upload_file(
            local_path,
            BUCKET,
            BINARY_KEY,
            ExtraArgs={"ContentType": "application/octet-stream"},
        )
        print("  [ok] Binary uploaded.")
    except ClientError as e:
        print(f"  [ERROR] {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Set up cspm-vulnerability-agent S3 bucket")
    parser.add_argument("--upload-binary", metavar="PATH", help="Path to vul-agent binary to upload")
    args = parser.parse_args()

    s3 = get_s3()
    verify_bucket_private(s3)
    apply_lifecycle_rule(s3)

    if args.upload_binary:
        upload_binary(s3, args.upload_binary)

    check_binary(s3)
    print()
    print("[done] S3 bucket setup complete.")


if __name__ == "__main__":
    main()
