import os
import boto3
import botocore
from typing import Optional


def _assume_role(sts_client, role_arn: str, session_name: str, external_id: Optional[str] = None) -> dict:
    params = {
        "RoleArn": role_arn,
        "RoleSessionName": session_name or "compliance-session",
        "DurationSeconds": int(os.getenv("ASSUMED_ROLE_DURATION", "3600"))
    }
    if external_id:
        params["ExternalId"] = external_id
    resp = sts_client.assume_role(**params)
    return resp["Credentials"]


def get_boto3_session(default_region: Optional[str] = None) -> boto3.session.Session:
    """Create a boto3 Session.
    - Honors AWS_PROFILE
    - Optionally assumes role if AWS_ROLE_ARN is set
    - Falls back to environment/default credentials
    """
    profile = os.getenv("AWS_PROFILE")
    role_arn = os.getenv("AWS_ROLE_ARN")
    role_session_name = os.getenv("AWS_ROLE_SESSION_NAME", "compliance-session")
    external_id = os.getenv("AWS_EXTERNAL_ID")

    if role_arn:
        # Use a base session (optionally with profile) to call STS AssumeRole
        base_session = boto3.session.Session(profile_name=profile, region_name=default_region)
        sts = base_session.client("sts")
        creds = _assume_role(sts, role_arn, role_session_name, external_id)
        return boto3.session.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=default_region,
            profile_name=None,
        )

    # No assume role, return session based on profile/env
    return boto3.session.Session(profile_name=profile, region_name=default_region)


def get_session_for_account(
    account_id: str,
    role_name: Optional[str] = None,
    default_region: Optional[str] = None,
    base_profile: Optional[str] = None,
    external_id: Optional[str] = None,
) -> boto3.session.Session:
    """Return a boto3 session targeted to the given account.

    If role_name is provided, assumes arn:aws:iam::ACCOUNT_ID:role/ROLE_NAME using the
    base profile (or default credentials) and returns a session using the assumed role
    credentials. Otherwise, returns a session using the provided base profile/env.
    """
    if role_name:
        role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
        base_session = boto3.session.Session(profile_name=base_profile, region_name=default_region)
        sts = base_session.client("sts")
        creds = _assume_role(sts, role_arn, os.getenv("AWS_ROLE_SESSION_NAME", "compliance-session"), external_id)
        return boto3.session.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=default_region,
        )
    # Fallback: use base profile or default env credentials
    return boto3.session.Session(profile_name=base_profile, region_name=default_region)
