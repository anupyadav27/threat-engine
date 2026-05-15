"""Unit tests for the crown jewel auto-classification rules (AP-P1-01).

Architecture reference: Section 4.3 — Crown Jewel Classification.

Covers:
    - S3 bucket with data_classification=pii → is_crown_jewel=true, type=data
    - S3 bucket with data_classification=none → NOT crown jewel
    - RDS instance → always crown jewel, type=data
    - SecretsManager secret → always crown jewel, type=secrets
    - IAMRole with is_admin_role=true → crown jewel, type=identity
    - IAMRole with is_admin_role=false → NOT crown jewel
    - EKS cluster → always crown jewel, type=infra_control
    - EC2 with can_access_pii=true → crown jewel (Deepseek enhancement), type=compute
    - Lambda with is_admin_role=true → crown jewel (serverless admin)
    - Manual override is_crown_jewel=false overrides auto-classification to true
    - Manual override is_crown_jewel=true overrides auto-classification to false

No external dependencies. Pure classification logic only.
"""

from __future__ import annotations

import pytest
from dataclasses import dataclass
from typing import Optional


# ── Minimal stubs ─────────────────────────────────────────────────────────────

@dataclass
class Resource:
    resource_uid: str
    resource_type: str
    tenant_id: str = "tenant-1"
    account_id: str = "123456789012"
    provider: str = "aws"
    # Classification signals
    data_classification: Optional[str] = None   # pii|financial|credentials|none
    is_admin_role: bool = False
    has_wildcard_policy: bool = False
    can_access_pii: bool = False
    can_write_data: bool = False


@dataclass
class ManualOverride:
    resource_uid: str
    tenant_id: str
    is_crown_jewel: bool
    crown_jewel_type: Optional[str] = None
    reason: Optional[str] = None
    set_by: str = "analyst@cspm.local"


@dataclass
class CrownJewelResult:
    is_crown_jewel: bool
    crown_jewel_type: Optional[str] = None
    classified_by: str = "auto"  # auto|override


# ── Classifier implementation (from architecture doc Section 4.3) ─────────────

# Resource types that are ALWAYS crown jewels, regardless of other properties
_ALWAYS_CROWN_JEWEL: dict[str, str] = {
    # Databases (type=data)
    "rds.instance":         "data",
    "aurora.cluster":       "data",
    "cloud_sql.instance":   "data",
    "oci.autonomous_db":    "data",
    "redshift.cluster":     "data",
    "elasticsearch.domain": "data",
    # Secrets (type=secrets)
    "secretsmanager.secret": "secrets",
    # Infra control (type=infra_control)
    "eks.cluster":          "infra_control",
    "aks.cluster":          "infra_control",
    "gke.cluster":          "infra_control",
    # Code supply chain (type=code)
    "ecr.repository":       "code",
    "acr.registry":         "code",
    "gcr.repository":       "code",
    # AI/ML (type=ai_model)
    "sagemaker.endpoint":   "ai_model",
    "bedrock.model":        "ai_model",
    # Encryption control (type=secrets)
    "kms.key":              "secrets",
    "key_vault.key":        "secrets",
}

# Storage resource types where data_classification drives crown jewel status
_CONDITIONAL_STORAGE_TYPES = {
    "s3.bucket", "blob.container", "gcs.bucket", "oci.object_storage",
}

# IAM resource types where admin-ness drives crown jewel status
_IAM_TYPES = {"iam.role", "iam.user"}

# SSM parameter type with conditional logic
_SSM_PARAM_TYPE = "ssm.parameter"

# CloudFormation stack type
_CFN_STACK_TYPE = "cloudformation.stack"


def classify_crown_jewel(
    resource: Resource,
    override: Optional[ManualOverride] = None,
) -> CrownJewelResult:
    """Auto-classify a resource as a crown jewel, then apply any manual override."""

    # Apply manual override last — always wins
    if override is not None and override.resource_uid == resource.resource_uid:
        return CrownJewelResult(
            is_crown_jewel=override.is_crown_jewel,
            crown_jewel_type=override.crown_jewel_type,
            classified_by="override",
        )

    rtype = resource.resource_type.lower()

    # Always-crown-jewel resource types
    if rtype in _ALWAYS_CROWN_JEWEL:
        return CrownJewelResult(
            is_crown_jewel=True,
            crown_jewel_type=_ALWAYS_CROWN_JEWEL[rtype],
            classified_by="auto",
        )

    # Storage resources: crown jewel if classified as pii/financial/credentials
    if rtype in _CONDITIONAL_STORAGE_TYPES:
        if resource.data_classification in ("pii", "financial", "credentials"):
            return CrownJewelResult(
                is_crown_jewel=True, crown_jewel_type="data", classified_by="auto",
            )
        return CrownJewelResult(is_crown_jewel=False)

    # IAM resources: crown jewel if admin role or wildcard policy
    if rtype in _IAM_TYPES:
        if resource.is_admin_role or resource.has_wildcard_policy:
            return CrownJewelResult(
                is_crown_jewel=True, crown_jewel_type="identity", classified_by="auto",
            )
        return CrownJewelResult(is_crown_jewel=False)

    # Lambda: crown jewel if has admin role
    if rtype == "lambda.function":
        if resource.is_admin_role:
            return CrownJewelResult(
                is_crown_jewel=True, crown_jewel_type="identity", classified_by="auto",
            )
        # Additional: can_access_pii enhancement
        if resource.can_access_pii:
            return CrownJewelResult(
                is_crown_jewel=True, crown_jewel_type="compute", classified_by="auto",
            )
        return CrownJewelResult(is_crown_jewel=False)

    # EC2: crown jewel if can_access_pii
    if rtype == "ec2.instance":
        if resource.can_access_pii:
            return CrownJewelResult(
                is_crown_jewel=True, crown_jewel_type="compute", classified_by="auto",
            )
        return CrownJewelResult(is_crown_jewel=False)

    # SSM Parameter (SecureString): always crown jewel
    if rtype == _SSM_PARAM_TYPE:
        return CrownJewelResult(
            is_crown_jewel=True, crown_jewel_type="secrets", classified_by="auto",
        )

    # CloudFormation stack with admin IAM permissions
    if rtype == _CFN_STACK_TYPE:
        if resource.is_admin_role:
            return CrownJewelResult(
                is_crown_jewel=True, crown_jewel_type="infra_control", classified_by="auto",
            )
        return CrownJewelResult(is_crown_jewel=False)

    return CrownJewelResult(is_crown_jewel=False)


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestS3BucketClassification:
    def test_s3_with_pii_is_crown_jewel_data_type(self):
        r = Resource("arn:aws:s3:::prod-customers", "s3.bucket",
                     data_classification="pii")
        result = classify_crown_jewel(r)
        assert result.is_crown_jewel is True
        assert result.crown_jewel_type == "data"
        assert result.classified_by == "auto"

    def test_s3_with_financial_is_crown_jewel(self):
        r = Resource("arn:aws:s3:::finance-data", "s3.bucket",
                     data_classification="financial")
        result = classify_crown_jewel(r)
        assert result.is_crown_jewel is True
        assert result.crown_jewel_type == "data"

    def test_s3_with_credentials_is_crown_jewel(self):
        r = Resource("arn:aws:s3:::creds-vault", "s3.bucket",
                     data_classification="credentials")
        result = classify_crown_jewel(r)
        assert result.is_crown_jewel is True

    def test_s3_with_none_classification_is_not_crown_jewel(self):
        r = Resource("arn:aws:s3:::logs-bucket", "s3.bucket",
                     data_classification="none")
        result = classify_crown_jewel(r)
        assert result.is_crown_jewel is False

    def test_s3_with_no_classification_is_not_crown_jewel(self):
        r = Resource("arn:aws:s3:::empty-bucket", "s3.bucket",
                     data_classification=None)
        result = classify_crown_jewel(r)
        assert result.is_crown_jewel is False

    def test_blob_container_with_pii_is_crown_jewel(self):
        """Azure Blob containers follow the same conditional storage logic."""
        r = Resource("azure::container::prod-pii", "blob.container",
                     data_classification="pii")
        result = classify_crown_jewel(r)
        assert result.is_crown_jewel is True
        assert result.crown_jewel_type == "data"


class TestRDSClassification:
    def test_rds_instance_always_crown_jewel(self):
        r = Resource("arn:aws:rds:us-east-1:123:db:mydb", "rds.instance")
        result = classify_crown_jewel(r)
        assert result.is_crown_jewel is True
        assert result.crown_jewel_type == "data"

    def test_aurora_cluster_always_crown_jewel(self):
        r = Resource("arn:aws:rds:us-east-1:123:cluster:mycluster", "aurora.cluster")
        result = classify_crown_jewel(r)
        assert result.is_crown_jewel is True
        assert result.crown_jewel_type == "data"

    def test_rds_classification_is_auto(self):
        r = Resource("arn:aws:rds:us-east-1:123:db:mydb", "rds.instance")
        result = classify_crown_jewel(r)
        assert result.classified_by == "auto"


class TestSecretsManagerClassification:
    def test_secretsmanager_secret_always_crown_jewel(self):
        r = Resource("arn:aws:secretsmanager:us-east-1:123:secret:db-password", "secretsmanager.secret")
        result = classify_crown_jewel(r)
        assert result.is_crown_jewel is True
        assert result.crown_jewel_type == "secrets"

    def test_kms_key_always_crown_jewel(self):
        r = Resource("arn:aws:kms:us-east-1:123:key/abc", "kms.key")
        result = classify_crown_jewel(r)
        assert result.is_crown_jewel is True
        assert result.crown_jewel_type == "secrets"

    def test_ssm_parameter_always_crown_jewel(self):
        r = Resource("/prod/db/password", "ssm.parameter")
        result = classify_crown_jewel(r)
        assert result.is_crown_jewel is True
        assert result.crown_jewel_type == "secrets"


class TestIAMRoleClassification:
    def test_iam_role_with_admin_is_crown_jewel(self):
        r = Resource("arn:aws:iam::123:role/admin-role", "iam.role",
                     is_admin_role=True)
        result = classify_crown_jewel(r)
        assert result.is_crown_jewel is True
        assert result.crown_jewel_type == "identity"

    def test_iam_role_with_wildcard_policy_is_crown_jewel(self):
        r = Resource("arn:aws:iam::123:role/overperm-role", "iam.role",
                     has_wildcard_policy=True)
        result = classify_crown_jewel(r)
        assert result.is_crown_jewel is True
        assert result.crown_jewel_type == "identity"

    def test_iam_role_non_admin_not_crown_jewel(self):
        r = Resource("arn:aws:iam::123:role/readonly-role", "iam.role",
                     is_admin_role=False, has_wildcard_policy=False)
        result = classify_crown_jewel(r)
        assert result.is_crown_jewel is False

    def test_iam_user_with_admin_is_crown_jewel(self):
        r = Resource("arn:aws:iam::123:user/svc-admin", "iam.user",
                     is_admin_role=True)
        result = classify_crown_jewel(r)
        assert result.is_crown_jewel is True
        assert result.crown_jewel_type == "identity"


class TestEKSClassification:
    def test_eks_cluster_always_crown_jewel(self):
        r = Resource("arn:aws:eks:us-east-1:123:cluster/prod", "eks.cluster")
        result = classify_crown_jewel(r)
        assert result.is_crown_jewel is True
        assert result.crown_jewel_type == "infra_control"

    def test_aks_cluster_always_crown_jewel(self):
        r = Resource("azure::aks::prod-cluster", "aks.cluster")
        result = classify_crown_jewel(r)
        assert result.is_crown_jewel is True
        assert result.crown_jewel_type == "infra_control"

    def test_gke_cluster_always_crown_jewel(self):
        r = Resource("gcp::gke::prod-cluster", "gke.cluster")
        result = classify_crown_jewel(r)
        assert result.is_crown_jewel is True
        assert result.crown_jewel_type == "infra_control"


class TestEC2Classification:
    def test_ec2_with_can_access_pii_is_crown_jewel(self):
        """EC2 that can access PII (Deepseek enhancement) is a crown jewel."""
        r = Resource("arn:aws:ec2:us-east-1:123:instance/i-abc", "ec2.instance",
                     can_access_pii=True)
        result = classify_crown_jewel(r)
        assert result.is_crown_jewel is True
        assert result.crown_jewel_type == "compute"

    def test_ec2_without_pii_access_not_crown_jewel(self):
        r = Resource("arn:aws:ec2:us-east-1:123:instance/i-xyz", "ec2.instance",
                     can_access_pii=False)
        result = classify_crown_jewel(r)
        assert result.is_crown_jewel is False


class TestLambdaClassification:
    def test_lambda_with_admin_role_is_crown_jewel(self):
        r = Resource("arn:aws:lambda:us-east-1:123:function/admin-fn", "lambda.function",
                     is_admin_role=True)
        result = classify_crown_jewel(r)
        assert result.is_crown_jewel is True
        assert result.crown_jewel_type == "identity"

    def test_lambda_with_pii_access_is_crown_jewel(self):
        r = Resource("arn:aws:lambda:us-east-1:123:function/data-proc", "lambda.function",
                     can_access_pii=True)
        result = classify_crown_jewel(r)
        assert result.is_crown_jewel is True
        assert result.crown_jewel_type == "compute"

    def test_lambda_without_admin_or_pii_not_crown_jewel(self):
        r = Resource("arn:aws:lambda:us-east-1:123:function/hello-world", "lambda.function")
        result = classify_crown_jewel(r)
        assert result.is_crown_jewel is False


class TestAIMLClassification:
    def test_sagemaker_endpoint_always_crown_jewel(self):
        r = Resource("arn:aws:sagemaker:us-east-1:123:endpoint/prod-model", "sagemaker.endpoint")
        result = classify_crown_jewel(r)
        assert result.is_crown_jewel is True
        assert result.crown_jewel_type == "ai_model"

    def test_bedrock_model_always_crown_jewel(self):
        r = Resource("arn:aws:bedrock:us-east-1:123:model/claude-3", "bedrock.model")
        result = classify_crown_jewel(r)
        assert result.is_crown_jewel is True
        assert result.crown_jewel_type == "ai_model"


class TestCodeSupplyChainClassification:
    def test_ecr_repository_always_crown_jewel(self):
        r = Resource("arn:aws:ecr:us-east-1:123:repository/prod-api", "ecr.repository")
        result = classify_crown_jewel(r)
        assert result.is_crown_jewel is True
        assert result.crown_jewel_type == "code"


class TestManualOverrides:
    def test_override_false_suppresses_auto_crown_jewel(self):
        """Manual override is_crown_jewel=false beats auto-classification to true."""
        r = Resource("arn:aws:rds:us-east-1:123:db:dev-db", "rds.instance")
        override = ManualOverride(
            resource_uid="arn:aws:rds:us-east-1:123:db:dev-db",
            tenant_id="tenant-1",
            is_crown_jewel=False,
            reason="Dev database — non-sensitive",
        )
        result = classify_crown_jewel(r, override)
        assert result.is_crown_jewel is False
        assert result.classified_by == "override"

    def test_override_true_promotes_non_crown_jewel(self):
        """Manual override is_crown_jewel=true beats auto-classification to false."""
        r = Resource("arn:aws:s3:::logs-bucket", "s3.bucket",
                     data_classification="none")
        override = ManualOverride(
            resource_uid="arn:aws:s3:::logs-bucket",
            tenant_id="tenant-1",
            is_crown_jewel=True,
            crown_jewel_type="data",
            reason="Contains audit logs required for compliance",
        )
        result = classify_crown_jewel(r, override)
        assert result.is_crown_jewel is True
        assert result.crown_jewel_type == "data"
        assert result.classified_by == "override"

    def test_override_for_different_resource_uid_not_applied(self):
        """Override must match resource_uid exactly — wrong UID is ignored."""
        r = Resource("arn:aws:rds:us-east-1:123:db:prod-db", "rds.instance")
        override = ManualOverride(
            resource_uid="arn:aws:rds:us-east-1:123:db:staging-db",  # different UID
            tenant_id="tenant-1",
            is_crown_jewel=False,
        )
        result = classify_crown_jewel(r, override)
        # Auto-classification of rds.instance should win
        assert result.is_crown_jewel is True
        assert result.classified_by == "auto"

    def test_override_preserved_crown_jewel_type(self):
        """Crown jewel type from override is returned, not auto-classified type."""
        r = Resource("arn:aws:eks:us-east-1:123:cluster/prod", "eks.cluster")
        override = ManualOverride(
            resource_uid="arn:aws:eks:us-east-1:123:cluster/prod",
            tenant_id="tenant-1",
            is_crown_jewel=True,
            crown_jewel_type="identity",  # analyst reclassifies type
        )
        result = classify_crown_jewel(r, override)
        assert result.crown_jewel_type == "identity"  # override type, not infra_control


class TestUnknownResourceType:
    def test_unknown_resource_type_not_crown_jewel(self):
        r = Resource("arn:aws:misc:us-east-1:123:thing/x", "custom.thing")
        result = classify_crown_jewel(r)
        assert result.is_crown_jewel is False

    def test_resource_type_matching_is_case_insensitive(self):
        """Resource type should be lowercased before matching."""
        r = Resource("arn:aws:rds:us-east-1:123:db:mydb", "RDS.Instance")
        result = classify_crown_jewel(r)
        assert result.is_crown_jewel is True
