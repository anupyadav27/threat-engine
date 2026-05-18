"""Unit tests for the 5 AWS analysis modules."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../engines/api-security"))

from datetime import datetime, timezone, timedelta

import pytest


def _stage(auth_type="NONE", endpoint_types=None, burst=5000, rate=10000,
           arn="arn:aws:apigateway:us-east-1::/restapis/abc123/stages/prod"):
    return {
        "resource_uid": arn,
        "resource_type": "aws.apigateway.stage",
        "resource_name": "prod",
        "configuration": {
            "authorizationType": auth_type,
            "endpointConfiguration": {"types": endpoint_types or ["INTERNET"]},
            "defaultRouteSettings": {
                "throttlingBurstLimit": burst,
                "throttlingRateLimit": rate,
            },
            "restApiId": "abc123",
            "stageName": "prod",
        },
        "tags": {},
    }


def _api(name="payments-v1-legacy", version="v1",
         arn="arn:aws:apigateway:us-east-1::/restapis/abc123"):
    return {
        "resource_uid": arn,
        "resource_type": "aws.apigateway.rest_api",
        "resource_name": name,
        "configuration": {"name": name, "version": version},
        "tags": {},
    }


def _api_key(age_days=100):
    created = (datetime.now(timezone.utc) - timedelta(days=age_days)).isoformat()
    return {
        "resource_uid": "arn:aws:apigateway:us-east-1::/apikeys/key1",
        "resource_type": "aws.apigateway.api_key",
        "resource_name": "key1",
        "configuration": {"name": "my-key", "enabled": True, "createdDate": created},
        "tags": {},
    }


KWARGS = dict(scan_run_id="scan-1", tenant_id="t1", account_id="acct1")


# ─── AuthSchemeModule ─────────────────────────────────────────────────────────

def test_auth_none_public_stage_raises_finding():
    from api_security_engine.modules.auth_scheme import AuthSchemeModule
    findings = AuthSchemeModule().run([_stage("NONE")], **KWARGS)
    assert len(findings) == 1
    assert findings[0]["owasp_api_category"] == "API2"
    assert findings[0]["severity"] == "high"
    assert findings[0]["finding_source"] == "config"


def test_auth_iam_stage_no_finding():
    from api_security_engine.modules.auth_scheme import AuthSchemeModule
    findings = AuthSchemeModule().run([_stage("AWS_IAM")], **KWARGS)
    assert findings == []


def test_auth_jwt_stage_no_finding():
    from api_security_engine.modules.auth_scheme import AuthSchemeModule
    findings = AuthSchemeModule().run([_stage("JWT")], **KWARGS)
    assert findings == []


# ─── ThrottleAuditModule ──────────────────────────────────────────────────────

def test_default_throttle_raises_finding():
    from api_security_engine.modules.throttle_audit import ThrottleAuditModule
    findings = ThrottleAuditModule().run([_stage(burst=5000, rate=10000)], **KWARGS)
    assert len(findings) == 1
    assert findings[0]["owasp_api_category"] == "API4"
    assert findings[0]["severity"] == "medium"


def test_low_throttle_no_finding():
    from api_security_engine.modules.throttle_audit import ThrottleAuditModule
    findings = ThrottleAuditModule().run([_stage(burst=100, rate=50)], **KWARGS)
    assert findings == []


def test_borderline_throttle_no_finding():
    from api_security_engine.modules.throttle_audit import ThrottleAuditModule
    # burst=999 (< 1000) should not trigger
    findings = ThrottleAuditModule().run([_stage(burst=999, rate=499)], **KWARGS)
    assert findings == []


# ─── WAFCoverageModule ────────────────────────────────────────────────────────

def test_no_waf_association_raises_finding():
    from api_security_engine.modules.waf_coverage import WAFCoverageModule
    mod = WAFCoverageModule(waf_map={})
    findings = mod.run([_stage()], **KWARGS)
    assert len(findings) == 1
    assert findings[0]["owasp_api_category"] == "API8"
    assert findings[0]["has_waf"] is False


def test_waf_associated_no_finding():
    from api_security_engine.modules.waf_coverage import WAFCoverageModule
    arn = "arn:aws:apigateway:us-east-1::/restapis/abc123/stages/prod"
    mod = WAFCoverageModule(waf_map={arn: True})
    findings = mod.run([_stage(arn=arn)], **KWARGS)
    assert findings == []


# ─── VersioningAuditModule ────────────────────────────────────────────────────

def test_legacy_api_name_raises_finding():
    from api_security_engine.modules.versioning_audit import VersioningAuditModule
    findings = VersioningAuditModule().run([_api(name="payments-v1-legacy")], **KWARGS)
    assert len(findings) == 1
    assert findings[0]["owasp_api_category"] == "API9"


def test_beta_api_name_raises_finding():
    from api_security_engine.modules.versioning_audit import VersioningAuditModule
    findings = VersioningAuditModule().run([_api(name="payments-beta-api")], **KWARGS)
    assert len(findings) == 1


def test_current_api_name_no_finding():
    from api_security_engine.modules.versioning_audit import VersioningAuditModule
    findings = VersioningAuditModule().run([_api(name="payments-v2", version="2.0")], **KWARGS)
    assert findings == []


# ─── APIKeyExposureModule ─────────────────────────────────────────────────────

def test_key_200_days_old_is_critical():
    from api_security_engine.modules.api_key_exposure import APIKeyExposureModule
    findings = APIKeyExposureModule().run([_api_key(age_days=200)], **KWARGS)
    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"


def test_key_100_days_old_is_high():
    from api_security_engine.modules.api_key_exposure import APIKeyExposureModule
    findings = APIKeyExposureModule().run([_api_key(age_days=100)], **KWARGS)
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"


def test_key_30_days_old_no_finding():
    from api_security_engine.modules.api_key_exposure import APIKeyExposureModule
    findings = APIKeyExposureModule().run([_api_key(age_days=30)], **KWARGS)
    assert findings == []


def test_disabled_key_no_finding():
    from api_security_engine.modules.api_key_exposure import APIKeyExposureModule
    created = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
    res = {
        "resource_uid": "arn:aws:apigateway:us-east-1::/apikeys/key1",
        "resource_type": "aws.apigateway.api_key",
        "resource_name": "key1",
        "configuration": {"name": "my-key", "enabled": False, "createdDate": created},
        "tags": {},
    }
    findings = APIKeyExposureModule().run([res], **KWARGS)
    assert findings == []
