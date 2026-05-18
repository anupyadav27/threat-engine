"""Tests for Sprint 2/3 modules: BackendSSRFModule, MTLSGapModule, GraphQLIntrospectionModule, SpecValidationModule."""

import pytest
from api_security_engine.modules.backend_ssrf import BackendSSRFModule
from api_security_engine.modules.mtls_gap import MTLSGapModule
from api_security_engine.modules.graphql_introspection import GraphQLIntrospectionModule
from api_security_engine.modules.spec_validation import SpecValidationModule

SCAN = "00000000-0000-0000-0000-000000000001"
TENANT = "tenant-1"
ACCOUNT = "123456789012"


def _res(rtype, config):
    return {
        "resource_uid": f"arn:aws:test/{rtype}",
        "resource_type": rtype,
        "resource_name": "test-api",
        "provider": rtype.split(".")[0],
        "configuration": config,
        "tags": {},
    }


# ── BackendSSRFModule ────────────────────────────────────────────────────────

class TestBackendSSRF:
    def test_metadata_url_is_critical(self):
        res = _res("aws.apigateway.rest_api", {"uri": "http://169.254.169.254/latest/meta-data"})
        findings = BackendSSRFModule().run([res], SCAN, TENANT, ACCOUNT)
        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"
        assert findings[0]["owasp_api_category"] == "API7"

    def test_rfc1918_is_high(self):
        res = _res("aws.apigateway.rest_api", {"uri": "http://10.0.1.5/internal"})
        findings = BackendSSRFModule().run([res], SCAN, TENANT, ACCOUNT)
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"

    def test_public_url_no_finding(self):
        res = _res("aws.apigateway.rest_api", {"uri": "https://api.external.com/v1"})
        findings = BackendSSRFModule().run([res], SCAN, TENANT, ACCOUNT)
        assert len(findings) == 0

    def test_no_backend_url_no_finding(self):
        res = _res("aws.apigateway.rest_api", {})
        findings = BackendSSRFModule().run([res], SCAN, TENANT, ACCOUNT)
        assert len(findings) == 0


# ── MTLSGapModule ────────────────────────────────────────────────────────────

class TestMTLSGap:
    def test_rest_api_without_mtls_flagged(self):
        res = _res("aws.apigateway.rest_api", {"name": "my-api"})
        findings = MTLSGapModule().run([res], SCAN, TENANT, ACCOUNT)
        assert len(findings) == 1
        assert findings[0]["owasp_api_category"] == "API2"

    def test_rest_api_with_mtls_no_finding(self):
        res = _res("aws.apigateway.rest_api", {
            "mutualTlsAuthentication": {"truststoreUri": "s3://bucket/ca.pem"}
        })
        findings = MTLSGapModule().run([res], SCAN, TENANT, ACCOUNT)
        assert len(findings) == 0

    def test_non_eligible_resource_type_skipped(self):
        res = _res("aws.apigatewayv2.route", {"name": "route"})
        findings = MTLSGapModule().run([res], SCAN, TENANT, ACCOUNT)
        assert len(findings) == 0


# ── GraphQLIntrospectionModule ───────────────────────────────────────────────

class TestGraphQLIntrospection:
    def test_appsync_introspection_enabled_flagged(self):
        res = _res("aws.appsync.graphql_api", {
            "name": "my-graphql",
            "introspectionConfig": "ENABLED",
            "authenticationType": "API_KEY",
        })
        findings = GraphQLIntrospectionModule().run([res], SCAN, TENANT, ACCOUNT)
        rule_ids = {f["rule_id"] for f in findings}
        assert "aws.appsync.graphql_api.introspection_enabled" in rule_ids

    def test_appsync_disabled_no_introspection_finding(self):
        res = _res("aws.appsync.graphql_api", {
            "name": "secure-gql",
            "introspectionConfig": "DISABLED",
            "logConfig": {"cloudWatchLogsRoleArn": "arn:aws:iam::123:role/appsync-log"},
        })
        findings = GraphQLIntrospectionModule().run([res], SCAN, TENANT, ACCOUNT)
        rule_ids = {f["rule_id"] for f in findings}
        assert "aws.appsync.graphql_api.introspection_enabled" not in rule_ids

    def test_appsync_no_logging_flagged(self):
        res = _res("aws.appsync.graphql_api", {
            "name": "my-graphql",
            "introspectionConfig": "DISABLED",
        })
        findings = GraphQLIntrospectionModule().run([res], SCAN, TENANT, ACCOUNT)
        rule_ids = {f["rule_id"] for f in findings}
        assert "aws.appsync.graphql_api.no_field_logging" in rule_ids

    def test_non_graphql_resource_skipped(self):
        res = _res("aws.apigateway.rest_api", {"name": "plain-rest"})
        findings = GraphQLIntrospectionModule().run([res], SCAN, TENANT, ACCOUNT)
        assert len(findings) == 0


# ── SpecValidationModule ─────────────────────────────────────────────────────

class TestSpecValidation:
    def _spec_with_sensitive_response(self):
        return {
            "paths": {
                "/user": {
                    "get": {
                        "responses": {
                            "200": {
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "properties": {
                                                "password": {"type": "string"},
                                                "name": {"type": "string"},
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

    def test_sensitive_response_field_flagged(self):
        res = _res("aws.apigateway.rest_api", {"body": self._spec_with_sensitive_response()})
        findings = SpecValidationModule().run([res], SCAN, TENANT, ACCOUNT)
        rule_ids = {f["rule_id"] for f in findings}
        assert "api.spec.sensitive_field_in_response" in rule_ids

    def test_wildcard_additional_properties_flagged(self):
        spec = {
            "paths": {
                "/data": {
                    "get": {
                        "responses": {
                            "200": {
                                "content": {
                                    "application/json": {
                                        "schema": {"additionalProperties": True}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        res = _res("aws.apigateway.rest_api", {"body": spec})
        findings = SpecValidationModule().run([res], SCAN, TENANT, ACCOUNT)
        rule_ids = {f["rule_id"] for f in findings}
        assert "api.spec.wildcard_additional_properties" in rule_ids

    def test_no_spec_no_finding(self):
        res = _res("aws.apigateway.rest_api", {"name": "no-spec"})
        findings = SpecValidationModule().run([res], SCAN, TENANT, ACCOUNT)
        assert len(findings) == 0
