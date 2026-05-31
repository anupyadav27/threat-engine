"""SpecValidationModule — OWASP API3: Broken Object Property Level Authorization.

Checks API specifications (OpenAPI / Swagger) for properties that expose
excessive data — missing readOnly on sensitive fields, response schemas with
no field-level filtering, and wildcard additionalProperties. These patterns
lead to mass assignment and over-exposure vulnerabilities.
"""

import re
from typing import Any, Dict, List

_SENSITIVE_FIELD_PATTERNS = re.compile(
    r"(password|secret|token|api_key|apikey|credit_card|ssn|social_security"
    r"|cvv|private_key|access_key|refresh_token|auth_token)",
    re.IGNORECASE,
)

_SENSITIVE_RESPONSE_FIELDS: set = {
    "password", "passwordHash", "secret", "token", "accessToken", "refreshToken",
    "apiKey", "api_key", "privateKey", "creditCard", "cvv", "ssn",
}


def _walk_schema_properties(schema: dict, path: str = "") -> List[dict]:
    """Recursively walk an OpenAPI schema object and return (path, property_name, schema) triples."""
    issues = []
    props = schema.get("properties", {}) or {}
    for field_name, field_schema in props.items():
        if not isinstance(field_schema, dict):
            continue
        full_path = f"{path}.{field_name}" if path else field_name
        issues.append({"path": full_path, "name": field_name, "schema": field_schema})
        # Recurse into nested objects
        issues.extend(_walk_schema_properties(field_schema, full_path))
    # Handle array item schemas
    items = schema.get("items")
    if isinstance(items, dict):
        issues.extend(_walk_schema_properties(items, f"{path}[]"))
    return issues


def _check_openapi_spec(spec: dict, resource_uid: str, resource_type: str, api_name: str) -> List[Dict[str, Any]]:
    """Scan an OpenAPI spec dict for OWASP API3 violations."""
    findings = []
    paths = spec.get("paths", {}) or {}

    for path_key, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method not in {"get", "post", "put", "patch", "delete", "options"}:
                continue
            if not isinstance(operation, dict):
                continue

            # Check request body for sensitive fields without readOnly
            req_body = operation.get("requestBody", {}) or {}
            for media_type, media_schema in (req_body.get("content", {}) or {}).items():
                schema = (media_schema.get("schema") or {}) if isinstance(media_schema, dict) else {}
                for prop in _walk_schema_properties(schema):
                    if _SENSITIVE_FIELD_PATTERNS.search(prop["name"]):
                        if not prop["schema"].get("writeOnly", False):
                            findings.append({
                                "rule_id": "api.spec.sensitive_field_not_writeonly",
                                "resource_uid": resource_uid,
                                "resource_type": resource_type,
                                "severity": "medium",
                                "title": "API spec exposes sensitive field without writeOnly constraint",
                                "description": (
                                    f"Field '{prop['path']}' in {method.upper()} {path_key} "
                                    "request body matches a sensitive name pattern but is not "
                                    "marked writeOnly. Mass assignment attacks may exploit this."
                                ),
                                "remediation": (
                                    "Mark sensitive request fields as writeOnly: true in the "
                                    "OpenAPI spec and validate server-side that clients cannot "
                                    "set internal/computed fields."
                                ),
                                "owasp_api_category": "API3",
                                "finding_source": "config",
                                "auth_type": "none",
                                "has_waf": False,
                                "has_rate_limit": False,
                                "is_publicly_accessible": True,
                                "api_gateway_id": resource_uid,
                                "api_name": api_name,
                                "api_stage": "",
                                "evidence": {
                                    "fieldPath": prop["path"],
                                    "operation": f"{method.upper()} {path_key}",
                                },
                            })

            # Check response schemas for sensitive fields without readOnly
            responses = operation.get("responses", {}) or {}
            for status_code, response in responses.items():
                if not isinstance(response, dict):
                    continue
                for media_type, media_schema in (response.get("content", {}) or {}).items():
                    schema = (media_schema.get("schema") or {}) if isinstance(media_schema, dict) else {}
                    for prop in _walk_schema_properties(schema):
                        if prop["name"] in _SENSITIVE_RESPONSE_FIELDS:
                            findings.append({
                                "rule_id": "api.spec.sensitive_field_in_response",
                                "resource_uid": resource_uid,
                                "resource_type": resource_type,
                                "severity": "high",
                                "title": "API spec includes sensitive field in response schema",
                                "description": (
                                    f"Field '{prop['path']}' appears in the {status_code} response "
                                    f"schema for {method.upper()} {path_key}. Returning sensitive "
                                    "data (credentials, tokens) in API responses enables data "
                                    "over-exposure (OWASP API3)."
                                ),
                                "remediation": (
                                    "Remove sensitive fields from response schemas. "
                                    "Apply field-level filtering at the application layer. "
                                    "Use DTOs that explicitly exclude credential fields."
                                ),
                                "owasp_api_category": "API3",
                                "finding_source": "config",
                                "auth_type": "none",
                                "has_waf": False,
                                "has_rate_limit": False,
                                "is_publicly_accessible": True,
                                "api_gateway_id": resource_uid,
                                "api_name": api_name,
                                "api_stage": "",
                                "evidence": {
                                    "fieldPath": prop["path"],
                                    "statusCode": status_code,
                                    "operation": f"{method.upper()} {path_key}",
                                },
                            })

            # Check for wildcard additionalProperties in response (over-exposure)
            for status_code, response in responses.items():
                if not isinstance(response, dict):
                    continue
                for media_type, media_schema in (response.get("content", {}) or {}).items():
                    schema = (media_schema.get("schema") or {}) if isinstance(media_schema, dict) else {}
                    if schema.get("additionalProperties") is True:
                        findings.append({
                            "rule_id": "api.spec.wildcard_additional_properties",
                            "resource_uid": resource_uid,
                            "resource_type": resource_type,
                            "severity": "medium",
                            "title": "API spec uses wildcard additionalProperties in response",
                            "description": (
                                f"Response schema for {method.upper()} {path_key} ({status_code}) "
                                "uses additionalProperties: true, allowing arbitrary fields in the "
                                "response. This may expose unintended internal data."
                            ),
                            "remediation": (
                                "Replace additionalProperties: true with an explicit schema. "
                                "Use a strict DTO to control exactly which fields are returned."
                            ),
                            "owasp_api_category": "API3",
                            "finding_source": "config",
                            "auth_type": "none",
                            "has_waf": False,
                            "has_rate_limit": False,
                            "is_publicly_accessible": True,
                            "api_gateway_id": resource_uid,
                            "api_name": api_name,
                            "api_stage": "",
                            "evidence": {
                                "operation": f"{method.upper()} {path_key}",
                                "statusCode": status_code,
                            },
                        })

    return findings


class SpecValidationModule:
    """Validate OpenAPI specifications attached to API gateway resources for OWASP API3 gaps."""

    def run(
        self,
        api_resources: List[Dict[str, Any]],
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        for res in api_resources:
            config = res.get("configuration") or {}
            name = config.get("name") or res.get("resource_name", "")

            # AWS API Gateway v1: body field contains OpenAPI JSON
            spec = config.get("body") or config.get("openApiSpec") or {}
            if isinstance(spec, str):
                import json
                try:
                    spec = json.loads(spec)
                except Exception:
                    spec = {}

            # GCP: openApiDocuments list
            if not spec:
                for doc in (config.get("openApiDocuments") or []):
                    if isinstance(doc, dict) and doc.get("document"):
                        import json
                        try:
                            spec = json.loads(doc["document"].get("contents", "{}"))
                            break
                        except Exception:
                            pass

            if not spec or not isinstance(spec, dict):
                continue

            findings.extend(
                _check_openapi_spec(spec, res["resource_uid"], res["resource_type"], name)
            )

        return findings
