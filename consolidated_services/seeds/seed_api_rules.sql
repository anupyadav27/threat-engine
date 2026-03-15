-- =============================================================================
-- DEPRECATED — API Security Engine removed. Do not run.
-- API Gateway security covered by Check Engine (53 AWS rules). DAST planned for SecOps.
-- See engines/api/DEPRECATED.md
-- =============================================================================
-- API Engine Rule Seeds — Task 4.2
-- 12 rules: OWASP API Top 10 + WAF + Runtime Anomaly
-- =============================================================================

INSERT INTO api_rules (rule_id, title, description, owasp_category, severity,
                       condition_type, condition, frameworks, remediation, csp, is_active)
VALUES

-- API-001: Broken Object Level Authorization (OWASP API1)
('API-001',
 'API endpoint has no authorizer attached',
 'An API endpoint is configured without any authorizer (Cognito, IAM, Lambda, or JWT). '
 'This allows unauthenticated access and violates OWASP API1 — Broken Object Level Authorization.',
 'API1', 'high',
 'field_check',
 '{"field": "auth_required", "operator": "eq", "value": false}',
 ARRAY['OWASP_API_2023', 'PCI-DSS', 'SOC2'],
 'Attach an authorizer (Cognito User Pool, IAM, or Lambda) to every API endpoint. '
 'Use resource-level authorization policies to enforce object-level access control.',
 ARRAY['aws'], true),

-- API-002: Broken Authentication (OWASP API2)
('API-002',
 'API uses API_KEY only without strong authentication',
 'The API relies solely on API key authentication without Cognito, IAM, or JWT-based auth. '
 'API keys are easily leaked and should not be the sole authentication mechanism.',
 'API2', 'medium',
 'field_check',
 '{"field": "auth_type", "operator": "in", "value": ["API_KEY", "NONE", null]}',
 ARRAY['OWASP_API_2023', 'SOC2'],
 'Add Cognito User Pool, IAM, or JWT-based authorization in addition to or instead of API keys. '
 'API keys should only be used for usage tracking, not authentication.',
 ARRAY['aws'], true),

-- API-003: No WAF Associated (OWASP API7)
('API-003',
 'No WAF associated with API',
 'The API does not have an AWS WAF Web ACL associated with it. WAF provides protection '
 'against common web exploits, SQL injection, XSS, and bot traffic.',
 'API7', 'high',
 'field_check',
 '{"field": "has_waf", "operator": "eq", "value": false}',
 ARRAY['OWASP_API_2023', 'PCI-DSS'],
 'Associate an AWS WAF Web ACL with the API Gateway stage or ALB. Configure managed rule groups '
 'for OWASP common attack vectors and rate-based rules.',
 ARRAY['aws'], true),

-- API-004: Unrestricted Resource Consumption (OWASP API4)
('API-004',
 'No rate limiting (usage plan) configured',
 'The API does not have throttling or usage plan configured. Without rate limiting, '
 'the API is vulnerable to resource exhaustion and denial-of-service attacks.',
 'API4', 'high',
 'field_check',
 '{"field": "has_rate_limiting", "operator": "eq", "value": false}',
 ARRAY['OWASP_API_2023', 'PCI-DSS'],
 'Configure a usage plan with throttle settings (burst limit and rate limit) on the API stage. '
 'For HTTP APIs, configure route-level throttling. For ALBs, use WAF rate-based rules.',
 ARRAY['aws'], true),

-- API-005: API access logging not enabled (OWASP API10)
('API-005',
 'API access logging not enabled',
 'Access logging is not configured for the API stage. Without access logs, '
 'you cannot detect anomalous API usage, security incidents, or audit API access.',
 'API10', 'high',
 'field_check',
 '{"field": "logging_enabled", "operator": "eq", "value": false}',
 ARRAY['OWASP_API_2023', 'PCI-DSS', 'HIPAA', 'SOC2'],
 'Enable access logging on the API Gateway stage by configuring a CloudWatch log group destination. '
 'Use JSON log format for structured analysis.',
 ARRAY['aws'], true),

-- API-006: Weak TLS (OWASP API7)
('API-006',
 'TLS 1.0 or 1.1 allowed on listener/stage',
 'The API or ALB listener allows TLS 1.0 or 1.1, which have known vulnerabilities. '
 'Modern security standards require TLS 1.2 as minimum.',
 'API7', 'high',
 'field_check',
 '{"field": "tls_minimum", "operator": "in", "value": ["TLS_1_0", "TLS_1_1", "ELBSecurityPolicy-2016-08"]}',
 ARRAY['OWASP_API_2023', 'PCI-DSS', 'NIST_800-53'],
 'Update the security policy to enforce TLS 1.2 minimum. For API Gateway, set the minimum TLS version '
 'on the custom domain. For ALB, use ELBSecurityPolicy-TLS13-1-2-2021-06 or newer.',
 ARRAY['aws'], true),

-- API-007: No Request Validator (OWASP API8)
('API-007',
 'No request validator configured on API',
 'The API does not have request validation enabled. Without input validation, '
 'the API is vulnerable to injection attacks, malformed requests, and data integrity issues.',
 'API8', 'medium',
 'field_check',
 '{"field": "request_validator", "operator": "eq", "value": false}',
 ARRAY['OWASP_API_2023'],
 'Enable request validation on the API Gateway method. Configure request models to validate '
 'query parameters, headers, and request body against a JSON schema.',
 ARRAY['aws'], true),

-- API-008: CORS Wildcard Origin (OWASP API7)
('API-008',
 'CORS wildcard origin (*) configured',
 'The API allows requests from any origin (CORS Access-Control-Allow-Origin: *). '
 'This can expose the API to cross-site request attacks from malicious websites.',
 'API7', 'high',
 'field_check',
 '{"field": "cors_policy.allow_origins", "operator": "contains", "value": "*"}',
 ARRAY['OWASP_API_2023', 'SOC2'],
 'Restrict CORS origins to specific trusted domains instead of using wildcard (*). '
 'Configure allowed methods and headers to the minimum necessary.',
 ARRAY['aws'], true),

-- API-009: X-Ray Tracing Disabled (OWASP API10)
('API-009',
 'X-Ray tracing disabled on API stage',
 'AWS X-Ray tracing is not enabled on the API stage. X-Ray provides request tracing '
 'for monitoring and debugging API performance and errors.',
 'API10', 'low',
 'field_check',
 '{"field": "xray_tracing_enabled", "operator": "eq", "value": false}',
 ARRAY['SOC2'],
 'Enable X-Ray tracing on the API Gateway stage for request-level tracing and latency analysis.',
 ARRAY['aws'], true),

-- API-010: AppSync Field-Level Logging Disabled (OWASP API10)
('API-010',
 'AppSync field-level logging not enabled',
 'The AppSync GraphQL API does not have field-level logging enabled. Without detailed logging, '
 'you cannot audit individual field resolvers or detect data exfiltration.',
 'API10', 'medium',
 'field_check',
 '{"field": "log_config.fieldLogLevel", "operator": "in", "value": ["NONE", null]}',
 ARRAY['OWASP_API_2023', 'SOC2'],
 'Enable field-level logging on the AppSync API with at least ERROR level. '
 'Configure a CloudWatch log role ARN for log delivery.',
 ARRAY['aws'], true),

-- API-011: Deprecated API Version Active (OWASP API9)
('API-011',
 'Old API version still active alongside newer version',
 'An older version of the API (e.g., v1) is still deployed and active while a newer version '
 '(e.g., v2) exists. Deprecated APIs may not receive security patches.',
 'API9', 'medium',
 'field_check',
 '{"field": "has_newer_version", "operator": "eq", "value": true}',
 ARRAY['OWASP_API_2023'],
 'Deprecate and decommission old API versions once newer versions are stable. '
 'Implement API versioning strategy with sunset dates and migration plans.',
 ARRAY['aws'], true),

-- API-RT-001: Runtime Anomaly — Error Rate Spike
('API-RT-001',
 'API error rate spike exceeds 10% in last 24h',
 'The API error rate (4xx + 5xx responses) exceeded 10% in the last 24-hour window. '
 'This may indicate an ongoing attack, misconfiguration, or application error.',
 'API7', 'medium',
 'threshold',
 '{"metric": "error_rate_pct", "operator": "gt", "baseline_field": null, "absolute_threshold": 10.0}',
 ARRAY['SOC2', 'ISO27001'],
 'Investigate the root cause of the error rate spike. Check CloudWatch logs for 4xx/5xx patterns, '
 'review recent deployments, and verify backend health.',
 ARRAY['aws'], true);

-- =============================================================================
-- End of API Engine Rule Seeds (12 rules)
-- =============================================================================
