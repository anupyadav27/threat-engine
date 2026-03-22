-- ============================================================================
-- DEPRECATED — Container Engine removed. Do not run.
-- K8s pod security covered by Check Engine. ECR posture covered by Check Engine (16 rules).
-- See engines/container/DEPRECATED.md
-- ============================================================================
-- Container Engine Rule Seed — Task 1.2 [Seq 48 | DE]
-- 10 rules across 2 categories (K8s Pod Security + ECR Registry Posture)
-- CVE rules removed — CVE scanning centralized in Vulnerability Engine
-- ============================================================================

-- ---- K8s Pod Security Context Rules (7) ----

INSERT INTO container_rules (rule_id, title, description, category, severity, condition_type, condition, evidence_fields, frameworks, remediation, csp, is_active)
VALUES
(
    'CONT-K8S-001',
    'Container running as root',
    'Container does not set runAsNonRoot=true, allowing processes to run as UID 0.',
    'k8s_security',
    'high',
    'field_check',
    '{"field": "run_as_non_root", "operator": "eq", "value": false}'::jsonb,
    '["run_as_non_root", "pod_name", "namespace"]'::jsonb,
    '["CIS_K8s_5.2.6", "PCI-DSS_2.2", "SOC2_CC6.1"]'::jsonb,
    'Set securityContext.runAsNonRoot: true in the pod spec. Choose a non-root UID with runAsUser.',
    ARRAY['all'],
    TRUE
),
(
    'CONT-K8S-002',
    'Privileged container detected',
    'Container runs with privileged=true, granting full host access including all devices and kernel capabilities.',
    'k8s_security',
    'critical',
    'field_check',
    '{"field": "privileged", "operator": "eq", "value": true}'::jsonb,
    '["privileged", "pod_name", "namespace", "cluster_name"]'::jsonb,
    '["CIS_K8s_5.2.1", "PCI-DSS_2.2", "HIPAA_164.312(a)(1)", "SOC2_CC6.1"]'::jsonb,
    'Remove privileged: true from the container securityContext. Use specific capabilities (CAP_NET_ADMIN, etc.) instead.',
    ARRAY['all'],
    TRUE
),
(
    'CONT-K8S-003',
    'Host network access enabled',
    'Pod uses hostNetwork=true, sharing the host network namespace and bypassing network policies.',
    'k8s_security',
    'high',
    'field_check',
    '{"field": "host_network", "operator": "eq", "value": true}'::jsonb,
    '["host_network", "pod_name", "namespace"]'::jsonb,
    '["CIS_K8s_5.2.4", "PCI-DSS_1.3"]'::jsonb,
    'Remove hostNetwork: true from the pod spec. Use Kubernetes Services and NetworkPolicies for connectivity.',
    ARRAY['all'],
    TRUE
),
(
    'CONT-K8S-004',
    'Privilege escalation allowed',
    'Container does not explicitly disable privilege escalation (allowPrivilegeEscalation is not set to false).',
    'k8s_security',
    'high',
    'composite',
    '{"operator": "or", "conditions": [{"condition_type": "field_check", "condition": {"field": "allow_privilege_escalation", "operator": "eq", "value": true}}, {"condition_type": "field_check", "condition": {"field": "allow_privilege_escalation", "operator": "is_null"}}]}'::jsonb,
    '["allow_privilege_escalation", "pod_name"]'::jsonb,
    '["CIS_K8s_5.2.5", "SOC2_CC6.1"]'::jsonb,
    'Set securityContext.allowPrivilegeEscalation: false explicitly in the container spec.',
    ARRAY['all'],
    TRUE
),
(
    'CONT-K8S-005',
    'No CPU/memory limits set',
    'Container does not define resource limits, risking resource exhaustion and noisy-neighbor issues.',
    'k8s_security',
    'medium',
    'field_check',
    '{"field": "resource_limits", "operator": "is_empty"}'::jsonb,
    '["resource_limits", "pod_name", "namespace"]'::jsonb,
    '["CIS_K8s_5.4.1", "SOC2_CC7.2"]'::jsonb,
    'Set resources.limits with appropriate CPU and memory values in the container spec.',
    ARRAY['all'],
    TRUE
),
(
    'CONT-K8S-006',
    'Default service account used',
    'Pod uses the default service account which may have overly broad RBAC permissions.',
    'k8s_security',
    'medium',
    'field_check',
    '{"field": "service_account", "operator": "eq", "value": "default"}'::jsonb,
    '["service_account", "pod_name", "namespace"]'::jsonb,
    '["CIS_K8s_5.1.5", "SOC2_CC6.3"]'::jsonb,
    'Create a dedicated service account with least-privilege RBAC and set automountServiceAccountToken: false if not needed.',
    ARRAY['all'],
    TRUE
),
(
    'CONT-K8S-007',
    'Root filesystem writable',
    'Container root filesystem is not read-only, allowing attackers to modify binaries or plant malware.',
    'k8s_security',
    'medium',
    'composite',
    '{"operator": "or", "conditions": [{"condition_type": "field_check", "condition": {"field": "read_only_root_fs", "operator": "eq", "value": false}}, {"condition_type": "field_check", "condition": {"field": "read_only_root_fs", "operator": "is_null"}}]}'::jsonb,
    '["read_only_root_fs", "pod_name"]'::jsonb,
    '["CIS_K8s_5.2.8", "PCI-DSS_2.2"]'::jsonb,
    'Set securityContext.readOnlyRootFilesystem: true. Use emptyDir volumes for writable paths.',
    ARRAY['all'],
    TRUE
)
ON CONFLICT (rule_id) DO UPDATE SET
    title = EXCLUDED.title,
    description = EXCLUDED.description,
    condition = EXCLUDED.condition,
    severity = EXCLUDED.severity,
    frameworks = EXCLUDED.frameworks,
    remediation = EXCLUDED.remediation,
    updated_at = NOW();


-- ---- ECR Registry Posture Rules (3) ----

INSERT INTO container_rules (rule_id, title, description, category, severity, condition_type, condition, evidence_fields, frameworks, remediation, csp, is_active)
VALUES
(
    'CONT-ECR-001',
    'ECR image scan on push disabled',
    'ECR repository does not have scan-on-push enabled, meaning pushed images are not automatically scanned for vulnerabilities.',
    'ecr_posture',
    'medium',
    'field_check',
    '{"field": "scan_on_push", "operator": "eq", "value": false}'::jsonb,
    '["scan_on_push", "repository", "registry_type"]'::jsonb,
    '["CIS_AWS_2.1", "HIPAA_164.312(a)(1)"]'::jsonb,
    'Enable image scanning on push in ECR repository settings: aws ecr put-image-scanning-configuration --repository-name <repo> --image-scanning-configuration scanOnPush=true',
    ARRAY['aws'],
    TRUE
),
(
    'CONT-ECR-002',
    'ECR image tags mutable',
    'ECR repository allows tag mutation, meaning image tags can be overwritten with different content.',
    'ecr_posture',
    'low',
    'field_check',
    '{"field": "tag_mutability", "operator": "eq", "value": "MUTABLE"}'::jsonb,
    '["tag_mutability", "repository"]'::jsonb,
    '["CISA_CE", "SOC2_CC8.1"]'::jsonb,
    'Set image tag mutability to IMMUTABLE: aws ecr put-image-tag-mutability --repository-name <repo> --image-tag-mutability IMMUTABLE',
    ARRAY['aws'],
    TRUE
),
(
    'CONT-ECR-003',
    'ECR repository not encrypted with CMK',
    'ECR repository uses default AES256 encryption instead of a customer-managed KMS key.',
    'ecr_posture',
    'medium',
    'composite',
    '{"operator": "or", "conditions": [{"condition_type": "field_check", "condition": {"field": "encryption_type", "operator": "ne", "value": "KMS"}}, {"condition_type": "field_check", "condition": {"field": "encryption_type", "operator": "is_null"}}]}'::jsonb,
    '["encryption_type", "repository"]'::jsonb,
    '["PCI-DSS_3.4", "HIPAA_164.312(a)(2)(iv)", "ISO27001_A.10.1"]'::jsonb,
    'Create ECR repository with KMS encryption: aws ecr create-repository --repository-name <repo> --encryption-configuration encryptionType=KMS,kmsKey=<key-arn>',
    ARRAY['aws'],
    TRUE
)
ON CONFLICT (rule_id) DO UPDATE SET
    title = EXCLUDED.title,
    description = EXCLUDED.description,
    condition = EXCLUDED.condition,
    severity = EXCLUDED.severity,
    frameworks = EXCLUDED.frameworks,
    remediation = EXCLUDED.remediation,
    updated_at = NOW();


-- ---- CVE Severity Rules — REMOVED ----
-- CVE scanning (CONT-CVE-001/002/003) has been centralized in the
-- Vulnerability Engine. Container engine focuses on K8s runtime security
-- context and ECR registry posture only.
-- To deactivate any existing CVE rules in the DB:
UPDATE container_rules SET is_active = FALSE WHERE rule_id IN ('CONT-CVE-001', 'CONT-CVE-002', 'CONT-CVE-003');
