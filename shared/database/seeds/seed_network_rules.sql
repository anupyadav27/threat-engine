-- ============================================================================
-- Network Engine Rule Seed Data — Task 2.2 [Seq 56 | DE]
-- 12 rules: 4 SG, 2 VPC, 1 NACL, 2 ALB, 3 Anomaly/Threat
-- Uses ON CONFLICT to allow re-running safely
-- ============================================================================

-- ---------------------------------------------------------------------------
-- Security Group Rules (Posture) — NET-SG-001 to NET-SG-004
-- ---------------------------------------------------------------------------

INSERT INTO network_rules (
    rule_id, title, description, mode, category, severity,
    condition_type, condition, evidence_fields, frameworks,
    remediation, "references", csp, is_active
) VALUES (
    'NET-SG-001',
    'SSH open to internet (0.0.0.0/0 on port 22)',
    'Security group allows SSH (port 22) from any IP address (0.0.0.0/0). This exposes the resource to brute-force and unauthorized SSH access from the internet.',
    'posture', 'exposure', 'critical',
    'field_check',
    '{"field": "inbound_rules", "operator": "contains_match", "match": {"port": 22, "cidr": "0.0.0.0/0"}}'::jsonb,
    '["inbound_rules", "resource_id", "vpc_id"]'::jsonb,
    '["CIS_AWS_4.1", "PCI-DSS", "NIST_800-53", "SOC2"]'::jsonb,
    'Restrict SSH access to specific trusted IP addresses or CIDR ranges. Use AWS Systems Manager Session Manager as an alternative.',
    '["https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html#ec2-13"]'::jsonb,
    ARRAY['aws'], TRUE
) ON CONFLICT (rule_id) DO UPDATE SET
    title = EXCLUDED.title,
    condition = EXCLUDED.condition,
    updated_at = NOW();

INSERT INTO network_rules (
    rule_id, title, description, mode, category, severity,
    condition_type, condition, evidence_fields, frameworks,
    remediation, "references", csp, is_active
) VALUES (
    'NET-SG-002',
    'RDP open to internet (0.0.0.0/0 on port 3389)',
    'Security group allows RDP (port 3389) from any IP address. This exposes Windows resources to remote desktop brute-force attacks.',
    'posture', 'exposure', 'critical',
    'field_check',
    '{"field": "inbound_rules", "operator": "contains_match", "match": {"port": 3389, "cidr": "0.0.0.0/0"}}'::jsonb,
    '["inbound_rules", "resource_id", "vpc_id"]'::jsonb,
    '["CIS_AWS_4.2", "PCI-DSS", "NIST_800-53"]'::jsonb,
    'Restrict RDP access to specific trusted IP addresses. Consider using AWS Systems Manager Fleet Manager or a bastion host.',
    '["https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html#ec2-14"]'::jsonb,
    ARRAY['aws'], TRUE
) ON CONFLICT (rule_id) DO UPDATE SET
    title = EXCLUDED.title,
    condition = EXCLUDED.condition,
    updated_at = NOW();

INSERT INTO network_rules (
    rule_id, title, description, mode, category, severity,
    condition_type, condition, evidence_fields, frameworks,
    remediation, "references", csp, is_active
) VALUES (
    'NET-SG-003',
    'All traffic allowed inbound (0.0.0.0/0 all ports)',
    'Security group allows all traffic from any IP on all ports. This effectively disables network-level access control.',
    'posture', 'exposure', 'critical',
    'field_check',
    '{"field": "inbound_rules", "operator": "contains_match", "match": {"port": -1, "cidr": "0.0.0.0/0"}}'::jsonb,
    '["inbound_rules", "resource_id", "vpc_id"]'::jsonb,
    '["CIS_AWS", "PCI-DSS", "SOC2", "HIPAA"]'::jsonb,
    'Remove the unrestricted inbound rule. Apply least-privilege access by allowing only required ports from specific CIDR ranges.',
    '["https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html#ec2-18"]'::jsonb,
    ARRAY['aws'], TRUE
) ON CONFLICT (rule_id) DO UPDATE SET
    title = EXCLUDED.title,
    condition = EXCLUDED.condition,
    updated_at = NOW();

INSERT INTO network_rules (
    rule_id, title, description, mode, category, severity,
    condition_type, condition, evidence_fields, frameworks,
    remediation, "references", csp, is_active
) VALUES (
    'NET-SG-004',
    'All traffic allowed outbound (0.0.0.0/0 all ports)',
    'Security group allows all outbound traffic to any destination. While common, this can facilitate data exfiltration.',
    'posture', 'exposure', 'medium',
    'field_check',
    '{"field": "outbound_rules", "operator": "contains_match", "match": {"port": -1, "cidr": "0.0.0.0/0"}}'::jsonb,
    '["outbound_rules", "resource_id", "vpc_id"]'::jsonb,
    '["CIS_AWS", "SOC2"]'::jsonb,
    'Restrict outbound rules to only allow traffic to necessary destinations and ports.',
    '[]'::jsonb,
    ARRAY['aws'], TRUE
) ON CONFLICT (rule_id) DO UPDATE SET
    title = EXCLUDED.title,
    condition = EXCLUDED.condition,
    updated_at = NOW();

-- ---------------------------------------------------------------------------
-- VPC Rules (Posture) — NET-VPC-001 to NET-VPC-002
-- ---------------------------------------------------------------------------

INSERT INTO network_rules (
    rule_id, title, description, mode, category, severity,
    condition_type, condition, evidence_fields, frameworks,
    remediation, "references", csp, is_active
) VALUES (
    'NET-VPC-001',
    'VPC Flow Logs disabled',
    'VPC does not have flow logging enabled. Flow logs are essential for monitoring network traffic, investigating security incidents, and detecting anomalous behavior.',
    'posture', 'logging', 'high',
    'field_check',
    '{"field": "flow_logs_enabled", "operator": "eq", "value": false}'::jsonb,
    '["flow_logs_enabled", "vpc_id", "resource_id"]'::jsonb,
    '["CIS_AWS_2.9", "PCI-DSS", "HIPAA", "SOC2", "NIST_800-53"]'::jsonb,
    'Enable VPC flow logs and configure them to publish to S3 or CloudWatch Logs. Enable logging for both ACCEPT and REJECT traffic.',
    '["https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html"]'::jsonb,
    ARRAY['aws'], TRUE
) ON CONFLICT (rule_id) DO UPDATE SET
    title = EXCLUDED.title,
    condition = EXCLUDED.condition,
    updated_at = NOW();

INSERT INTO network_rules (
    rule_id, title, description, mode, category, severity,
    condition_type, condition, evidence_fields, frameworks,
    remediation, "references", csp, is_active
) VALUES (
    'NET-VPC-002',
    'VPC does not have DNS resolution enabled',
    'VPC DNS resolution is disabled. This may break service discovery and prevent resources from resolving public DNS names.',
    'posture', 'configuration', 'low',
    'field_check',
    '{"field": "enable_dns_support", "operator": "eq", "value": false}'::jsonb,
    '["enable_dns_support", "enable_dns_hostnames", "vpc_id"]'::jsonb,
    '["CIS_AWS"]'::jsonb,
    'Enable DNS resolution (enableDnsSupport) in the VPC settings.',
    '["https://docs.aws.amazon.com/vpc/latest/userguide/vpc-dns.html"]'::jsonb,
    ARRAY['aws'], TRUE
) ON CONFLICT (rule_id) DO UPDATE SET
    title = EXCLUDED.title,
    condition = EXCLUDED.condition,
    updated_at = NOW();

-- ---------------------------------------------------------------------------
-- NACL Rules (Posture) — NET-NACL-001
-- ---------------------------------------------------------------------------

INSERT INTO network_rules (
    rule_id, title, description, mode, category, severity,
    condition_type, condition, evidence_fields, frameworks,
    remediation, "references", csp, is_active
) VALUES (
    'NET-NACL-001',
    'NACL allows unrestricted inbound on all ports',
    'Network ACL has a rule allowing all inbound traffic (0.0.0.0/0 on all ports). NACLs are stateless and should provide defense-in-depth.',
    'posture', 'exposure', 'high',
    'field_check',
    '{"field": "nacl_inbound_rules", "operator": "contains_match", "match": {"rule_action": "allow", "cidr": "0.0.0.0/0", "port_range": "0-65535"}}'::jsonb,
    '["nacl_inbound_rules", "resource_id", "vpc_id"]'::jsonb,
    '["CIS_AWS", "PCI-DSS", "NIST_800-53"]'::jsonb,
    'Restrict NACL inbound rules to only allow traffic on required ports from known CIDR ranges.',
    '["https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html"]'::jsonb,
    ARRAY['aws'], TRUE
) ON CONFLICT (rule_id) DO UPDATE SET
    title = EXCLUDED.title,
    condition = EXCLUDED.condition,
    updated_at = NOW();

-- ---------------------------------------------------------------------------
-- ALB / TLS Rules (Posture) — NET-ALB-001 to NET-ALB-002
-- ---------------------------------------------------------------------------

INSERT INTO network_rules (
    rule_id, title, description, mode, category, severity,
    condition_type, condition, evidence_fields, frameworks,
    remediation, "references", csp, is_active
) VALUES (
    'NET-ALB-001',
    'ALB listener using HTTP (not HTTPS)',
    'Application Load Balancer listener is configured to use HTTP instead of HTTPS. Traffic is transmitted in plaintext, exposing data to interception.',
    'posture', 'encryption', 'high',
    'field_check',
    '{"field": "protocol", "operator": "eq", "value": "HTTP"}'::jsonb,
    '["protocol", "listener_port", "resource_id"]'::jsonb,
    '["PCI-DSS", "HIPAA", "SOC2", "NIST_800-53"]'::jsonb,
    'Configure the ALB listener to use HTTPS with a valid TLS certificate from ACM.',
    '["https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html"]'::jsonb,
    ARRAY['aws'], TRUE
) ON CONFLICT (rule_id) DO UPDATE SET
    title = EXCLUDED.title,
    condition = EXCLUDED.condition,
    updated_at = NOW();

INSERT INTO network_rules (
    rule_id, title, description, mode, category, severity,
    condition_type, condition, evidence_fields, frameworks,
    remediation, "references", csp, is_active
) VALUES (
    'NET-ALB-002',
    'ALB TLS policy allows TLS 1.0 or 1.1',
    'ALB is configured with a TLS policy that permits TLS 1.0 or 1.1, which have known vulnerabilities.',
    'posture', 'encryption', 'medium',
    'field_check',
    '{"field": "ssl_policy", "operator": "in", "value": ["ELBSecurityPolicy-2016-08", "ELBSecurityPolicy-TLS-1-0-2015-04", "ELBSecurityPolicy-TLS-1-1-2017-01"]}'::jsonb,
    '["ssl_policy", "protocol", "resource_id"]'::jsonb,
    '["PCI-DSS", "NIST_800-53", "HIPAA"]'::jsonb,
    'Update the ALB to use a TLS 1.2+ policy such as ELBSecurityPolicy-TLS13-1-2-2021-06 or ELBSecurityPolicy-FS-1-2-2019-08.',
    '["https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html#describe-ssl-policies"]'::jsonb,
    ARRAY['aws'], TRUE
) ON CONFLICT (rule_id) DO UPDATE SET
    title = EXCLUDED.title,
    condition = EXCLUDED.condition,
    updated_at = NOW();

-- ---------------------------------------------------------------------------
-- Runtime Anomaly Rules — NET-ANOM-001 to NET-ANOM-003
-- ---------------------------------------------------------------------------

INSERT INTO network_rules (
    rule_id, title, description, mode, category, severity,
    condition_type, condition, evidence_fields, frameworks,
    remediation, "references", csp, is_active
) VALUES (
    'NET-ANOM-001',
    'Outbound data spike exceeds 3x baseline',
    'Resource is sending significantly more outbound data than its 14-day baseline average, which may indicate data exfiltration or compromised workload.',
    'runtime', 'anomaly', 'high',
    'threshold',
    '{"metric": "total_bytes", "operator": "gt", "baseline_field": "baseline_bytes", "multiplier": 3.0}'::jsonb,
    '["total_bytes", "baseline_bytes", "deviation_factor", "src_ip", "dst_ip"]'::jsonb,
    '["SOC2", "ISO27001", "NIST_800-53"]'::jsonb,
    'Investigate the source resource for signs of compromise. Review outbound traffic destinations and check for unauthorized data transfers.',
    '[]'::jsonb,
    ARRAY['aws'], TRUE
) ON CONFLICT (rule_id) DO UPDATE SET
    title = EXCLUDED.title,
    condition = EXCLUDED.condition,
    updated_at = NOW();

INSERT INTO network_rules (
    rule_id, title, description, mode, category, severity,
    condition_type, condition, evidence_fields, frameworks,
    remediation, "references", csp, is_active
) VALUES (
    'NET-ANOM-002',
    'Connection to known malicious IP (threat intel)',
    'Network traffic detected to or from an IP address flagged in threat intelligence feeds as malicious, associated with C2 servers, botnets, or known attacker infrastructure.',
    'runtime', 'threat', 'critical',
    'set_membership',
    '{"field": "dst_ip", "operator": "in_set", "set_table": "threat_intel_ioc", "set_column": "indicator_value"}'::jsonb,
    '["dst_ip", "src_ip", "threat_intel_source", "total_bytes"]'::jsonb,
    '["CISA_CE", "PCI-DSS", "SOC2", "ISO27001"]'::jsonb,
    'Immediately isolate the affected resource. Investigate for compromise indicators. Block the malicious IP at the network firewall level.',
    '[]'::jsonb,
    ARRAY['aws'], TRUE
) ON CONFLICT (rule_id) DO UPDATE SET
    title = EXCLUDED.title,
    condition = EXCLUDED.condition,
    updated_at = NOW();

INSERT INTO network_rules (
    rule_id, title, description, mode, category, severity,
    condition_type, condition, evidence_fields, frameworks,
    remediation, "references", csp, is_active
) VALUES (
    'NET-ANOM-003',
    'Port scan detected (>100 unique destination ports in 5 min)',
    'A single source IP connected to more than 100 unique destination ports within a 5-minute window, indicating a port scanning reconnaissance attempt.',
    'runtime', 'anomaly', 'high',
    'threshold',
    '{"metric": "unique_dst_ports", "operator": "gt", "baseline_field": null, "multiplier": null, "absolute_threshold": 100}'::jsonb,
    '["unique_dst_ports", "src_ip", "dst_ip", "total_bytes"]'::jsonb,
    '["ISO27001", "SOC2", "NIST_800-53"]'::jsonb,
    'Investigate the source IP for unauthorized activity. Consider blocking the IP at the security group or NACL level. Review for lateral movement indicators.',
    '[]'::jsonb,
    ARRAY['aws'], TRUE
) ON CONFLICT (rule_id) DO UPDATE SET
    title = EXCLUDED.title,
    condition = EXCLUDED.condition,
    updated_at = NOW();
