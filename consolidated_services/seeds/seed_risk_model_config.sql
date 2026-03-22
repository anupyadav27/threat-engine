-- =============================================================================
-- Risk Engine Model Config Seeds — Task 5.2
-- Per-industry FAIR model parameters (IBM Cost of Breach 2024 benchmarks)
-- =============================================================================

INSERT INTO risk_model_config (tenant_id, industry, per_record_cost, revenue_range,
                                estimated_annual_revenue, applicable_regs,
                                downtime_cost_hr, sensitivity_multipliers,
                                default_record_count, is_default)
VALUES

-- Healthcare (highest per-record cost)
(NULL, 'healthcare', 10.93, NULL, NULL,
 '["HIPAA", "GDPR"]',
 25000.00,
 '{"restricted": 3.0, "confidential": 2.0, "internal": 1.0, "public": 0.1}',
 5000, true),

-- Finance / Banking
(NULL, 'finance', 6.08, NULL, NULL,
 '["PCI_DSS", "GDPR", "SOX"]',
 50000.00,
 '{"restricted": 3.0, "confidential": 2.0, "internal": 1.0, "public": 0.1}',
 10000, true),

-- Technology
(NULL, 'technology', 4.88, NULL, NULL,
 '["GDPR", "CCPA"]',
 15000.00,
 '{"restricted": 3.0, "confidential": 2.0, "internal": 1.0, "public": 0.1}',
 5000, true),

-- Retail / E-commerce
(NULL, 'retail', 3.28, NULL, NULL,
 '["PCI_DSS", "GDPR", "CCPA"]',
 10000.00,
 '{"restricted": 3.0, "confidential": 2.0, "internal": 1.0, "public": 0.1}',
 50000, true),

-- Default (cross-industry average)
(NULL, 'default', 4.45, NULL, NULL,
 '["GDPR"]',
 10000.00,
 '{"restricted": 3.0, "confidential": 2.0, "internal": 1.0, "public": 0.1}',
 1000, true);

-- =============================================================================
-- End of Risk Model Config Seeds (5 industry profiles)
-- =============================================================================
