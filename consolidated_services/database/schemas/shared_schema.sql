-- PostgreSQL Schema for Shared Cross-Engine Data
-- Common tables and data shared across all engines

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Global Tenants Table (referenced by all engines)
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id VARCHAR(255) PRIMARY KEY,
    tenant_name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'active',  -- 'active', 'suspended', 'inactive'
    tier VARCHAR(50) DEFAULT 'standard',  -- 'free', 'standard', 'premium', 'enterprise'
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'
);

-- Global Customers Table (for multi-tenant scenarios)
CREATE TABLE IF NOT EXISTS customers (
    customer_id VARCHAR(255) PRIMARY KEY,
    customer_name VARCHAR(255) NOT NULL,
    customer_type VARCHAR(50) DEFAULT 'enterprise',  -- 'individual', 'startup', 'enterprise'
    contact_email VARCHAR(255),
    billing_info JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'
);

-- Cross-Engine Scan Orchestration
CREATE TABLE IF NOT EXISTS scan_orchestration (
    orchestration_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(255) NOT NULL,
    scan_name VARCHAR(255),
    scan_type VARCHAR(50) NOT NULL,  -- 'full', 'incremental', 'targeted'
    trigger_type VARCHAR(50) NOT NULL,  -- 'manual', 'scheduled', 'event_driven'
    engines_requested JSONB NOT NULL,  -- ['configscan', 'compliance', 'inventory', 'threat']
    engines_completed JSONB DEFAULT '[]',
    overall_status VARCHAR(50) NOT NULL DEFAULT 'pending',  -- 'pending', 'running', 'completed', 'failed'
    started_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    total_resources INTEGER DEFAULT 0,
    total_findings INTEGER DEFAULT 0,
    scan_config JSONB DEFAULT '{}',
    results_summary JSONB DEFAULT '{}',
    error_details JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT fk_tenant_orchestration FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- Engine Status and Health Monitoring
CREATE TABLE IF NOT EXISTS engine_status (
    engine_id VARCHAR(50) PRIMARY KEY,  -- 'configscan', 'compliance', 'inventory', 'threat'
    tenant_id VARCHAR(255),  -- NULL for global engine status
    status VARCHAR(50) NOT NULL,  -- 'healthy', 'degraded', 'down', 'maintenance'
    last_heartbeat TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    version VARCHAR(50),
    health_metrics JSONB DEFAULT '{}',  -- CPU, memory, queue depth, etc.
    error_count INTEGER DEFAULT 0,
    warning_count INTEGER DEFAULT 0,
    uptime_seconds INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT fk_tenant_engine FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- Cross-Engine Notifications and Alerts
CREATE TABLE IF NOT EXISTS notifications (
    notification_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(255) NOT NULL,
    source_engine VARCHAR(50) NOT NULL,  -- Which engine generated this
    notification_type VARCHAR(50) NOT NULL,  -- 'alert', 'info', 'warning', 'error'
    category VARCHAR(100),  -- 'security', 'compliance', 'performance', 'system'
    priority VARCHAR(20) NOT NULL,  -- 'low', 'medium', 'high', 'critical'
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    details JSONB DEFAULT '{}',
    affected_resources JSONB DEFAULT '[]',
    action_required BOOLEAN DEFAULT FALSE,
    acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_by VARCHAR(255),
    acknowledged_at TIMESTAMP WITH TIME ZONE,
    resolved BOOLEAN DEFAULT FALSE,
    resolved_by VARCHAR(255),
    resolved_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT fk_tenant_notification FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- Cross-Engine Audit Log
CREATE TABLE IF NOT EXISTS audit_log (
    log_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(255) NOT NULL,
    user_id VARCHAR(255),
    session_id VARCHAR(255),
    action VARCHAR(100) NOT NULL,  -- 'scan_started', 'config_updated', 'user_login'
    entity_type VARCHAR(50),  -- 'tenant', 'user', 'scan', 'rule'
    entity_id VARCHAR(255),
    source_engine VARCHAR(50),  -- Which engine logged this
    source_ip INET,
    user_agent TEXT,
    request_details JSONB DEFAULT '{}',
    response_details JSONB DEFAULT '{}',
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT,
    execution_time_ms INTEGER,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT fk_tenant_audit FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- Global Configuration Store
CREATE TABLE IF NOT EXISTS global_config (
    config_key VARCHAR(255) PRIMARY KEY,
    config_value JSONB NOT NULL,
    config_type VARCHAR(50) DEFAULT 'system',  -- 'system', 'engine', 'tenant'
    description TEXT,
    is_encrypted BOOLEAN DEFAULT FALSE,
    is_sensitive BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_by VARCHAR(255)
);

-- Tenant-Specific Configuration
CREATE TABLE IF NOT EXISTS tenant_config (
    tenant_id VARCHAR(255) NOT NULL,
    config_key VARCHAR(255) NOT NULL,
    config_value JSONB NOT NULL,
    config_type VARCHAR(50) DEFAULT 'tenant',
    description TEXT,
    is_encrypted BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_by VARCHAR(255),
    
    PRIMARY KEY (tenant_id, config_key),
    CONSTRAINT fk_tenant_config FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- Cross-Engine Data Lineage and Relationships
CREATE TABLE IF NOT EXISTS data_lineage (
    lineage_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(255) NOT NULL,
    parent_entity_type VARCHAR(50) NOT NULL,  -- 'scan', 'resource', 'finding'
    parent_entity_id VARCHAR(255) NOT NULL,
    parent_engine VARCHAR(50) NOT NULL,
    child_entity_type VARCHAR(50) NOT NULL,
    child_entity_id VARCHAR(255) NOT NULL,
    child_engine VARCHAR(50) NOT NULL,
    relationship_type VARCHAR(50) NOT NULL,  -- 'generated_from', 'enriched_by', 'triggered_by'
    relationship_data JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT fk_tenant_lineage FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- Performance Indexes
CREATE INDEX IF NOT EXISTS idx_tenants_status ON tenants(status);
CREATE INDEX IF NOT EXISTS idx_tenants_tier ON tenants(tier);
CREATE INDEX IF NOT EXISTS idx_customers_type ON customers(customer_type);

CREATE INDEX IF NOT EXISTS idx_orchestration_tenant ON scan_orchestration(tenant_id);
CREATE INDEX IF NOT EXISTS idx_orchestration_status ON scan_orchestration(overall_status, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_orchestration_type ON scan_orchestration(scan_type, trigger_type);

CREATE INDEX IF NOT EXISTS idx_engine_status_engine ON engine_status(engine_id, tenant_id);
CREATE INDEX IF NOT EXISTS idx_engine_status_health ON engine_status(status, last_heartbeat DESC);

CREATE INDEX IF NOT EXISTS idx_notifications_tenant ON notifications(tenant_id);
CREATE INDEX IF NOT EXISTS idx_notifications_priority ON notifications(priority, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notifications_unacked ON notifications(acknowledged, action_required);
CREATE INDEX IF NOT EXISTS idx_notifications_source ON notifications(source_engine, notification_type);

CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_log(tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_log(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_audit_source ON audit_log(source_engine, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_global_config_type ON global_config(config_type);
CREATE INDEX IF NOT EXISTS idx_tenant_config_tenant ON tenant_config(tenant_id);

CREATE INDEX IF NOT EXISTS idx_lineage_tenant ON data_lineage(tenant_id);
CREATE INDEX IF NOT EXISTS idx_lineage_parent ON data_lineage(parent_engine, parent_entity_type, parent_entity_id);
CREATE INDEX IF NOT EXISTS idx_lineage_child ON data_lineage(child_engine, child_entity_type, child_entity_id);
CREATE INDEX IF NOT EXISTS idx_lineage_relationship ON data_lineage(relationship_type);

-- JSONB GIN Indexes
CREATE INDEX IF NOT EXISTS idx_orchestration_engines_gin ON scan_orchestration USING gin(engines_requested);
CREATE INDEX IF NOT EXISTS idx_orchestration_results_gin ON scan_orchestration USING gin(results_summary);
CREATE INDEX IF NOT EXISTS idx_engine_metrics_gin ON engine_status USING gin(health_metrics);
CREATE INDEX IF NOT EXISTS idx_notifications_details_gin ON notifications USING gin(details);
CREATE INDEX IF NOT EXISTS idx_audit_request_gin ON audit_log USING gin(request_details);
CREATE INDEX IF NOT EXISTS idx_global_config_value_gin ON global_config USING gin(config_value);
CREATE INDEX IF NOT EXISTS idx_tenant_config_value_gin ON tenant_config USING gin(config_value);

-- Triggers for updated_at
CREATE OR REPLACE FUNCTION update_shared_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

DROP TRIGGER IF EXISTS update_tenants_updated_at ON tenants;
CREATE TRIGGER update_tenants_updated_at BEFORE UPDATE ON tenants
    FOR EACH ROW EXECUTE FUNCTION update_shared_updated_at_column();

DROP TRIGGER IF EXISTS update_engine_status_updated_at ON engine_status;
CREATE TRIGGER update_engine_status_updated_at BEFORE UPDATE ON engine_status
    FOR EACH ROW EXECUTE FUNCTION update_shared_updated_at_column();

DROP TRIGGER IF EXISTS update_global_config_updated_at ON global_config;
CREATE TRIGGER update_global_config_updated_at BEFORE UPDATE ON global_config
    FOR EACH ROW EXECUTE FUNCTION update_shared_updated_at_column();

DROP TRIGGER IF EXISTS update_tenant_config_updated_at ON tenant_config;
CREATE TRIGGER update_tenant_config_updated_at BEFORE UPDATE ON tenant_config
    FOR EACH ROW EXECUTE FUNCTION update_shared_updated_at_column();

-- Insert default global configurations
INSERT INTO global_config (config_key, config_value, config_type, description) VALUES 
('scan.default_timeout', '"3600"', 'system', 'Default scan timeout in seconds'),
('scan.max_parallel_engines', '"4"', 'system', 'Maximum number of engines that can run in parallel'),
('notifications.default_retention_days', '"90"', 'system', 'Default retention period for notifications'),
('audit.default_retention_days', '"365"', 'system', 'Default retention period for audit logs'),
('engines.health_check_interval', '"60"', 'system', 'Health check interval in seconds')
ON CONFLICT (config_key) DO NOTHING;

-- Insert default engine status records
INSERT INTO engine_status (engine_id, status, version) VALUES 
('configscan', 'healthy', '1.0.0'),
('compliance', 'healthy', '1.0.0'),
('inventory', 'healthy', '1.0.0'),
('threat', 'healthy', '1.0.0')
ON CONFLICT (engine_id) DO NOTHING;