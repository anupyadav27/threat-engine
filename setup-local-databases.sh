#!/bin/bash
# Setup Local PostgreSQL Databases for All Engines
# This script creates clean databases and all required tables

set -e

# Database configuration
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-postgres}"
DB_PASSWORD="${DB_PASSWORD:-postgres}"

# Database names
COMPLIANCE_DB="compliance_engine"
ONBOARDING_DB="threat_engine"
INVENTORY_DB="inventory_engine"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "Local PostgreSQL Database Setup"
echo "=========================================="
echo ""

# Check PostgreSQL connection
echo "Checking PostgreSQL connection..."
export PGPASSWORD="$DB_PASSWORD"
if psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres -c "SELECT 1;" > /dev/null 2>&1; then
    echo -e "${GREEN}✅ PostgreSQL is accessible${NC}"
else
    echo -e "${RED}❌ Cannot connect to PostgreSQL${NC}"
    echo ""
    echo "Please ensure PostgreSQL is running:"
    echo "  brew services start postgresql@14"
    echo "  OR"
    echo "  sudo systemctl start postgresql"
    echo ""
    echo "Or set connection details:"
    echo "  export DB_HOST=localhost"
    echo "  export DB_PORT=5432"
    echo "  export DB_USER=postgres"
    echo "  export DB_PASSWORD=your_password"
    exit 1
fi

# Function to drop database if exists
drop_database() {
    local db_name=$1
    echo "Dropping database '$db_name' if exists..."
    psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres \
        -c "DROP DATABASE IF EXISTS $db_name;" 2>/dev/null || true
    echo -e "${GREEN}  ✅ Database '$db_name' dropped${NC}"
}

# Function to create database
create_database() {
    local db_name=$1
    echo "Creating database '$db_name'..."
    psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres \
        -c "CREATE DATABASE $db_name;" 2>/dev/null || {
        echo -e "${YELLOW}  ⚠️  Database '$db_name' might already exist${NC}"
    }
    echo -e "${GREEN}  ✅ Database '$db_name' created${NC}"
}

# Step 1: Drop existing databases (clean deployment)
echo "Step 1: Cleaning existing databases..."
drop_database "$COMPLIANCE_DB"
drop_database "$ONBOARDING_DB"
drop_database "$INVENTORY_DB"
echo ""

# Step 2: Create databases
echo "Step 2: Creating databases..."
create_database "$COMPLIANCE_DB"
create_database "$ONBOARDING_DB"
create_database "$INVENTORY_DB"
echo ""

# Step 3: Create Compliance Engine tables
echo "Step 3: Creating Compliance Engine tables..."
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$COMPLIANCE_DB" << 'COMPLIANCE_SQL'
-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Tenants Table
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id VARCHAR(255) PRIMARY KEY,
    tenant_name VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Report Index Table
CREATE TABLE IF NOT EXISTS report_index (
    report_id UUID PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    scan_run_id VARCHAR(255) NOT NULL,
    cloud VARCHAR(50) NOT NULL,
    trigger_type VARCHAR(50) NOT NULL,
    collection_mode VARCHAR(50) NOT NULL,
    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE NOT NULL,
    total_controls INTEGER NOT NULL DEFAULT 0,
    controls_passed INTEGER NOT NULL DEFAULT 0,
    controls_failed INTEGER NOT NULL DEFAULT 0,
    total_findings INTEGER NOT NULL DEFAULT 0,
    report_data JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT fk_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- Finding Index Table
CREATE TABLE IF NOT EXISTS finding_index (
    finding_id VARCHAR(255) PRIMARY KEY,
    report_id UUID NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    scan_run_id VARCHAR(255) NOT NULL,
    rule_id VARCHAR(255) NOT NULL,
    rule_version VARCHAR(50),
    category VARCHAR(100),
    severity VARCHAR(20) NOT NULL,
    confidence VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'open',
    first_seen_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL,
    resource_type VARCHAR(100),
    resource_id VARCHAR(255),
    resource_arn TEXT,
    region VARCHAR(50),
    finding_data JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT fk_report FOREIGN KEY (report_id) REFERENCES report_index(report_id) ON DELETE CASCADE,
    CONSTRAINT fk_tenant_finding FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- Compliance Framework Mappings
CREATE TABLE IF NOT EXISTS compliance_framework_mappings (
    id SERIAL PRIMARY KEY,
    rule_id VARCHAR(255) NOT NULL,
    csp VARCHAR(50) NOT NULL,
    framework VARCHAR(100) NOT NULL,
    framework_version VARCHAR(50),
    control_id VARCHAR(100) NOT NULL,
    control_title TEXT,
    control_category VARCHAR(100),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Compliance Scan Results
CREATE TABLE IF NOT EXISTS compliance_scan_results (
    id SERIAL PRIMARY KEY,
    scan_id UUID NOT NULL,
    csp VARCHAR(50) NOT NULL,
    account_id VARCHAR(100),
    framework VARCHAR(100) NOT NULL,
    control_id VARCHAR(100) NOT NULL,
    status VARCHAR(20) NOT NULL,
    rule_id VARCHAR(255),
    resource_arn TEXT,
    severity VARCHAR(20),
    scanned_at TIMESTAMP NOT NULL,
    evidence JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Compliance Scores
CREATE TABLE IF NOT EXISTS compliance_scores (
    id SERIAL PRIMARY KEY,
    scan_id UUID NOT NULL,
    csp VARCHAR(50) NOT NULL,
    account_id VARCHAR(100),
    framework VARCHAR(100) NOT NULL,
    overall_score DECIMAL(5,2),
    controls_total INTEGER,
    controls_passed INTEGER,
    controls_failed INTEGER,
    scanned_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Compliance Trends
CREATE TABLE IF NOT EXISTS compliance_trends (
    id SERIAL PRIMARY KEY,
    csp VARCHAR(50) NOT NULL,
    account_id VARCHAR(100),
    framework VARCHAR(100) NOT NULL,
    score DECIMAL(5,2),
    scanned_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for Compliance Engine
CREATE INDEX IF NOT EXISTS idx_report_tenant_scan ON report_index(tenant_id, scan_run_id);
CREATE INDEX IF NOT EXISTS idx_report_completed_at ON report_index(completed_at DESC);
CREATE INDEX IF NOT EXISTS idx_report_cloud ON report_index(cloud);

CREATE INDEX IF NOT EXISTS idx_finding_tenant_scan ON finding_index(tenant_id, scan_run_id);
CREATE INDEX IF NOT EXISTS idx_finding_severity ON finding_index(severity);
CREATE INDEX IF NOT EXISTS idx_finding_status ON finding_index(status);
CREATE INDEX IF NOT EXISTS idx_finding_rule_id ON finding_index(rule_id);
CREATE INDEX IF NOT EXISTS idx_finding_resource_type ON finding_index(resource_type);
CREATE INDEX IF NOT EXISTS idx_finding_last_seen ON finding_index(last_seen_at DESC);

CREATE INDEX IF NOT EXISTS idx_report_data_gin ON report_index USING gin(report_data);
CREATE INDEX IF NOT EXISTS idx_finding_data_gin ON finding_index USING gin(finding_data);

CREATE INDEX IF NOT EXISTS idx_finding_severity_status ON finding_index(severity, status);
CREATE INDEX IF NOT EXISTS idx_finding_rule_status ON finding_index(rule_id, status);
CREATE INDEX IF NOT EXISTS idx_finding_tenant_severity ON finding_index(tenant_id, severity, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS idx_framework_mappings_rule ON compliance_framework_mappings(rule_id, csp);
CREATE INDEX IF NOT EXISTS idx_scan_results_scan_id ON compliance_scan_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_compliance_scores_scan_id ON compliance_scores(scan_id);
CREATE INDEX IF NOT EXISTS idx_compliance_trends_csp ON compliance_trends(csp, framework, scanned_at);
COMPLIANCE_SQL

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Compliance Engine tables created${NC}"
else
    echo -e "${RED}❌ Failed to create Compliance Engine tables${NC}"
    exit 1
fi
echo ""

# Step 4: Create Onboarding Engine tables
echo "Step 4: Creating Onboarding Engine tables..."
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$ONBOARDING_DB" << 'ONBOARDING_SQL'
-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Tenants Table
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id VARCHAR(255) PRIMARY KEY,
    tenant_name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Providers Table
CREATE TABLE IF NOT EXISTS providers (
    provider_id VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    provider_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    CONSTRAINT fk_provider_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- Accounts Table
CREATE TABLE IF NOT EXISTS accounts (
    account_id VARCHAR(255) PRIMARY KEY,
    provider_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    account_name VARCHAR(255) NOT NULL,
    account_number VARCHAR(50),
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    onboarding_status VARCHAR(50) NOT NULL DEFAULT 'pending',
    onboarding_id VARCHAR(255),
    last_validated_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    CONSTRAINT fk_account_provider FOREIGN KEY (provider_id) REFERENCES providers(provider_id) ON DELETE CASCADE,
    CONSTRAINT fk_account_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- Schedules Table
CREATE TABLE IF NOT EXISTS schedules (
    schedule_id VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    account_id VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    schedule_type VARCHAR(50) NOT NULL,
    provider_type VARCHAR(50) NOT NULL,
    cron_expression VARCHAR(255),
    interval_seconds INTEGER DEFAULT 0,
    regions JSONB DEFAULT '[]',
    services JSONB DEFAULT '[]',
    exclude_services JSONB DEFAULT '[]',
    timezone VARCHAR(50) NOT NULL DEFAULT 'UTC',
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    next_run_at TIMESTAMP WITH TIME ZONE,
    run_count INTEGER NOT NULL DEFAULT 0,
    success_count INTEGER NOT NULL DEFAULT 0,
    failure_count INTEGER NOT NULL DEFAULT 0,
    notify_on_success BOOLEAN NOT NULL DEFAULT FALSE,
    notify_on_failure BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    CONSTRAINT fk_schedule_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    CONSTRAINT fk_schedule_account FOREIGN KEY (account_id) REFERENCES accounts(account_id) ON DELETE CASCADE
);

-- Executions Table
CREATE TABLE IF NOT EXISTS executions (
    execution_id VARCHAR(255) PRIMARY KEY,
    schedule_id VARCHAR(255) NOT NULL,
    account_id VARCHAR(255) NOT NULL,
    scan_id VARCHAR(255),
    started_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(50) NOT NULL DEFAULT 'running',
    triggered_by VARCHAR(50) NOT NULL DEFAULT 'scheduler',
    total_checks INTEGER,
    passed_checks INTEGER,
    failed_checks INTEGER,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    CONSTRAINT fk_execution_schedule FOREIGN KEY (schedule_id) REFERENCES schedules(schedule_id) ON DELETE CASCADE,
    CONSTRAINT fk_execution_account FOREIGN KEY (account_id) REFERENCES accounts(account_id) ON DELETE CASCADE
);

-- Scan Results Table
CREATE TABLE IF NOT EXISTS scan_results (
    scan_id VARCHAR(255) PRIMARY KEY,
    account_id VARCHAR(255) NOT NULL,
    provider_type VARCHAR(50) NOT NULL,
    scan_type VARCHAR(50) NOT NULL DEFAULT 'scheduled',
    started_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(50) NOT NULL DEFAULT 'running',
    total_checks INTEGER,
    passed_checks INTEGER,
    failed_checks INTEGER,
    error_checks INTEGER,
    result_storage_path TEXT,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    CONSTRAINT fk_scan_result_account FOREIGN KEY (account_id) REFERENCES accounts(account_id) ON DELETE CASCADE
);

-- Indexes for Onboarding Engine
CREATE INDEX IF NOT EXISTS idx_providers_tenant ON providers(tenant_id);
CREATE INDEX IF NOT EXISTS idx_providers_type ON providers(provider_type);

CREATE INDEX IF NOT EXISTS idx_accounts_provider ON accounts(provider_id);
CREATE INDEX IF NOT EXISTS idx_accounts_tenant ON accounts(tenant_id);
CREATE INDEX IF NOT EXISTS idx_accounts_status ON accounts(status);

CREATE INDEX IF NOT EXISTS idx_schedules_tenant ON schedules(tenant_id);
CREATE INDEX IF NOT EXISTS idx_schedules_account ON schedules(account_id);
CREATE INDEX IF NOT EXISTS idx_schedules_enabled ON schedules(enabled, next_run_at);
CREATE INDEX IF NOT EXISTS idx_schedules_status ON schedules(status);

CREATE INDEX IF NOT EXISTS idx_executions_schedule ON executions(schedule_id);
CREATE INDEX IF NOT EXISTS idx_executions_account ON executions(account_id);
CREATE INDEX IF NOT EXISTS idx_executions_status ON executions(status);
CREATE INDEX IF NOT EXISTS idx_executions_scan_id ON executions(scan_id);

CREATE INDEX IF NOT EXISTS idx_scan_results_account ON scan_results(account_id);
CREATE INDEX IF NOT EXISTS idx_scan_results_provider ON scan_results(provider_type);
CREATE INDEX IF NOT EXISTS idx_scan_results_status ON scan_results(status);
CREATE INDEX IF NOT EXISTS idx_scan_results_started ON scan_results(started_at DESC);
ONBOARDING_SQL

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Onboarding Engine tables created${NC}"
else
    echo -e "${RED}❌ Failed to create Onboarding Engine tables${NC}"
    exit 1
fi
echo ""

# Step 5: Verify tables
echo "Step 5: Verifying database setup..."
echo ""
echo "Compliance Engine tables:"
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$COMPLIANCE_DB" \
    -c "\dt" | grep -E "tenants|report_index|finding_index|compliance" || true

echo ""
echo "Onboarding Engine tables:"
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$ONBOARDING_DB" \
    -c "\dt" | grep -E "tenants|providers|accounts|schedules|executions|scan_results" || true

echo ""
echo "Step 6: Creating Inventory Engine tables..."
INVENTORY_SCHEMA_PATH="$(dirname "$0")/../inventory-engine/inventory_engine/index/database_schema.sql"
if [ -f "$INVENTORY_SCHEMA_PATH" ]; then
    # First create tenants table (required by FK)
    psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$INVENTORY_DB" << 'INVENTORY_TENANTS_SQL'
-- Tenants Table (required for FK constraints)
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id VARCHAR(255) PRIMARY KEY,
    tenant_name VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
INVENTORY_TENANTS_SQL
    
    # Then run full schema
    psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$INVENTORY_DB" -f "$INVENTORY_SCHEMA_PATH" 2>/dev/null || {
        # If file path doesn't work, embed schema inline
        psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$INVENTORY_DB" << 'INVENTORY_SQL'
-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Tenants Table (if not exists)
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id VARCHAR(255) PRIMARY KEY,
    tenant_name VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Inventory Run Index
CREATE TABLE IF NOT EXISTS inventory_run_index (
    scan_run_id VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(50) NOT NULL,
    total_assets INTEGER NOT NULL DEFAULT 0,
    total_relationships INTEGER NOT NULL DEFAULT 0,
    assets_by_provider JSONB DEFAULT '{}',
    assets_by_resource_type JSONB DEFAULT '{}',
    assets_by_region JSONB DEFAULT '{}',
    providers_scanned JSONB DEFAULT '[]',
    accounts_scanned JSONB DEFAULT '[]',
    regions_scanned JSONB DEFAULT '[]',
    errors_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT fk_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- Asset Index Latest
CREATE TABLE IF NOT EXISTS asset_index_latest (
    asset_id VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    resource_uid TEXT NOT NULL,
    provider VARCHAR(50) NOT NULL,
    account_id VARCHAR(255) NOT NULL,
    region VARCHAR(100),
    resource_type VARCHAR(255) NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    tags JSONB DEFAULT '{}',
    latest_scan_run_id VARCHAR(255) NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT fk_tenant_asset FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    CONSTRAINT fk_scan_run FOREIGN KEY (latest_scan_run_id) REFERENCES inventory_run_index(scan_run_id) ON DELETE CASCADE
);

-- Relationship Index Latest
CREATE TABLE IF NOT EXISTS relationship_index_latest (
    relationship_id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    scan_run_id VARCHAR(255) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    account_id VARCHAR(255) NOT NULL,
    region VARCHAR(100),
    relation_type VARCHAR(100) NOT NULL,
    from_uid TEXT NOT NULL,
    to_uid TEXT NOT NULL,
    properties JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT fk_tenant_rel FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    CONSTRAINT fk_scan_run_rel FOREIGN KEY (scan_run_id) REFERENCES inventory_run_index(scan_run_id) ON DELETE CASCADE
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_run_tenant ON inventory_run_index(tenant_id);
CREATE INDEX IF NOT EXISTS idx_run_completed_at ON inventory_run_index(completed_at DESC);
CREATE INDEX IF NOT EXISTS idx_run_status ON inventory_run_index(status);

CREATE INDEX IF NOT EXISTS idx_asset_tenant ON asset_index_latest(tenant_id);
CREATE INDEX IF NOT EXISTS idx_asset_resource_uid ON asset_index_latest(resource_uid);
CREATE INDEX IF NOT EXISTS idx_asset_provider ON asset_index_latest(provider);
CREATE INDEX IF NOT EXISTS idx_asset_resource_type ON asset_index_latest(resource_type);
CREATE INDEX IF NOT EXISTS idx_asset_region ON asset_index_latest(region);
CREATE INDEX IF NOT EXISTS idx_asset_account ON asset_index_latest(account_id);
CREATE INDEX IF NOT EXISTS idx_asset_tags_gin ON asset_index_latest USING gin(tags);

CREATE INDEX IF NOT EXISTS idx_rel_tenant ON relationship_index_latest(tenant_id);
CREATE INDEX IF NOT EXISTS idx_rel_from_uid ON relationship_index_latest(from_uid);
CREATE INDEX IF NOT EXISTS idx_rel_to_uid ON relationship_index_latest(to_uid);
CREATE INDEX IF NOT EXISTS idx_rel_type ON relationship_index_latest(relation_type);

CREATE INDEX IF NOT EXISTS idx_asset_tenant_type ON asset_index_latest(tenant_id, resource_type);
CREATE INDEX IF NOT EXISTS idx_asset_tenant_region ON asset_index_latest(tenant_id, region);
CREATE INDEX IF NOT EXISTS idx_asset_tenant_provider ON asset_index_latest(tenant_id, provider);
INVENTORY_SQL
    }
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Inventory Engine tables created${NC}"
    else
        echo -e "${RED}❌ Failed to create Inventory Engine tables${NC}"
        exit 1
    fi
else
    echo -e "${YELLOW}⚠️  Inventory schema file not found, skipping${NC}"
fi
echo ""

echo "Inventory Engine tables:"
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$INVENTORY_DB" \
    -c "\dt" | grep -E "inventory_run_index|asset_index_latest|relationship_index_latest" || true

echo ""
echo "=========================================="
echo -e "${GREEN}✅ Database Setup Complete!${NC}"
echo "=========================================="
echo ""
echo "Databases created:"
echo "  - $COMPLIANCE_DB (Compliance Engine)"
echo "  - $ONBOARDING_DB (Onboarding Engine)"
echo "  - $INVENTORY_DB (Inventory Engine)"
echo ""
echo "Connection strings:"
echo "  Compliance Engine:"
echo "    postgresql://$DB_USER:$DB_PASSWORD@$DB_HOST:$DB_PORT/$COMPLIANCE_DB"
echo ""
echo "  Onboarding Engine:"
echo "    postgresql://$DB_USER:$DB_PASSWORD@$DB_HOST:$DB_PORT/$ONBOARDING_DB"
echo ""
echo "  Inventory Engine:"
echo "    postgresql://$DB_USER:$DB_PASSWORD@$DB_HOST:$DB_PORT/$INVENTORY_DB"
echo ""
echo "To test connection:"
echo "  psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $COMPLIANCE_DB"
echo "  psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $ONBOARDING_DB"
echo "  psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $INVENTORY_DB"
echo ""

# Unset password
unset PGPASSWORD

