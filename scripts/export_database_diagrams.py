#!/usr/bin/env python3
"""
Export database ER diagrams to PNG/SVG images.

Requirements:
    npm install -g @mermaid-js/mermaid-cli
    OR
    pip install playwright
    playwright install chromium

Usage:
    python scripts/export_database_diagrams.py
    python scripts/export_database_diagrams.py --format svg
    python scripts/export_database_diagrams.py --output docs/diagrams
"""

import os
import sys
import subprocess
import argparse
import tempfile
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Diagram definitions
DIAGRAMS = {
    "dynamodb": {
        "name": "DynamoDB Schema (Onboarding Engine)",
        "type": "erDiagram",
        "content": """erDiagram
    dynamodb_tenants ||--o{ dynamodb_providers : "has_many"
    dynamodb_providers ||--o{ dynamodb_accounts : "has_many"
    dynamodb_accounts ||--o{ dynamodb_schedules : "has_many"
    dynamodb_schedules ||--o{ dynamodb_executions : "triggers_many"
    dynamodb_executions ||--o{ dynamodb_scan_metadata : "generates"
    dynamodb_scan_metadata ||--o{ dynamodb_orchestration_status : "tracks_engines"
    dynamodb_accounts ||--o{ dynamodb_executions : "executes_scans"
    dynamodb_accounts ||--o{ dynamodb_scan_metadata : "scanned_in"
    
    dynamodb_tenants {
        string tenant_id PK "Primary Key (HASH)"
        string tenant_name "Tenant Name"
        string description "Tenant Description"
        string status "active|inactive"
        string created_at "Created Timestamp"
        string updated_at "Updated Timestamp"
        map metadata "Additional Metadata"
    }
    
    dynamodb_providers {
        string provider_id PK "Primary Key (HASH)"
        string tenant_id FK "Foreign Key to tenants"
        string provider_type "AWS|Azure|GCP|AliCloud|OCI|IBM"
        string status "active|inactive"
        string created_at "Created Timestamp"
        string updated_at "Updated Timestamp"
        map metadata "Additional Metadata"
    }
    
    dynamodb_accounts {
        string account_id PK "Primary Key (HASH)"
        string provider_id FK "Foreign Key to providers"
        string tenant_id FK "Foreign Key to tenants"
        string account_name "Account Name"
        string account_number "Account Number"
        string status "active|inactive"
        string onboarding_status "pending|completed|failed"
        string last_validated_at "Last Validation Time"
        string created_at "Created Timestamp"
        string updated_at "Updated Timestamp"
        map metadata "Additional Metadata"
    }
    
    dynamodb_schedules {
        string schedule_id PK "Primary Key (HASH)"
        string tenant_id FK "Foreign Key to tenants"
        string account_id FK "Foreign Key to accounts"
        string name "Schedule Name"
        string description "Schedule Description"
        string schedule_type "cron|interval"
        string cron_expression "Cron Expression"
        number interval_seconds "Interval in Seconds"
        string timezone "Timezone"
        list regions "Regions to Scan"
        list services "Services to Scan"
        list exclude_services "Services to Exclude"
        string status "active|paused"
        boolean enabled "Is Schedule Enabled"
        string last_run_at "Last Run Time"
        string next_run_at "Next Run Time"
        number run_count "Total Runs"
        number success_count "Successful Runs"
        number failure_count "Failed Runs"
        boolean notify_on_success "Notify on Success"
        boolean notify_on_failure "Notify on Failure"
        list notification_channels "Notification Channels"
        string created_at "Created Timestamp"
        string updated_at "Updated Timestamp"
    }
    
    dynamodb_executions {
        string execution_id PK "Primary Key (HASH)"
        string schedule_id FK "Foreign Key to schedules"
        string account_id FK "Foreign Key to accounts"
        string started_at "Execution Start Time"
        string completed_at "Execution Completion Time"
        string status "running|success|failed"
        string scan_id "Legacy Scan ID"
        string scan_run_id "Unified Scan Run ID"
        number total_checks "Total Checks"
        number passed_checks "Passed Checks"
        number failed_checks "Failed Checks"
        string error_message "Error Message (if failed)"
        string triggered_by "manual|scheduled|api"
        number execution_time_seconds "Execution Duration"
        string created_at "Created Timestamp"
    }
    
    dynamodb_scan_metadata {
        string scan_run_id PK "Primary Key (HASH)"
        string tenant_id FK "Foreign Key to tenants"
        string account_id FK "Foreign Key to accounts"
        string provider "Cloud Provider"
        string status "running|completed|failed"
        string started_at "Scan Start Time"
        string completed_at "Scan Completion Time"
        list engines_triggered "Engines Triggered"
        list engines_completed "Engines Completed"
        list engines_failed "Engines Failed"
        map metadata "Additional Metadata"
    }
    
    dynamodb_orchestration_status {
        string scan_run_id PK "Composite Key Part 1"
        string engine PK "Composite Key Part 2 (threat|compliance|datasec|inventory)"
        string status "pending|running|completed|failed"
        string started_at "Engine Start Time"
        string completed_at "Engine Completion Time"
        string error_message "Error Message (if failed)"
        map metadata "Additional Metadata"
    }"""
    },
    "configscan": {
        "name": "PostgreSQL Schema (ConfigScan Engine)",
        "type": "erDiagram",
        "content": """erDiagram
    customers ||--o{ tenants : "has_many"
    tenants ||--o{ csp_hierarchies : "has_many"
    csp_hierarchies ||--o{ csp_hierarchies : "parent_child"
    customers ||--o{ scans : "triggers"
    tenants ||--o{ scans : "belongs_to"
    csp_hierarchies ||--o{ scans : "scanned_in"
    scans ||--o{ discoveries : "contains_many"
    scans ||--o{ check_results : "contains_many"
    customers ||--o{ checks : "defines_custom"
    tenants ||--o{ checks : "defines_custom"
    discoveries ||--o{ discovery_history : "tracks_changes"
    discovery_history ||--o{ drift_detections : "generates_alerts"
    scans ||--o{ discovery_history : "creates_history"
    
    customers {
        string customer_id PK "Primary Key"
        string customer_name "Customer Name"
        timestamp created_at "Created Timestamp"
        jsonb metadata "Additional Metadata"
    }
    
    tenants {
        string tenant_id PK "Primary Key"
        string customer_id FK "Foreign Key to customers"
        string provider "AWS|Azure|GCP|AliCloud|OCI|IBM"
        string tenant_name "Tenant Name"
        timestamp created_at "Created Timestamp"
        jsonb metadata "Additional Metadata"
    }
    
    csp_hierarchies {
        int id PK "Primary Key (Auto Increment)"
        string tenant_id FK "Foreign Key to tenants"
        string provider "Cloud Provider"
        string hierarchy_type "account|project|subscription|org|resource_group"
        string hierarchy_id "Account/Project ID"
        string hierarchy_name "Display Name"
        int parent_id FK "Self-Referencing FK (nullable)"
        jsonb metadata "Additional Metadata"
        timestamp created_at "Created Timestamp"
    }
    
    scans {
        string scan_id PK "Primary Key"
        string customer_id FK "Foreign Key to customers"
        string tenant_id FK "Foreign Key to tenants"
        string provider "Cloud Provider"
        string hierarchy_id "Account/Project ID"
        string hierarchy_type "Type of Hierarchy"
        string region "AWS Region"
        string service "Service Name"
        timestamp scan_timestamp "When Scan Ran"
        string scan_type "discovery|check|full"
        string status "running|completed|failed|partial"
        jsonb metadata "Additional Metadata"
    }
    
    discoveries {
        int id PK "Primary Key (Auto Increment)"
        string scan_id FK "Foreign Key to scans"
        string customer_id FK "Foreign Key to customers"
        string tenant_id FK "Foreign Key to tenants"
        string provider "Cloud Provider"
        string hierarchy_id "Account/Project ID"
        string hierarchy_type "Type of Hierarchy"
        string discovery_id "API Method ID (e.g., aws.s3.get_bucket_encryption)"
        string region "AWS Region"
        string service "Service Name"
        text resource_arn "Resource ARN"
        string resource_id "Resource ID"
        jsonb raw_response "Full API Response"
        jsonb emitted_fields "Extracted Fields"
        string config_hash "SHA256 Hash for Drift Detection"
        timestamp scan_timestamp "When Discovery Ran"
        int version "Version Number"
    }
    
    discovery_history {
        int id PK "Primary Key (Auto Increment)"
        string customer_id FK "Foreign Key to customers"
        string tenant_id FK "Foreign Key to tenants"
        string provider "Cloud Provider"
        string hierarchy_id "Account/Project ID"
        string hierarchy_type "Type of Hierarchy"
        string discovery_id "API Method ID"
        text resource_arn "Resource ARN"
        string scan_id "Scan ID"
        string config_hash "Current Config Hash"
        jsonb raw_response "Full API Response"
        jsonb emitted_fields "Extracted Fields"
        timestamp scan_timestamp "When History Recorded"
        int version "Version Number"
        string change_type "created|modified|deleted|unchanged"
        string previous_hash "Previous Config Hash"
        jsonb diff_summary "Change Summary"
    }
    
    checks {
        int id PK "Primary Key (Auto Increment)"
        string rule_id "Rule Identifier"
        string service "Service Name"
        string provider "Cloud Provider"
        string check_type "default|custom"
        string customer_id FK "Foreign Key (nullable for default checks)"
        string tenant_id FK "Foreign Key (nullable for default checks)"
        jsonb check_config "Full Check YAML Config"
        timestamp created_at "Created Timestamp"
        timestamp updated_at "Updated Timestamp"
        boolean is_active "Is Check Active"
    }
    
    check_results {
        int id PK "Primary Key (Auto Increment)"
        string scan_id FK "Foreign Key to scans"
        string customer_id FK "Foreign Key to customers"
        string tenant_id FK "Foreign Key to tenants"
        string provider "Cloud Provider"
        string hierarchy_id "Account/Project ID"
        string hierarchy_type "Type of Hierarchy"
        string rule_id "Rule Identifier"
        text resource_arn "Resource ARN"
        string resource_id "Resource ID"
        string resource_type "Resource Type"
        string status "PASS|FAIL|ERROR"
        jsonb checked_fields "Fields That Were Checked"
        jsonb finding_data "Full Finding Data"
        timestamp scan_timestamp "When Check Ran"
    }
    
    drift_detections {
        int id PK "Primary Key (Auto Increment)"
        string customer_id FK "Foreign Key to customers"
        string tenant_id FK "Foreign Key to tenants"
        string provider "Cloud Provider"
        string hierarchy_id "Account/Project ID"
        string hierarchy_type "Type of Hierarchy"
        text resource_arn "Resource ARN"
        string discovery_id "Discovery Method ID"
        string baseline_scan_id "Baseline Scan ID"
        string current_scan_id "Current Scan ID"
        string drift_type "configuration|deletion|addition"
        string severity "low|medium|high|critical"
        jsonb change_summary "Change Summary"
        timestamp detected_at "When Drift Detected"
    }"""
    },
    "compliance": {
        "name": "PostgreSQL Schema (Compliance Engine)",
        "type": "erDiagram",
        "content": """erDiagram
    tenants ||--o{ report_index : "has_many"
    report_index ||--o{ finding_index : "contains_many"
    
    tenants {
        string tenant_id PK "Primary Key"
        string tenant_name "Tenant Name"
        timestamp created_at "Created Timestamp"
    }
    
    report_index {
        uuid report_id PK "Primary Key (UUID)"
        string tenant_id FK "Foreign Key to tenants"
        string scan_run_id "Unified Scan Identifier"
        string cloud "AWS|Azure|GCP|AliCloud|OCI|IBM"
        string trigger_type "manual|scheduled|api"
        string collection_mode "full|incremental"
        timestamp started_at "Report Start Time"
        timestamp completed_at "Report Completion Time"
        int total_controls "Total Controls Checked"
        int controls_passed "Controls That Passed"
        int controls_failed "Controls That Failed"
        int total_findings "Total Findings"
        jsonb report_data "Full Report JSON"
        timestamp created_at "Created Timestamp"
    }
    
    finding_index {
        string finding_id PK "Primary Key"
        uuid report_id FK "Foreign Key to report_index"
        string tenant_id FK "Foreign Key to tenants"
        string scan_run_id "Unified Scan Identifier"
        string rule_id "Rule Identifier"
        string rule_version "Rule Version"
        string category "Security|Compliance|Cost"
        string severity "critical|high|medium|low"
        string confidence "high|medium|low"
        string status "open|resolved|suppressed"
        timestamp first_seen_at "First Detection Time"
        timestamp last_seen_at "Last Detection Time"
        string resource_type "Resource Type"
        string resource_id "Resource ID"
        text resource_arn "Resource ARN"
        string region "AWS Region"
        jsonb finding_data "Full Finding JSON"
        timestamp created_at "Created Timestamp"
    }"""
    },
    "inventory": {
        "name": "PostgreSQL Schema (Inventory Engine)",
        "type": "erDiagram",
        "content": """erDiagram
    tenants ||--o{ inventory_run_index : "has_many"
    inventory_run_index ||--o{ asset_index_latest : "tracks_latest_state"
    inventory_run_index ||--o{ relationship_index_latest : "tracks_relationships"
    asset_index_latest ||--o{ relationship_index_latest : "from_asset"
    asset_index_latest ||--o{ relationship_index_latest : "to_asset"
    
    tenants {
        string tenant_id PK "Primary Key"
        string tenant_name "Tenant Name"
        timestamp created_at "Created Timestamp"
    }
    
    inventory_run_index {
        string scan_run_id PK "Primary Key (Unified Scan ID)"
        string tenant_id FK "Foreign Key to tenants"
        timestamp started_at "Scan Start Time"
        timestamp completed_at "Scan Completion Time"
        string status "running|completed|failed"
        int total_assets "Total Assets Discovered"
        int total_relationships "Total Relationships Found"
        jsonb assets_by_provider "Count by Provider"
        jsonb assets_by_resource_type "Count by Resource Type"
        jsonb assets_by_region "Count by Region"
        jsonb providers_scanned "List of Providers"
        jsonb accounts_scanned "List of Accounts"
        jsonb regions_scanned "List of Regions"
        int errors_count "Number of Errors"
        timestamp created_at "Created Timestamp"
    }
    
    asset_index_latest {
        string asset_id PK "Primary Key"
        string tenant_id FK "Foreign Key to tenants"
        text resource_uid "Unique Resource Identifier"
        string provider "AWS|Azure|GCP|AliCloud|OCI|IBM"
        string account_id "Account ID"
        string region "AWS Region"
        string resource_type "Resource Type"
        string resource_id "Resource ID"
        string name "Resource Name"
        jsonb tags "Resource Tags"
        string latest_scan_run_id FK "Foreign Key to inventory_run_index"
        timestamp updated_at "Last Updated Timestamp"
    }
    
    relationship_index_latest {
        int relationship_id PK "Primary Key (Auto Increment)"
        string tenant_id FK "Foreign Key to tenants"
        string scan_run_id FK "Foreign Key to inventory_run_index"
        string provider "Cloud Provider"
        string account_id "Account ID"
        string region "AWS Region"
        string relation_type "uses|contains|depends_on|encrypted_by|etc"
        text from_uid "Source Resource UID"
        text to_uid "Target Resource UID"
        jsonb properties "Relationship Properties"
        timestamp created_at "Created Timestamp"
    }"""
    },
    "admin": {
        "name": "PostgreSQL Schema (Admin/Portal Backend)",
        "type": "erDiagram",
        "content": """erDiagram
    users ||--o{ user_sessions : "has_many"
    users ||--o{ tenant_users : "belongs_to"
    users ||--o{ user_roles : "has_many"
    roles ||--o{ user_roles : "assigned_to"
    roles ||--o{ role_permissions : "has_many"
    permissions ||--o{ role_permissions : "granted_to"
    tenants ||--o{ tenant_users : "has_many"
    tenants ||--o{ onboarding_tenants : "maps_to"
    onboarding_tenants ||--o{ onboarding_providers : "has_many"
    onboarding_providers ||--o{ onboarding_accounts : "has_many"
    onboarding_accounts ||--o{ onboarding_schedules : "has_many"
    onboarding_schedules ||--o{ onboarding_executions : "triggers_many"
    onboarding_executions ||--o{ onboarding_scan_results : "generates_many"
    users ||--o{ admin_audit_logs : "performs_actions"
    tenants ||--o{ admin_metrics : "has_metrics"
    tenants ||--o{ admin_tenant_quotas : "has_quota"
    
    users {
        string user_id PK "Primary Key"
        string email "User Email (Unique)"
        string first_name "First Name"
        string last_name "Last Name"
        boolean is_active "Is User Active"
        boolean is_superuser "Is Superuser"
        timestamp created_at "Created Timestamp"
        timestamp last_login "Last Login Time"
    }
    
    tenants {
        string tenant_id PK "Primary Key"
        string tenant_name "Tenant Name"
        string description "Tenant Description"
        string status "active|suspended|inactive"
        timestamp created_at "Created Timestamp"
    }
    
    onboarding_tenants {
        string id PK "Primary Key"
        string tenant_name "Tenant Name"
        string description "Tenant Description"
        string status "active|inactive"
        timestamp created_at "Created Timestamp"
        timestamp updated_at "Updated Timestamp"
    }
    
    onboarding_providers {
        string id PK "Primary Key"
        string tenant_id FK "Foreign Key to onboarding_tenants"
        string provider_type "AWS|Azure|GCP|AliCloud|OCI|IBM"
        string status "active|inactive"
        timestamp created_at "Created Timestamp"
        timestamp updated_at "Updated Timestamp"
    }
    
    onboarding_accounts {
        string id PK "Primary Key"
        string provider_id FK "Foreign Key to onboarding_providers"
        string tenant_id FK "Foreign Key to onboarding_tenants"
        string account_name "Account Name"
        string account_number "Account Number"
        string status "active|inactive"
        string onboarding_status "pending|completed|failed"
        timestamp last_validated_at "Last Validation Time"
        timestamp created_at "Created Timestamp"
        timestamp updated_at "Updated Timestamp"
    }
    
    onboarding_schedules {
        string id PK "Primary Key"
        string tenant_id FK "Foreign Key to onboarding_tenants"
        string account_id FK "Foreign Key to onboarding_accounts"
        string name "Schedule Name"
        string description "Schedule Description"
        string schedule_type "cron|interval"
        string cron_expression "Cron Expression"
        int interval_seconds "Interval in Seconds"
        string timezone "Timezone"
        jsonb regions "Regions to Scan"
        jsonb services "Services to Scan"
        jsonb exclude_services "Services to Exclude"
        string status "active|paused"
        boolean enabled "Is Schedule Enabled"
        timestamp last_run_at "Last Run Time"
        timestamp next_run_at "Next Run Time"
        int run_count "Total Runs"
        int success_count "Successful Runs"
        int failure_count "Failed Runs"
        boolean notify_on_success "Notify on Success"
        boolean notify_on_failure "Notify on Failure"
        jsonb notification_channels "Notification Channels"
        timestamp created_at "Created Timestamp"
        timestamp updated_at "Updated Timestamp"
    }
    
    onboarding_executions {
        string id PK "Primary Key"
        string schedule_id FK "Foreign Key to onboarding_schedules"
        string account_id FK "Foreign Key to onboarding_accounts"
        timestamp started_at "Execution Start Time"
        timestamp completed_at "Execution Completion Time"
        string status "running|success|failed"
        string scan_id "Scan ID"
        int total_checks "Total Checks"
        int passed_checks "Passed Checks"
        int failed_checks "Failed Checks"
        string error_message "Error Message (if failed)"
        string triggered_by "manual|scheduled|api"
        float execution_time_seconds "Execution Duration"
        timestamp created_at "Created Timestamp"
    }"""
    },
    "dataflow": {
        "name": "Data Flow Diagram",
        "type": "flowchart",
        "content": """flowchart TD
    User[User Request] --> Onboarding[Onboarding Engine<br/>DynamoDB]
    
    Onboarding --> |Creates| Schedule[Schedule Created<br/>threat-engine-schedules]
    Schedule --> |Triggers| Execution[Execution Started<br/>threat-engine-executions]
    Execution --> |Generates| ScanMetadata[Scan Metadata<br/>threat-engine-scan-metadata]
    
    ScanMetadata --> |Triggers| ConfigScan[ConfigScan Engine<br/>PostgreSQL]
    ConfigScan --> |Discovers| Discoveries[Resources Discovered<br/>discoveries table]
    ConfigScan --> |Runs Checks| CheckResults[Check Results<br/>check_results table]
    
    ScanMetadata --> |Tracks| Orchestration[Orchestration Status<br/>threat-engine-orchestration-status]
    
    Orchestration --> |Triggers| ThreatEngine[Threat Engine<br/>Reads from S3/Local]
    Orchestration --> |Triggers| ComplianceEngine[Compliance Engine<br/>PostgreSQL]
    Orchestration --> |Triggers| DataSecEngine[DataSec Engine<br/>Reads from S3/Local]
    Orchestration --> |Triggers| InventoryEngine[Inventory Engine<br/>PostgreSQL]
    
    ComplianceEngine --> |Generates| ComplianceReports[Compliance Reports<br/>report_index table]
    ComplianceReports --> |Contains| Findings[Findings<br/>finding_index table]
    
    InventoryEngine --> |Builds| AssetGraph[Asset Graph<br/>asset_index_latest]
    AssetGraph --> |Tracks| Relationships[Relationships<br/>relationship_index_latest]
    
    Discoveries --> |Tracks History| DiscoveryHistory[Discovery History<br/>discovery_history table]
    DiscoveryHistory --> |Detects| Drift[Configuration Drift<br/>drift_detections table]
    
    style Onboarding fill:#ff9999
    style ConfigScan fill:#99ccff
    style ComplianceEngine fill:#99ff99
    style InventoryEngine fill:#ffcc99
    style ThreatEngine fill:#cc99ff
    style DataSecEngine fill:#ffff99"""
    }
}


def check_mermaid_cli():
    """Check if mermaid-cli is installed."""
    try:
        result = subprocess.run(
            ["mmdc", "--version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def export_with_mermaid_cli(diagram_name, diagram_content, output_dir, format_type):
    """Export diagram using mermaid-cli."""
    output_file = output_dir / f"{diagram_name}.{format_type}"
    
    # Create temporary mermaid file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.mmd', delete=False) as f:
        f.write(diagram_content)
        temp_file = f.name
    
    try:
        # Export using mmdc
        cmd = [
            "mmdc",
            "-i", temp_file,
            "-o", str(output_file),
            "-e", format_type,
            "-b", "white",
            "-w", "2400",
            "-H", "1800"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print(f"✓ Exported {diagram_name} to {output_file}")
            return True
        else:
            print(f"✗ Failed to export {diagram_name}: {result.stderr}")
            return False
    finally:
        # Clean up temp file
        if os.path.exists(temp_file):
            os.unlink(temp_file)


def export_with_playwright(diagram_name, diagram_content, output_dir, format_type):
    """Export diagram using Playwright (fallback)."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("✗ Playwright not installed. Install with: pip install playwright && playwright install chromium")
        return False
    
    output_file = output_dir / f"{diagram_name}.{format_type}"
    
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <script src="https://cdn.jsdelivr.net/npm/mermaid@10.6.1/dist/mermaid.min.js"></script>
</head>
<body>
    <div class="mermaid">
{diagram_content}
    </div>
    <script>
        mermaid.initialize({{ startOnLoad: true }});
    </script>
</body>
</html>"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
        f.write(html_content)
        temp_file = f.name
    
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(f"file://{temp_file}")
            page.wait_for_selector(".mermaid svg", timeout=10000)
            
            if format_type == "png":
                page.screenshot(path=str(output_file), full_page=True)
            else:  # svg
                svg_content = page.evaluate("""
                    () => {
                        const svg = document.querySelector('.mermaid svg');
                        return svg ? svg.outerHTML : null;
                    }
                """)
                if svg_content:
                    with open(output_file, 'w') as f:
                        f.write(svg_content)
            
            browser.close()
        
        print(f"✓ Exported {diagram_name} to {output_file}")
        return True
    except Exception as e:
        print(f"✗ Failed to export {diagram_name}: {e}")
        return False
    finally:
        if os.path.exists(temp_file):
            os.unlink(temp_file)


def main():
    parser = argparse.ArgumentParser(description="Export database ER diagrams to images")
    parser.add_argument(
        "--format",
        choices=["png", "svg"],
        default="png",
        help="Output format (default: png)"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="docs/database_diagrams",
        help="Output directory (default: docs/database_diagrams)"
    )
    parser.add_argument(
        "--diagram",
        type=str,
        help="Export specific diagram only (dynamodb, configscan, compliance, inventory, admin, dataflow)"
    )
    
    args = parser.parse_args()
    
    # Create output directory
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Check for mermaid-cli
    use_mermaid_cli = check_mermaid_cli()
    
    if not use_mermaid_cli:
        print("⚠ mermaid-cli not found. Trying Playwright fallback...")
        print("  To install mermaid-cli: npm install -g @mermaid-js/mermaid-cli")
    
    # Determine which diagrams to export
    diagrams_to_export = [args.diagram] if args.diagram else DIAGRAMS.keys()
    
    success_count = 0
    total_count = len(diagrams_to_export)
    
    for diagram_name in diagrams_to_export:
        if diagram_name not in DIAGRAMS:
            print(f"✗ Unknown diagram: {diagram_name}")
            continue
        
        diagram = DIAGRAMS[diagram_name]
        print(f"\nExporting {diagram['name']}...")
        
        if use_mermaid_cli:
            success = export_with_mermaid_cli(
                diagram_name,
                diagram["content"],
                output_dir,
                args.format
            )
        else:
            success = export_with_playwright(
                diagram_name,
                diagram["content"],
                output_dir,
                args.format
            )
        
        if success:
            success_count += 1
    
    print(f"\n{'='*60}")
    print(f"Exported {success_count}/{total_count} diagrams to {output_dir}")
    print(f"Format: {args.format.upper()}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
