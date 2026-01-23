#!/usr/bin/env python3
"""
Test Data Security Engine with real scan output.

Tests the engine end-to-end:
1. Reads configScan output
2. Enriches findings
3. Runs analyzers
4. Generates report
5. Saves output to engines-output folder
"""

import sys
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, List
from collections import defaultdict

# Add to path
sys.path.insert(0, str(Path(__file__).parent))

from data_security_engine.reporter.data_security_reporter import DataSecurityReporter
from data_security_engine.input.configscan_reader import ConfigScanReader
from data_security_engine.enricher.finding_enricher import FindingEnricher


def test_engine_with_scan(csp: str = "aws", scan_id: str = "full_scan_all", tenant_id: str = "test-tenant", max_findings: int = 500, allowed_regions: Optional[List[str]] = None):
    """Test the data security engine with a real scan."""
    print("=" * 70)
    print("Data Security Engine - Test Run")
    print("=" * 70)
    print(f"CSP: {csp}")
    print(f"Scan ID: {scan_id}")
    print(f"Tenant ID: {tenant_id}")
    print(f"Max Findings to Process: {max_findings}")
    print(f"Residency Allowed Regions: {allowed_regions}")
    print()
    
    # Initialize reporter
    reporter = DataSecurityReporter()
    
    # Step 1: Test reading configScan output
    print("Step 1: Reading ConfigScan output...")
    try:
        data_findings = reporter.configscan_reader.filter_data_related_findings(csp, scan_id, max_findings=max_findings)
        print(f"  ✓ Found {len(data_findings)} data-related findings")
        
        if data_findings:
            sample_finding = data_findings[0]
            print(f"  Sample finding: {sample_finding.get('rule_id')} - {sample_finding.get('status')}")
    except Exception as e:
        print(f"  ✗ Error reading findings: {e}")
        import traceback
        traceback.print_exc()
        return None
    
    # Step 2: Test reading data stores
    print("\nStep 2: Reading data stores from inventory...")
    try:
        data_stores = reporter.configscan_reader.filter_data_stores(csp, scan_id)
        print(f"  ✓ Found {len(data_stores)} data stores")
        
        if data_stores:
            sample_store = data_stores[0]
            print(f"  Sample store: {sample_store.get('resource_type')} - {sample_store.get('resource_id')}")
    except Exception as e:
        print(f"  ✗ Error reading data stores: {e}")
        import traceback
        traceback.print_exc()
        return None
    
    # Step 3: Test enrichment (skip full analysis for now to speed up)
    print("\nStep 3: Testing finding enrichment...")
    try:
        # Test with a small subset
        sample_findings_for_enrichment = data_findings[:10] if len(data_findings) > 10 else data_findings
        enriched_sample = reporter.enricher.enrich_findings(sample_findings_for_enrichment)
        print(f"  ✓ Enriched {len(enriched_sample)} findings (sample)")
        
        data_security_relevant_count = sum(1 for f in enriched_sample if f.get("is_data_security_relevant"))
        print(f"  ✓ {data_security_relevant_count}/{len(enriched_sample)} are data security relevant")
        
        if enriched_sample:
            sample_enriched_finding = next((f for f in enriched_sample if f.get("is_data_security_relevant")), None)
            if sample_enriched_finding:
                print(f"  Sample enriched finding (rule_id): {sample_enriched_finding.get('rule_id')}")
                print(f"  Modules: {sample_enriched_finding.get('data_security_modules')}")
                print(f"  Priority: {sample_enriched_finding.get('data_security_context', {}).get('priority')}")
    except Exception as e:
        print(f"  ✗ Error during enrichment: {e}")
        import traceback
        traceback.print_exc()
        return None

    # Step 4: Generating data security report
    print("\nStep 4: Generating data security report...")
    try:
        report = reporter.generate_report(
            csp=csp,
            scan_id=scan_id,
            tenant_id=tenant_id,
            include_classification=False, # Keep false for faster test
            include_lineage=False,        # Keep false for faster test
            include_residency=True,       # Enable residency checks
            include_activity=False,       # Keep false for faster test
            allowed_regions=allowed_regions, # Pass allowed regions
            max_findings=max_findings,
        )
        print("  ✓ Report generated successfully")
        print(f"  Summary:")
        print(f"    Total findings: {report['summary']['total_findings']}")
        print(f"    Data security relevant: {report['summary']['data_security_relevant_findings']}")
        print(f"    Findings by module: {report['summary']['findings_by_module']}")
        residency_summary = report['summary'].get('residency', {})
        print(f"    Residency compliant: {residency_summary.get('compliant', 0)}")
        print(f"    Residency non-compliant: {residency_summary.get('non_compliant', 0)}")
        print(f"    Residency unknown: {residency_summary.get('unknown', 0)}")
    except Exception as e:
        print(f"  ✗ Error generating report: {e}")
        import traceback
        traceback.print_exc()
        return None

    # Step 5: Saving report to engines-output
    output_dir = save_report(report, tenant_id, scan_id, csp)
    print(f"\nOutput saved to: {output_dir}")

    print("\n======================================================================")
    print("Test Complete!")
    print("======================================================================")

    print("\nReport Summary:")
    print(f"  Total findings: {report['summary']['total_findings']}")
    print(f"  Data security relevant: {report['summary']['data_security_relevant_findings']}")
    print(f"  Coverage: {report['summary']['data_security_relevant_findings'] / report['summary']['total_findings'] * 100 if report['summary']['total_findings'] > 0 else 0.0:.1f}%")
    residency_summary = report['summary'].get('residency', {})
    print(f"  Residency Compliant: {residency_summary.get('compliant', 0)}")
    print(f"  Residency Non-Compliant: {residency_summary.get('non_compliant', 0)}")
    print(f"  Residency Unknown: {residency_summary.get('unknown', 0)}")

    return report


def extract_account_region_from_arn(resource_arn: str, default_region: str = "global") -> tuple:
    """Extract account_id and region from AWS ARN."""
    if not resource_arn or not resource_arn.startswith("arn:aws:"):
        return ("unknown", default_region)
    
    parts = resource_arn.split(":")
    if len(parts) >= 5:
        region = parts[3] if parts[3] else default_region
        account_id = parts[4] if parts[4] else "unknown"
        return (account_id, region)
    elif len(parts) >= 4:
        region = parts[3] if parts[3] else default_region
        return ("unknown", region)
    
    return ("unknown", default_region)


def save_report(report: dict, tenant_id: str, scan_id: str, csp: str):
    """
    Save report with structured hierarchy:
    {timestamp}/{account_id}/{csp}/{region}/[feature folders]
    
    Each finding must have:
    - scan_run_id
    - resource_arn or resource_uid
    - rule_id
    - status/result
    """
    print("\nStep 5: Saving report to engines-output...")
    
    # Generate timestamp for this scan
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    
    # Base output path
    base_path = Path(__file__).parent.parent / "engines-output" / "data-security-engine" / "output"
    
    # Group data by account_id, csp, and region
    grouped_data = defaultdict(lambda: {
        "findings": [],
        "classification": [],
        "residency": [],
        "inventory": [],  # Add inventory from configScan
        "lineage": {},
        "activity": {}
    })
    
    # Group findings by account/csp/region
    for finding in report.get("findings", []):
        # Ensure all required fields are present
        finding["scan_run_id"] = finding.get("scan_run_id", scan_id)
        if not finding.get("resource_arn") and not finding.get("resource_uid"):
            finding["resource_uid"] = finding.get("resource_uid", "unknown")
        
        account_id = finding.get("account_id", "unknown")
        provider = finding.get("provider", finding.get("csp", csp))
        region = finding.get("region", "global")
        key = (account_id, provider, region)
        grouped_data[key]["findings"].append(finding)
    
    # Group inventory by account/csp/region (for discovery catalog)
    # Read inventory from configScan output
    from data_security_engine.input.configscan_reader import ConfigScanReader
    configscan_reader = ConfigScanReader()
    data_services = ["s3", "rds", "dynamodb", "redshift", "glacier", "documentdb", "neptune"]
    
    for asset in configscan_reader.read_inventory(csp, scan_id):
        # Filter for data-related services
        service = asset.get("service", "").lower()
        if service in data_services:
            account_id = asset.get("account_id", "unknown")
            provider = asset.get("provider", csp)
            region = asset.get("region", "global")
            key = (account_id, provider, region)
            grouped_data[key]["inventory"].append(asset)
    
    # Group classification results
    for item in report.get("classification", []):
        resource_arn = item.get("resource_arn", "")
        region = item.get("region", "global")
        account_id, region = extract_account_region_from_arn(resource_arn, region)
        key = (account_id, csp, region)
        grouped_data[key]["classification"].append(item)
    
    # Group residency results
    for item in report.get("residency", []):
        resource_arn = item.get("resource_arn", "")
        region = item.get("primary_region", "global")
        account_id, region = extract_account_region_from_arn(resource_arn, region)
        key = (account_id, csp, region)
        grouped_data[key]["residency"].append(item)
    
    # Save to each account/csp/region combination
    saved_paths = []
    for (account_id, provider, region), data in grouped_data.items():
        # Create folder structure: {timestamp}/{account_id}/{csp}/{region}/
        region_output_dir = base_path / timestamp / account_id / provider / region
        region_output_dir.mkdir(parents=True, exist_ok=True)
        
        # Create feature-specific directories
        discovery_dir = region_output_dir / "discovery"
        governance_dir = region_output_dir / "governance"
        protection_dir = region_output_dir / "protection"
        residency_dir = region_output_dir / "residency"
        compliance_dir = region_output_dir / "compliance"
        classification_dir = region_output_dir / "classification"
        lineage_dir = region_output_dir / "lineage"
        monitoring_dir = region_output_dir / "monitoring"
        reports_dir = region_output_dir / "reports"
        
        for dir_path in [discovery_dir, governance_dir, protection_dir, residency_dir,
                         compliance_dir, classification_dir, lineage_dir, monitoring_dir, reports_dir]:
            dir_path.mkdir(exist_ok=True)
        
        # Save findings by module to feature-specific files
        findings_by_module = defaultdict(list)
        
        for finding in data["findings"]:
            # Ensure finding has all required fields
            finding.setdefault("scan_run_id", scan_id)
            finding.setdefault("rule_id", "unknown")
            finding.setdefault("status", finding.get("result", "UNKNOWN"))
            finding.setdefault("result", finding.get("status", "UNKNOWN"))
            
            for module in finding.get("data_security_modules", []):
                findings_by_module[module].append(finding)
        
        # Save module-specific findings
        module_file_map = {
            "data_protection_encryption": protection_dir / "encryption_status.ndjson",
            "data_access_governance": governance_dir / "access_analysis.ndjson",
            "data_activity_monitoring": monitoring_dir / "monitoring_findings.ndjson",
            "data_residency": residency_dir / "residency_findings.ndjson",
            "data_compliance": compliance_dir / "compliance_status.ndjson",
        }
        
        for module, findings_list in findings_by_module.items():
            if findings_list and module in module_file_map:
                file_path = module_file_map[module]
                with open(file_path, 'w') as f:
                    for finding in findings_list:
                        f.write(json.dumps(finding, default=str) + "\n")
        
        # Save all findings as NDJSON
        findings_file = region_output_dir / "findings.ndjson"
        with open(findings_file, 'w') as f:
            for finding in data["findings"]:
                f.write(json.dumps(finding, default=str) + "\n")
        
        # Save classification
        if data["classification"]:
            classification_file = classification_dir / "classified_data.ndjson"
            with open(classification_file, 'w') as f:
                for item in data["classification"]:
                    f.write(json.dumps(item, default=str) + "\n")
        
        # Save residency
        if data["residency"]:
            residency_file = residency_dir / "location_map.ndjson"
            with open(residency_file, 'w') as f:
                for item in data["residency"]:
                    f.write(json.dumps(item, default=str) + "\n")
        
        # Save data catalog (discovery) - BUILD FROM INVENTORY (actual discovered resources)
        # This is the correct approach: catalog = what was discovered, not what had findings
        catalog_file = discovery_dir / "data_catalog.ndjson"
        if data["inventory"]:
            with open(catalog_file, 'w') as f:
                for asset in data["inventory"]:
                    catalog_item = {
                        "resource_id": asset.get("resource_id", "unknown"),
                        "resource_arn": asset.get("resource_arn", ""),
                        "resource_uid": asset.get("resource_uid", "unknown"),
                        "resource_type": asset.get("resource_type", "unknown"),
                        "service": asset.get("service", "unknown"),
                        "region": asset.get("region", region),
                        "account_id": asset.get("account_id", account_id),
                        "name": asset.get("name", ""),
                        "tags": asset.get("tags", {}),
                        "lifecycle_state": asset.get("lifecycle_state", ""),
                        "health_status": asset.get("health_status", ""),
                    }
                    f.write(json.dumps(catalog_item, default=str) + "\n")
        
        # Save summary for this region
        summary_file = region_output_dir / "summary.json"
        summary = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "timestamp": timestamp,
            "tenant_id": tenant_id,
            "scan_run_id": scan_id,
            "account_id": account_id,
            "csp": provider,
            "region": region,
            "summary": {
                "total_findings": len(data["findings"]),
                "total_discovered_resources": len(data["inventory"]),
                "classification_count": len(data["classification"]),
                "residency_count": len(data["residency"]),
            }
        }
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2, default=str)
        
        saved_paths.append(str(region_output_dir))
        print(f"  ✓ Saved {account_id}/{provider}/{region}: {len(data['inventory'])} resources, {len(data['findings'])} findings")
    
    print(f"\n  ✓ Saved to {len(saved_paths)} region folders under: {base_path / timestamp}")
    return base_path / timestamp


def main():
    """Run the test."""
    # Use available scan
    csp = "aws"
    scan_id = "latest"  # Use the latest scan output
    tenant_id = "test-tenant"
    
    # Test with a limited number of findings for faster execution
    max_findings_limit = 5000
    
    # Example residency policy
    allowed_regions_policy = ["us-east-1", "us-west-2", "ap-south-1"]

    print("======================================================================")
    print("Starting Data Security Engine Test")
    print("======================================================================")
    
    test_engine_with_scan(csp, scan_id, tenant_id, max_findings=max_findings_limit, allowed_regions=allowed_regions_policy)


if __name__ == "__main__":
    main()
