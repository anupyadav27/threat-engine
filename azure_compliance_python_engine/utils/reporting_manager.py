import os
import json
import fnmatch
from datetime import datetime
from typing import Any, Dict, List, Tuple
import yaml

# Import exception reading from exception_manager to avoid duplication
try:
    from utils.exception_manager import (
        list_service_exceptions,
        list_check_exceptions
    )
except ImportError:
    # Fallback for direct execution
    from azure_compliance_python_engine.utils.exception_manager import (
        list_service_exceptions,
        list_check_exceptions
    )


def _config_dir() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "config"))


def _output_dir() -> str:
    """Get output base directory"""
    package_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    output_dir = os.path.join(package_root, "output")
    os.makedirs(output_dir, exist_ok=True)
    return output_dir


def generate_resource_id(service: str, location: str, subscription_id: str, resource_id: str, resource_type: str = None) -> str:
    """Generate Azure Resource ID for any resource based on service configuration"""
    config_path = os.path.join(_config_dir(), "service_list.json")
    with open(config_path, 'r') as f:
        config = json.load(f)
    
    # Find service configuration
    service_config = None
    for svc in config.get("services", []):
        if svc["name"] == service:
            service_config = svc
            break
    
    if not service_config:
        raise ValueError(f"Service '{service}' not found in configuration")
    
    # Get ARN pattern
    arn_pattern = service_config.get("arn_pattern")
    if not arn_pattern:
        raise ValueError(f"ARN pattern not defined for service '{service}'")
    
    # Determine if service is global or regional
    scope = service_config.get("scope", "regional")
    
    # For global services, region and account_id might be empty
    if scope == "global":
        if service == "s3":
            # S3 buckets don't include region/account in ARN
            return arn_pattern.format(resource_id=resource_id)
        elif service in ["iam", "organizations", "budgets", "ce", "artifact", "trustedadvisor", "wellarchitected", "tag"]:
            # These services use account_id but no region
            return arn_pattern.format(account_id=account_id, resource_type=resource_type or "resource", resource_id=resource_id)
        elif service == "route53":
            # Route53 uses account_id but no region
            return arn_pattern.format(account_id=account_id, resource_type=resource_type or "resource", resource_id=resource_id)
        elif service == "cloudfront":
            # CloudFront uses account_id but no region
            return arn_pattern.format(account_id=account_id, resource_type=resource_type or "resource", resource_id=resource_id)
    else:
        # Regional services
        if not region:
            raise ValueError(f"Region is required for regional service '{service}'")
        if not account_id:
            raise ValueError(f"Account ID is required for regional service '{service}'")
        
        return arn_pattern.format(
            region=region,
            account_id=account_id,
            resource_type=resource_type or "resource",
            resource_id=resource_id
        )


def parse_arn(arn: str) -> Dict[str, Any]:
    """Parse ARN to extract components"""
    parts = arn.split(":")
    
    if len(parts) < 6:
        return {
            "arn": arn,
            "service": "unknown",
            "region": None,
            "account_id": None,
            "resource_id": None,
            "resource_type": None,
            "scope": "unknown"
        }
    
    # Extract basic components
    service = parts[2]
    region = parts[3] if parts[3] != "" else None
    account_id = parts[4] if parts[4] != "" else None
    
    # Parse resource part (format: resource_type/resource_id or just resource_id)
    resource_part = parts[5]
    if "/" in resource_part:
        resource_type, resource_id = resource_part.split("/", 1)
    else:
        resource_type = None
        resource_id = resource_part
    
    # Determine scope
    config_path = os.path.join(_config_dir(), "service_list.json")
    with open(config_path, 'r') as f:
        config = json.load(f)
    scope = "unknown"
    for svc in config.get("services", []):
        if svc["name"] == service:
            scope = svc.get("scope", "unknown")
            break
    
    return {
        "arn": arn,
        "service": service,
        "region": region,
        "account_id": account_id,
        "resource_id": resource_id,
        "resource_type": resource_type,
        "scope": scope
    }


def is_global_service(service: str) -> bool:
    """Check if a service is global (no region required)"""
    config_path = os.path.join(_config_dir(), "service_list.json")
    with open(config_path, 'r') as f:
        config = json.load(f)
    for svc in config.get("services", []):
        if svc["name"] == service:
            return svc.get("scope") == "global"
    return False


def _timestamp() -> str:
    """Generate timestamp for scan ID"""
    return datetime.utcnow().strftime("%Y%m%d_%H%M%S")


def create_scan_folder(scan_id: str = None) -> tuple:
    """
    Create timestamped scan folder with logs subdirectory
    
    Returns:
        (scan_folder_path, scan_id)
    """
    if scan_id is None:
        scan_id = f"scan_{_timestamp()}"
    
    output_base = _output_dir()
    scan_folder = os.path.join(output_base, scan_id)
    os.makedirs(scan_folder, exist_ok=True)
    
    # Create logs subdirectory inside scan folder
    logs_dir = os.path.join(scan_folder, "logs")
    os.makedirs(logs_dir, exist_ok=True)
    
    # Create latest symlink
    latest_link = os.path.join(output_base, "latest")
    if os.path.islink(latest_link) or os.path.exists(latest_link):
        os.remove(latest_link)
    os.symlink(scan_id, latest_link)
    
    return scan_folder, scan_id


def create_report_folder() -> str:
    """Legacy compatibility - calls create_scan_folder"""
    scan_folder, _ = create_scan_folder()
    return scan_folder


def get_scan_log_file(scan_folder: str, log_type: str = "scan") -> str:
    """
    Get log file path inside scan folder
    
    Args:
        scan_folder: Path to scan folder
        log_type: 'scan', 'errors', or account_id
    
    Returns:
        Path to log file
    """
    logs_dir = os.path.join(scan_folder, "logs")
    os.makedirs(logs_dir, exist_ok=True)
    
    if log_type == "scan":
        return os.path.join(logs_dir, "scan.log")
    elif log_type == "errors":
        return os.path.join(logs_dir, "errors.log")
    else:
        # Account-specific log
        return os.path.join(logs_dir, f"account_{log_type}.log")


def setup_scan_logging(scan_folder: str, scan_id: str):
    """
    Setup logging for a scan
    
    Args:
        scan_folder: Path to scan folder
        scan_id: Scan identifier
    
    Returns:
        Logger instance
    """
    import logging
    
    log_file = get_scan_log_file(scan_folder, "scan")
    error_log_file = get_scan_log_file(scan_folder, "errors")
    
    # Create logger
    logger = logging.getLogger(f'compliance_scan_{scan_id}')
    logger.setLevel(logging.INFO)
    logger.handlers.clear()  # Remove any existing handlers
    
    # Also configure service scanner logger to use same handlers
    service_logger = logging.getLogger('azure-service-scanner')
    service_logger.setLevel(logging.INFO)
    service_logger.handlers.clear()
    
    # File handler - all logs
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.INFO)
    fh.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    logger.addHandler(fh)
    
    # Error file handler - errors only
    eh = logging.FileHandler(error_log_file)
    eh.setLevel(logging.ERROR)
    eh.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    logger.addHandler(eh)
    
    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    logger.addHandler(ch)
    
    # Add same handlers to service scanner logger
    service_logger.addHandler(fh)
    service_logger.addHandler(eh)
    service_logger.addHandler(ch)
    
    logger.info(f"[SCAN-START] {scan_id}")
    logger.info(f"Scan folder: {scan_folder}")
    logger.info(f"Log file: {log_file}")
    
    return logger


def _meta(account_id: str | None, folder: str) -> Dict[str, Any]:
    return {"account_id": account_id, "generated_at": datetime.utcnow().isoformat() + "Z", "report_folder": os.path.abspath(folder)}


# NOTE: Exception reading functions removed - now using exception_manager.py
# This eliminates code duplication and provides single source of truth
# Use list_service_exceptions() and list_check_exceptions() imported above


def _load_actions_config() -> Dict[str, Any]:
    path = os.path.join(_config_dir(), "actions.yaml")
    if not os.path.exists(path):
        return {}
    with open(path) as fh:
        return yaml.safe_load(fh) or {}


def _load_actions_selection() -> Dict[str, List[str]]:
    path = os.path.join(_config_dir(), "actions_selection.yaml")
    if not os.path.exists(path):
        return {}
    with open(path) as fh:
        data = yaml.safe_load(fh) or {}
    profiles = data.get("profiles") or {}
    active = data.get("active_profile") or "default"
    profile = profiles.get(active) or {}
    return (profile.get("selected_actions_by_check") or {})


def _iso_not_expired(expires_at: str | None) -> bool:
    if not expires_at:
        return True
    try:
        dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        return datetime.utcnow() <= dt
    except Exception:
        return True


def _match_scope(val: str | None, pattern: str | None) -> bool:
    if pattern is None:
        return True
    if val is None:
        return False
    return fnmatch.fnmatch(val, pattern)


def save_metadata(scan_folder: str, metadata: dict) -> None:
    """Save scan metadata to metadata.json"""
    metadata_path = os.path.join(scan_folder, "metadata.json")
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)


def save_summary(scan_folder: str, summary: dict) -> None:
    """Save scan summary to summary.json"""
    summary_path = os.path.join(scan_folder, "summary.json")
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)


def save_account_summary(scan_folder: str, account_id: str, summary: dict) -> None:
    """Save account-level summary"""
    account_dir = os.path.join(scan_folder, f"account_{account_id}")
    os.makedirs(account_dir, exist_ok=True)
    
    summary_path = os.path.join(account_dir, "account_summary.json")
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)


def save_region_summary(scan_folder: str, account_id: str, region: str, summary: dict) -> None:
    """Save region-level summary"""
    region_dir = os.path.join(scan_folder, f"account_{account_id}", region)
    os.makedirs(region_dir, exist_ok=True)
    
    summary_path = os.path.join(region_dir, "region_summary.json")
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)


def save_chunked_resources(scan_folder: str, account_id: str, region: str, 
                           service: str, resources: list, chunk_size: int = 100) -> str:
    """
    Save resources in chunked, compressed format
    
    Args:
        scan_folder: Base scan folder path
        account_id: AWS account ID
        region: AWS region (or 'global')
        service: Service name (e.g., 'ec2', 's3')
        resources: List of resource dictionaries with inventory + compliance
        chunk_size: Number of resources per chunk file
    
    Returns:
        Path to service directory
    """
    import gzip
    
    # Create directory structure
    service_dir = os.path.join(
        scan_folder,
        f"account_{account_id}",
        region,
        service
    )
    os.makedirs(service_dir, exist_ok=True)
    
    # Split into chunks and save
    chunks_metadata = []
    total_resources = len(resources)
    
    for i in range(0, total_resources, chunk_size):
        chunk = resources[i:i + chunk_size]
        chunk_id = i // chunk_size
        
        chunk_data = {
            "chunk_id": chunk_id,
            "account_id": account_id,
            "region": region,
            "service": service,
            "scan_id": os.path.basename(scan_folder),
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "resource_count": len(chunk),
            "resources": chunk
        }
        
        # Write compressed chunk
        chunk_file = f"chunk_{chunk_id:03d}.json.gz"
        chunk_path = os.path.join(service_dir, chunk_file)
        
        with gzip.open(chunk_path, 'wt', encoding='utf-8') as f:
            json.dump(chunk_data, f, indent=2)
        
        # Get file sizes
        compressed_size = os.path.getsize(chunk_path)
        
        # Calculate stats
        failed_count = sum(1 for r in chunk 
                          if r.get("compliance", {}).get("failed", 0) > 0)
        total_checks = sum(r.get("compliance", {}).get("total_checks", 0) 
                          for r in chunk)
        passed_checks = sum(r.get("compliance", {}).get("passed", 0) 
                           for r in chunk)
        failed_checks = sum(r.get("compliance", {}).get("failed", 0) 
                           for r in chunk)
        
        chunks_metadata.append({
            "chunk_id": chunk_id,
            "file": chunk_file,
            "resource_count": len(chunk),
            "size_compressed": compressed_size,
            "resource_ids": [r["resource_id"] for r in chunk],
            "stats": {
                "resources_with_failures": failed_count,
                "total_checks": total_checks,
                "passed": passed_checks,
                "failed": failed_checks
            }
        })
    
    # Write service index
    index_data = {
        "account_id": account_id,
        "region": region,
        "service": service,
        "scan_id": os.path.basename(scan_folder),
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_resources": total_resources,
        "total_chunks": len(chunks_metadata),
        "chunk_size": chunk_size,
        "chunks": chunks_metadata,
        "summary": {
            "total_checks": sum(c["stats"]["total_checks"] for c in chunks_metadata),
            "passed": sum(c["stats"]["passed"] for c in chunks_metadata),
            "failed": sum(c["stats"]["failed"] for c in chunks_metadata),
            "resources_with_failures": sum(c["stats"]["resources_with_failures"] 
                                          for c in chunks_metadata),
            "compliance_rate": 0
        }
    }
    
    # Calculate compliance rate
    if index_data["summary"]["total_checks"] > 0:
        index_data["summary"]["compliance_rate"] = round(
            100.0 * index_data["summary"]["passed"] / 
            index_data["summary"]["total_checks"], 2
        )
    
    index_path = os.path.join(service_dir, "index.json")
    with open(index_path, 'w') as f:
        json.dump(index_data, f, indent=2)
    
    return service_dir


def save_reporting_bundle(results: List[Dict[str, Any]], account_id: str | None = None) -> str:
    folder = create_report_folder()
    svc_ex = list_service_exceptions()  # Using exception_manager (no duplication)
    chk_ex = list_check_exceptions()     # Using exception_manager (no duplication)
    actions_cfg = _load_actions_config()
    selected = _load_actions_selection()
    standard_actions = actions_cfg.get("standard_actions") or {}

    # Service-specific data organization
    service_data = {}
    checks_main = []
    
    # Hierarchical structure
    hierarchical_data = {
        "metadata": {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "total_accounts": 0,
            "total_resources": 0,
            "total_checks": 0
        },
        "accounts": {}
    }

    for r in results:
        service = r.get("service")
        acct = r.get("account") or account_id or "unknown"
        region = r.get("region") or "unknown"
        
        # Initialize account in hierarchical structure
        if acct not in hierarchical_data["accounts"]:
            hierarchical_data["accounts"][acct] = {
                "account_id": acct,
                "total_resources": 0,
                "total_checks": 0,
                "regions": {},
                "global_services": {}
            }
        
        # Skip inventory processing for now - focus on checks only
        # Process checks with ARN generation
        for c in r.get("checks", []) or []:
            item = {**c}
            item.setdefault("service", service)
            item.setdefault("account", acct)
            if region:
                item.setdefault("region", region)

            reporting_result = item.get("reporting_result")

            # service-level exceptions
            for ex in svc_ex:
                if ex.get("effect") not in {"mark_skipped", "skip_service"}:
                    continue
                if ex.get("service") != service:
                    continue
                sel = ex.get("selector") or {}
                if not _match_scope(acct, sel.get("account")):
                    continue
                if "region" in sel and not _match_scope(region, sel.get("region")):
                    continue
                if not _iso_not_expired(ex.get("expires_at")):
                    continue
                reporting_result = "SKIPPED"
                item["skip_meta"] = {"id": ex.get("id"), "scope": "service", "reason": ex.get("reason"), "expires_at": ex.get("expires_at")}
                break

            if reporting_result != "SKIPPED":
                for ex in chk_ex:
                    if ex.get("effect") not in {"mark_skipped", "skip_check"}:
                        continue
                    if ex.get("rule_id") != item.get("rule_id"):
                        continue
                    sel = ex.get("selector") or {}
                    if not _match_scope(acct, sel.get("account")):
                        continue
                    if "region" in sel and not _match_scope(region, sel.get("region")):
                        continue
                    if not _iso_not_expired(ex.get("expires_at")):
                        continue
                    reporting_result = "SKIPPED"
                    item["skip_meta"] = {"id": ex.get("id"), "scope": "check", "reason": ex.get("reason"), "expires_at": ex.get("expires_at")}
                    break

            if item.get("result") == "FAIL":
                sel_actions = selected.get(item.get("rule_id")) or []
                if sel_actions:
                    item["actions"] = [{"action": a, "args": (standard_actions.get(a) or {})} for a in sel_actions]

            # Add ARN to check result with better resource ID detection
            try:
                # Try different possible resource ID fields based on service
                resource_id = None
                resource_type = None
                
                if service == "s3":
                    resource_id = item.get("bucket_name")
                    resource_type = "bucket"
                elif service == "iam":
                    resource_id = item.get("user_name") or item.get("role_name") or item.get("group_name")
                    resource_type = item.get("user_name") and "user" or item.get("role_name") and "role" or item.get("group_name") and "group" or "resource"
                elif service == "ec2":
                    resource_id = item.get("instance_id") or item.get("volume_id") or item.get("security_group_id")
                    resource_type = item.get("instance_id") and "instance" or item.get("volume_id") and "volume" or item.get("security_group_id") and "security-group" or "resource"
                elif service == "rds":
                    resource_id = item.get("db_instance_identifier") or item.get("db_cluster_identifier")
                    resource_type = item.get("db_instance_identifier") and "db" or item.get("db_cluster_identifier") and "cluster" or "resource"
                elif service == "kms":
                    resource_id = item.get("key_id") or item.get("key_arn")
                    resource_type = "key"
                else:
                    # Generic fallback
                    resource_id = (item.get("resource_id") or 
                                 item.get("resource_name") or 
                                 item.get("id") or
                                 item.get("name"))
                    resource_type = "resource"
                
                if resource_id and str(resource_id).strip() and str(resource_id) != "":  # Check if not empty
                    item["resource_arn"] = generate_arn(service, region if not is_global_service(service) else None, acct, str(resource_id), resource_type)
                else:
                    # Generate a service-level ARN for checks without specific resource IDs
                    if is_global_service(service):
                        item["resource_arn"] = f"arn:aws:{service}::{acct}:{service}"
                    else:
                        item["resource_arn"] = f"arn:aws:{service}:{region}:{acct}:{service}"
            except Exception as e:
                print(f"Warning: Failed to generate ARN for check: {e}")
                if is_global_service(service):
                    item["resource_arn"] = f"arn:aws:{service}::{acct}:{service}"
                else:
                    item["resource_arn"] = f"arn:aws:{service}:{region}:{acct}:{service}"

            # Get checked fields from the record (if stored)
            checked_fields = set(item.get('_checked_fields', []))
            # Remove the metadata field
            if '_checked_fields' in item:
                del item['_checked_fields']
            
            # Context fields that are always useful (ARN, ID, name, identifier, etc.)
            context_field_patterns = ['arn', 'id', 'name', 'identifier', 'arn']
            
            # Group evidence fields into a clean evidence dictionary
            evidence_fields = []
            for key, value in item.items():
                # Skip standard check fields
                if key in ["rule_id", "title", "severity", "assertion_id", "result", "region", 
                          "service", "account", "resource_arn", "reporting_result", "skip_meta", 
                          "actions", "timestamp", "message", "subscription", "location", "resource_id"]:
                    continue
                
                # Include if:
                # 1. It's a checked field (the var being evaluated)
                # 2. It's a context field (ARN, ID, name, etc.)
                key_lower = key.lower()
                is_checked_field = key in checked_fields
                is_context_field = any(key_lower.endswith(pattern) for pattern in context_field_patterns)
                
                # If we have checked fields, only include checked + context
                # If no checked fields (backward compat), include all
                if checked_fields:
                    if is_checked_field or is_context_field:
                        evidence_fields.append((key, value))
                else:
                    # Backward compatibility: include all if no checked fields specified
                    evidence_fields.append((key, value))
            
            # Create clean evidence dictionary
            item["evidence"] = dict(evidence_fields)
            
            # Remove evidence fields from main object to avoid duplication
            for key, _ in evidence_fields:
                if key in item:
                    del item[key]

            if reporting_result == "SKIPPED":
                item["reporting_result"] = "SKIPPED"
                checks_skipped.append(item)
            else:
                checks_main.append(item)

            # Add to hierarchical structure
            try:
                if is_global_service(service):
                    if service not in hierarchical_data["accounts"][acct]["global_services"]:
                        hierarchical_data["accounts"][acct]["global_services"][service] = {
                            "service": service,
                            "total_resources": 0,
                            "total_checks": 0,
                            "resources": [],
                            "checks": []
                        }
                    hierarchical_data["accounts"][acct]["global_services"][service]["checks"].append(item)
                    hierarchical_data["accounts"][acct]["global_services"][service]["total_checks"] += 1
                else:
                    if region not in hierarchical_data["accounts"][acct]["regions"]:
                        hierarchical_data["accounts"][acct]["regions"][region] = {
                            "region": region,
                            "total_resources": 0,
                            "total_checks": 0,
                            "services": {}
                        }
                    if service not in hierarchical_data["accounts"][acct]["regions"][region]["services"]:
                        hierarchical_data["accounts"][acct]["regions"][region]["services"][service] = {
                            "service": service,
                            "total_resources": 0,
                            "total_checks": 0,
                            "resources": [],
                            "checks": []
                        }
                    hierarchical_data["accounts"][acct]["regions"][region]["services"][service]["checks"].append(item)
                    hierarchical_data["accounts"][acct]["regions"][region]["services"][service]["total_checks"] += 1
                    hierarchical_data["accounts"][acct]["regions"][region]["total_checks"] += 1
                
                hierarchical_data["accounts"][acct]["total_checks"] += 1
            except Exception as e:
                print(f"Warning: Failed to add check to hierarchical structure: {e}")

    # Update hierarchical metadata
    hierarchical_data["metadata"]["total_accounts"] = len(hierarchical_data["accounts"])
    hierarchical_data["metadata"]["total_resources"] = sum(acc["total_resources"] for acc in hierarchical_data["accounts"].values())
    hierarchical_data["metadata"]["total_checks"] = sum(acc["total_checks"] for acc in hierarchical_data["accounts"].values())

    # Create account-specific folders and service-specific files
    account_folders = {}
    for account_id, account_data in hierarchical_data["accounts"].items():
        account_folder = os.path.join(folder, f"account_{account_id}")
        os.makedirs(account_folder, exist_ok=True)
        account_folders[account_id] = account_folder
        
        # Process global services
        for service, service_data in account_data["global_services"].items():
            if service_data["total_checks"] > 0:
                filename = f"{account_id}_global_{service}_checks.json"
                filepath = os.path.join(account_folder, filename)
                
                # Filter checks for this service
                service_checks = [check for check in checks_main if check.get("service") == service and check.get("account") == account_id]
                
                with open(filepath, "w") as fh:
                    json.dump({
                        "metadata": _meta(account_id, folder),
                        "service": service,
                        "scope": "global",
                        "account": account_id,
                        "total_checks": len(service_checks),
                        "checks": service_checks
                    }, fh, indent=2)
        
        # Process regional services
        for region, region_data in account_data["regions"].items():
            if region != "unknown":
                for service, service_data in region_data["services"].items():
                    if service_data["total_checks"] > 0:
                        filename = f"{account_id}_{region}_{service}_checks.json"
                        filepath = os.path.join(account_folder, filename)
                        
                        # Filter checks for this service and region
                        service_checks = [check for check in checks_main if check.get("service") == service and check.get("account") == account_id and check.get("region") == region]
                        
                        with open(filepath, "w") as fh:
                            json.dump({
                                "metadata": _meta(account_id, folder),
                                "service": service,
                                "scope": "regional",
                                "account": account_id,
                                "region": region,
                                "total_checks": len(service_checks),
                                "checks": service_checks
                            }, fh, indent=2)

    # Hierarchical summary removed - using individual service files instead
    
    # Save index with new file structure
    with open(os.path.join(folder, "index.json"), "w") as fh:
        json.dump({
            "metadata": _meta(account_id, folder),
            "summary": {
                "total_checks": hierarchical_data["metadata"]["total_checks"],
                "total_resources": hierarchical_data["metadata"]["total_resources"],
                "total_accounts": hierarchical_data["metadata"]["total_accounts"]
            },
            "account_folders": list(account_folders.keys()),
            "files": {
                "index": "index.json"
            }
        }, fh, indent=2)

    return os.path.abspath(folder) 