import os
import json
import fnmatch
from datetime import datetime
from typing import Any, Dict, List, Tuple
import yaml


def _config_dir() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "config"))


def generate_arn(service: str, region: str, account_id: str, resource_id: str, resource_type: str = None) -> str:
    """Generate ARN for any AWS resource based on service configuration"""
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
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")


def create_report_folder() -> str:
    package_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    base = os.path.join(package_root, "reporting")
    os.makedirs(base, exist_ok=True)
    folder = os.path.join(base, f"reporting_{_timestamp()}")
    os.makedirs(folder, exist_ok=True)
    return folder


def _meta(account_id: str | None, folder: str) -> Dict[str, Any]:
    return {"account_id": account_id, "generated_at": datetime.utcnow().isoformat() + "Z", "report_folder": os.path.abspath(folder)}


def _load_service_exceptions() -> List[Dict[str, Any]]:
    path = os.path.join(_config_dir(), "service_list.json")
    data: Dict[str, Any] = {}
    if os.path.exists(path):
        with open(path) as fh:
            data = json.load(fh) or {}
    out: List[Dict[str, Any]] = []
    for s in (data.get("services") or []):
        for ex in (s.get("exceptions") or []):
            out.append({**ex, "service": s.get("name")})
    return out


def _load_check_exceptions() -> List[Dict[str, Any]]:
    path = os.path.join(_config_dir(), "check_exceptions.yaml")
    if not os.path.exists(path):
        return []
    with open(path) as fh:
        data = yaml.safe_load(fh) or {}
    return list((data.get("exceptions") or []))


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


def save_reporting_bundle(results: List[Dict[str, Any]], account_id: str | None = None) -> str:
    folder = create_report_folder()
    svc_ex = _load_service_exceptions()
    chk_ex = _load_check_exceptions()
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

            # Group evidence fields into a clean evidence dictionary
            evidence_fields = []
            for key, value in item.items():
                # Skip standard check fields and group evidence fields
                if key not in ["rule_id", "title", "severity", "assertion_id", "result", "region", 
                              "service", "account", "resource_arn", "reporting_result", "skip_meta", 
                              "actions", "timestamp", "message"]:
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