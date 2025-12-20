#!/usr/bin/env python3
"""
Prerequisites Generator for AWS Service Dependency Graphs.

Generates:
1. direct_vars.json per service (from READ operations)
2. direct_vars_all_services.json (aggregated)
3. derived_catalog.yaml (seed if doesn't exist)
4. derived_candidates_report.json (from manual_review.json files)
"""

import json
import argparse
import sys
from pathlib import Path
from typing import Dict, List, Set, Any, Optional
from collections import defaultdict
from datetime import datetime, timezone
import re

try:
    import ruamel.yaml
    yaml = ruamel.yaml.YAML()
    yaml.preserve_quotes = True
    yaml.default_flow_style = False
    HAS_YAML = True
except ImportError:
    try:
        import yaml as pyyaml
        HAS_YAML = True
        YAML_LIB = 'pyyaml'
    except ImportError:
        HAS_YAML = False
        YAML_LIB = None

# ============================================================================
# DIRECT VARS GENERATION
# ============================================================================

READ_OPERATION_PREFIXES = ['List', 'Get', 'Describe', 'Search', 'Lookup']
EXCLUDED_KEYS = ['nextToken', 'maxResults']
PAGINATION_TOKEN_PATTERNS = [r'token', r'next', r'continuation', r'cursor']

def is_pagination_token(key: str) -> bool:
    """Check if a key looks like a pagination token."""
    key_lower = key.lower()
    for pattern in PAGINATION_TOKEN_PATTERNS:
        if pattern in key_lower:
            # But allow if it's clearly a resource attribute (e.g., "tokenId", "accessToken")
            if key_lower in ['tokenid', 'accesstoken', 'refreshtoken', 'idtoken']:
                return False
            return True
    return False

def extract_item_fields_from_operation(op_data: Dict[str, Any]) -> Set[str]:
    """Extract item field names from produces paths with source='item'."""
    produces = op_data.get('produces', [])
    fields = set()
    
    for produce in produces:
        if produce.get('source') == 'item':
            path = produce.get('path', '')
            # Extract field name from path
            # Examples: "analyzers[].arn" -> "arn", "accessPreview.id" -> "id"
            if '[]' in path:
                # List item: "analyzers[].arn" -> "arn"
                field = path.split('[]')[-1].lstrip('.')
            elif '.' in path:
                # Object field: "accessPreview.id" -> "id"
                field = path.split('.')[-1]
            else:
                # Direct field name
                field = path
            
            if field:
                fields.add(field)
    
    return fields

def is_read_operation(op_name: str) -> bool:
    """Check if operation name starts with a READ prefix."""
    return any(op_name.startswith(prefix) for prefix in READ_OPERATION_PREFIXES)

def is_list_operation(op_name: str) -> bool:
    """Check if operation is a list/search/lookup operation."""
    return any(op_name.startswith(prefix) for prefix in ['List', 'Search', 'Lookup'])

def is_get_describe_operation(op_name: str) -> bool:
    """Check if operation is a get/describe operation."""
    return any(op_name.startswith(prefix) for prefix in ['Get', 'Describe'])

def generate_direct_vars(service_name: str, registry: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate direct_vars.json for a service from operation_registry.json.
    
    Rules:
    - Only READ operations (List, Get, Describe, Search, Lookup)
    - seed_from_list: item_fields from List/Search/Lookup operations
    - enriched_from_get_describe: item_fields from Get/Describe operations
    - Exclude pagination tokens and excluded keys
    """
    operations = registry.get('operations', {})
    
    seed_from_list = set()
    enriched_from_get_describe = set()
    
    for op_name, op_data in operations.items():
        if not is_read_operation(op_name):
            continue
        
        item_fields = extract_item_fields_from_operation(op_data)
        
        # Filter out excluded keys and pagination tokens
        filtered_fields = {
            field for field in item_fields
            if field not in EXCLUDED_KEYS and not is_pagination_token(field)
        }
        
        if is_list_operation(op_name):
            seed_from_list.update(filtered_fields)
        elif is_get_describe_operation(op_name):
            enriched_from_get_describe.update(filtered_fields)
    
    # Convert to sorted lists (preserve original casing)
    seed_from_list = sorted(list(seed_from_list))
    enriched_from_get_describe = sorted(list(enriched_from_get_describe))
    final_union = sorted(list(set(seed_from_list) | set(enriched_from_get_describe)))
    
    return {
        "service": service_name,
        "seed_from_list": seed_from_list,
        "enriched_from_get_describe": enriched_from_get_describe,
        "final_union": final_union,
        "source": {
            "operation_registry": f"services/{service_name}/operation_registry.json",
            "read_ops_rule": "operation name startswith List/Get/Describe/Search/Lookup",
            "excluded_keys": EXCLUDED_KEYS
        }
    }

# ============================================================================
# DERIVED CATALOG GENERATION
# ============================================================================

DERIVED_CATALOG_SEED = {
    "is_public": {
        "meaning": "Resource is publicly accessible (no authentication required)",
        "default": {"op": "check_public_access", "value": "false"},
        "hints": ["public", "anonymous", "wildcard", "publicly accessible", "internet accessible"]
    },
    "has_findings": {
        "meaning": "Resource has security findings or issues",
        "default": {"op": "check_findings", "value": "false"},
        "hints": ["finding", "findings", "issue", "vulnerability", "security issue"]
    },
    "is_encrypted": {
        "meaning": "Resource data is encrypted at rest",
        "default": {"op": "check_encryption", "value": "true"},
        "hints": ["encrypt", "encryption", "kms", "encrypted", "cipher"]
    },
    "logging_enabled": {
        "meaning": "Resource has logging/audit trail enabled",
        "default": {"op": "check_logging", "value": "true"},
        "hints": ["logging", "log", "audit", "trail", "monitoring"]
    },
    "versioning_enabled": {
        "meaning": "Resource has versioning enabled",
        "default": {"op": "check_versioning", "value": "false"},
        "hints": ["versioning", "version", "versions", "versioned"]
    },
    "mfa_enabled": {
        "meaning": "Multi-factor authentication is enabled",
        "default": {"op": "check_mfa", "value": "true"},
        "hints": ["mfa", "multi-factor", "two-factor", "2fa"]
    },
    "has_wildcards": {
        "meaning": "Resource policy contains wildcard permissions",
        "default": {"op": "check_wildcards", "value": "false"},
        "hints": ["wildcard", "wildcards", "*", "any", "all"]
    },
    "tls_required": {
        "meaning": "TLS/SSL encryption is required for connections",
        "default": {"op": "check_tls", "value": "true"},
        "hints": ["tls", "ssl", "https", "encrypted connection", "secure connection"]
    },
    "public_access_block_enabled": {
        "meaning": "Public access block is enabled",
        "default": {"op": "check_public_access_block", "value": "true"},
        "hints": ["public access block", "block public", "public access"]
    },
    "has_admin_permissions": {
        "meaning": "Resource has administrative permissions",
        "default": {"op": "check_admin_permissions", "value": "false"},
        "hints": ["admin", "administrative", "full access", "all permissions"]
    }
}

def create_derived_catalog_if_not_exists(output_path: Path) -> bool:
    """Create derived_catalog.yaml if it doesn't exist."""
    if output_path.exists():
        return False  # Already exists, don't overwrite
    
    if not HAS_YAML:
        # Write as plain text if YAML library not available
        with open(output_path, 'w') as f:
            f.write("# Derived Variables Catalog\n")
            f.write("# This file defines derived variables used in compliance checks\n\n")
            for key, value in DERIVED_CATALOG_SEED.items():
                f.write(f"{key}:\n")
                f.write(f"  meaning: {value['meaning']}\n")
                f.write(f"  default:\n")
                f.write(f"    op: {value['default']['op']}\n")
                f.write(f"    value: {value['default']['value']}\n")
                f.write(f"  hints: {value['hints']}\n\n")
        return True
    
    # Use YAML library
    if YAML_LIB == 'ruamel':
        with open(output_path, 'w') as f:
            yaml.dump(DERIVED_CATALOG_SEED, f)
    else:
        with open(output_path, 'w') as f:
            pyyaml.dump(DERIVED_CATALOG_SEED, f, default_flow_style=False, sort_keys=False)
    
    return True

# ============================================================================
# DERIVED CANDIDATES REPORT
# ============================================================================

def extract_tokens_from_rule_id(rule_id: str) -> List[str]:
    """Extract meaningful tokens from rule_id."""
    # Split by common delimiters
    tokens = re.split(r'[._-]', rule_id.lower())
    # Filter out common non-meaningful tokens
    stopwords = {'aws', 'check', 'verify', 'ensure', 'must', 'should', 'rule', 'policy'}
    meaningful = [t for t in tokens if t and t not in stopwords and len(t) > 2]
    return meaningful

def suggest_derived_concept(tokens: List[str]) -> str:
    """Suggest a derived concept based on tokens."""
    token_set = set(tokens)
    
    # Check for specific patterns
    if any(t in token_set for t in ['public', 'wildcard', 'anonymous']):
        return 'is_public'
    if any(t in token_set for t in ['finding', 'findings']):
        return 'has_findings'
    if any(t in token_set for t in ['encrypt', 'kms', 'encryption']):
        return 'is_encrypted'
    if any(t in token_set for t in ['logging', 'log']):
        return 'logging_enabled'
    if any(t in token_set for t in ['versioning', 'version']):
        return 'versioning_enabled'
    if 'mfa' in token_set:
        return 'mfa_enabled'
    if any(t in token_set for t in ['tls', 'ssl', 'https']):
        return 'tls_required'
    if any(t in token_set for t in ['public', 'access', 'block']):
        return 'public_access_block_enabled'
    if any(t in token_set for t in ['admin', 'administrative']):
        return 'has_admin_permissions'
    
    return 'unknown'

def parse_manual_review(manual_review: Any) -> List[Dict[str, Any]]:
    """Parse manual_review.json which may be in different formats."""
    items = []
    
    if isinstance(manual_review, list):
        items = manual_review
    elif isinstance(manual_review, dict):
        # Try common keys
        if 'items' in manual_review:
            items = manual_review['items']
        elif 'manual_review' in manual_review:
            items = manual_review['manual_review']
        elif 'issues' in manual_review:
            # Flatten issues structure
            issues = manual_review['issues']
            for issue_type, issue_list in issues.items():
                if isinstance(issue_list, list):
                    items.extend(issue_list)
        else:
            # Treat entire dict as single item
            items = [manual_review]
    
    return items

def generate_derived_candidates_report(services_root: Path) -> Dict[str, Any]:
    """Generate derived_candidates_report.json from all manual_review.json files."""
    services_scanned = 0
    total_items = 0
    by_reason = defaultdict(int)
    suggested_concepts = defaultdict(int)
    examples = []
    
    for service_dir in sorted(services_root.iterdir()):
        if not service_dir.is_dir():
            continue
        
        manual_review_file = service_dir / "manual_review.json"
        if not manual_review_file.exists():
            continue
        
        try:
            with open(manual_review_file, 'r') as f:
                manual_review = json.load(f)
            
            items = parse_manual_review(manual_review)
            services_scanned += 1
            total_items += len(items)
            
            for item in items:
                if not isinstance(item, dict):
                    continue
                
                # Extract fields - handle different manual_review.json formats
                rule_id = (item.get('rule_id') or item.get('id') or 
                          item.get('operation') or item.get('mapping', ''))
                reason = (item.get('reason') or item.get('issue') or 
                         item.get('description') or item.get('token', 'unknown'))
                file_path = item.get('file_path') or item.get('path', '')
                notes = item.get('notes') or item.get('note', '')
                
                # Count by reason
                by_reason[reason] += 1
                
                # Extract tokens from various fields
                text_to_analyze = ''
                if rule_id:
                    text_to_analyze = str(rule_id)
                elif 'mapping' in item:
                    text_to_analyze = str(item.get('mapping', ''))
                elif 'evidence' in item:
                    text_to_analyze = str(item.get('evidence', ''))
                elif 'operation' in item:
                    text_to_analyze = str(item.get('operation', ''))
                
                if text_to_analyze:
                    tokens = extract_tokens_from_rule_id(text_to_analyze)
                    suggested = suggest_derived_concept(tokens)
                    suggested_concepts[suggested] += 1
                    
                    # Add example (limit to 100)
                    if len(examples) < 100:
                        examples.append({
                            "service": service_dir.name,
                            "rule_id": str(rule_id) if rule_id else text_to_analyze[:50],
                            "reason": str(reason),
                            "suggested_derived": suggested,
                            "file_path": str(file_path),
                            "tokens": tokens[:5]  # Limit tokens for readability
                        })
        
        except Exception as e:
            # Skip on error, but could log
            continue
    
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_services_scanned": services_scanned,
        "total_manual_review_items": total_items,
        "by_reason": dict(sorted(by_reason.items(), key=lambda x: x[1], reverse=True)),
        "suggested_derived_concepts": dict(sorted(suggested_concepts.items(), key=lambda x: x[1], reverse=True)),
        "examples": examples[:50]  # Limit to 50 examples
    }

# ============================================================================
# MAIN PROCESSING
# ============================================================================

def process_services(services_root: Path, output_root: Optional[Path] = None) -> Dict[str, Any]:
    """Process all services and generate outputs."""
    if output_root is None:
        output_root = services_root.parent if services_root.name == 'services' else services_root
    
    services_processed = []
    services_skipped = []
    all_direct_vars = {}
    
    # Process each service
    for service_dir in sorted(services_root.iterdir()):
        if not service_dir.is_dir():
            continue
        
        service_name = service_dir.name
        registry_file = service_dir / "operation_registry.json"
        
        if not registry_file.exists():
            services_skipped.append({
                "service": service_name,
                "reason": "operation_registry.json not found"
            })
            continue
        
        try:
            with open(registry_file, 'r') as f:
                registry = json.load(f)
            
            # Generate direct_vars.json
            direct_vars = generate_direct_vars(service_name, registry)
            
            # Write per-service direct_vars.json
            output_file = service_dir / "direct_vars.json"
            with open(output_file, 'w') as f:
                json.dump(direct_vars, f, indent=2)
            
            # Store for aggregation
            all_direct_vars[service_name] = {
                "seed_from_list": direct_vars["seed_from_list"],
                "enriched_from_get_describe": direct_vars["enriched_from_get_describe"],
                "final_union": direct_vars["final_union"]
            }
            
            services_processed.append(service_name)
        
        except Exception as e:
            services_skipped.append({
                "service": service_name,
                "reason": f"Error processing: {str(e)}"
            })
    
    # Write aggregated direct_vars_all_services.json
    aggregated = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "services": all_direct_vars
    }
    
    aggregated_file = output_root / "direct_vars_all_services.json"
    with open(aggregated_file, 'w') as f:
        json.dump(aggregated, f, indent=2)
    
    # Create derived_catalog.yaml if it doesn't exist
    derived_catalog_file = output_root / "derived_catalog.yaml"
    catalog_created = create_derived_catalog_if_not_exists(derived_catalog_file)
    
    # Generate derived_candidates_report.json
    candidates_report = generate_derived_candidates_report(services_root)
    candidates_file = output_root / "derived_candidates_report.json"
    with open(candidates_file, 'w') as f:
        json.dump(candidates_report, f, indent=2)
    
    return {
        "services_processed": len(services_processed),
        "services_skipped": len(services_skipped),
        "services_processed_list": services_processed,
        "services_skipped_list": services_skipped,
        "outputs": {
            "direct_vars_per_service": len(services_processed),
            "direct_vars_all_services": str(aggregated_file),
            "derived_catalog": str(derived_catalog_file) + (" (created)" if catalog_created else " (already exists)"),
            "derived_candidates_report": str(candidates_file)
        }
    }

def main():
    parser = argparse.ArgumentParser(
        description="Generate prerequisites (direct_vars.json, derived_catalog.yaml, etc.)"
    )
    parser.add_argument(
        "--root",
        type=str,
        required=True,
        help="Root directory containing service folders"
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Output root directory (default: same as --root)"
    )
    
    args = parser.parse_args()
    
    services_root = Path(args.root)
    if not services_root.exists():
        print(f"Error: Root directory not found: {services_root}", file=sys.stderr)
        sys.exit(1)
    
    output_root = Path(args.output) if args.output else None
    
    print(f"Processing services from: {services_root}")
    print("=" * 60)
    
    result = process_services(services_root, output_root)
    
    print(f"\nSummary:")
    print(f"  Services processed: {result['services_processed']}")
    print(f"  Services skipped: {result['services_skipped']}")
    print(f"\nOutputs generated:")
    for key, value in result['outputs'].items():
        print(f"  {key}: {value}")
    
    if result['services_skipped'] > 0:
        print(f"\nSkipped services:")
        for skip in result['services_skipped_list'][:10]:  # Show first 10
            print(f"  - {skip['service']}: {skip['reason']}")
        if len(result['services_skipped_list']) > 10:
            print(f"  ... and {len(result['services_skipped_list']) - 10} more")

if __name__ == "__main__":
    main()

