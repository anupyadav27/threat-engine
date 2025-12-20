#!/usr/bin/env python3
"""
Manual Review Auto-Fixer

Processes service folders and auto-fixes manual_review.json issues using:
1. Deterministic rules (direct vars, derived mapping, aliases)
2. Optional LLM assistance for remaining unresolved items
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import yaml
from difflib import SequenceMatcher

# Optional LLM client import
try:
    from llm_client import LLMClient
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False


class DirectVarsGenerator:
    """Generate direct_vars.json from operation_registry.json (read ops only)"""
    
    READ_PREFIXES = ["List", "Get", "Describe", "Search", "Lookup"]
    EXCLUDED_KEYS = {"nextToken", "maxResults"}
    
    def __init__(self, operation_registry: Dict[str, Any]):
        self.operation_registry = operation_registry
        self.service = operation_registry.get("service", "unknown")
    
    def extract_item_fields(self, produces: List[Dict], source_type: str) -> Set[str]:
        """Extract field names from item_fields (source='item')"""
        fields = set()
        for item in produces:
            if item.get("source") == source_type:
                path = item.get("path", "")
                # Extract field name from path (e.g., "Buckets[].Name" -> "Name")
                if "[]" in path:
                    # Array item field
                    field = path.split("[].")[-1] if "[]." in path else path.split("[")[0]
                else:
                    # Direct field
                    field = path.split(".")[-1]
                
                # Exclude pagination tokens
                field_lower = field.lower()
                if any(token in field_lower for token in ["token", "next", "max"]):
                    if any(excluded in field_lower for excluded in self.EXCLUDED_KEYS):
                        continue
                
                if field:
                    fields.add(field)
        return fields
    
    def generate(self) -> Dict[str, Any]:
        """Generate direct_vars.json structure"""
        operations = self.operation_registry.get("operations", {})
        
        seed_from_list = set()
        enriched_from_get_describe = set()
        
        for op_name, op_data in operations.items():
            kind = op_data.get("kind", "")
            produces = op_data.get("produces", [])
            
            # Read list operations (List/Search/Lookup)
            if kind == "read_list" or any(op_name.startswith(prefix) for prefix in ["List", "Search", "Lookup"]):
                fields = self.extract_item_fields(produces, "item")
                seed_from_list.update(fields)
            
            # Read get/describe operations
            if kind == "read_get" or any(op_name.startswith(prefix) for prefix in ["Get", "Describe"]):
                # Get both output and item fields
                output_fields = self.extract_item_fields(produces, "output")
                item_fields = self.extract_item_fields(produces, "item")
                enriched_from_get_describe.update(output_fields)
                enriched_from_get_describe.update(item_fields)
        
        # Final union
        final_union = sorted(set(seed_from_list) | set(enriched_from_get_describe))
        
        return {
            "service": self.service,
            "seed_from_list": sorted(seed_from_list),
            "enriched_from_get_describe": sorted(enriched_from_get_describe),
            "final_union": final_union,
            "source": {
                "operation_registry": f"services/{self.service}/operation_registry.json",
                "read_ops_rule": "operation name startswith List/Get/Describe/Search/Lookup",
                "excluded_keys": list(self.EXCLUDED_KEYS)
            }
        }


class DerivedCatalogManager:
    """Manage derived_catalog.yaml"""
    
    DEFAULT_CATALOG = {
        "is_public": {
            "meaning": "Resource is publicly accessible (no authentication required)",
            "default": {"op": "equals", "value": "false"},
            "hints": ["public", "wildcard", "anonymous", "principal", "0.0.0.0"]
        },
        "has_findings": {
            "meaning": "Resource has security findings or issues",
            "default": {"op": "equals", "value": "false"},
            "hints": ["findings", "finding", "without_findings", "no_findings"]
        },
        "is_encrypted": {
            "meaning": "Resource data is encrypted at rest",
            "default": {"op": "equals", "value": "true"},
            "hints": ["encrypt", "encryption", "kms", "cmk"]
        },
        "logging_enabled": {
            "meaning": "Resource has logging/audit trail enabled",
            "default": {"op": "equals", "value": "true"},
            "hints": ["logging", "logs", "cloudtrail", "accesslog"]
        },
        "versioning_enabled": {
            "meaning": "Resource has versioning enabled",
            "default": {"op": "equals", "value": "true"},
            "hints": ["versioning", "version"]
        },
        "mfa_enabled": {
            "meaning": "Multi-factor authentication is enabled",
            "default": {"op": "equals", "value": "true"},
            "hints": ["mfa"]
        },
        "tls_required": {
            "meaning": "TLS/SSL encryption is required for connections",
            "default": {"op": "equals", "value": "true"},
            "hints": ["tls", "ssl", "https"]
        },
        "public_access_block_enabled": {
            "meaning": "Public access block is enabled",
            "default": {"op": "equals", "value": "true"},
            "hints": ["public_access_block"]
        },
        "has_admin_permissions": {
            "meaning": "Resource has administrative permissions",
            "default": {"op": "equals", "value": "false"},
            "hints": ["admin", "full_access", "star_policy"]
        },
        "has_wildcards": {
            "meaning": "Resource policy contains wildcard permissions",
            "default": {"op": "equals", "value": "false"},
            "hints": ["wildcard", "action", "principal"]
        }
    }
    
    def ensure_exists(self, catalog_path: Path) -> Dict[str, Any]:
        """Ensure derived_catalog.yaml exists, create if missing"""
        if catalog_path.exists():
            with open(catalog_path, 'r') as f:
                return yaml.safe_load(f) or {}
        else:
            # Create default catalog
            with open(catalog_path, 'w') as f:
                yaml.dump(self.DEFAULT_CATALOG, f, default_flow_style=False, sort_keys=False)
            return self.DEFAULT_CATALOG
    
    def get_derived_keys(self, catalog: Dict[str, Any]) -> Set[str]:
        """Get set of derived variable keys"""
        return set(catalog.keys())


class ManualReviewFixer:
    """Auto-fix manual_review.json issues"""
    
    def __init__(self, service: str, direct_vars: Dict[str, Any], 
                 derived_catalog: Dict[str, Any], operation_registry: Dict[str, Any]):
        self.service = service
        self.direct_vars = direct_vars
        self.derived_catalog = derived_catalog
        self.operation_registry = operation_registry
        self.fixes_applied = []
        self.overrides = {}
    
    def fuzzy_match_var(self, var_name: str, candidates: Set[str], threshold: float = 0.7) -> Optional[str]:
        """Fuzzy match variable name to closest candidate"""
        var_normalized = var_name.lower().replace("_", "").replace("-", "")
        best_match = None
        best_score = 0.0
        
        for candidate in candidates:
            candidate_normalized = candidate.lower().replace("_", "").replace("-", "")
            score = SequenceMatcher(None, var_normalized, candidate_normalized).ratio()
            if score > best_score and score >= threshold:
                best_score = score
                best_match = candidate
        
        return best_match
    
    def infer_derived_var(self, rule_id: str, issue_text: str, requirement: Optional[str] = None) -> Optional[Tuple[str, str, str]]:
        """Infer derived variable from keywords"""
        text = f"{rule_id} {issue_text} {requirement or ''}".lower()
        
        # Check each derived var's hints
        for var_key, var_data in self.derived_catalog.items():
            hints = var_data.get("hints", [])
            if any(hint in text for hint in hints):
                default = var_data.get("default", {})
                op = default.get("op", "equals")
                value = default.get("value", "false")
                
                # Infer topic from rule_id
                topic = "derived"
                known_topics = ["bucketpolicy", "encryption", "findings", "logging", "policy", "public_access"]
                for known_topic in known_topics:
                    if known_topic in rule_id.lower():
                        topic = known_topic
                        break
                
                derive_key = f"aws.{self.service}.{topic}.{var_key}"
                return (var_key, op, value, derive_key)
        
        return None
    
    def fix_missing_var(self, item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Fix missing/unknown var issues"""
        issue = item.get("issue", "")
        var_mentioned = None
        
        # Extract var name from issue text
        if "missing var" in issue.lower() or "unknown var" in issue.lower():
            # Try to extract var name
            patterns = [
                r"var\s+['\"]?(\w+)['\"]?",
                r"variable\s+['\"]?(\w+)['\"]?",
                r"['\"](\w+)['\"]\s+is\s+missing",
            ]
            for pattern in patterns:
                match = re.search(pattern, issue, re.IGNORECASE)
                if match:
                    var_mentioned = match.group(1)
                    break
        
        if not var_mentioned:
            return None
        
        # Check if exists in direct_vars
        final_union = set(self.direct_vars.get("final_union", []))
        if var_mentioned in final_union:
            return {"var": var_mentioned, "source": "direct_var"}
        
        # Try fuzzy match
        matched = self.fuzzy_match_var(var_mentioned, final_union)
        if matched:
            return {"var": matched, "source": "fuzzy_match", "original": var_mentioned}
        
        # Try derived mapping
        derived_result = self.infer_derived_var(
            item.get("rule_id", ""),
            issue,
            item.get("requirement") or item.get("title")
        )
        if derived_result:
            var_key, op, value, derive_key = derived_result
            return {
                "var": f"derived.{var_key}",
                "op": op,
                "value": value,
                "derive_key": derive_key,
                "source": "derived_mapping"
            }
        
        return None
    
    def fix_suspicious_path(self, item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Fix suspicious path issues (alias mismatches)"""
        operation = item.get("operation", "")
        param = item.get("param", "")
        path = item.get("path", "")
        consume_entity = item.get("consume_entity", "")
        produce_entity = item.get("produce_entity", "")
        
        # Check if this is an alias issue
        if param and path and consume_entity != produce_entity:
            # Try to infer alias from operation registry
            op_data = self.operation_registry.get("operations", {}).get(operation, {})
            consumes = op_data.get("consumes", [])
            produces = op_data.get("produces", [])
            
            # Find matching param in consumes
            param_entity = None
            for consume in consumes:
                if consume.get("param") == param:
                    param_entity = consume.get("entity")
                    break
            
            # Find matching path in produces
            path_entity = None
            for produce in produces:
                if produce.get("path") == path:
                    path_entity = produce.get("entity")
                    break
            
            # If entities match but were different, suggest alias
            if param_entity and path_entity and param_entity != path_entity:
                # Check if we can infer canonical from direct_vars
                final_union = set(self.direct_vars.get("final_union", []))
                param_field = param
                path_field = path.split(".")[-1]
                
                # Suggest alias if fields are similar
                if param_field.lower() == path_field.lower() or \
                   self.fuzzy_match_var(param_field, {path_field}, 0.8):
                    return {
                        "type": "alias",
                        "entity_aliases": {path_entity: param_entity},
                        "reason": f"Param '{param}' and path '{path}' map to same field but different entities"
                    }
        
        return None
    
    def fix_item(self, item: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Attempt to fix a single manual review item"""
        issue = item.get("issue", "")
        rule_id = item.get("rule_id", "")
        requirement = item.get("requirement") or item.get("title", "")
        
        # A) Missing/unknown var
        if "missing var" in issue.lower() or "unknown var" in issue.lower():
            fix = self.fix_missing_var(item)
            if fix:
                return True, {"type": "var_fix", "original": item, "fix": fix}
        
        # B) Suspicious path (alias issue)
        if "similar but map to different" in issue.lower() or "suspicious_paths" in str(type(item).__name__):
            fix = self.fix_suspicious_path(item)
            if fix:
                return True, {"type": "alias_fix", "original": item, "fix": fix}
        
        # C) Derived mapping by keywords (check rule_id, issue, requirement)
        if rule_id or requirement:
            derived_result = self.infer_derived_var(rule_id, issue, requirement)
            if derived_result:
                var_key, op, value, derive_key = derived_result
                return True, {
                    "type": "derived_fix",
                    "original": item,
                    "fix": {
                        "var": f"derived.{var_key}",
                        "op": op,
                        "value": value,
                        "derive_key": derive_key
                    }
                }
        
        return False, None
    
    def process_manual_review(self, manual_review: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """Process manual_review.json and return fixed version + unresolved items"""
        fixed = {
            "service": self.service,
            "issues": {},
            "alias_candidates_not_applied": manual_review.get("alias_candidates_not_applied", []),
            "suggested_overrides": []
        }
        unresolved = []
        
        # Handle different manual_review formats
        issues = manual_review.get("issues", {})
        
        # Process each issue category
        for category, items in issues.items():
            if category == "suspicious_paths":
                # Process suspicious_paths (list of dicts)
                fixed_paths = []
                for path_item in items:
                    if isinstance(path_item, dict):
                        was_fixed, fix_data = self.fix_item(path_item)
                        if was_fixed and fix_data:
                            self.fixes_applied.append(fix_data)
                            # Mark as fixed (could remove from list or mark)
                        else:
                            unresolved.append(path_item)
                            fixed_paths.append(path_item)
                    else:
                        fixed_paths.append(path_item)
                fixed["issues"][category] = fixed_paths
            elif category == "ambiguous_tokens":
                # Process ambiguous_tokens (dict of token -> list of mappings)
                fixed_tokens = {}
                for token, mappings in items.items():
                    if isinstance(mappings, list):
                        fixed_mappings = []
                        for mapping in mappings:
                            if isinstance(mapping, dict):
                                # Try to fix ambiguous token mappings
                                was_fixed, fix_data = self.fix_item(mapping)
                                if was_fixed and fix_data:
                                    self.fixes_applied.append(fix_data)
                                else:
                                    unresolved.append(mapping)
                                fixed_mappings.append(mapping)
                            else:
                                fixed_mappings.append(mapping)
                        fixed_tokens[token] = fixed_mappings
                    else:
                        fixed_tokens[token] = mappings
                fixed["issues"][category] = fixed_tokens
            elif category == "unresolved_consumes":
                # Process unresolved_consumes (list)
                fixed_consumes = []
                for consume_item in items:
                    if isinstance(consume_item, dict):
                        was_fixed, fix_data = self.fix_item(consume_item)
                        if was_fixed and fix_data:
                            self.fixes_applied.append(fix_data)
                        else:
                            unresolved.append(consume_item)
                            fixed_consumes.append(consume_item)
                    else:
                        fixed_consumes.append(consume_item)
                fixed["issues"][category] = fixed_consumes
            else:
                # Other categories (generic_entities, etc.)
                fixed["issues"][category] = items
        
        # Process suggested_overrides
        suggested_overrides = manual_review.get("suggested_overrides", [])
        fixed_overrides = []
        for override_item in suggested_overrides:
            if isinstance(override_item, dict):
                # Try to auto-apply high confidence overrides
                confidence = override_item.get("confidence", "").upper()
                if confidence == "HIGH":
                    # Apply override - add to overrides
                    key = override_item.get("key", "")
                    suggested_entity = override_item.get("suggested_entity", "")
                    if key and suggested_entity:
                        if "entity_aliases" not in self.overrides:
                            self.overrides["entity_aliases"] = {}
                        # Infer the canonical entity from the suggested
                        self.overrides["entity_aliases"][suggested_entity] = suggested_entity
                        self.fixes_applied.append({
                            "type": "override_fix",
                            "original": override_item,
                            "fix": {"entity_alias": suggested_entity}
                        })
                else:
                    fixed_overrides.append(override_item)
            else:
                fixed_overrides.append(override_item)
        fixed["suggested_overrides"] = fixed_overrides
        
        return fixed, unresolved


def process_service(service_path: Path, root_path: Path, use_llm: bool = False, 
                   llm_model: str = "gpt-4o-mini", max_batch: int = 50) -> Dict[str, Any]:
    """Process a single service folder"""
    service_name = service_path.name
    result = {
        "service": service_name,
        "status": "success",
        "fixed_count": 0,
        "remaining_count": 0,
        "errors": []
    }
    
    try:
        # Load operation_registry.json
        op_reg_path = service_path / "operation_registry.json"
        if not op_reg_path.exists():
            result["status"] = "skipped"
            result["errors"].append("operation_registry.json not found")
            return result
        
        with open(op_reg_path, 'r') as f:
            operation_registry = json.load(f)
        
        # Generate/refresh direct_vars.json
        generator = DirectVarsGenerator(operation_registry)
        direct_vars = generator.generate()
        direct_vars_path = service_path / "direct_vars.json"
        with open(direct_vars_path, 'w') as f:
            json.dump(direct_vars, f, indent=2)
        
        # Ensure derived_catalog.yaml exists
        catalog_manager = DerivedCatalogManager()
        catalog_path = root_path / "derived_catalog.yaml"
        derived_catalog = catalog_manager.ensure_exists(catalog_path)
        
        # Load manual_review.json
        manual_review_path = service_path / "manual_review.json"
        if not manual_review_path.exists():
            result["status"] = "skipped"
            result["errors"].append("manual_review.json not found")
            return result
        
        with open(manual_review_path, 'r') as f:
            manual_review = json.load(f)
        
        # Process manual review
        fixer = ManualReviewFixer(service_name, direct_vars, derived_catalog, operation_registry)
        fixed_review, unresolved = fixer.process_manual_review(manual_review)
        
        # Optional LLM pass for unresolved items
        if use_llm and unresolved and LLM_AVAILABLE:
            try:
                llm_client = LLMClient(model=llm_model)
                llm_fixes = llm_client.batch_fix(unresolved[:max_batch], direct_vars, derived_catalog, service_name)
                # Apply LLM fixes with confidence check
                resolved_by_llm = []
                for llm_fix in llm_fixes:
                    if llm_fix.get("confidence", 0) >= 0.80:
                        # Check if var is valid
                        var = llm_fix.get("suggested_check", {}).get("var", "")
                        is_valid = False
                        if var.startswith("derived."):
                            derived_key = var.replace("derived.", "")
                            is_valid = derived_key in derived_catalog
                        elif var:
                            is_valid = var in direct_vars.get("final_union", [])
                        
                        if is_valid:
                            fixer.fixes_applied.append({
                                "type": "llm_fix",
                                "original": llm_fix.get("rule_id") or "unknown",
                                "fix": llm_fix.get("suggested_check", {}),
                                "confidence": llm_fix.get("confidence", 0),
                                "reason": llm_fix.get("reason", ""),
                                "aliases": llm_fix.get("suggested_aliases", {})
                            })
                            # Mark original item as resolved
                            rule_id = llm_fix.get("rule_id")
                            if rule_id:
                                resolved_by_llm.append(rule_id)
            except Exception as e:
                result["errors"].append(f"LLM error: {str(e)}")
            
            # Remove resolved items from unresolved
            if resolved_by_llm:
                unresolved = [u for u in unresolved if not (isinstance(u, dict) and u.get("rule_id") in resolved_by_llm)]
        
        # Write updated manual_review.json (keep structure, mark unresolved separately)
        # Add unresolved items to a separate list in the output
        if unresolved:
            fixed_review["unresolved_items"] = unresolved
        with open(manual_review_path, 'w') as f:
            json.dump(fixed_review, f, indent=2)
        
        # Write overrides.json if any aliases were created
        if fixer.overrides:
            overrides_path = service_path / "overrides.json"
            existing_overrides = {}
            if overrides_path.exists():
                with open(overrides_path, 'r') as f:
                    existing_overrides = json.load(f)
            
            # Merge overrides
            merged = {
                "entity_aliases": {**existing_overrides.get("entity_aliases", {}), **fixer.overrides.get("entity_aliases", {})},
                "param_aliases": {**existing_overrides.get("param_aliases", {}), **fixer.overrides.get("param_aliases", {})}
            }
            
            with open(overrides_path, 'w') as f:
                json.dump(merged, f, indent=2)
        
        # Write fixes_applied.json (preserve existing fixes)
        fixes_path = service_path / "fixes_applied.json"
        existing_fixes = []
        if fixes_path.exists():
            try:
                with open(fixes_path, 'r') as f:
                    existing_data = json.load(f)
                    existing_fixes = existing_data.get("fixes", [])
            except:
                pass
        
        # Merge fixes (avoid duplicates)
        all_fixes = existing_fixes.copy()
        for new_fix in fixer.fixes_applied:
            # Check if this fix already exists
            is_duplicate = False
            for existing_fix in existing_fixes:
                if existing_fix == new_fix or (isinstance(existing_fix, dict) and isinstance(new_fix, dict) and 
                    existing_fix.get("type") == new_fix.get("type") and 
                    existing_fix.get("original") == new_fix.get("original")):
                    is_duplicate = True
                    break
            if not is_duplicate:
                all_fixes.append(new_fix)
        
        with open(fixes_path, 'w') as f:
            json.dump({
                "service": service_name,
                "fixes": all_fixes,
                "summary": {
                    "total_fixes": len(all_fixes),
                    "remaining_unresolved": len(unresolved)
                }
            }, f, indent=2)
        
        result["fixed_count"] = len(fixer.fixes_applied)
        result["remaining_count"] = len(unresolved)
        
    except Exception as e:
        result["status"] = "error"
        result["errors"].append(str(e))
    
    return result


def main():
    parser = argparse.ArgumentParser(description="Auto-fix manual review issues")
    parser.add_argument("--root", required=True, help="Root directory containing service folders")
    parser.add_argument("--use-llm", action="store_true", help="Use LLM for unresolved items")
    parser.add_argument("--model", default="gpt-4o-mini", help="LLM model name")
    parser.add_argument("--max-batch", type=int, default=50, help="Max items per LLM batch")
    
    args = parser.parse_args()
    
    root_path = Path(args.root)
    if not root_path.exists():
        print(f"Error: Root path does not exist: {root_path}")
        sys.exit(1)
    
    # Find all service folders
    service_folders = [d for d in root_path.iterdir() if d.is_dir() and (d / "operation_registry.json").exists()]
    
    if not service_folders:
        print(f"No service folders found in {root_path}")
        sys.exit(1)
    
    print(f"Processing {len(service_folders)} service(s)...")
    
    global_summary = {
        "total_services": len(service_folders),
        "services": [],
        "summary": {
            "total_fixed": 0,
            "total_remaining": 0,
            "successful": 0,
            "skipped": 0,
            "errors": 0
        }
    }
    
    for service_path in sorted(service_folders):
        try:
            print(f"\nProcessing {service_path.name}...")
            result = process_service(service_path, root_path, args.use_llm, args.model, args.max_batch)
            global_summary["services"].append(result)
            
            if result["status"] == "success":
                global_summary["summary"]["successful"] += 1
                global_summary["summary"]["total_fixed"] += result["fixed_count"]
                global_summary["summary"]["total_remaining"] += result["remaining_count"]
                print(f"  ✓ Fixed: {result['fixed_count']}, Remaining: {result['remaining_count']}")
            elif result["status"] == "skipped":
                global_summary["summary"]["skipped"] += 1
                print(f"  ⊘ Skipped: {', '.join(result['errors'])}")
            else:
                global_summary["summary"]["errors"] += 1
                print(f"  ✗ Error: {', '.join(result['errors'])}")
        except KeyboardInterrupt:
            print("\n\nInterrupted by user. Saving progress...")
            break
        except Exception as e:
            print(f"  ✗ Unexpected error: {e}")
            global_summary["summary"]["errors"] += 1
            global_summary["services"].append({
                "service": service_path.name,
                "status": "error",
                "errors": [str(e)]
            })
    
    # Write global summary
    summary_path = root_path / "manual_review_global_summary.json"
    with open(summary_path, 'w') as f:
        json.dump(global_summary, f, indent=2)
    
    print(f"\n✓ Global summary written to {summary_path}")
    print(f"\nSummary:")
    print(f"  Successful: {global_summary['summary']['successful']}")
    print(f"  Skipped: {global_summary['summary']['skipped']}")
    print(f"  Errors: {global_summary['summary']['errors']}")
    print(f"  Total Fixed: {global_summary['summary']['total_fixed']}")
    print(f"  Total Remaining: {global_summary['summary']['total_remaining']}")


if __name__ == "__main__":
    main()

