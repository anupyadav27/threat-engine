"""
Attack edge validators — Phase 1 (VAL-01).

Validators read asset_relationships + asset_inventory + resource_security_posture
and INSERT derived attack-capable edges into asset_relationships with is_attack_edge=TRUE.

Rule catalog reference (from improvement/attack_path_catalog):
  AWS-INET-001..005  → validate_internet_reachability
  AWS-SVC-001..005   → validate_service_chain
  AWS-ID-001..003    → validate_identity_usage
  AWS-ID-004..005    → validate_assume_role
  AWS-DATA-001..005  → validate_data_access
  AWS-SEC-001..002   → validate_data_access
  AWS-KMS-001..002   → validate_data_access
"""
from .runner import run_all_validators

__all__ = ["run_all_validators"]
