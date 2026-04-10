"""
Key-to-Resource Dependency Graph Builder.

Maps which KMS keys are used by which resources, building a bidirectional
adjacency list. Data sources:
  1. inventory_relationships (explicit edges)
  2. datasec enhanced data (kms_key_id in resource metadata)
  3. discovery emitted_fields (KmsKeyId references in service resources)
"""

import logging
from typing import Dict, Any, List, Set, Optional
from collections import defaultdict

logger = logging.getLogger(__name__)


class DependencyGraph:
    """Bidirectional graph: KMS key <-> dependent resources."""

    def __init__(self):
        # key_arn -> set of resource_uids
        self.key_to_resources: Dict[str, Set[str]] = defaultdict(set)
        # resource_uid -> set of key_arns
        self.resource_to_keys: Dict[str, Set[str]] = defaultdict(set)
        # resource metadata cache
        self.resource_metadata: Dict[str, Dict[str, Any]] = {}
        # key metadata cache
        self.key_metadata: Dict[str, Dict[str, Any]] = {}

    @property
    def total_edges(self) -> int:
        return sum(len(v) for v in self.key_to_resources.values())

    def add_edge(self, key_arn: str, resource_uid: str):
        """Add a key -> resource dependency edge."""
        if key_arn and resource_uid and key_arn != resource_uid:
            self.key_to_resources[key_arn].add(resource_uid)
            self.resource_to_keys[resource_uid].add(key_arn)

    def get_resources_for_key(self, key_arn: str) -> List[str]:
        """Get all resources that depend on a KMS key."""
        return list(self.key_to_resources.get(key_arn, set()))

    def get_keys_for_resource(self, resource_uid: str) -> List[str]:
        """Get all KMS keys used by a resource."""
        return list(self.resource_to_keys.get(resource_uid, set()))

    def get_dependency_count(self, key_arn: str) -> int:
        """Get the number of resources depending on a key."""
        return len(self.key_to_resources.get(key_arn, set()))

    def to_dict(self) -> Dict[str, Any]:
        """Serialize graph to a JSON-safe dict."""
        return {
            "key_to_resources": {k: list(v) for k, v in self.key_to_resources.items()},
            "resource_to_keys": {k: list(v) for k, v in self.resource_to_keys.items()},
            "total_keys": len(self.key_to_resources),
            "total_resources": len(self.resource_to_keys),
            "total_edges": self.total_edges,
        }


def build_dependency_graph(
    kms_relationships: List[Dict[str, Any]],
    enhanced_data: List[Dict[str, Any]],
    discovery_resources: Dict[str, List[Dict[str, Any]]],
    key_inventory: List[Dict[str, Any]],
    datasec_findings: Optional[List[Dict[str, Any]]] = None,
) -> DependencyGraph:
    """Build the KMS key dependency graph from multiple data sources.

    Args:
        kms_relationships: Inventory relationships involving KMS keys.
        enhanced_data: DataSec enhanced_input_transformed rows.
        discovery_resources: {service: [resources]} from DiscoveryReader.
        key_inventory: Key inventory list for metadata.
        datasec_findings: Optional datasec findings with kms_key_id in finding_data.

    Returns:
        DependencyGraph with all edges populated.
    """
    graph = DependencyGraph()

    # Cache key metadata
    known_key_arns = set()
    for k in key_inventory:
        arn = k.get("key_arn", "")
        if arn:
            known_key_arns.add(arn)
            graph.key_metadata[arn] = k
            # Also index by key_id for matching
            kid = k.get("key_id", "")
            if kid:
                known_key_arns.add(kid)
                graph.key_metadata[kid] = k

    # 1. Inventory relationships (explicit edges from graph builder)
    for rel in kms_relationships:
        source = rel.get("source_uid", "")
        target = rel.get("target_uid", "")
        source_type = (rel.get("source_type") or "").lower()
        target_type = (rel.get("target_type") or "").lower()

        if "kms" in target_type:
            # source uses target (KMS key)
            graph.add_edge(target, source)
            graph.resource_metadata[source] = {
                "resource_uid": source,
                "resource_type": rel.get("source_type"),
            }
        elif "kms" in source_type:
            # target uses source (KMS key)
            graph.add_edge(source, target)
            graph.resource_metadata[target] = {
                "resource_uid": target,
                "resource_type": rel.get("target_type"),
            }

    logger.info(f"Dependency graph: {graph.total_edges} edges from inventory relationships")

    # 2. DataSec enhanced data (kms_key_type + resource_arn)
    for ed in enhanced_data:
        resource_arn = ed.get("resource_arn", "")
        kms_key_type = ed.get("kms_key_type", "")
        if not resource_arn:
            continue

        # Store resource metadata
        graph.resource_metadata[resource_arn] = {
            "resource_uid": resource_arn,
            "resource_type": ed.get("resource_type"),
            "data_store_service": ed.get("data_store_service"),
            "data_classification": ed.get("data_classification"),
            "is_public": ed.get("is_public", False),
            "cross_account_access": ed.get("cross_account_access", False),
            "account_id": ed.get("account_id"),
            "region": ed.get("region"),
        }

        # If we can resolve the actual key ARN, add the edge
        # Enhanced data doesn't always have the key ARN directly
        if kms_key_type == "customer_managed":
            # Try to find matching key from known keys
            _try_match_key(graph, resource_arn, known_key_arns, ed)

    edges_after_enhanced = graph.total_edges
    logger.info(f"Dependency graph: {edges_after_enhanced} edges after enhanced data")

    # 3. DataSec findings (kms_key_id in finding_data JSONB)
    if datasec_findings:
        for df in datasec_findings:
            resource_uid = df.get("resource_uid", "")
            fd = df.get("finding_data") or {}
            if not isinstance(fd, dict):
                continue

            kms_key_id = fd.get("kms_key_id") or fd.get("kms_key_arn") or fd.get("KmsKeyId")
            if kms_key_id and resource_uid:
                # Resolve key_id to full ARN if possible
                resolved = _resolve_key_arn(kms_key_id, graph.key_metadata)
                graph.add_edge(resolved, resource_uid)
                if resource_uid not in graph.resource_metadata:
                    graph.resource_metadata[resource_uid] = {
                        "resource_uid": resource_uid,
                        "resource_type": df.get("resource_type"),
                        "account_id": df.get("account_id"),
                        "region": df.get("region"),
                    }

    # 4. Discovery resources (KmsKeyId in emitted_fields of non-KMS services)
    for service, resources in discovery_resources.items():
        if service == "kms":
            continue  # Skip KMS keys themselves
        for r in resources:
            emitted = r.get("emitted_fields") or {}
            if not isinstance(emitted, dict):
                continue
            resource_uid = r.get("resource_uid", "")
            if not resource_uid:
                continue

            # Look for KMS key references in emitted fields
            for field_name in ("KmsKeyId", "KmsMasterKeyId", "KmsKeyArn",
                               "SSEDescription", "EncryptionConfiguration"):
                val = emitted.get(field_name)
                if isinstance(val, str) and ("kms" in val.lower() or val.startswith("arn:")):
                    resolved = _resolve_key_arn(val, graph.key_metadata)
                    graph.add_edge(resolved, resource_uid)
                    break
                elif isinstance(val, dict):
                    # Nested KMS ref (e.g., SSEDescription.KMSMasterKeyArn)
                    nested_key = val.get("KMSMasterKeyArn") or val.get("KmsKeyArn") or val.get("KmsKeyId")
                    if nested_key:
                        resolved = _resolve_key_arn(nested_key, graph.key_metadata)
                        graph.add_edge(resolved, resource_uid)
                        break

            if resource_uid not in graph.resource_metadata:
                graph.resource_metadata[resource_uid] = {
                    "resource_uid": resource_uid,
                    "resource_type": r.get("resource_type"),
                    "service": service,
                    "account_id": r.get("account_id"),
                    "region": r.get("region"),
                }

    logger.info(
        f"Dependency graph complete: {len(graph.key_to_resources)} keys, "
        f"{len(graph.resource_to_keys)} resources, {graph.total_edges} edges"
    )
    return graph


def _resolve_key_arn(key_ref: str, key_metadata: Dict[str, Dict]) -> str:
    """Resolve a key reference (ID, alias, or partial ARN) to full ARN."""
    if not key_ref:
        return key_ref
    # Direct match
    if key_ref in key_metadata:
        return key_metadata[key_ref].get("key_arn", key_ref)
    # Strip alias/ prefix
    if key_ref.startswith("alias/"):
        for arn, meta in key_metadata.items():
            if meta.get("key_alias") == key_ref:
                return arn
    return key_ref


def _try_match_key(
    graph: DependencyGraph,
    resource_arn: str,
    known_key_arns: Set[str],
    enhanced_row: Dict,
):
    """Try to match a resource to a KMS key based on region/account heuristics."""
    region = enhanced_row.get("region", "")
    account_id = enhanced_row.get("account_id", "")

    # Look for a customer-managed key in the same region/account
    for key_arn in known_key_arns:
        meta = graph.key_metadata.get(key_arn, {})
        if (meta.get("key_manager") == "CUSTOMER"
                and meta.get("region") == region
                and meta.get("account_id") == account_id):
            graph.add_edge(key_arn, resource_arn)
            return
