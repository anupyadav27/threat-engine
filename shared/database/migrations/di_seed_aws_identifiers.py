"""
DI Identifier Seeder — AWS

Reads step6 YAML discovery files + AWS check rules to generate the correct
resource_inventory_identifier rows driven by what check rules actually need.

Output: inserts into resource_inventory_identifier (threat_engine_inventory DB).

Run:
    python3 di_seed_aws_identifiers.py --dry-run      # print SQL only
    python3 di_seed_aws_identifiers.py --apply        # write to DB

The seeder builds:
  - One identifier row per ROOT discovery op that check rules reference
    (either directly as for_each, or as parent of an enrichment for_each)
  - root_ops  = the YAML ops needed to enumerate resources (may be chained)
  - enrich_ops = the YAML ops check rules reference as for_each (not the root op itself)
  - uid_template = how to build canonical UID from item + context + parent
  - discovery_id = root op's discovery_id (stored in asset_inventory.discovery_id for root rows)

Enrichment rows in asset_inventory use discovery_id = enrich_op.discovery_id.
DIReader queries: WHERE discovery_id = for_each_value (direct match — no translation).
"""
from __future__ import annotations

import argparse
import glob
import json
import logging
import os
import sys
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("di_seeder")

CATALOG_DIR = os.path.join(
    os.path.dirname(__file__), "../../..",
    "catalog/discovery_generator_data/aws"
)
RULES_DIR = os.path.join(
    os.path.dirname(__file__), "../../..",
    "catalog/rule/aws_rule_check"
)
CATALOG_DIR = os.path.abspath(CATALOG_DIR)
RULES_DIR = os.path.abspath(RULES_DIR)


# ---------------------------------------------------------------------------
# UID template heuristics
# Fields that ARE already a canonical ARN when present in the emit section.
# ---------------------------------------------------------------------------
_ARN_EMIT_FIELDS = {
    "Arn", "arn", "ARN", "ResourceArn", "FunctionArn", "RoleArn", "PolicyArn",
    "TopicArn", "QueueArn", "StreamArn", "ClusterArn", "BucketArn", "KeyArn",
    "CertificateArn", "LoadBalancerArn", "TargetGroupArn", "AccessPointArn",
    "ApplicationArn", "PipelineArn", "DatasetArn", "TableArn", "DomainArn",
    "RegistryArn", "RepositoryArn", "FileSystemArn", "VaultArn", "BackupPlanArn",
    "BackupVaultArn", "EnvironmentArn", "ApplicationVersionArn", "NotebookInstanceArn",
    "TrainingJobArn", "EndpointConfigArn", "ModelPackageArn", "HyperParameterTuningJobArn",
    "TransformJobArn", "FeatureGroupArn", "FlowDefinitionArn", "PipelineArn",
    "MonitorArn", "WorkspaceArn", "HubArn", "SubscriptionArn", "DeliveryStreamArn",
    "FirewallArn", "FirewallPolicyArn", "GraphArn", "GraphqlApiArn", "DiscoveryArn",
    "AssessmentArn", "EventDataStoreArn", "ChannelArn", "ConnectorArn",
    "jobArn", "clusterArn", "fargateProfileArn", "accessEntryArn",
    "nodegroupArn", "taskDefinitionArn",
}

# AWS ARN patterns by service for when we need to construct the ARN
# {context.partition} = aws, {context.region}, {context.account_id}
_SERVICE_ARN_PATTERNS: Dict[str, str] = {
    "ec2":            "arn:{context.partition}:ec2:{context.region}:{context.account_id}:{resource_entity}/{item.{id_field}}",
    "s3":             "arn:{context.partition}:s3:::{item.Name}",
    "iam":            "arn:{context.partition}:iam::{context.account_id}:{resource_entity}/{item.{id_field}}",
    "lambda":         "arn:{context.partition}:lambda:{context.region}:{context.account_id}:function:{item.FunctionName}",
    "rds":            "arn:{context.partition}:rds:{context.region}:{context.account_id}:db:{item.DBInstanceIdentifier}",
    "eks":            "arn:{context.partition}:eks:{context.region}:{context.account_id}:cluster/{item.name}",
    "kms":            "arn:{context.partition}:kms:{context.region}:{context.account_id}:key/{item.KeyId}",
    "secretsmanager": "arn:{context.partition}:secretsmanager:{context.region}:{context.account_id}:secret:{item.Name}",
    "sns":            "arn:{context.partition}:sns:{context.region}:{context.account_id}:{item.TopicArn}",
    "sqs":            "arn:{context.partition}:sqs:{context.region}:{context.account_id}:{item.QueueUrl}",
    "cloudtrail":     "arn:{context.partition}:cloudtrail:{context.region}:{context.account_id}:trail/{item.Name}",
    "cloudwatch":     "arn:{context.partition}:cloudwatch:{context.region}:{context.account_id}:alarm:{item.AlarmName}",
}


def _guess_uid_template(
    emit_item: Dict[str, str],
    service: str,
    discovery_id: str,
) -> Tuple[str, str]:
    """
    Returns (uid_template, uid_source).

    Priority:
      1. If emit_item has a known ARN field → uid_template = "{item.ArnField}"
      2. Else → uid_source = "heuristic" (uid_builder.py fallback at runtime)
    """
    for field in _ARN_EMIT_FIELDS:
        if field in emit_item:
            return f"{{item.{field}}}", "field"

    # No ARN field found — uid_builder.py will apply heuristic at runtime
    return "", "heuristic"


def _build_root_op_entry(
    entry: Dict[str, Any],
    discovery_id: str,
    items_for: bool,
) -> Dict[str, Any]:
    """Build a root_ops array entry from a YAML discovery entry."""
    calls = entry.get("calls", [])
    primary_call = calls[0] if calls else {}
    params = primary_call.get("params", {})

    return {
        "discovery_id": discovery_id,
        "operation": primary_call.get("action", ""),
        "params": params,
        "items_for": items_for,
        "on_error": primary_call.get("on_error", "continue"),
    }


def _build_enrich_op_entry(
    entry: Dict[str, Any],
    discovery_id: str,
    items_for: bool,
) -> Dict[str, Any]:
    """Build an enrich_ops array entry from a YAML discovery entry."""
    calls = entry.get("calls", [])
    primary_call = calls[0] if calls else {}
    params = primary_call.get("params", {})
    emit_fields = list(entry.get("emit", {}).get("item", {}).keys())

    return {
        "discovery_id": discovery_id,
        "operation": primary_call.get("action", ""),
        "params": params,
        "items_for": items_for,
        "emit_fields": emit_fields,
        "on_error": primary_call.get("on_error", "continue"),
    }


# ---------------------------------------------------------------------------
# Main seeder logic
# ---------------------------------------------------------------------------

def load_yaml_ops() -> Dict[str, Dict[str, Any]]:
    """Load all AWS step6 YAML ops. Returns {discovery_id: entry_dict}."""
    all_ops: Dict[str, Dict[str, Any]] = {}
    yaml_files = glob.glob(f"{CATALOG_DIR}/**/step6_*.discovery.yaml", recursive=True)
    for yf in yaml_files:
        service_dir = os.path.basename(os.path.dirname(yf))
        try:
            with open(yf) as f:
                data = yaml.safe_load(f)
            if not data or "discovery" not in data:
                continue
            for entry in data["discovery"]:
                did = entry.get("discovery_id")
                if did:
                    entry["_service_dir"] = service_dir
                    all_ops[did] = entry
        except Exception as e:
            logger.warning("Failed to parse %s: %s", yf, e)
    logger.info("Loaded %d YAML ops from %d files", len(all_ops), len(yaml_files))
    return all_ops


def load_check_rule_for_each() -> Dict[str, List[str]]:
    """Returns {for_each_discovery_id: [rule_ids]}."""
    mapping: Dict[str, List[str]] = defaultdict(list)
    for root, _, files in os.walk(RULES_DIR):
        for fname in files:
            if not fname.endswith(".yaml"):
                continue
            try:
                with open(os.path.join(root, fname)) as f:
                    data = yaml.safe_load(f)
                if not data or "checks" not in data:
                    continue
                for check in data["checks"]:
                    fe = check.get("for_each")
                    rid = check.get("rule_id", "unknown")
                    if fe:
                        mapping[fe].append(rid)
            except Exception:
                pass
    return dict(mapping)


def build_identifiers(
    all_ops: Dict[str, Dict[str, Any]],
    check_for_each: Dict[str, List[str]],
) -> List[Dict[str, Any]]:
    """
    Build the list of identifier row dicts to insert.

    Logic:
      - root ops (no for_each in YAML): one identifier row, discovery_id = root op's did
      - enrichment ops (have for_each in YAML): find their root, add them to that
        root's enrich_ops list

    Returns list of identifier dicts ready for DB insert.
    """
    root_ops_set: Set[str] = {
        did for did, e in all_ops.items() if not e.get("for_each")
    }
    enrichment_parent: Dict[str, str] = {
        did: e["for_each"] for did, e in all_ops.items() if e.get("for_each")
    }

    def trace_to_root(did: str, depth: int = 0) -> Optional[str]:
        if depth > 8:
            return None
        if did in root_ops_set:
            return did
        parent = enrichment_parent.get(did)
        if not parent:
            return None
        return trace_to_root(parent, depth + 1)

    # Map: root_discovery_id → set of for_each values referencing it
    root_to_for_each: Dict[str, Set[str]] = defaultdict(set)
    missing: List[str] = []
    for fe in check_for_each:
        if fe in root_ops_set:
            root_to_for_each[fe].add(fe)
        elif fe in enrichment_parent:
            root = trace_to_root(fe)
            if root:
                root_to_for_each[root].add(fe)
            else:
                missing.append(fe)
        else:
            missing.append(fe)

    if missing:
        logger.warning("for_each values not found in YAML (%d): %s", len(missing), missing)

    identifiers: List[Dict[str, Any]] = []

    for root_did in sorted(root_to_for_each.keys()):
        root_entry = all_ops.get(root_did, {})
        service_dir = root_entry.get("_service_dir", root_did.split(".")[1] if "." in root_did else "unknown")
        service = root_did.split(".")[1] if "." in root_did else service_dir

        emit = root_entry.get("emit", {})
        emit_item = emit.get("item", {})
        items_for_root = bool(emit.get("items_for"))

        uid_template, uid_source = _guess_uid_template(emit_item, service, root_did)

        # Build root_ops list (single entry for flat roots; chained for nested)
        root_ops = [_build_root_op_entry(root_entry, root_did, items_for_root)]

        # For each for_each value that maps to this root, build enrich_op entries
        enrich_ops: List[Dict[str, Any]] = []
        enrich_did_set = root_to_for_each[root_did] - {root_did}

        for enrich_did in sorted(enrich_did_set):
            enrich_entry = all_ops.get(enrich_did)
            if not enrich_entry:
                continue
            enrich_emit = enrich_entry.get("emit", {})
            items_for_enrich = bool(enrich_emit.get("items_for"))

            # Collect intermediate ops in the chain between root and this enrichment
            # e.g. root=list_clusters → intermediate=list_nodegroups → enrich=describe_nodegroup
            chain = _build_op_chain(enrich_did, root_did, all_ops, enrichment_parent)
            for chain_did in chain:
                if chain_did == root_did:
                    continue
                chain_entry = all_ops.get(chain_did, {})
                chain_items_for = bool(chain_entry.get("emit", {}).get("items_for"))
                enrich_ops.append(
                    _build_enrich_op_entry(chain_entry, chain_did, chain_items_for)
                )

        # Deduplicate enrich_ops (same discovery_id may appear from multiple paths)
        seen_enrich: Set[str] = set()
        unique_enrich: List[Dict[str, Any]] = []
        for eo in enrich_ops:
            if eo["discovery_id"] not in seen_enrich:
                seen_enrich.add(eo["discovery_id"])
                unique_enrich.append(eo)

        rule_count = sum(
            len(check_for_each.get(fe, []))
            for fe in root_to_for_each[root_did]
        )

        identifiers.append({
            "csp": "aws",
            "service": service,
            "resource_type": _guess_resource_type(root_did, service),
            "discovery_id": root_did,
            "uid_template": uid_template,
            "uid_source": uid_source,
            "root_ops": root_ops,
            "enrich_ops": unique_enrich,
            "should_inventory": True,
            "can_inventory_from_roots": True,
            "used_by_engines": ["check"],
            "_rule_count": rule_count,
        })

    logger.info("Built %d identifier entries", len(identifiers))
    return identifiers


def _build_op_chain(
    target_did: str,
    root_did: str,
    all_ops: Dict[str, Any],
    enrichment_parent: Dict[str, str],
) -> List[str]:
    """
    Returns the ordered chain of discovery_ids from root_did (exclusive) to
    target_did (inclusive). Used for intermediate enumeration hops.
    """
    chain: List[str] = []
    current = target_did
    for _ in range(10):
        chain.append(current)
        if current == root_did:
            break
        parent = enrichment_parent.get(current)
        if not parent:
            break
        current = parent
    chain.reverse()
    # Remove the root from chain (it's already in root_ops)
    return [d for d in chain if d != root_did]


def _guess_resource_type(discovery_id: str, service: str) -> str:
    """Derive a snake_case resource_type from the discovery_id operation name."""
    parts = discovery_id.split(".")
    if len(parts) >= 3:
        op = parts[2]  # e.g. "list_buckets" → "bucket"
        for prefix in ("list_", "describe_", "get_", "batch_get_"):
            if op.startswith(prefix):
                noun = op[len(prefix):]
                # Singularise simple plurals
                if noun.endswith("ies"):
                    noun = noun[:-3] + "y"
                elif noun.endswith("ses"):
                    noun = noun[:-2]
                elif noun.endswith("s") and not noun.endswith("ss"):
                    noun = noun[:-1]
                return noun
        return op
    return service


# ---------------------------------------------------------------------------
# SQL generation
# ---------------------------------------------------------------------------

def generate_sql(identifiers: List[Dict[str, Any]]) -> str:
    lines = [
        "-- Auto-generated by di_seed_aws_identifiers.py",
        "-- DO NOT EDIT MANUALLY — re-run seeder to regenerate",
        "",
        "BEGIN;",
        "",
        "-- Clear existing AWS entries (migration di_003 already did this, safe to repeat)",
        "DELETE FROM resource_inventory_identifier WHERE csp = 'aws';",
        "",
        "INSERT INTO resource_inventory_identifier (",
        "    csp, service, resource_type, discovery_id,",
        "    uid_template, uid_source,",
        "    root_ops, enrich_ops,",
        "    should_inventory, can_inventory_from_roots,",
        "    used_by_engines",
        ") VALUES",
    ]

    row_parts = []
    for idf in identifiers:
        root_ops_json = json.dumps(idf["root_ops"]).replace("'", "''")
        enrich_ops_json = json.dumps(idf["enrich_ops"]).replace("'", "''")
        used_by_json = json.dumps(idf["used_by_engines"]).replace("'", "''")
        uid_template = (idf["uid_template"] or "").replace("'", "''")
        uid_source = idf["uid_source"].replace("'", "''")

        row_parts.append(
            f"  ('{idf['csp']}', '{idf['service']}', '{idf['resource_type']}', "
            f"'{idf['discovery_id']}',\n"
            f"   '{uid_template}', '{uid_source}',\n"
            f"   '{root_ops_json}'::jsonb, '{enrich_ops_json}'::jsonb,\n"
            f"   TRUE, TRUE, '{used_by_json}'::jsonb)"
        )

    lines.append(",\n".join(row_parts) + ";")
    lines.append("")
    lines.append(f"-- Total: {len(identifiers)} AWS identifier entries")
    lines.append("")
    lines.append("COMMIT;")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# DB apply
# ---------------------------------------------------------------------------

def apply_to_db(sql: str) -> None:
    import psycopg2
    conn = psycopg2.connect(
        host=os.environ["INVENTORY_DB_HOST"],
        port=int(os.environ.get("INVENTORY_DB_PORT", 5432)),
        dbname=os.environ["INVENTORY_DB_NAME"],
        user=os.environ["INVENTORY_DB_USER"],
        password=os.environ["INVENTORY_DB_PASSWORD"],
        sslmode=os.environ.get("DB_SSLMODE", "prefer"),
    )
    try:
        with conn.cursor() as cur:
            cur.execute(sql)
        conn.commit()
        logger.info("Seeder applied successfully")
    except Exception as e:
        conn.rollback()
        logger.error("Seeder failed: %s", e)
        raise
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Seed AWS resource_inventory_identifier")
    parser.add_argument("--dry-run", action="store_true", help="Print SQL, do not apply")
    parser.add_argument("--apply", action="store_true", help="Apply to DB")
    parser.add_argument("--output", default="/tmp/di_seed_aws.sql", help="SQL output file")
    args = parser.parse_args()

    if not args.dry_run and not args.apply:
        parser.error("Specify --dry-run or --apply")

    all_ops = load_yaml_ops()
    check_for_each = load_check_rule_for_each()
    identifiers = build_identifiers(all_ops, check_for_each)

    sql = generate_sql(identifiers)

    with open(args.output, "w") as f:
        f.write(sql)
    logger.info("SQL written to %s (%d bytes)", args.output, len(sql))

    if args.dry_run:
        print(sql[:3000])
        print(f"\n... ({len(identifiers)} total identifier rows)")
        return

    if args.apply:
        apply_to_db(sql)


if __name__ == "__main__":
    main()
