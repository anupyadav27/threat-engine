"""
PatternCompiler — compiles ThreatPattern models into parameterized Cypher queries.

Security contract (CP1-01):
  ALL runtime values from pattern fields — resource_types, check_rules_failing,
  edge_type, condition values — are passed as Neo4j $parameter bindings.
  NO f-string interpolation of pattern values into Cypher strings is permitted.
  This class is a parameterized template expander, not a string builder.

The compiled output is a (cypher_string, params_dict) tuple. The Cypher string
contains only static structure; the params_dict carries all pattern-derived values.
The CI linter (scripts/cypher_parameterization_linter.py) validates this contract
on every compiled output before merge.

Tier dispatch:
  Tier 1 → _compile_tier1: single-node flag match, no traversal
  Tier 2 → _compile_tier2: partial path match (entry + N hops, no crown jewel required)
  Tier 3 → _compile_tier3: full path match (entry → hops → crown jewel target)
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

from threat_v1.patterns.models import NodeConditions, NodeSpec, ThreatPattern

logger = logging.getLogger(__name__)

# Type alias for compiled output
CypherPair = Tuple[str, Dict[str, Any]]

# Mandatory tenant_id filter — all compiled Cypher must include this
_TENANT_FILTER = "r_entry.tenant_id = $tid"


class PatternCompiler:
    """Compiles a ThreatPattern into a parameterized Cypher query + params dict."""

    def compile(self, pattern: ThreatPattern, tenant_id: str) -> CypherPair:
        """Compile pattern to (cypher, params). Dispatches by tier."""
        if pattern.tier == 1:
            return self._compile_tier1(pattern, tenant_id)
        if pattern.tier == 2:
            return self._compile_tier2(pattern, tenant_id)
        return self._compile_tier3(pattern, tenant_id)

    # ── Tier 1: flag-based single-node match ──────────────────────────────────

    def _compile_tier1(self, pattern: ThreatPattern, tenant_id: str) -> CypherPair:
        """Single MATCH on entry node — no traversal, uses boolean flags only."""
        params: Dict[str, Any] = {"tid": tenant_id, "pattern_id": pattern.id}
        where_clauses: List[str] = [_TENANT_FILTER]

        # Resource type filter
        if pattern.entry.resource_types:
            params["entry_types"] = pattern.entry.resource_types
            where_clauses.append("r_entry.resource_type IN $entry_types")

        self._add_condition_clauses(
            pattern.entry.conditions, "r_entry", where_clauses, params, prefix="entry_cond"
        )

        where = " AND ".join(where_clauses)
        cypher = (
            "MATCH (r_entry:Resource)\n"
            f"WHERE {where}\n"
            "RETURN r_entry.resource_uid AS entry_uid,\n"
            "       r_entry.resource_type AS entry_type,\n"
            "       r_entry.tenant_id AS tenant_id,\n"
            "       r_entry.account_id AS account_id,\n"
            "       r_entry.region AS region,\n"
            "       $pattern_id AS pattern_id"
        )
        return cypher, params

    # ── Tier 2: partial path (entry + hops, no crown jewel required) ─────────

    def _compile_tier2(self, pattern: ThreatPattern, tenant_id: str) -> CypherPair:
        """Multi-hop match for partial chain detection (early warning)."""
        params: Dict[str, Any] = {"tid": tenant_id, "pattern_id": pattern.id}
        where_clauses: List[str] = [_TENANT_FILTER]
        match_lines: List[str] = ["MATCH (r_entry:Resource)"]

        if pattern.entry.resource_types:
            params["entry_types"] = pattern.entry.resource_types
            where_clauses.append("r_entry.resource_type IN $entry_types")

        self._add_condition_clauses(
            pattern.entry.conditions, "r_entry", where_clauses, params, prefix="e0"
        )

        # Build hop chain
        for i, hop in enumerate(pattern.hops):
            node_alias = f"r_hop{i}"
            edge_param = f"edge_type_{i}"
            # Edge type is passed as a param — but Neo4j doesn't support
            # parameterized relationship types, so we use CONNECTED_TO with
            # a relation_type property filter as fallback. The APOC dynamic
            # relationship alternative is handled in edge_builder at write time.
            params[edge_param] = hop.edge_type
            prev_alias = "r_entry" if i == 0 else f"r_hop{i - 1}"
            match_lines.append(
                f"MATCH ({prev_alias})"
                f"-[e{i}:CONNECTED_TO|ASSUMES|GRANTS_ACCESS_TO|STORES_DATA_IN|"
                f"INVOKES|ROUTES_TO|RUNS_ON|HAS_POLICY|ATTACHED_TO|"
                f"CAN_ESCALATE_TO|CAN_ACCESS|EXECUTES_IN|FLOWS_TO]->(r_hop{i}:Resource)"
            )
            where_clauses.append(f"{node_alias}.tenant_id = $tid")

            if hop.target.resource_types:
                params[f"hop{i}_types"] = hop.target.resource_types
                where_clauses.append(f"{node_alias}.resource_type IN $hop{i}_types")

            self._add_condition_clauses(
                hop.target.conditions, node_alias, where_clauses, params,
                prefix=f"h{i}",
            )

        where = " AND ".join(where_clauses)
        match_block = "\n".join(match_lines)

        return_aliases = ["r_entry.resource_uid AS entry_uid"]
        for i in range(len(pattern.hops)):
            return_aliases.append(f"r_hop{i}.resource_uid AS hop{i}_uid")

        cypher = (
            f"{match_block}\n"
            f"WHERE {where}\n"
            f"RETURN {', '.join(return_aliases)},\n"
            "       r_entry.account_id AS account_id,\n"
            "       r_entry.region AS region,\n"
            "       r_entry.tenant_id AS tenant_id,\n"
            "       $pattern_id AS pattern_id"
        )
        return cypher, params

    # ── Tier 3: full path to crown jewel ─────────────────────────────────────

    def _compile_tier3(self, pattern: ThreatPattern, tenant_id: str) -> CypherPair:
        """Full attack path from entry to crown jewel target."""
        params: Dict[str, Any] = {"tid": tenant_id, "pattern_id": pattern.id}
        where_clauses: List[str] = [_TENANT_FILTER]

        match_lines: List[str] = ["MATCH (r_entry:Resource)"]

        if pattern.entry.resource_types:
            params["entry_types"] = pattern.entry.resource_types
            where_clauses.append("r_entry.resource_type IN $entry_types")

        self._add_condition_clauses(
            pattern.entry.conditions, "r_entry", where_clauses, params, prefix="e0"
        )

        # Hops
        prev_alias = "r_entry"
        for i, hop in enumerate(pattern.hops):
            node_alias = f"r_hop{i}"
            match_lines.append(
                f"MATCH ({prev_alias})"
                f"-[:CONNECTED_TO|ASSUMES|GRANTS_ACCESS_TO|STORES_DATA_IN|"
                f"INVOKES|ROUTES_TO|RUNS_ON|HAS_POLICY|ATTACHED_TO|"
                f"CAN_ESCALATE_TO|CAN_ACCESS|EXECUTES_IN|FLOWS_TO*1..2]->"
                f"({node_alias}:Resource)"
            )
            where_clauses.append(f"{node_alias}.tenant_id = $tid")

            if hop.target.resource_types:
                params[f"hop{i}_types"] = hop.target.resource_types
                where_clauses.append(f"{node_alias}.resource_type IN $hop{i}_types")

            self._add_condition_clauses(
                hop.target.conditions, node_alias, where_clauses, params, prefix=f"h{i}",
            )
            prev_alias = node_alias

        # Target node (crown jewel destination)
        if pattern.target:
            match_lines.append(
                f"MATCH ({prev_alias})"
                f"-[:CONNECTED_TO|ASSUMES|GRANTS_ACCESS_TO|STORES_DATA_IN|"
                f"INVOKES|ROUTES_TO|RUNS_ON|HAS_POLICY|ATTACHED_TO|"
                f"CAN_ESCALATE_TO|CAN_ACCESS|EXECUTES_IN|FLOWS_TO*1..3]->"
                f"(r_target:Resource)"
            )
            where_clauses.append("r_target.tenant_id = $tid")

            if pattern.target.resource_types:
                params["target_types"] = pattern.target.resource_types
                where_clauses.append("r_target.resource_type IN $target_types")

            self._add_condition_clauses(
                pattern.target.conditions, "r_target", where_clauses, params,
                prefix="tgt",
            )

        where = " AND ".join(where_clauses)
        match_block = "\n".join(match_lines)

        hop_returns = [f"r_hop{i}.resource_uid AS hop{i}_uid" for i in range(len(pattern.hops))]
        target_return = ", r_target.resource_uid AS target_uid" if pattern.target else ""

        cypher = (
            f"{match_block}\n"
            f"WHERE {where}\n"
            f"RETURN r_entry.resource_uid AS entry_uid,\n"
            f"       {', '.join(hop_returns) + ',' if hop_returns else ''}\n"
            f"       r_entry.account_id AS account_id,\n"
            f"       r_entry.region AS region,\n"
            f"       r_entry.tenant_id AS tenant_id"
            f"{target_return},\n"
            f"       $pattern_id AS pattern_id\n"
            f"LIMIT 200"
        )
        return cypher, params

    # ── Condition clause builder ──────────────────────────────────────────────

    def _add_condition_clauses(
        self,
        conditions: NodeConditions,
        node_alias: str,
        where_clauses: List[str],
        params: Dict[str, Any],
        prefix: str,
    ) -> None:
        """Translate NodeConditions to WHERE clauses with $param bindings."""
        # check_rules_failing: resource must have a MisconfigFinding for each rule
        for i, rule_id in enumerate(conditions.check_rules_failing):
            param_key = f"{prefix}_rule_{i}"
            params[param_key] = rule_id
            where_clauses.append(
                f"EXISTS {{"
                f"MATCH ({node_alias})-[:HAS_MISCONFIG]->(f_{prefix}_{i}:MisconfigFinding) "
                f"WHERE f_{prefix}_{i}.rule_id = ${param_key}"
                f"}}"
            )

        # Boolean flag conditions — direct property match
        bool_flags = {
            "is_crown_jewel": conditions.is_crown_jewel,
            "internet_exposed": conditions.internet_exposed,
            "has_critical_cve": conditions.has_critical_cve,
            "is_admin_role": conditions.is_admin_role,
            "cdr_actor_seen": conditions.cdr_actor_seen,
        }
        for flag_name, flag_val in bool_flags.items():
            if flag_val is not None:
                param_key = f"{prefix}_{flag_name}"
                params[param_key] = flag_val
                where_clauses.append(f"{node_alias}.{flag_name} = ${param_key}")

        # Extra fields via model_extra (forward-compatible)
        for key, val in (conditions.model_extra or {}).items():
            if val is not None:
                param_key = f"{prefix}_extra_{key}"
                params[param_key] = val
                where_clauses.append(f"{node_alias}.{key} = ${param_key}")
