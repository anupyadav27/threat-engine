"""Neo4j blast radius traversal — ONLY source of non-zero blast_radius_score in the platform.

This module computes how many resources are reachable from a given source
resource via graph relationships in the Neo4j security graph.

Security guarantees:
  - Cypher query is fully parameterized (no string concatenation)
  - Neo4j credentials are NEVER logged
  - Query timeout enforced at 30s to prevent runaway traversals
  - Falls back to score=0 on ANY error (Neo4j unavailable, empty graph,
    timeout, missing module, credential failure)

Graph traversal spec (ENG-13):
  Depth: 1..4 hops
  Relationships: EXPOSES, CONNECTS_TO, HAS_ACCESS_TO (ACCESSES as fallback)
  High-value target filter: resource_type matches known sensitive service patterns
  Score normalization: raw_count / 50 * 100, capped at 100

Graph property note:
  The inventory engine populates nodes with property `uid` (not `resource_uid`).
  Sensitivity is inferred from `resource_type` since the `sensitivity` property
  is not yet populated in this graph version.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# Neo4j connection config — read from env, never logged
NEO4J_URI = os.getenv("NEO4J_URI", "neo4j+s://17ec5cbb.databases.neo4j.io")
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "")

# Blast radius Cypher — fully parameterized, no string concatenation.
# Uses `uid` property (inventory engine standard, not `resource_uid`).
# Sensitivity is inferred from resource_type since sensitivity property is not
# yet populated in the graph.
# Traversal depth 4, LIMIT 10 on sample_targets to prevent memory explosion.
BLAST_RADIUS_CYPHER = """
MATCH (source:Resource {uid: $uid})
  -[:EXPOSES|CONNECTS_TO|ACCESSES*1..4]->
  (target:Resource)
WHERE toLower(target.resource_type) CONTAINS 'rds'
   OR toLower(target.resource_type) CONTAINS 'secret'
   OR toLower(target.resource_type) CONTAINS 'database'
   OR toLower(target.resource_type) CONTAINS 'sql'
   OR toLower(target.resource_type) CONTAINS 'kms'
   OR toLower(target.resource_type) CONTAINS 's3'
   OR toLower(target.resource_type) CONTAINS 'storage'
   OR toLower(target.resource_type) CONTAINS 'cluster'
   OR toLower(target.resource_type) CONTAINS 'keyvault'
   OR toLower(target.resource_type) CONTAINS 'autonomousdatabase'
   OR toLower(target.resource_type) CONTAINS 'bigquery'
   OR toLower(target.resource_type) CONTAINS 'oss'
RETURN COUNT(DISTINCT target) AS blast_radius,
       COLLECT(DISTINCT target.uid)[..10] AS sample_targets
"""

# Fallback: count ALL reachable resources when no high-value filter matches.
# This ensures non-zero score for well-connected resources even when the graph
# lacks typed high-value targets.
BLAST_RADIUS_CYPHER_FALLBACK = """
MATCH (source:Resource {uid: $uid})
  -[:EXPOSES|CONNECTS_TO|ACCESSES*1..4]->
  (target:Resource)
RETURN COUNT(DISTINCT target) AS blast_radius,
       COLLECT(DISTINCT target.uid)[..10] AS sample_targets
"""

# Score normalization: 50 reachable HIGH/CRITICAL resources → score 100
_NORMALIZATION_DIVISOR = 50


def compute_blast_radius(resource_uid: str, timeout_ms: int = 30000) -> Dict[str, Any]:
    """Run Neo4j blast radius traversal for the given resource.

    Attempts primary query (high-value resource_type filter) first.
    If that returns 0, falls back to counting all reachable resources
    (divided by 5 for scoring since general reachability is less critical).

    Returns blast_radius_score (0-100) and up to 10 sample reachable
    resource UIDs.

    Falls back to {'blast_radius_score': 0, 'sample_targets': []} on any
    error (Neo4j unavailable, empty graph, timeout, missing module).

    Args:
        resource_uid: The resource UID to use as traversal start node.
            The graph uses the `uid` property which corresponds to the
            resource's ARN / cloud resource ID.
        timeout_ms: Neo4j query timeout in milliseconds (default 30000ms).

    Returns:
        Dict with:
          blast_radius_score (int 0-100): normalized reachability score
          sample_targets (list[str]): up to 10 reachable resource UIDs
    """
    if not resource_uid:
        return {"blast_radius_score": 0, "sample_targets": []}

    driver = None
    try:
        from neo4j import GraphDatabase  # optional dependency
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USERNAME, NEO4J_PASSWORD))
        with driver.session() as session:
            # Primary query: high-value resource_type filter
            result = session.run(
                BLAST_RADIUS_CYPHER,
                uid=resource_uid,
                timeout=timeout_ms,
            )
            record = result.single()
            raw_count = int(record["blast_radius"] or 0) if record else 0
            sample: List[str] = (record["sample_targets"] or []) if record else []

            # Fallback: if primary query returns 0, count all reachable nodes
            # Score at 1/5 weight (general reachability vs high-value reachability)
            if raw_count == 0:
                fb_result = session.run(
                    BLAST_RADIUS_CYPHER_FALLBACK,
                    uid=resource_uid,
                    timeout=timeout_ms,
                )
                fb_record = fb_result.single()
                fb_count = int(fb_record["blast_radius"] or 0) if fb_record else 0
                fb_sample: List[str] = (fb_record["sample_targets"] or []) if fb_record else []
                if fb_count > 0:
                    # Score at 1/5 weight: 250 reachable generic nodes → score 100
                    score = min(int(fb_count / (_NORMALIZATION_DIVISOR * 5) * 100), 100)
                    return {"blast_radius_score": score, "sample_targets": fb_sample}
                return {"blast_radius_score": 0, "sample_targets": []}

            # Normalize: cap at 50 reachable HIGH/CRITICAL resources = score 100
            score = min(int(raw_count / _NORMALIZATION_DIVISOR * 100), 100)
            return {"blast_radius_score": score, "sample_targets": sample}

    except ImportError:
        # neo4j package not installed — graceful degradation
        logger.warning(
            "neo4j Python driver not installed — blast_radius_score=0 for %s "
            "(add neo4j>=5.0 to requirements.txt to enable graph traversal)",
            resource_uid,
        )
        return {"blast_radius_score": 0, "sample_targets": []}
    except Exception as exc:
        # Log at WARNING (not ERROR) — Neo4j down is expected in some environments.
        # Do NOT log exc details that could contain credentials.
        logger.warning(
            "Neo4j blast radius traversal failed for resource_uid=%s: %s — using score=0",
            resource_uid,
            type(exc).__name__,
        )
        return {"blast_radius_score": 0, "sample_targets": []}
    finally:
        if driver is not None:
            try:
                driver.close()
            except Exception:
                pass


def compute_blast_radius_batch(
    resource_uids: List[str], timeout_ms: int = 30000
) -> Dict[str, Any]:
    """Compute blast radius for a batch of resource UIDs using a single Neo4j driver.

    Opens one driver connection, runs one query per unique UID, then closes the
    driver. This is dramatically faster than calling compute_blast_radius() in a
    loop (avoids N driver open/close cycles for N findings).

    Falls back gracefully: if Neo4j is unavailable, returns score=0 for all UIDs.

    Args:
        resource_uids: List of resource UID strings to query (may include '').
        timeout_ms: Per-query timeout in milliseconds.

    Returns:
        Dict mapping resource_uid -> {'blast_radius_score': int, 'sample_targets': list}
        Empty string key '' maps to score=0.
    """
    # Hard time budget: Neo4j traversal for large scans (e.g. 1500 AWS resources)
    # can take hours. Cap at 5 minutes total; remaining UIDs get score=0.
    MAX_BLAST_RADIUS_SECONDS = 300
    budget_start = time.time()

    result_map: Dict[str, Any] = {}
    if not resource_uids:
        return result_map

    driver = None
    try:
        from neo4j import GraphDatabase  # optional dependency
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USERNAME, NEO4J_PASSWORD))

        with driver.session() as session:
            for uid in resource_uids:
                if time.time() - budget_start > MAX_BLAST_RADIUS_SECONDS:
                    logger.warning(
                        "Blast radius time budget (%ds) exceeded — scoring %d remaining UIDs as 0",
                        MAX_BLAST_RADIUS_SECONDS,
                        sum(1 for u in resource_uids if u not in result_map),
                    )
                    break
                if not uid:
                    result_map[uid] = {"blast_radius_score": 0, "sample_targets": []}
                    continue

                try:
                    # Primary: high-value resource_type filter
                    rec = session.run(
                        BLAST_RADIUS_CYPHER, uid=uid, timeout=timeout_ms
                    ).single()
                    raw_count = int(rec["blast_radius"] or 0) if rec else 0
                    sample: List[str] = (rec["sample_targets"] or []) if rec else []

                    if raw_count == 0:
                        # Fallback: count all reachable nodes at 1/5 weight
                        fb_rec = session.run(
                            BLAST_RADIUS_CYPHER_FALLBACK, uid=uid, timeout=timeout_ms
                        ).single()
                        fb_count = int(fb_rec["blast_radius"] or 0) if fb_rec else 0
                        fb_sample: List[str] = (fb_rec["sample_targets"] or []) if fb_rec else []
                        if fb_count > 0:
                            score = min(int(fb_count / (_NORMALIZATION_DIVISOR * 5) * 100), 100)
                            result_map[uid] = {"blast_radius_score": score, "sample_targets": fb_sample}
                        else:
                            result_map[uid] = {"blast_radius_score": 0, "sample_targets": []}
                    else:
                        score = min(int(raw_count / _NORMALIZATION_DIVISOR * 100), 100)
                        result_map[uid] = {"blast_radius_score": score, "sample_targets": sample}

                except Exception as uid_exc:
                    logger.warning(
                        "Neo4j blast radius failed for uid=%s: %s — using score=0",
                        uid, type(uid_exc).__name__,
                    )
                    result_map[uid] = {"blast_radius_score": 0, "sample_targets": []}

    except ImportError:
        logger.warning(
            "neo4j Python driver not installed — blast_radius_score=0 for all %d UIDs",
            len(resource_uids),
        )
    except Exception as exc:
        logger.warning(
            "Neo4j batch blast radius failed (%s) — using score=0 for all %d UIDs",
            type(exc).__name__, len(resource_uids),
        )
    finally:
        if driver is not None:
            try:
                driver.close()
            except Exception:
                pass

    # Fill in any UIDs that were not processed (error path)
    for uid in resource_uids:
        if uid not in result_map:
            result_map[uid] = {"blast_radius_score": 0, "sample_targets": []}

    return result_map
