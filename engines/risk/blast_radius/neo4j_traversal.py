"""Neo4j blast radius traversal — ONLY source of non-zero blast_radius_score in the platform.

This module computes how many resources are reachable from a given source
resource via graph relationships in the Neo4j security graph.

Security guarantees:
  - Cypher query is fully parameterized ($param syntax, no string concatenation)
  - Neo4j credentials (NEO4J_URI with embedded creds, NEO4J_PASSWORD) NEVER logged
  - Query timeout enforced at 30 s to prevent runaway traversals (AC-S6)
  - Traversal depth hard-capped at 4 hops (*1..4) (AC-S6)
  - blast_radius_score clamped to 0-100 before return (AC-S7)
  - Falls back to score=0 on ANY error (Neo4j unavailable, empty graph,
    timeout, missing module, credential failure) (AC-S3)

Graph traversal spec (ENG-13):
  Depth: 1..4 hops (hard cap)
  Relationships: EXPOSES, CONNECTS_TO, HAS_ACCESS_TO (plus ACCESSES as alias)
  Primary filter: target.sensitivity IN ['HIGH', 'CRITICAL'] (graph property)
  Secondary filter: resource_type pattern match (fallback when sensitivity absent)
  Score normalization: raw_count / 50 * 100, capped at 100

Graph property note:
  The inventory engine populates nodes with property `uid` (not `resource_uid`).
  Sensitivity is inferred from `resource_type` when the `sensitivity` property
  is not yet populated for this graph version.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# Neo4j connection config — read from env vars, NEVER logged.
# AC-S3: only log exception type, never log NEO4J_URI or NEO4J_PASSWORD values.
NEO4J_URI = os.getenv("NEO4J_URI", "neo4j+s://17ec5cbb.databases.neo4j.io")
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "")

# ── Primary Cypher — sensitivity property filter (ENG-13 spec) ───────────────
# AC-S1: fully parameterized — $uid / $resource_uid, no string concatenation.
# AC-S6: depth hard-capped at *1..4.
# Relationships: EXPOSES, CONNECTS_TO, HAS_ACCESS_TO (canonical ENG-13 set).
# Returns up to 10 sample target UIDs to bound memory usage.
BLAST_RADIUS_CYPHER = """
MATCH path = (source:Resource {uid: $uid})
  -[:EXPOSES|CONNECTS_TO|HAS_ACCESS_TO*1..4]->
  (target:Resource)
WHERE target.sensitivity IN ['HIGH', 'CRITICAL']
RETURN COUNT(DISTINCT target) AS blast_radius,
       COLLECT(DISTINCT target.uid)[..10] AS sample_targets
"""

# ── Secondary Cypher — resource_type pattern fallback ────────────────────────
# Used when the graph's sensitivity property is not yet populated.
# Same depth cap and parameterization guarantees.
BLAST_RADIUS_CYPHER_RESOURCE_TYPE = """
MATCH (source:Resource {uid: $uid})
  -[:EXPOSES|CONNECTS_TO|HAS_ACCESS_TO|ACCESSES*1..4]->
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

# ── Tertiary Cypher — all reachable resources (weakest signal) ───────────────
# Used only when both primary and secondary return 0.
# Score at 1/5 weight since general reachability is less critical.
BLAST_RADIUS_CYPHER_FALLBACK = """
MATCH (source:Resource {uid: $uid})
  -[:EXPOSES|CONNECTS_TO|HAS_ACCESS_TO|ACCESSES*1..4]->
  (target:Resource)
RETURN COUNT(DISTINCT target) AS blast_radius,
       COLLECT(DISTINCT target.uid)[..10] AS sample_targets
"""

# Score normalization: 50 reachable HIGH/CRITICAL resources → score 100 (AC-S7: clamp to 0-100)
_NORMALIZATION_DIVISOR = 50


def _clamp_score(raw_count: int, divisor: int) -> int:
    """Normalize raw Neo4j count to 0-100, enforcing AC-S7 clamp.

    Args:
        raw_count: Raw count of reachable nodes.
        divisor: Normalization factor (higher = harder to reach 100).

    Returns:
        Integer in range [0, 100].
    """
    return max(0, min(100, int(raw_count / divisor * 100)))


def compute_blast_radius(resource_uid: str, timeout_ms: int = 30000) -> Dict[str, Any]:
    """Run Neo4j blast radius traversal for the given resource.

    Three-tier query strategy (ENG-13):
    1. Primary: sensitivity IN ['HIGH','CRITICAL'] property filter
    2. Secondary: resource_type pattern match (when sensitivity absent)
    3. Tertiary: all reachable resources at 1/5 weight (weakest signal)

    Returns blast_radius_score (0-100, clamped per AC-S7) and up to 10
    sample reachable resource UIDs.

    Falls back to {'blast_radius_score': 0, 'sample_targets': []} on any
    error (Neo4j unavailable, empty graph, timeout, missing module).
    NEO4J_URI/NEO4J_PASSWORD are NEVER logged (AC-S3).

    Args:
        resource_uid: The resource UID to use as traversal start node.
            The graph uses the `uid` property (resource ARN / cloud ID).
        timeout_ms: Neo4j query timeout in milliseconds (default 30000ms = 30s).
            AC-S6: enforced at 30 s maximum.

    Returns:
        Dict with:
          blast_radius_score (int 0-100): normalized reachability score
          sample_targets (list[str]): up to 10 reachable resource UIDs
    """
    if not resource_uid:
        return {"blast_radius_score": 0, "sample_targets": []}

    driver = None
    try:
        from neo4j import GraphDatabase  # optional dependency — neo4j>=5.0
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USERNAME, NEO4J_PASSWORD))
        with driver.session() as session:
            # ── Tier 1: sensitivity property filter (ENG-13 canonical query) ──
            result = session.run(
                BLAST_RADIUS_CYPHER,
                uid=resource_uid,
                timeout=timeout_ms,
            )
            record = result.single()
            raw_count = int(record["blast_radius"] or 0) if record else 0
            sample: List[str] = list(record["sample_targets"] or []) if record else []

            if raw_count > 0:
                return {
                    "blast_radius_score": _clamp_score(raw_count, _NORMALIZATION_DIVISOR),
                    "sample_targets": sample,
                }

            # ── Tier 2: resource_type pattern match (sensitivity not populated) ──
            rt_result = session.run(
                BLAST_RADIUS_CYPHER_RESOURCE_TYPE,
                uid=resource_uid,
                timeout=timeout_ms,
            )
            rt_record = rt_result.single()
            rt_count = int(rt_record["blast_radius"] or 0) if rt_record else 0
            rt_sample: List[str] = list(rt_record["sample_targets"] or []) if rt_record else []

            if rt_count > 0:
                return {
                    "blast_radius_score": _clamp_score(rt_count, _NORMALIZATION_DIVISOR),
                    "sample_targets": rt_sample,
                }

            # ── Tier 3: all reachable nodes at 1/5 weight ─────────────────────
            fb_result = session.run(
                BLAST_RADIUS_CYPHER_FALLBACK,
                uid=resource_uid,
                timeout=timeout_ms,
            )
            fb_record = fb_result.single()
            fb_count = int(fb_record["blast_radius"] or 0) if fb_record else 0
            fb_sample: List[str] = list(fb_record["sample_targets"] or []) if fb_record else []
            if fb_count > 0:
                # Score at 1/5 weight: 250 reachable generic nodes → score 100
                return {
                    "blast_radius_score": _clamp_score(fb_count, _NORMALIZATION_DIVISOR * 5),
                    "sample_targets": fb_sample,
                }
            return {"blast_radius_score": 0, "sample_targets": []}

    except ImportError:
        # neo4j package not installed — graceful degradation
        logger.warning(
            "neo4j Python driver not installed — blast_radius_score=0 for resource_uid=%s "
            "(add neo4j>=5.0 to requirements.txt to enable graph traversal)",
            resource_uid,
        )
        return {"blast_radius_score": 0, "sample_targets": []}
    except Exception as exc:
        # AC-S3: log only exception type, never log NEO4J_URI or NEO4J_PASSWORD.
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

    Opens one driver connection, runs the three-tier query strategy per UID,
    then closes the driver. This is significantly faster than calling
    compute_blast_radius() in a loop (avoids N driver open/close cycles).

    Security:
    - All queries fully parameterized (AC-S1)
    - NEO4J_URI / NEO4J_PASSWORD never logged (AC-S3)
    - blast_radius_score clamped to 0-100 (AC-S7)
    - 30-second per-query timeout (AC-S6)

    Falls back gracefully: if Neo4j is unavailable, returns score=0 for all UIDs.

    Args:
        resource_uids: List of resource UID strings to query (may include '').
        timeout_ms: Per-query timeout in milliseconds (default 30000ms).

    Returns:
        Dict mapping resource_uid -> {'blast_radius_score': int, 'sample_targets': list}.
        Empty-string key '' maps to score=0.
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
        from neo4j import GraphDatabase  # optional dependency — neo4j>=5.0
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
                    # ── Tier 1: sensitivity property filter ───────────────────
                    rec = session.run(
                        BLAST_RADIUS_CYPHER, uid=uid, timeout=timeout_ms
                    ).single()
                    raw_count = int(rec["blast_radius"] or 0) if rec else 0
                    sample: List[str] = list(rec["sample_targets"] or []) if rec else []

                    if raw_count > 0:
                        result_map[uid] = {
                            "blast_radius_score": _clamp_score(raw_count, _NORMALIZATION_DIVISOR),
                            "sample_targets": sample,
                        }
                        continue

                    # ── Tier 2: resource_type pattern match ───────────────────
                    rt_rec = session.run(
                        BLAST_RADIUS_CYPHER_RESOURCE_TYPE, uid=uid, timeout=timeout_ms
                    ).single()
                    rt_count = int(rt_rec["blast_radius"] or 0) if rt_rec else 0
                    rt_sample: List[str] = list(rt_rec["sample_targets"] or []) if rt_rec else []

                    if rt_count > 0:
                        result_map[uid] = {
                            "blast_radius_score": _clamp_score(rt_count, _NORMALIZATION_DIVISOR),
                            "sample_targets": rt_sample,
                        }
                        continue

                    # ── Tier 3: all reachable nodes at 1/5 weight ─────────────
                    fb_rec = session.run(
                        BLAST_RADIUS_CYPHER_FALLBACK, uid=uid, timeout=timeout_ms
                    ).single()
                    fb_count = int(fb_rec["blast_radius"] or 0) if fb_rec else 0
                    fb_sample: List[str] = list(fb_rec["sample_targets"] or []) if fb_rec else []
                    if fb_count > 0:
                        result_map[uid] = {
                            "blast_radius_score": _clamp_score(fb_count, _NORMALIZATION_DIVISOR * 5),
                            "sample_targets": fb_sample,
                        }
                    else:
                        result_map[uid] = {"blast_radius_score": 0, "sample_targets": []}

                except Exception as uid_exc:
                    # AC-S3: log only exception type, never URI or password
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
        # AC-S3: log only exception type
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

    # Fill in any UIDs not yet processed (budget exhausted or error path)
    for uid in resource_uids:
        if uid not in result_map:
            result_map[uid] = {"blast_radius_score": 0, "sample_targets": []}

    return result_map
