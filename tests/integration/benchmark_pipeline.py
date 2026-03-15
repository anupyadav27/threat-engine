"""
Pipeline Performance Benchmark
================================

Measures execution time for the 5-layer pipeline under simulated load.
Engines are mocked with configurable latency to model realistic conditions.

Usage:
    python tests/integration/benchmark_pipeline.py
    python tests/integration/benchmark_pipeline.py --iterations 10 --latency 0.5
"""
from __future__ import annotations

import argparse
import asyncio
import statistics
import time
from typing import Dict, List
from unittest.mock import AsyncMock, MagicMock

# ── Simulated engine responses ────────────────────────────────────────────────


def _make_mock_handler(name: str, latency: float = 0.1) -> AsyncMock:
    """Create a mock handler that simulates engine latency."""
    async def _handler(*args, **kwargs):
        await asyncio.sleep(latency)
        return {
            "status": "completed",
            "scan_id": f"{name}-scan-001",
            f"{name}_scan_id": f"{name}-scan-001",
        }
    mock = AsyncMock(side_effect=_handler)
    mock.__name__ = f"trigger_{name}"
    return mock


def _make_failing_mock(name: str, fail_rate: float = 0.2, latency: float = 0.1) -> AsyncMock:
    """Create a mock that fails at a given rate to test resilience."""
    import random
    async def _handler(*args, **kwargs):
        await asyncio.sleep(latency)
        if random.random() < fail_rate:
            raise Exception(f"{name} simulated failure")
        return {"status": "completed", "scan_id": f"{name}-scan-001"}
    return AsyncMock(side_effect=_handler)


# ── Benchmark runner ──────────────────────────────────────────────────────────


async def benchmark_pipeline(
    iterations: int = 5,
    engine_latency: float = 0.1,
    fail_rate: float = 0.0,
) -> Dict[str, any]:
    """Run the pipeline multiple times and collect timing statistics.

    Args:
        iterations: Number of pipeline runs.
        engine_latency: Simulated per-engine latency in seconds.
        fail_rate: Probability of engine failure (0.0 - 1.0).

    Returns:
        Dict with timing statistics.
    """
    # Import here to allow patching
    from unittest.mock import patch
    import os

    os.environ["SQS_PIPELINE_QUEUE_URL"] = "https://sqs.test/benchmark"
    os.environ["ENABLE_COLLECTORS"] = "true"
    os.environ["ENABLE_NEW_ENGINES"] = "true"

    from shared.pipeline_worker.worker import run_pipeline

    # All 16 handlers
    handler_names = [
        "log_collector", "external_collector",
        "inventory", "container", "api_engine",
        "check", "iam", "secops", "network", "ai_security",
        "threat", "datasec", "supplychain", "datasec_enhanced",
        "compliance", "risk",
    ]

    patches = {}
    for name in handler_names:
        target = f"shared.pipeline_worker.handlers.trigger_{name}"
        if fail_rate > 0:
            patches[name] = patch(target, _make_failing_mock(name, fail_rate, engine_latency))
        else:
            patches[name] = patch(target, _make_mock_handler(name, engine_latency))

    # Create mock event and SQS
    event = MagicMock()
    event.orchestration_id = "bench-orch-001"
    event.tenant_id = "bench-tenant"
    event.account_id = "123456789012"
    event.provider = "aws"
    sqs = MagicMock()
    sqs.publish = MagicMock()

    timings: List[float] = []
    errors: int = 0

    # Start all patches
    mocks = {name: p.start() for name, p in patches.items()}

    try:
        for i in range(iterations):
            start = time.monotonic()
            try:
                await run_pipeline(event, sqs)
            except Exception:
                errors += 1
            elapsed = time.monotonic() - start
            timings.append(elapsed)
            print(f"  iteration {i+1}/{iterations}: {elapsed:.3f}s")
    finally:
        for p in patches.values():
            p.stop()

    # Calculate statistics
    results = {
        "iterations": iterations,
        "engine_latency_s": engine_latency,
        "fail_rate": fail_rate,
        "total_engines": len(handler_names),
        "layers": 5,
        "timings_s": timings,
        "min_s": min(timings),
        "max_s": max(timings),
        "mean_s": statistics.mean(timings),
        "median_s": statistics.median(timings),
        "stdev_s": statistics.stdev(timings) if len(timings) > 1 else 0,
        "errors": errors,
    }

    # Theoretical minimum: 5 layers × engine_latency (all parallel within layer)
    theoretical_min = 5 * engine_latency
    results["theoretical_min_s"] = theoretical_min
    results["overhead_pct"] = (
        ((results["mean_s"] - theoretical_min) / theoretical_min * 100)
        if theoretical_min > 0 else 0
    )

    return results


def print_report(results: Dict) -> None:
    """Print a formatted benchmark report."""
    print("\n" + "=" * 70)
    print("PIPELINE PERFORMANCE BENCHMARK REPORT")
    print("=" * 70)
    print(f"  Iterations:        {results['iterations']}")
    print(f"  Engine latency:    {results['engine_latency_s']:.3f}s")
    print(f"  Fail rate:         {results['fail_rate']:.1%}")
    print(f"  Total engines:     {results['total_engines']}")
    print(f"  Pipeline layers:   {results['layers']}")
    print()
    print("  TIMING RESULTS:")
    print(f"    Min:             {results['min_s']:.3f}s")
    print(f"    Max:             {results['max_s']:.3f}s")
    print(f"    Mean:            {results['mean_s']:.3f}s")
    print(f"    Median:          {results['median_s']:.3f}s")
    print(f"    Std Dev:         {results['stdev_s']:.3f}s")
    print()
    print(f"  Theoretical min:   {results['theoretical_min_s']:.3f}s (5 layers × latency)")
    print(f"  Overhead:          {results['overhead_pct']:.1f}%")
    print(f"  Pipeline errors:   {results['errors']}")
    print("=" * 70)

    # Pass/fail assessment
    if results["overhead_pct"] < 50:
        print("  RESULT: PASS — Overhead within acceptable range (<50%)")
    elif results["overhead_pct"] < 100:
        print("  RESULT: WARN — Overhead is elevated (50-100%)")
    else:
        print("  RESULT: FAIL — Overhead exceeds acceptable range (>100%)")
    print()


# ── Main ──────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(description="Pipeline performance benchmark")
    parser.add_argument("--iterations", type=int, default=5, help="Number of runs")
    parser.add_argument("--latency", type=float, default=0.1, help="Simulated engine latency (s)")
    parser.add_argument("--fail-rate", type=float, default=0.0, help="Engine failure probability")
    args = parser.parse_args()

    print(f"\nRunning pipeline benchmark ({args.iterations} iterations, "
          f"{args.latency}s latency, {args.fail_rate:.0%} fail rate)...\n")

    results = asyncio.run(benchmark_pipeline(
        iterations=args.iterations,
        engine_latency=args.latency,
        fail_rate=args.fail_rate,
    ))
    print_report(results)

    # Also run with failure simulation
    if args.fail_rate == 0.0:
        print("\nRunning resilience benchmark (20% failure rate)...\n")
        results_fail = asyncio.run(benchmark_pipeline(
            iterations=args.iterations,
            engine_latency=args.latency,
            fail_rate=0.2,
        ))
        print_report(results_fail)


if __name__ == "__main__":
    main()
