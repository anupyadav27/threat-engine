#!/usr/bin/env python3
import os
import argparse
import json
from datetime import datetime
from typing import List, Dict, Any

from .engine import run_yaml_engine
from .utils.reporting import create_reporter


def parse_args():
    p = argparse.ArgumentParser(description="Run YAML-driven Kubernetes checks")
    p.add_argument("--rules-dir", type=str, default=os.path.join(os.path.dirname(__file__), "rules"))
    p.add_argument("--kubeconfig", type=str, default=None)
    p.add_argument("--context", type=str, default=None)
    p.add_argument("--components", nargs="+", default=["apiserver"]) 
    p.add_argument("--verbose", action="store_true")
    # If --output is a file path, write a single combined JSON there (backward compatible)
    p.add_argument("--output", type=str, default=None)
    # Preferred: base directory where timestamped outputs are written (default to service output/)
    default_output_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "output"))
    p.add_argument("--output-dir", type=str, default=default_output_dir)
    p.add_argument("--mock-dir", type=str, default=None, help="Directory with mock component JSON files, named by component")
    return p.parse_args()


def load_mocks(mock_dir: str) -> Dict[str, Any]:
    mocks: Dict[str, Any] = {}
    if not mock_dir:
        return mocks
    for name in os.listdir(mock_dir):
        if not name.endswith('.json'):
            continue
        component = os.path.splitext(name)[0]
        path = os.path.join(mock_dir, name)
        with open(path, 'r') as fh:
            mocks[component] = json.load(fh)
    return mocks


def _write_per_component_check_reports(results, checks_dir: str):
    os.makedirs(checks_dir, exist_ok=True)
    # Group by component from metadata
    by_component: Dict[str, list] = {}
    for r in results:
        comp = (r.metadata or {}).get("component") or (r.resource_name.split(":")[0] if r.resource_name else "kubernetes")
        by_component.setdefault(comp, []).append(r)

    # Use reporter per component to generate JSON
    for comp, comp_results in by_component.items():
        reporter = create_reporter(cluster_info={})
        reporter.add_results(comp_results)
        out_path = os.path.join(checks_dir, f"{comp}_checks.json")
        reporter.generate_json_report(out_path)


def main():
    args = parse_args()
    mocks = load_mocks(args.mock_dir) if args.mock_dir else {}

    # If args.output is a file path that doesn't look like a directory, honor it (single file)
    single_output_file = None
    if args.output and (os.path.splitext(args.output)[1] or (args.output and not args.output.endswith(os.sep) and not os.path.isdir(args.output))):
        single_output_file = args.output

    # Prepare timestamped output directories when not writing a single combined file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_output_dir = args.output_dir
    inventory_dir = None
    checks_dir = None
    if not single_output_file:
        base_output_dir = os.path.join(base_output_dir, timestamp)
        inventory_dir = os.path.join(base_output_dir, "inventory")
        checks_dir = os.path.join(base_output_dir, "checks")
        os.makedirs(inventory_dir, exist_ok=True)
        os.makedirs(checks_dir, exist_ok=True)
 
    results = run_yaml_engine(
        yaml_root=args.rules_dir,
        kubeconfig=args.kubeconfig,
        context=args.context,
        target_components=args.components,
        verbose=args.verbose,
        mocks=mocks,
        # When inventory_dir is provided, the engine will write per-component inventory JSON files
        discovery_dump_path=(inventory_dir + os.sep) if inventory_dir else None,
    )
    reporter = create_reporter(cluster_info={})
    reporter.add_results(results)
    if single_output_file:
        reporter.generate_json_report(single_output_file)
    else:
        # Write per-component checks JSON files under checks_dir and also print human-readable summary
        _write_per_component_check_reports(results, checks_dir)
        print(reporter.generate_text_report())


if __name__ == "__main__":
    main() 