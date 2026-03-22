#!/usr/bin/env python3
"""
Parallel Discovery Scan Trigger

Splits the full service list into N chunks and triggers parallel scans
by sending each chunk to a SPECIFIC pod via kubectl exec + curl localhost.

This bypasses the K8s Service load-balancer to ensure each pod gets
exactly one chunk of services.

Usage:
  python trigger_parallel_scan.py \
    --scan-run-id 337a7425-5a53-4664-8569-04c1f0d6abf0 \
    --chunks 5
"""

import argparse
import json
import math
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from typing import List


def get_pod_names(namespace: str = "threat-engine-engines") -> List[str]:
    """Get all Ready engine-discoveries pod names."""
    result = subprocess.run(
        [
            "kubectl", "get", "pods", "-n", namespace,
            "-l", "app=engine-discoveries",
            "-o", "jsonpath={.items[?(@.status.phase=='Running')].metadata.name}",
        ],
        capture_output=True, text=True, timeout=15,
    )
    if result.returncode != 0:
        print(f"ERROR listing pods: {result.stderr}")
        sys.exit(1)
    pods = result.stdout.strip().split()
    return [p for p in pods if p]


def get_service_list(namespace: str = "threat-engine-engines") -> List[str]:
    """Get all enabled services from the check DB via kubectl exec."""
    result = subprocess.run(
        [
            "kubectl", "exec", "-n", namespace,
            "deployment/engine-discoveries", "-c", "engine-discoveries",
            "--", "python3", "-c",
            "import os,sys;sys.path.insert(0,'/app');"
            "from common.database.check_db_reader import CheckDBReader;"
            "r=CheckDBReader();c=r.read_all_discoveries_configs(provider='aws');"
            "import json;print(json.dumps(sorted(c.keys())))"
        ],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        print(f"ERROR getting service list: {result.stderr}")
        sys.exit(1)
    return json.loads(result.stdout.strip())


def chunk_list(lst: List[str], n: int) -> List[List[str]]:
    """Split list into n roughly equal chunks."""
    chunk_size = math.ceil(len(lst) / n)
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]


def trigger_scan_on_pod(
    pod_name: str,
    namespace: str,
    scan_run_id: str,
    account_id: str,
    services: List[str],
    chunk_id: int,
) -> dict:
    """
    Trigger a scan on a specific pod by exec'ing a Python script inside it.
    This sends an HTTP request to localhost:8001 from within the pod.
    """
    # Pre-serialize the payload as a JSON string to embed in the Python code
    payload_json_str = json.dumps({
        "scan_run_id": scan_run_id,
        "provider": "aws",
        "account_id": account_id,
        "hierarchy_type": "account",
        "include_services": services,
        "use_database": True,
    })

    # Use Python inside the pod to POST to localhost
    # Pass the payload as a raw string literal to avoid JSON true/false issues
    python_code = (
        "import urllib.request\n"
        f"data = {repr(payload_json_str)}.encode('utf-8')\n"
        "req = urllib.request.Request(\n"
        "    'http://localhost:8001/api/v1/discovery',\n"
        "    data=data,\n"
        "    headers={'Content-Type': 'application/json'},\n"
        "    method='POST',\n"
        ")\n"
        "resp = urllib.request.urlopen(req, timeout=30)\n"
        "print(resp.read().decode())\n"
    )

    try:
        result = subprocess.run(
            [
                "kubectl", "exec", "-n", namespace,
                pod_name, "-c", "engine-discoveries",
                "--", "python3", "-c", python_code,
            ],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0:
            return {"chunk": chunk_id, "pod": pod_name, "status": "error", "error": result.stderr.strip()}

        body = json.loads(result.stdout.strip())
        return {"chunk": chunk_id, "pod": pod_name, "status": "ok", "response": body}
    except Exception as e:
        return {"chunk": chunk_id, "pod": pod_name, "status": "error", "error": str(e)}


def main():
    parser = argparse.ArgumentParser(description="Trigger parallel discovery scans")
    parser.add_argument(
        "--scan-run-id", required=True,
        help="scan_run_id from scan_orchestration table",
    )
    parser.add_argument(
        "--hierarchy-id", default="588989875114",
        help="AWS account ID (default: 588989875114)",
    )
    parser.add_argument(
        "--chunks", type=int, default=5,
        help="Number of parallel scan chunks (default: 5)",
    )
    parser.add_argument(
        "--namespace", default="threat-engine-engines",
        help="K8s namespace (default: threat-engine-engines)",
    )
    args = parser.parse_args()

    print("=== Parallel Discovery Scan Trigger ===")
    print(f"scan_run_id:  {args.scan_run_id}")
    print(f"Account ID:   {args.hierarchy_id}")
    print(f"Chunks:           {args.chunks}")
    print()

    # Step 1: Get pods
    print("Step 1: Getting Running pods...")
    pods = get_pod_names(args.namespace)
    print(f"  Found {len(pods)} Running pods: {pods}")
    if len(pods) < args.chunks:
        print(f"  WARNING: Only {len(pods)} pods available, but {args.chunks} chunks requested.")
        print(f"  Will use {len(pods)} chunks instead.")
        args.chunks = len(pods)
    print()

    # Step 2: Get service list
    print("Step 2: Getting enabled service list from check DB...")
    services = get_service_list(args.namespace)
    print(f"  Found {len(services)} enabled services")
    print()

    # Step 3: Split into chunks
    chunks = chunk_list(services, args.chunks)
    print(f"Step 3: Split into {len(chunks)} chunks:")
    for i, chunk in enumerate(chunks):
        print(f"  Chunk {i+1} -> {pods[i][:40]}...: {len(chunk)} services ({chunk[0]}...{chunk[-1]})")
    print()

    # Step 4: Trigger all scans in parallel (one per pod)
    print(f"Step 4: Triggering {len(chunks)} parallel scans (one per pod)...")
    start = time.time()

    with ThreadPoolExecutor(max_workers=len(chunks)) as pool:
        futures = [
            pool.submit(
                trigger_scan_on_pod,
                pods[i], args.namespace, args.scan_run_id,
                args.hierarchy_id, chunk, i,
            )
            for i, chunk in enumerate(chunks)
        ]
        results = [f.result() for f in futures]

    elapsed = time.time() - start
    print(f"  All {len(chunks)} scans triggered in {elapsed:.1f}s")
    print()

    # Step 5: Print results
    print("Step 5: Scan IDs:")
    scan_ids = []
    for r in results:
        chunk_id = r["chunk"]
        pod = r["pod"]
        if r["status"] == "ok":
            scan_id = r["response"].get("scan_run_id", "?")
            scan_ids.append(scan_id)
            status = r["response"].get("status", "?")
            print(f"  Chunk {chunk_id + 1} [{pod[:30]}...]: {scan_id} ({status})")
        else:
            print(f"  Chunk {chunk_id + 1} [{pod[:30]}...]: ERROR - {r['error'][:100]}")

    print()
    print("=== Monitor Progress ===")
    print(f"kubectl logs -l app=engine-discoveries -n {args.namespace} -c engine-discoveries --since=5m | grep '\\[DISCOVERY\\]'")
    print()
    if scan_ids:
        ids_str = "', '".join(scan_ids)
        print("=== Check DB Progress ===")
        print(f"SELECT COUNT(DISTINCT service), COUNT(*) FROM discovery_findings")
        print(f"WHERE scan_run_id IN ('{ids_str}');")


if __name__ == "__main__":
    main()
