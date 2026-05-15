#!/usr/bin/env python3
"""
AI-powered MITRE ATT&CK tagger for ALL CSPM rule metadata files.
Uses DeepSeek API (OpenAI-compatible) to classify rules with accurate techniques.

Covers: AWS, Azure, GCP, OCI, AliCloud, IBM, K8s, Container, Linux,
        Database, Data, DevOps, Networking, Cloud SaaS, Virtualization

Usage:
    export DEEPSEEK_API_KEY=sk-...
    python tag_mitre_ai.py --csp all --dry-run          # Preview (no writes)
    python tag_mitre_ai.py --csp aws                    # Tag all AWS rules
    python tag_mitre_ai.py --csp all                    # Tag everything (~$1-2)
    python tag_mitre_ai.py --csp azure --service sql    # Single CSP + service
    python tag_mitre_ai.py --resume                     # Resume interrupted run
    python tag_mitre_ai.py --csp all --force-retag      # Overwrite existing tags
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import yaml
from openai import OpenAI, RateLimitError, APIError

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("mitre-tagger")

# ── Paths ─────────────────────────────────────────────────────────────────────
CATALOG_DIR = Path(__file__).parent
PROGRESS_FILE = CATALOG_DIR / ".mitre_tag_progress.json"

# ── CSP → rule metadata directory mapping ─────────────────────────────────────
CSP_DIRS: dict[str, list[str]] = {
    "aws":           ["aws_rule_metadata"],
    "azure":         ["azure_rule_metadata", "azure_rule_metadata_policy"],
    "gcp":           ["gcp_rule_metadata"],
    "oci":           ["oci_rule_metadata"],
    "alicloud":      ["alicloud_rule_metadata"],
    "ibm":           ["ibm_rule_metadata"],
    "k8s":           ["k8s_rule_metadata"],
    "container":     ["container_rule_metadata"],
    "linux":         ["linux_rule_metadata"],
    "database":      ["database_rule_metadata"],
    "data":          ["data_rule_metadata"],
    "devops":        ["devops_rule_metadata"],
    "networking":    ["networking_rule_metadata"],
    "cloudsaas":     ["cloud_saas_rule_metadata"],
    "virtualization":["virtualization_rule_metadata"],
    "web":           ["web_server_rule_metadata"],
}

# ── MITRE ATT&CK for Cloud — curated technique list sent to the LLM ───────────
MITRE_TECHNIQUES_REF = """
ALLOWED MITRE ATT&CK TECHNIQUE IDs (use ONLY these):

INITIAL ACCESS:
  T1078.004  Valid Accounts: Cloud Accounts
  T1133      External Remote Services (VPN, RDP, SSH exposed to internet)
  T1190      Exploit Public-Facing Application (public APIs, open ports)
  T1195.002  Supply Chain Compromise: Compromise Software Supply Chain
  T1199      Trusted Relationship (third-party access, cross-account trusts)

EXECUTION:
  T1059.009  Command and Scripting Interpreter: Cloud API
  T1203      Exploitation for Client Execution

PERSISTENCE:
  T1098.001  Account Manipulation: Additional Cloud Credentials (access keys)
  T1098.004  Account Manipulation: SSH Authorized Keys
  T1136.003  Create Account: Cloud Account
  T1525      Implant Internal Image (backdoored container/AMI)
  T1546      Event Triggered Execution (Lambda triggers, SNS, event rules)

PRIVILEGE ESCALATION:
  T1548.005  Abuse Elevation Control Mechanism: Temp Elevated Cloud Access
  T1611      Escape to Host (container breakout, privileged containers)

DEFENSE EVASION:
  T1562.001  Impair Defenses: Disable or Modify Tools (GuardDuty, Security Hub off)
  T1562.008  Impair Defenses: Disable or Modify Cloud Logs (CloudTrail, Flow Logs off)
  T1578      Modify Cloud Compute Infrastructure (instance type changes, deletion)
  T1578.001  Modify Cloud Compute: Create Snapshot (exfil via snapshot copy)
  T1578.004  Modify Cloud Compute: Revert Cloud Instance

CREDENTIAL ACCESS:
  T1110      Brute Force (login attempts, password spray)
  T1528      Steal Application Access Token (OAuth, JWT)
  T1552.005  Unsecured Credentials: Cloud Instance Metadata API (IMDSv1 abuse)
  T1556      Modify Authentication Process (MFA bypass, auth policy changes)

DISCOVERY:
  T1069.003  Permission Groups Discovery: Cloud Groups
  T1087.004  Account Discovery: Cloud Account
  T1518.001  Software Discovery: Security Software Discovery
  T1580      Cloud Infrastructure Discovery (enumerate instances, buckets, DBs)
  T1619      Cloud Storage Object Discovery (S3/Blob enumeration)

LATERAL MOVEMENT:
  T1021.004  Remote Services: SSH
  T1021.007  Remote Services: Cloud Services (SSM, CloudShell)
  T1550.001  Use Alternate Authentication Material: Application Access Token

COLLECTION:
  T1530      Data from Cloud Storage (S3, Blob, GCS data access)
  T1602      Data from Configuration Repository

COMMAND AND CONTROL:
  T1071.001  Application Layer Protocol: Web Protocols
  T1095      Non-Application Layer Protocol

EXFILTRATION:
  T1537      Transfer Data to Cloud Account (cross-account/region copy)
  T1567.002  Exfiltration Over Web Service: Exfil to Cloud Storage

IMPACT:
  T1485      Data Destruction (delete buckets, RDS, backups)
  T1486      Data Encrypted for Impact (ransomware, unauthorized KMS)
  T1496      Resource Hijacking (cryptomining, EC2 abuse)
  T1498      Network Denial of Service
  T1499      Endpoint Denial of Service

ALLOWED TACTICS (use ONLY these lowercase values):
  initial-access, execution, persistence, privilege-escalation, defense-evasion,
  credential-access, discovery, lateral-movement, collection, exfiltration,
  command-and-control, impact
"""

SYSTEM_PROMPT = f"""You are a cloud security expert specializing in MITRE ATT&CK for Cloud.
Your task is to classify cloud security configuration rules with the most appropriate MITRE ATT&CK technique(s).

{MITRE_TECHNIQUES_REF}

CLASSIFICATION RULES:
1. Encryption-at-rest disabled → T1486 (impact) — encrypted data harder to exfil
2. Public access / open ports / internet-facing resources → T1190 (initial-access)
3. Logging/monitoring/audit trail disabled → T1562.008 (defense-evasion)
4. MFA disabled / auth weakened → T1556 (credential-access)
5. Access keys / credentials exposed → T1552.005 or T1098.001
6. Overly permissive IAM (admin, wildcard *) → T1548.005 (privilege-escalation)
7. Cross-account / trust policies → T1199 (initial-access)
8. Unused accounts / stale credentials → T1087.004 (discovery) — attacker can abuse them
9. Backup / snapshot / versioning disabled → T1485 (impact)
10. Container privileged / root / escape risk → T1611 (privilege-escalation)
11. Database public / no encryption / no auth → T1190 + T1530
12. S3 public ACL / policy → T1530 (collection)
13. Root account usage → T1078.004 (initial-access)
14. VPN / remote access not restricted → T1133 (initial-access)
15. Resource hijacking / compute abuse risk → T1496 (impact)

RESPONSE FORMAT — return ONLY a JSON array, no markdown fences, no explanation:
[
  {{
    "rule_id": "<exact rule_id from input>",
    "mitre_techniques": ["T1234", "T1234.001"],
    "mitre_tactics": ["initial-access"],
    "threat_tags": ["cloud-exposure"],
    "threat_category": "initial_access"
  }}
]

threat_category must match the primary tactic with underscores:
  initial-access → initial_access
  privilege-escalation → privilege_escalation
  defense-evasion → defense_evasion
  credential-access → credential_access
  (etc.)

Select at most 2 techniques per rule. Select the most specific technique available.
"""


# ── DeepSeek client ───────────────────────────────────────────────────────────

def make_client() -> OpenAI:
    api_key = os.environ.get("DEEPSEEK_API_KEY")
    if not api_key:
        log.error("DEEPSEEK_API_KEY environment variable not set.")
        sys.exit(1)
    return OpenAI(api_key=api_key, base_url="https://api.deepseek.com")


# ── Rule file discovery ───────────────────────────────────────────────────────

def find_rule_files(csp: str, service_filter: str | None = None) -> list[Path]:
    """Find all rule metadata YAML files for the given CSP(s)."""
    dirs: list[str] = []
    if csp == "all":
        for csp_dirs in CSP_DIRS.values():
            dirs.extend(csp_dirs)
    else:
        csps = [c.strip() for c in csp.split(",")]
        for c in csps:
            if c not in CSP_DIRS:
                log.warning(f"Unknown CSP: {c}. Valid: {sorted(CSP_DIRS)}")
                continue
            dirs.extend(CSP_DIRS[c])

    files: list[Path] = []
    for d in dirs:
        base = CATALOG_DIR / d
        if not base.exists():
            log.debug(f"Directory not found, skipping: {base}")
            continue
        pattern = "**/*.yaml"
        for f in base.glob(pattern):
            if service_filter:
                # Match on directory name (service) or rule_id prefix
                if service_filter.lower() not in str(f).lower():
                    continue
            files.append(f)
    return sorted(files)


# ── Progress tracking ─────────────────────────────────────────────────────────

def load_progress() -> set[str]:
    if PROGRESS_FILE.exists():
        data = json.loads(PROGRESS_FILE.read_text())
        return set(data.get("done", []))
    return set()


def save_progress(done: set[str]) -> None:
    PROGRESS_FILE.write_text(json.dumps({"done": sorted(done)}, indent=2))


# ── YAML helpers ──────────────────────────────────────────────────────────────

def read_rule(path: Path) -> dict[str, Any] | None:
    try:
        content = path.read_text(encoding="utf-8")
        data = yaml.safe_load(content)
        if not isinstance(data, dict) or "rule_id" not in data:
            return None
        return data
    except Exception as e:
        log.warning(f"Failed to parse {path}: {e}")
        return None


def write_rule(path: Path, data: dict[str, Any]) -> None:
    """Write YAML preserving field order (rule_id first, MITRE fields last)."""
    path.write_text(yaml.dump(data, default_flow_style=False, allow_unicode=True, sort_keys=False), encoding="utf-8")


def summarize_rule(data: dict[str, Any]) -> str:
    """Compact single-line summary of a rule to include in LLM batch prompt."""
    return json.dumps({
        "rule_id":    data.get("rule_id", ""),
        "title":      data.get("title", "")[:120],
        "service":    data.get("service", ""),
        "domain":     data.get("domain", ""),
        "severity":   data.get("severity", ""),
        "description": (data.get("description") or data.get("rationale") or "")[:200],
    })


# ── LLM call with retry ───────────────────────────────────────────────────────

def call_deepseek(
    client: OpenAI,
    batch: list[dict[str, Any]],
    max_retries: int = 4,
) -> list[dict[str, Any]]:
    """Call DeepSeek and return list of MITRE classification dicts."""
    user_content = "Classify these rules:\n" + "\n".join(summarize_rule(r) for r in batch)

    for attempt in range(max_retries):
        try:
            response = client.chat.completions.create(
                model="deepseek-chat",
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user",   "content": user_content},
                ],
                temperature=0.1,
                max_tokens=4096,
            )
            raw = response.choices[0].message.content.strip()
            # Strip markdown fences if present
            raw = re.sub(r"^```[a-z]*\n?", "", raw)
            raw = re.sub(r"\n?```$", "", raw)
            results = json.loads(raw)
            if not isinstance(results, list):
                raise ValueError("LLM returned non-list JSON")
            return results
        except RateLimitError:
            wait = 2 ** attempt * 5
            log.warning(f"Rate limited. Waiting {wait}s before retry {attempt+1}/{max_retries}")
            time.sleep(wait)
        except (json.JSONDecodeError, ValueError) as e:
            log.warning(f"JSON parse error on attempt {attempt+1}: {e}")
            if attempt == max_retries - 1:
                return []
            time.sleep(2)
        except APIError as e:
            log.error(f"API error: {e}")
            time.sleep(5)

    return []


# ── Apply classification to YAML ──────────────────────────────────────────────

VALID_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
VALID_TACTICS = {
    "initial-access", "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery", "lateral-movement",
    "collection", "exfiltration", "command-and-control", "impact",
}


def validate_and_apply(
    path: Path,
    data: dict[str, Any],
    classification: dict[str, Any],
    dry_run: bool,
) -> bool:
    """Validate LLM output fields and write to YAML. Returns True on success."""
    techniques = classification.get("mitre_techniques") or []
    tactics = classification.get("mitre_tactics") or []
    tags = classification.get("threat_tags") or []
    category = classification.get("threat_category") or ""

    # Validate
    techniques = [t for t in techniques if VALID_TECHNIQUE_RE.match(str(t))]
    tactics = [t for t in tactics if t in VALID_TACTICS]

    if not techniques or not tactics:
        log.warning(f"Invalid/empty classification for {data['rule_id']}: {classification}")
        return False

    data["mitre_techniques"] = techniques
    data["mitre_tactics"] = tactics
    data["threat_tags"] = tags if tags else [tactics[0].replace("-", "_")]
    data["threat_category"] = category or tactics[0].replace("-", "_")

    if not dry_run:
        write_rule(path, data)
    return True


# ── Batch processor ───────────────────────────────────────────────────────────

def process_batch(
    client: OpenAI,
    batch_files: list[tuple[Path, dict[str, Any]]],
    done: set[str],
    dry_run: bool,
    stats: dict[str, int],
    lock: object,
) -> None:
    """Process one batch: call LLM, apply results, update progress."""
    batch_data = [d for _, d in batch_files]
    results = call_deepseek(client, batch_data)

    # Build lookup by rule_id
    result_map: dict[str, dict[str, Any]] = {r.get("rule_id", ""): r for r in results}

    for path, data in batch_files:
        rule_id = data.get("rule_id", "")
        classification = result_map.get(rule_id)

        if not classification:
            log.warning(f"No result returned for {rule_id}")
            with lock:
                stats["errors"] += 1
            continue

        ok = validate_and_apply(path, data, classification, dry_run)
        with lock:
            if ok:
                done.add(str(path))
                stats["tagged"] += 1
                log.debug(f"  ✓ {rule_id} → {data.get('mitre_techniques')}")
            else:
                stats["errors"] += 1

    if not dry_run:
        with lock:
            save_progress(done)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="AI MITRE tagger for all CSPM rules")
    parser.add_argument("--csp",         default="all",
                        help="CSP(s) to tag: all, aws, azure, gcp, oci, alicloud, ibm, k8s, ...")
    parser.add_argument("--service",     default=None, help="Filter by service name (substring match)")
    parser.add_argument("--batch-size",  type=int, default=20, help="Rules per API call (default 20)")
    parser.add_argument("--concurrent",  type=int, default=3,  help="Concurrent API calls (default 3)")
    parser.add_argument("--dry-run",     action="store_true",  help="Preview only — do not write files")
    parser.add_argument("--force-retag", action="store_true",  help="Re-tag already-tagged files")
    parser.add_argument("--resume",      action="store_true",  help="Resume from progress file")
    parser.add_argument("--verbose",     action="store_true",  help="Debug logging")
    args = parser.parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    if args.dry_run:
        log.info("DRY RUN — no files will be written.")

    client = make_client()

    # Discover files
    all_files = find_rule_files(args.csp, args.service)
    log.info(f"Found {len(all_files)} rule YAML files for csp={args.csp!r}")

    # Load progress
    done: set[str] = load_progress() if args.resume else set()
    if args.resume:
        log.info(f"Resuming: {len(done)} already processed.")

    # Filter files to process
    to_process: list[tuple[Path, dict[str, Any]]] = []
    skipped_already_tagged = 0
    skipped_no_rule_id = 0

    for path in all_files:
        str_path = str(path)
        if args.resume and str_path in done:
            continue
        data = read_rule(path)
        if data is None:
            skipped_no_rule_id += 1
            continue
        # Never tag deprecated rules — they must not reach PatternExecutor
        rule_id = data.get("rule_id", "")
        title   = (data.get("title") or "").lower()
        if "deprecated" in rule_id.lower() or "deprecated" in title:
            continue

        if not args.force_retag and data.get("mitre_techniques"):
            skipped_already_tagged += 1
            continue
        to_process.append((path, data))

    log.info(
        f"To process: {len(to_process)} | "
        f"Skip (already tagged): {skipped_already_tagged} | "
        f"Skip (no rule_id): {skipped_no_rule_id}"
    )

    if not to_process:
        log.info("Nothing to tag. Use --force-retag to overwrite existing tags.")
        return

    # Batch into groups
    batches: list[list[tuple[Path, dict[str, Any]]]] = [
        to_process[i : i + args.batch_size]
        for i in range(0, len(to_process), args.batch_size)
    ]
    log.info(f"Will make {len(batches)} API calls in batches of {args.batch_size} "
             f"with {args.concurrent} concurrent workers.")

    # Stats
    import threading
    stats: dict[str, int] = {"tagged": 0, "errors": 0}
    lock = threading.Lock()

    start_time = time.time()

    with ThreadPoolExecutor(max_workers=args.concurrent) as executor:
        futures = {
            executor.submit(process_batch, client, batch, done, args.dry_run, stats, lock): i
            for i, batch in enumerate(batches)
        }
        for i, future in enumerate(as_completed(futures), 1):
            try:
                future.result()
            except Exception as e:
                log.error(f"Batch failed: {e}")
                with lock:
                    stats["errors"] += args.batch_size

            elapsed = time.time() - start_time
            rate = stats["tagged"] / elapsed if elapsed > 0 else 0
            remaining = len(to_process) - stats["tagged"] - stats["errors"]
            eta = remaining / rate if rate > 0 else 0
            log.info(
                f"[{i}/{len(batches)}] Tagged: {stats['tagged']} | "
                f"Errors: {stats['errors']} | "
                f"Rate: {rate:.1f}/s | "
                f"ETA: {eta/60:.1f}min"
            )

    elapsed_total = time.time() - start_time
    log.info("─" * 60)
    log.info(f"DONE in {elapsed_total/60:.1f} min")
    log.info(f"  Tagged:  {stats['tagged']}")
    log.info(f"  Errors:  {stats['errors']}")
    log.info(f"  Skipped (already tagged): {skipped_already_tagged}")
    log.info(f"  Skipped (no rule_id):     {skipped_no_rule_id}")

    if args.dry_run:
        log.info("DRY RUN complete — no files written.")
    else:
        log.info(f"Progress saved to: {PROGRESS_FILE}")
        log.info("Next step: run S0-05 coverage gate script to verify ≥80% coverage.")


if __name__ == "__main__":
    main()
