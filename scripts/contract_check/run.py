"""
CLI runner for the contract-checking agent (DeepSeek).

Usage:
  python scripts/contract_check/run.py --view threat-command-room --engine threat
  python scripts/contract_check/run.py --view risk --engine risk --extra-engines threat
  python scripts/contract_check/run.py --view billing --engine billing --format json
  python scripts/contract_check/run.py --list-views
  python scripts/contract_check/run.py --all

Environment:
  DEEPSEEK_API_KEY  — required  (export DEEPSEEK_API_KEY=sk-...)
  DEEPSEEK_MODEL    — optional  (default: deepseek-chat)

Install deps first:
  pip install -r scripts/contract_check/requirements.txt
"""

from __future__ import annotations
import argparse
import json
import logging
import os
import sys

# Make sibling packages importable
sys.path.insert(0, os.path.dirname(__file__))

from agent import run_contract_check

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


# Full view → engine mapping for all 25 UI pages
KNOWN_VIEWS: dict[str, dict] = {
    # ── Threat ────────────────────────────────────────────────────────────────
    "threat-command-room": {"engine": "threat",           "extra": ["risk"]},
    "threats":             {"engine": "threat",           "extra": []},
    "threats-graph":       {"engine": "threat",           "extra": []},
    # ── Risk ──────────────────────────────────────────────────────────────────
    "risk":                {"engine": "risk",             "extra": ["threat"]},
    # ── Compliance ────────────────────────────────────────────────────────────
    "compliance":          {"engine": "compliance",       "extra": []},
    # ── Network ───────────────────────────────────────────────────────────────
    "network-security":    {"engine": "network-security", "extra": []},
    # ── Identity & Access ─────────────────────────────────────────────────────
    "iam":                 {"engine": "iam",              "extra": ["check"]},
    "ciem":                {"engine": "ciem",             "extra": []},
    # ── Data & Workload ───────────────────────────────────────────────────────
    "datasec":             {"engine": "datasec",          "extra": []},
    "vulnerability":       {"engine": "vulnerability",    "extra": []},
    "secops":              {"engine": "secops",           "extra": []},
    # ── Infrastructure ────────────────────────────────────────────────────────
    "container-security":  {"engine": "container-security", "extra": []},
    "encryption":          {"engine": "encryption",       "extra": []},
    "database-security":   {"engine": "dbsec",            "extra": []},
    "ai-security":         {"engine": "ai-security",      "extra": []},
    # ── Aggregators ───────────────────────────────────────────────────────────
    "cnapp":               {"engine": "threat",           "extra": ["risk", "compliance"]},
    "cwpp":                {"engine": "vulnerability",    "extra": []},
    # ── Asset & Inventory ─────────────────────────────────────────────────────
    "inventory":           {"engine": "inventory",        "extra": []},
    # ── Platform ──────────────────────────────────────────────────────────────
    "billing":             {"engine": "billing",          "extra": []},
    "admin-billing":       {"engine": "platform-admin",   "extra": []},
    "scans":               {"engine": "discoveries",      "extra": []},
    "onboarding":          {"engine": "discoveries",      "extra": []},
    # ── Rules & Policies ──────────────────────────────────────────────────────
    "policies":            {"engine": "check",            "extra": []},
    "rules":               {"engine": "check",            "extra": []},
    # ── Reports & Findings ────────────────────────────────────────────────────
    "reports":             {"engine": "compliance",       "extra": ["risk"]},
    "findings":            {"engine": "check",            "extra": ["threat"]},
}


def _print_report_human(report) -> None:
    RESET  = "\033[0m"
    RED    = "\033[31m"
    YELLOW = "\033[33m"
    CYAN   = "\033[36m"
    GREEN  = "\033[32m"
    BOLD   = "\033[1m"

    score_color = GREEN if report.coverage_score >= 80 else (YELLOW if report.coverage_score >= 50 else RED)

    print(f"\n{BOLD}{'═' * 70}{RESET}")
    print(f"{BOLD}  CONTRACT REPORT — {report.view_name.upper()}{RESET}")
    print(f"{'═' * 70}")
    print(f"  Coverage Score : {score_color}{BOLD}{report.coverage_score:.0f}/100{RESET}")
    print(f"  Breaking       : {RED}{report.breaking_count}{RESET}")
    print(f"  Warnings       : {YELLOW}{report.warning_count}{RESET}")
    print(f"\n  {report.summary}")

    if report.layers:
        print(f"\n{BOLD}  LAYERS{RESET}")
        for layer in report.layers:
            print(f"    [{layer.layer.upper():6}]  {len(layer.fields)} fields  "
                  f"← {', '.join(os.path.basename(f) for f in layer.source_files[:2])}")
            if layer.notes:
                for note in layer.notes:
                    print(f"             ⚠  {note}")

    if report.mismatches:
        print(f"\n{BOLD}  MISMATCHES ({len(report.mismatches)}){RESET}")
        for m in report.mismatches:
            sev_color = RED if m.severity == "breaking" else (YELLOW if m.severity == "warning" else CYAN)
            print(f"\n    {sev_color}[{m.severity.upper()}]{RESET}  {m.layer_from} → {m.layer_to}")
            print(f"    Field   : {BOLD}{m.field_path}{RESET}")
            print(f"    Issue   : {m.issue}")
            print(f"    Fix     : {m.suggestion}")
    else:
        print(f"\n    {GREEN}✓ No mismatches found — contract is clean.{RESET}")

    print(f"\n{'═' * 70}\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="End-to-end contract checker: UI → BFF → Engine → DB",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--view", "-v",
        help="BFF view name to check (e.g. threat-command-room)",
    )
    parser.add_argument(
        "--engine", "-e",
        help="Primary engine backing this view (e.g. threat)",
    )
    parser.add_argument(
        "--extra-engines",
        nargs="*",
        default=[],
        metavar="ENGINE",
        help="Additional engines the BFF fans out to (e.g. risk)",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["human", "json"],
        default="human",
        help="Output format (default: human)",
    )
    parser.add_argument(
        "--list-views",
        action="store_true",
        help="List all known view → engine mappings and exit",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run contract check for ALL known views",
    )
    args = parser.parse_args()

    if args.list_views:
        print("\nKnown views and their engines:\n")
        for view, cfg in KNOWN_VIEWS.items():
            extras = f"  +{', '.join(cfg['extra'])}" if cfg['extra'] else ""
            print(f"  {view:<30}  engine={cfg['engine']}{extras}")
        print()
        return

    if args.all:
        views_to_check = list(KNOWN_VIEWS.items())
    elif args.view:
        engine = args.engine or KNOWN_VIEWS.get(args.view, {}).get("engine")
        if not engine:
            parser.error(
                f"--engine is required (or add '{args.view}' to KNOWN_VIEWS)"
            )
        extra = args.extra_engines or KNOWN_VIEWS.get(args.view, {}).get("extra", [])
        views_to_check = [(args.view, {"engine": engine, "extra": extra})]
    else:
        parser.error("Specify --view VIEW or --all")
        return

    all_reports = []
    for view_name, cfg in views_to_check:
        print(f"  → Checking {view_name} (engine={cfg['engine']}) …", end="", flush=True)
        try:
            report = run_contract_check(
                view_name,
                cfg["engine"],
                extra_engines=cfg.get("extra", []),
            )
            all_reports.append(report)
            print(f"  score={report.coverage_score:.0f}  breaking={report.breaking_count}")
        except Exception as exc:
            print(f"  ERROR: {exc}")
            logger.exception(f"Contract check failed for {view_name}")

    if args.format == "json":
        output = [r.model_dump() for r in all_reports]
        print(json.dumps(output, indent=2, default=str))
    else:
        for report in all_reports:
            _print_report_human(report)


if __name__ == "__main__":
    main()
