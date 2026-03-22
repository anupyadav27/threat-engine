"""
DAST Engine - Main entry point
Step 1: Target Input Module
"""

import sys
from typing import Tuple, Dict, Any, List
import requests

from dast_engine.config.config_parser import TargetConfig, ConfigurationError
from dast_engine.config.validator import InputValidator, ValidationError
from dast_engine.auth.auth_manager import AuthenticationManager, AuthenticationError
from dast_engine.cli import parse_cli_args
from dast_engine.crawler import ApplicationDiscoveryEngine
from dast_engine.parameters import ParameterEnricher


# Severity ordering — used by fail-on threshold check
_SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']


def _check_fail_threshold(vulnerabilities: List[Any], fail_on: str) -> bool:
    """
    Return True if any finding meets or exceeds the fail_on severity threshold.

    fail_on='any' triggers on any finding regardless of severity.
    """
    if not fail_on or not vulnerabilities:
        return False

    if fail_on == 'any':
        return len(vulnerabilities) > 0

    threshold_idx = _SEVERITY_ORDER.index(fail_on.lower())

    for v in vulnerabilities:
        if isinstance(v, dict):
            sev = v.get('severity', 'Info')
        else:
            raw = getattr(v, 'severity', 'Info')
            sev = getattr(raw, 'value', str(raw))

        sev_lower = sev.lower()
        if sev_lower in _SEVERITY_ORDER:
            if _SEVERITY_ORDER.index(sev_lower) <= threshold_idx:
                return True

    return False


def _classify_vuln(v: Any) -> str:
    """Return the module name that produced vulnerability v."""
    if isinstance(v, dict):
        # Cookie findings
        if v.get('cookie_name') or v.get('issue_type') in (
            'missing_secure_flag', 'missing_httponly_flag',
            'missing_samesite', 'weak_samesite', 'sensitive_cookie_detected',
        ):
            return 'Session / Cookie Security'
        # Security-header findings
        if v.get('header_name') or v.get('status') in (
            'missing', 'weak', 'misconfigured', 'insecure', 'information_leak',
        ):
            return 'Security Headers'
        # Error-disclosure findings
        vtype = v.get('type', '')
        if vtype in ('stack_trace', 'path_disclosure', 'database_error',
                     'debug_info', 'version_disclosure', 'sensitive_data'):
            return 'Error / Info Disclosure'
        # Named vuln types
        if 'sql' in vtype.lower() or 'injection' in vtype.lower():
            return 'Input Validation (SQLi / CMDi)'
        if 'xss' in vtype.lower() or 'cross-site scripting' in vtype.lower():
            return 'Input Validation (XSS)'
        if 'redirect' in vtype.lower():
            return 'Open Redirect'
        if 'csrf' in vtype.lower():
            return 'CSRF Detection'
        if 'upload' in vtype.lower():
            return 'File Upload Testing'
        if 'ssrf' in vtype.lower():
            return 'API / SSRF Testing'
        # Business logic findings — type starts with "Business Logic –"
        if vtype.lower().startswith('business logic'):
            return 'Business Logic Testing'
        return 'Other'
    else:
        raw = getattr(v, 'type', None)
        vtype = getattr(raw, 'value', str(raw)).lower() if raw else ''
        if 'sql' in vtype or 'injection' in vtype:
            return 'Input Validation (SQLi / CMDi)'
        if 'xss' in vtype or 'cross-site' in vtype:
            return 'Input Validation (XSS)'
        if 'redirect' in vtype:
            return 'Open Redirect'
        if 'csrf' in vtype:
            return 'CSRF Detection'
        if 'upload' in vtype:
            return 'File Upload Testing'
        if 'ssrf' in vtype:
            return 'API / SSRF Testing'
        if vtype.startswith('business logic'):
            return 'Business Logic Testing'
        return 'Other'


def _highest_severity(vulns: List[Any]) -> str:
    """Return highest severity string across a list of findings."""
    order = ['Critical', 'High', 'Medium', 'Low', 'Info']
    found = set()
    for v in vulns:
        if isinstance(v, dict):
            found.add(v.get('severity', 'Info'))
        else:
            raw = getattr(v, 'severity', 'Info')
            found.add(getattr(raw, 'value', str(raw)))
    for s in order:
        if s in found:
            return s
    return 'Info'


def _print_module_summary(vulnerabilities: List[Any], endpoints_count: int,
                          parameters_count: int, attacks_count: int) -> List[Dict[str, Any]]:
    """
    Print a per-module summary table matching the 5-column DAST reference format:
      Module Checks | Typical Input Needed | Supporting Input Document
      | Actual Findings | Features/
    """

    # ── Module catalogue ───────────────────────────────────────────────────────
    # Keys must match _classify_vuln() return values exactly.
    # Each entry maps to the row the screenshot shows, plus 'internal_key' for
    # bucketing findings.
    MODULE_ROWS = [
        {
            'key':       'Session / Cookie Security',
            'label':     'Authentication/Session',
            'sublabel':  'handling, cookie flags',
            'input':     'App URL, login creds, session config',
            'docs':      'Credentials file, session config docs',
            'typical':   'Session fixation, insecure cookies, auth flaws',
            'features':  'Login/logout, session',
        },
        {
            'key':       'Input Validation (SQLi / CMDi)',
            'label':     'Input Validation/Fuzzing',
            'sublabel':  'path traversal',
            'input':     'App/API URL, endpoints, payloads',
            'docs':      'Fuzz payload lists, endpoint map',
            'typical':   'SQLi, XSS, command injection findings',
            'features':  'Fuzzing, injection',
        },
        {
            'key':       'Input Validation (XSS)',
            'label':     'Input Validation/Fuzzing',
            'sublabel':  'XSS',
            'input':     'App/API URL, endpoints, payloads',
            'docs':      'Fuzz payload lists, endpoint map',
            'typical':   'Reflected / Stored XSS',
            'features':  'Fuzzing, injection',
        },
        {
            'key':       'API / SSRF Testing',
            'label':     'API Testing',
            'sublabel':  'auth, rate limits',
            'input':     'API URL, docs/spec, tokens/keys',
            'docs':      'OpenAPI/Swagger spec, API keys/tokens',
            'typical':   'API-specific vulns, broken auth, data leaks',
            'features':  'REST/SOAP/GraphQL',
        },
        {
            'key':       'CSRF Detection',
            'label':     'CSRF Testing',
            'sublabel':  'checks',
            'input':     'App URL, forms, cookies',
            'docs':      'Form schema, cookie policy docs',
            'typical':   'CSRF vulnerabilities, missing tokens',
            'features':  'Form analysis, token checks',
        },
        {
            'key':       'Security Headers',
            'label':     'Security Headers',
            'sublabel':  'X-Frame-Options, etc.',
            'input':     'App URL',
            'docs':      'Header policy reference',
            'typical':   'Missing/insecure headers report',
            'features':  'CSP, HSTS',
        },
        {
            'key':       'File Upload Testing',
            'label':     'File Upload/Download',
            'sublabel':  'type checks',
            'input':     'App URL, file endpoints',
            'docs':      'Allowed file types list, endpoint map',
            'typical':   'Insecure file handling, path traversal',
            'features':  'Upload/download, file',
        },
        {
            'key':       'Business Logic Testing',
            'label':     'Business Logic Testing',
            'sublabel':  'privilege escalation',
            'input':     'App URL, workflow info',
            'docs':      'Workflow diagrams, test data files',
            'typical':   'Access control, logic flaws',
            'features':  'Custom workflow',
        },
        {
            'key':       'Error / Info Disclosure',
            'label':     'Error Handling/Disclosure',
            'sublabel':  'info disclosure',
            'input':     'App URL, error triggers',
            'docs':      'Error trigger scenarios, sensitive data list',
            'typical':   'Info leaks, stack traces, sensitive data',
            'features':  'Error page analysis',
        },
        {
            'key':       'Open Redirect',
            'label':     'Open Redirects',
            'sublabel':  'redirect checks',
            'input':     'App URL, redirect endpoints',
            'docs':      'Redirect endpoint map',
            'typical':   'Redirect vulnerabilities',
            'features':  'URL manipulation',
        },
    ]

    # ── Bucket findings by module ──────────────────────────────────────────────
    by_key: Dict[str, List[Any]] = {}
    for v in vulnerabilities:
        k = _classify_vuln(v)
        by_key.setdefault(k, []).append(v)

    # ── Build "Input Used" strings from actual scan data ───────────────────────
    def _input_used(key: str) -> str:
        """Return what was actually used as input when testing this module."""
        from urllib.parse import urlparse

        found = by_key.get(key, [])

        # Collect URLs and parameter names from findings
        urls: list = []
        params: list = []
        seen_urls: set = set()
        seen_params: set = set()

        for v in found:
            ep = (v.get('endpoint', {}) if isinstance(v, dict)
                  else getattr(v, 'endpoint', {})) or {}
            url = ep.get('url', '') if isinstance(ep, dict) else ''
            if url and url not in seen_urls:
                seen_urls.add(url)
                parsed = urlparse(url)
                short = (parsed.netloc or '') + (parsed.path or '')
                urls.append(short[:30])

            param = (v.get('parameter', {}) if isinstance(v, dict)
                     else getattr(v, 'parameter', {})) or {}
            pname = (param.get('name', '') if isinstance(param, dict) else str(param))
            if pname and pname not in seen_params:
                seen_params.add(pname)
                params.append(pname)

        # Modules that test HTTP response metadata — URLs are the input
        if key in ('Security Headers', 'Session / Cookie Security',
                   'Error / Info Disclosure'):
            if urls:
                label = urls[0] + (f' +{len(urls)-1} more' if len(urls) > 1 else '')
                return f'{len(seen_urls)} endpoint(s): {label}'
            return f'{endpoints_count} endpoint responses (HTTP headers/body)'

        # Attack modules — parameters are the primary input
        if params:
            plist = ', '.join(params[:2]) + (f' +{len(params)-2}' if len(params) > 2 else '')
            suffix = f' ({len(seen_urls)} URL(s))' if urls else ''
            return f'Params: {plist}{suffix}'

        # Module ran but found nothing — describe what it scanned
        if key == 'CSRF Detection':
            return f'Form actions + cookie flags ({endpoints_count} pages)'
        if key == 'Open Redirect':
            return f'Redirect params ({parameters_count} tested)'
        if key in ('Input Validation (SQLi / CMDi)', 'Input Validation (XSS)'):
            return f'{parameters_count} params, {attacks_count} payloads sent'
        if key == 'API / SSRF Testing':
            return f'URL-type params ({parameters_count} tested)'
        if key == 'File Upload Testing':
            return 'multipart/form-data file fields'
        if key == 'Business Logic Testing':
            return f'Numeric ID params, sensitive paths ({endpoints_count} endpoints)'

        return 'App URL'

    # ── Build actual-findings strings ──────────────────────────────────────────
    def _actual_findings(key: str, typical: str) -> str:
        """Return a one-line description of what was actually found."""
        found = by_key.get(key, [])
        if not found:
            return 'None detected'
        # Collect unique finding names (up to 2)
        names = []
        seen: set = set()
        for v in found:
            if isinstance(v, dict):
                name = (v.get('header_name') or v.get('cookie_name')
                        or v.get('type') or typical.split(',')[0].strip())
            else:
                raw = getattr(v, 'type', None)
                name = getattr(raw, 'value', str(raw)) if raw else typical.split(',')[0].strip()
            if name not in seen:
                seen.add(name)
                names.append(name)
            if len(names) == 2:
                break
        suffix = f' (+{len(found)-2} more)' if len(found) > 2 else ''
        return f'[{len(found)} found] ' + ', '.join(names) + suffix

    # ── Column widths — sized to fit a standard 120-char terminal ─────────────
    # Total = W1+W2+W3+W4+W5 + 16 overhead (pipes + spaces) = 120
    W1 = 24   # Module Checks
    W2 = 22   # Input Used
    W3 = 22   # Supporting Input Document
    W4 = 24   # Actual Findings
    W5 = 12   # Features/
    TOTAL = W1 + W2 + W3 + W4 + W5 + 16   # pipes + spaces

    SEP = ('+-' + '-'*W1 + '-+-' + '-'*W2 + '-+-' + '-'*W3
           + '-+-' + '-'*W4 + '-+-' + '-'*W5 + '-+')

    def _fit(s: str, w: int) -> str:
        s = str(s)
        if len(s) <= w:
            return s.ljust(w)
        return s[:w-3] + '...'

    def _row(c1, c2, c3, c4, c5):
        return (f'| {_fit(c1,W1)} | {_fit(c2,W2)} | {_fit(c3,W3)}'
                f' | {_fit(c4,W4)} | {_fit(c5,W5)} |')

    # ── Severity totals ────────────────────────────────────────────────────────
    severity_totals: Dict[str, int] = {}
    for v in vulnerabilities:
        if isinstance(v, dict):
            s = v.get('severity', 'Info')
        else:
            raw = getattr(v, 'severity', 'Info')
            s = getattr(raw, 'value', str(raw))
        severity_totals[s] = severity_totals.get(s, 0) + 1

    # ── Print ──────────────────────────────────────────────────────────────────
    print()
    TOP = SEP.replace('-', '=').replace('+', '+')
    HDR_SEP = ('+-' + '='*W1 + '-+-' + '='*W2 + '-+-' + '='*W3
               + '-+-' + '='*W4 + '-+-' + '='*W5 + '-+')

    print()
    print(TOP)
    print(f'  DAST MODULE SUMMARY  |  '
          f'Endpoints: {endpoints_count}  '
          f'Params: {parameters_count}  '
          f'Attacks: {attacks_count}')
    print(TOP)
    print(_row('Module Checks', 'Input Used',
               'Supporting Input Document', 'Actual Findings', 'Features/'))
    print(HDR_SEP)

    for meta in MODULE_ROWS:
        label    = meta['label']
        sublabel = meta['sublabel']
        actual   = _actual_findings(meta['key'], meta['typical'])
        used     = _input_used(meta['key'])

        print(_row(label, used, meta['docs'], actual, meta['features']))
        print(_row(sublabel, '', '', '', ''))
        print(SEP)

    # ── Footer ─────────────────────────────────────────────────────────────────
    total = len(vulnerabilities)
    sev_line = '  '.join(
        f'{s}: {severity_totals[s]}'
        for s in ['Critical', 'High', 'Medium', 'Low', 'Info']
        if severity_totals.get(s)
    )
    print()
    print(f'  Total findings: {total}' + (f'   {sev_line}' if sev_line else '   None'))
    print('  Note: Cloud/CSPM checks handled by separate engines.')
    print(TOP)

    # ── Build and return full (non-truncated) module data for the JSON report ──
    module_data = []
    for meta in MODULE_ROWS:
        found = by_key.get(meta['key'], [])
        finding_details = []
        for v in found:
            if isinstance(v, dict):
                ep = v.get('endpoint', {})
                prm = v.get('parameter', {})
                finding_details.append({
                    'type': v.get('header_name') or v.get('cookie_name') or v.get('type') or 'Finding',
                    'severity': v.get('severity', 'Info'),
                    'endpoint_url': ep.get('url', '') if isinstance(ep, dict) else str(ep),
                    'endpoint_method': ep.get('method', '') if isinstance(ep, dict) else '',
                    'parameter': prm.get('name', '') if isinstance(prm, dict) else str(prm),
                    'description': v.get('description', ''),
                    'evidence': v.get('evidence', ''),
                    'remediation': v.get('remediation', ''),
                })
            else:
                raw_type = getattr(v, 'type', None)
                raw_sev = getattr(v, 'severity', 'Info')
                finding_details.append({
                    'type': getattr(raw_type, 'value', str(raw_type)) if raw_type else 'Finding',
                    'severity': getattr(raw_sev, 'value', str(raw_sev)),
                    'endpoint_url': getattr(v, 'endpoint_url', ''),
                    'endpoint_method': getattr(v, 'endpoint_method', ''),
                    'parameter': getattr(v, 'parameter_name', ''),
                    'description': getattr(v, 'description', ''),
                    'evidence': str(getattr(v, 'evidence', '')),
                    'remediation': getattr(v, 'remediation', ''),
                })
        module_data.append({
            'module': meta['label'] + (' – ' + meta['sublabel'] if meta['sublabel'] else ''),
            'key': meta['key'],
            'input_used': _input_used(meta['key']),
            'supporting_docs': meta['docs'],
            'typical_findings': meta['typical'],
            'features': meta['features'],
            'finding_count': len(found),
            'highest_severity': _highest_severity(found) if found else 'None',
            'findings': finding_details,
        })
    return module_data


def configure_scan_target(cli_args=None, config_file=None,
                          profile=None) -> Tuple[Dict[str, Any], requests.Session]:
    """
    Step 1: Configure scan target
    
    This function orchestrates the complete target configuration process:
    1. Load configuration from multiple sources
    2. Validate all inputs
    3. Setup authentication
    4. Verify authentication
    5. Display summary and get confirmation
    
    Args:
        cli_args: Parsed CLI arguments
        config_file: Path to config file
    
    Returns:
        Tuple of (config_dict, authenticated_session)
    
    Raises:
        ConfigurationError: If configuration is invalid
        AuthenticationError: If authentication fails
    """
    
    # Load config
    try:
        config = TargetConfig(config_file=config_file, profile=profile)
        if cli_args:
            config.update_from_cli(vars(cli_args))
    except ConfigurationError as e:
        print(f"[FAIL] Configuration error: {e}")
        sys.exit(2)

    # Validate
    try:
        errors = InputValidator.validate_full_config(config.to_dict())
        if errors:
            print("[FAIL] Configuration invalid:")
            for err in errors:
                print(f"  - {err}")
            sys.exit(2)
    except Exception as e:
        print(f"[FAIL] Validation error: {e}")
        sys.exit(2)

    # Setup auth
    try:
        auth_manager = AuthenticationManager(config.get('authentication'))
        session = auth_manager.get_session()
    except AuthenticationError as e:
        print(f"[FAIL] Authentication error: {e}")
        sys.exit(2)

    # Verify auth endpoint if configured (non-fatal on network errors)
    verify_endpoint = config.get('authentication.session.verify_endpoint')
    if verify_endpoint:
        try:
            if not auth_manager.verify_authentication(verify_endpoint):
                print("[FAIL] Authentication verification failed — check credentials")
                sys.exit(2)
        except Exception:
            pass

    return config.to_dict(), session


def main():
    """Main entry point"""
    args = None

    try:
        args = parse_cli_args()

        # --show-config: dump full resolved config and exit
        if args.show_config:
            profile = getattr(args, 'profile', None) or 'normal'
            config_dict, _ = configure_scan_target(
                cli_args=args, config_file=args.config, profile=profile
            )
            import json as _json
            print(_json.dumps(config_dict, indent=2))
            return 0

        profile = getattr(args, 'profile', None) or 'normal'
        target_display = args.url or (args.config or '').split('/')[-1]
        print(f"\nDAST Scanner  |  {target_display}  |  Profile: {profile}\n")

        # ── [1/5] Configure ──────────────────────────────────────────────────
        print("[1/5] Loading configuration...", end=' ', flush=True)
        config_dict, _session = configure_scan_target(
            cli_args=args, config_file=args.config, profile=profile
        )

        # Production safety gate — runs after config loads, before any scan step
        if config_dict.get('safety', {}).get('environment') == 'production':
            print()  # newline after "Loading configuration..."
            print("[WARN] PRODUCTION environment — ensure you have authorisation to scan.")
            if config_dict.get('safety', {}).get('require_authorization', False):
                if not getattr(args, 'authorized', False):
                    print("[FAIL] Add --authorized to confirm permission for production scans.")
                    sys.exit(2)
            confirm = input("Proceed with production scan? (yes/no): ")
            if confirm.strip().lower() != 'yes':
                print("Scan cancelled.")
                sys.exit(0)

        print("Successful")

        if args.config_only:
            print("Config-only mode — use without --config-only to run a full scan.")
            return 0

        config = TargetConfig(config_file=args.config, profile=profile)
        config.update_from_cli(vars(args))

        # ── [2/5] Discover ───────────────────────────────────────────────────
        sys.stdout.write("[2/5] Discovering endpoints... ")
        sys.stdout.flush()
        try:
            discovery_engine = ApplicationDiscoveryEngine(config)
            result = discovery_engine.discover(
                enable_js_rendering=getattr(args, 'enable_js_rendering', False)
            )
            pages = discovery_engine.stats.get('web_crawler', {}).get('pages_crawled', 0)
            print(f"Successful  ({result.total_endpoints} endpoints, {pages} pages)")
        except Exception as e:
            print(f"Failed  ({e})")
            if args.debug:
                import traceback; traceback.print_exc()
            from dast_engine.crawler.discovery_engine import DiscoveryResult
            result = DiscoveryResult(
                target_url=config.get('target.url'),
                endpoints_discovered=[], total_endpoints=0, statistics={}
            )

        # ── [3/5] Parameters ─────────────────────────────────────────────────
        sys.stdout.write("[3/5] Identifying parameters... ")
        sys.stdout.flush()
        enricher = ParameterEnricher()
        enriched_endpoints = enricher.enrich_crawl_result(result)
        stats = enricher.get_statistics(enriched_endpoints)
        print(f"Successful  ({stats['injectable_parameters']} injectable / {stats['total_parameters']} total)")

        # ── [4/5] Attack ─────────────────────────────────────────────────────
        attack_results = None
        if result.total_endpoints > 0 and stats['injectable_parameters'] > 0:
            print("[4/5] Running attacks...")
            try:
                from dast_engine.attack.attack_executor import AttackExecutor
                from dast_engine.auth.auth_manager import AuthenticationManager as _AM

                executor = AttackExecutor(
                    config=config.to_dict(),
                    endpoints=enriched_endpoints,
                    auth_manager=_AM(config.get('authentication'))
                )
                attack_results = executor.execute_attacks()

            except Exception as e:
                print(f"\n[WARN] Attack phase error: {e}")
                if args.debug:
                    import traceback; traceback.print_exc()
        else:
            print("[4/5] Running attacks... Skipped  (no injectable parameters found)")

        # ── [5/5] Reports ────────────────────────────────────────────────────
        vulns = attack_results['vulnerabilities'] if attack_results else []
        atk_stats = attack_results['stats'] if attack_results else {}

        output_dir = getattr(args, 'output', None) or config.get('output.reports_dir', 'reports')
        effective_fmts = getattr(args, 'formats', None) or config.get('output.format', ['json'])
        if isinstance(effective_fmts, str):
            effective_fmts = [effective_fmts]

        # Print summary table first so module_summary data is available for the report
        print()
        module_summary = _print_module_summary(
            vulnerabilities=vulns,
            endpoints_count=result.total_endpoints,
            parameters_count=stats['total_parameters'],
            attacks_count=atk_stats.get('total_attacks', 0),
        )

        sys.stdout.write("\n[5/5] Generating reports... ")
        sys.stdout.flush()
        from dast_engine.report.report_generator import ReportGenerator
        report_gen = ReportGenerator(output_dir=output_dir)
        report_files = report_gen.generate_all_reports(
            vulnerabilities=vulns,
            scan_config=config.to_dict(),
            scan_stats={**atk_stats, 'pages_crawled': pages},
            formats=effective_fmts,
            endpoints=enriched_endpoints,
            parameter_stats=stats,
            module_summary=module_summary,
        )
        print(f"Successful  ({', '.join(effective_fmts)})")

        print(f"Target  : {config.get('target.url')}")
        print(f"Profile : {profile}")
        print(f"Reports : {', '.join(str(p) for p in report_files.values())}")
        print()

        fail_on = getattr(args, 'fail_on', None) or config.get('output.fail_on')
        if fail_on and _check_fail_threshold(vulns, fail_on):
            print(f"[FAIL] --fail-on '{fail_on}' threshold breached.")
            return 1

        return 0

    except KeyboardInterrupt:
        print("\n[WARN] Interrupted by user")
        return 130

    except Exception as e:
        print(f"\n[FAIL] {e}")
        if args is not None and args.debug:
            import traceback; traceback.print_exc()
        return 2


if __name__ == '__main__':
    sys.exit(main())
