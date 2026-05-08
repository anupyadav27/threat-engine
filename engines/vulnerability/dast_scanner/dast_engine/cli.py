"""
Command-line interface for DAST Scanner

4-Layer CLI:
  Layer 1  URL only          python -m dast_engine --url https://example.com
  Layer 2  Named profile     python -m dast_engine --url https://example.com --profile deep
  Layer 3  Full YAML config  python -m dast_engine --config config/my_scan.yaml
  Layer 4  CI/CD pipeline    python -m dast_engine --url https://ci-target.com --fail-on high --format sarif
"""

import argparse
import sys


def create_cli_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser"""

    parser = argparse.ArgumentParser(
        description='DAST Scanner - Dynamic Application Security Testing',
        epilog="""
Examples:
  # Layer 1: URL only (zero config)
  python -m dast_engine --url https://example.com

  # Layer 2: Named profile
  python -m dast_engine --url https://example.com --profile deep

  # Layer 3: Full YAML config file
  python -m dast_engine --config config/my_scan.yaml

  # Layer 4: CI/CD pipeline (fail on high+, emit SARIF)
  python -m dast_engine --url https://example.com --fail-on high --format sarif --output reports/scan

  # Bearer token auth
  python -m dast_engine --url https://example.com --auth-type bearer --auth-token abc123

  # Custom header auth (API key)
  python -m dast_engine --url https://example.com --auth-header "X-API-Key:secret"

  # Multiple formats
  python -m dast_engine --url https://example.com --format json --format html

  # Production scan (requires authorization)
  python -m dast_engine --url https://example.com --environment production --authorized
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Target configuration
    target_group = parser.add_argument_group('Target Configuration')
    target_group.add_argument(
        '-u', '--url',
        help='Target URL (e.g., https://example.com)'
    )
    target_group.add_argument(
        '--scope',
        action='append',
        help='Scope pattern to include (can be specified multiple times, e.g., /api/*)'
    )
    target_group.add_argument(
        '--exclude',
        action='append',
        help='Scope pattern to exclude (can be specified multiple times, e.g., /admin/*)'
    )
    
    # Authentication
    auth_group = parser.add_argument_group('Authentication')
    auth_group.add_argument(
        '--auth-type',
        choices=['none', 'basic', 'bearer', 'cookie', 'oauth2'],
        help='Authentication type (default: none)'
    )
    auth_group.add_argument(
        '--auth-token',
        help='Bearer token for authentication'
    )
    auth_group.add_argument(
        '--auth-header',
        metavar='NAME:VALUE',
        help='Custom auth header, e.g. "X-API-Key:secret" or "Authorization:Token abc"'
    )
    auth_group.add_argument(
        '--username',
        help='Username for basic auth'
    )
    auth_group.add_argument(
        '--password',
        help='Password for basic auth'
    )
    auth_group.add_argument(
        '--cookie',
        help='Session cookie value'
    )
    
    # Scan configuration
    scan_group = parser.add_argument_group('Scan Configuration')
    scan_group.add_argument(
        '--profile',
        choices=['quick', 'normal', 'deep'],
        help=(
            'Scan profile — quick (depth=2, 100 pages, 20 req/s), '
            'normal (depth=5, 1000 pages, 50 req/s), '
            'deep (depth=10, 5000 pages, 100 req/s). '
            'Individual --max-depth / --max-pages / --rate-limit override the profile.'
        )
    )
    scan_group.add_argument(
        '--intensity',
        choices=['quick', 'normal', 'thorough', 'aggressive'],
        help='Scan intensity level (default: normal)'
    )
    scan_group.add_argument(
        '--rate-limit',
        type=int,
        help='Maximum requests per second'
    )
    scan_group.add_argument(
        '--threads',
        type=int,
        help='Number of concurrent threads'
    )
    scan_group.add_argument(
        '--max-depth',
        type=int,
        help='Maximum crawl depth'
    )
    scan_group.add_argument(
        '--max-pages',
        type=int,
        help='Maximum pages to crawl'
    )
    
    # Crawler/Discovery configuration (Step 2)
    crawler_group = parser.add_argument_group('Crawler & Discovery (Step 2)')
    crawler_group.add_argument(
        '--enable-js-rendering',
        action='store_true',
        help='Enable JavaScript rendering with Playwright (for SPAs)'
    )
    crawler_group.add_argument(
        '--disable-pattern-discovery',
        action='store_true',
        help='Disable pattern-based API endpoint discovery'
    )
    crawler_group.add_argument(
        '--config-only',
        action='store_true',
        help='Only configure target, skip discovery and scanning'
    )
    
    # Safety
    safety_group = parser.add_argument_group('Safety & Authorization')
    safety_group.add_argument(
        '--environment',
        choices=['development', 'staging', 'production'],
        help='Target environment (affects safety settings, default: staging)'
    )
    safety_group.add_argument(
        '--authorized',
        action='store_true',
        help='Confirm authorization to scan (required for production)'
    )
    
    # Configuration file
    parser.add_argument(
        '-c', '--config',
        help='Load configuration from YAML/JSON file'
    )
    
    # Output
    output_group = parser.add_argument_group('Output')
    output_group.add_argument(
        '-o', '--output',
        help='Output directory for reports (default: reports)'
    )
    output_group.add_argument(
        '--format',
        dest='formats',
        action='append',
        choices=['html', 'json', 'pdf', 'sarif', 'all'],
        metavar='FORMAT',
        help=(
            'Report format: html, json, pdf, sarif, all. '
            'Repeat to emit multiple formats: --format json --format sarif. '
            'Default: json'
        )
    )
    output_group.add_argument(
        '--fail-on',
        choices=['critical', 'high', 'medium', 'low', 'any'],
        metavar='SEVERITY',
        help=(
            'Exit with code 1 if any finding at or above SEVERITY is found. '
            'Values: critical, high, medium, low, any. '
            'Exit code 0=clean, 1=threshold breached, 2=scan error.'
        )
    )
    output_group.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
    )
    output_group.add_argument(
        '--debug',
        action='store_true',
        help='Debug mode'
    )
    
    # Display configuration only (dry-run)
    parser.add_argument(
        '--show-config',
        action='store_true',
        help='Display configuration and exit (dry-run)'
    )
    
    return parser


def parse_cli_args():
    """Parse and return CLI arguments"""
    parser = create_cli_parser()
    args = parser.parse_args()

    # Validate that URL is provided either via CLI or config file
    if not args.url and not args.config:
        parser.error("Either --url or --config must be provided")

    # Normalise --format / --formats
    # 'all' expands to every concrete format; deduplicate; default to ['json']
    _ALL_FORMATS = ['html', 'json', 'pdf', 'sarif']
    if args.formats:
        expanded = []
        for f in args.formats:
            if f == 'all':
                expanded.extend(_ALL_FORMATS)
            else:
                expanded.append(f)
        # Deduplicate while preserving order
        seen: set = set()
        args.formats = [x for x in expanded if not (x in seen or seen.add(x))]
    else:
        args.formats = None   # defer to config file / report_generator default

    return args
