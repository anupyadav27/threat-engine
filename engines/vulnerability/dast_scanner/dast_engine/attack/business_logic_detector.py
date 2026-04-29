"""
Business Logic Detector
Automated checks for common business-logic vulnerabilities:
  1. IDOR  — Insecure Direct Object Reference (numeric ID enumeration)
  2. Forced Browsing — sensitive admin/config paths accessible without auth
  3. Parameter Tampering — negative/zero/overflow values on numeric params
  4. HTTP Method Override — unexpected methods accepted on endpoints
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse


# ── Sensitive paths for forced-browsing check ─────────────────────────────────
_SENSITIVE_PATHS = [
    # Admin panels
    '/admin', '/admin/', '/administrator', '/admin/login', '/admin/dashboard',
    '/wp-admin', '/wp-admin/admin.php', '/phpmyadmin', '/cpanel',
    # Config / env
    '/.env', '/config', '/config.php', '/configuration.php', '/web.config',
    '/app/config', '/settings.py', '/application.yml', '/application.properties',
    # Backups
    '/backup', '/backup.zip', '/backup.tar.gz', '/db.sql', '/dump.sql',
    '/site.zip', '/.git/config', '/.svn/entries',
    # Debug / monitoring
    '/debug', '/trace', '/actuator', '/actuator/health', '/actuator/env',
    '/actuator/beans', '/_debug', '/swagger-ui.html', '/api-docs',
    '/v1/api-docs', '/openapi.json', '/swagger.json',
    # User management
    '/users', '/api/users', '/api/v1/users', '/api/admin', '/api/admin/users',
    '/manage', '/management', '/console',
    # Common sensitive files (robots.txt and sitemap.xml are intentionally public — excluded)
    '/server-status', '/server-info',
    '/.htaccess', '/crossdomain.xml', '/clientaccesspolicy.xml',
]

# ── Numeric parameter patterns that suggest business-critical values ──────────
_BUSINESS_PARAMS = re.compile(
    r'(price|amount|qty|quantity|total|cost|fee|balance|credit|discount'
    r'|limit|quota|count|num|rate|score|rank|level|age|year|id|uid'
    r'|user_?id|account_?id|order_?id|item_?id|product_?id)',
    re.IGNORECASE,
)

# ── Tampered values to try on numeric business params ────────────────────────
_TAMPER_VALUES = ['-1', '0', '-9999', '99999999', '2147483647', '0.001', '-0.01']

# ── HTTP methods to probe ─────────────────────────────────────────────────────
_PROBE_METHODS = ['PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE']


@dataclass
class BusinessLogicIssue:
    """A single business-logic finding."""
    check_type: str        # idor | forced_browsing | param_tamper | method_override
    severity: str          # Critical / High / Medium / Low
    endpoint_url: str
    http_method: str
    parameter: str
    evidence: str
    description: str
    impact: str
    remediation: str
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'type': f'Business Logic – {self.check_type.replace("_", " ").title()}',
            'severity': self.severity,
            'evidence': self.evidence,
            'endpoint': {'url': self.endpoint_url, 'method': self.http_method},
            'parameter': {'name': self.parameter} if self.parameter else {},
            'description': self.description,
            'impact': self.impact,
            'remediation': self.remediation,
            'references': self.references,
        }


class BusinessLogicDetector:
    """
    Runs four automated business-logic checks against discovered endpoints.

    Usage:
        detector = BusinessLogicDetector(session, base_url, timeout=8)
        issues   = detector.check_endpoint(endpoint)
    """

    def __init__(self, session, base_url: str, timeout: int = 8):
        self.session  = session
        self.base_url = base_url.rstrip('/')
        self.timeout  = timeout

    # ── Public entry point ────────────────────────────────────────────────────

    def check_endpoint(self, endpoint) -> List[BusinessLogicIssue]:
        """Run all four checks against one endpoint; return any findings."""
        issues: List[BusinessLogicIssue] = []
        issues.extend(self._check_idor(endpoint))
        issues.extend(self._check_param_tamper(endpoint))
        issues.extend(self._check_method_override(endpoint))
        return issues

    def run_forced_browsing(self) -> List[BusinessLogicIssue]:
        """
        Forced-browsing check — called once per scan (not per endpoint).
        Returns findings for every sensitive path that responds 200/301/302
        without an auth challenge.
        """
        issues: List[BusinessLogicIssue] = []
        for path in _SENSITIVE_PATHS:
            url = urljoin(self.base_url + '/', path.lstrip('/'))
            try:
                resp = self.session.get(url, timeout=self.timeout,
                                        allow_redirects=False)
            except Exception:
                continue

            # Flag 200 (found) and redirects to non-login pages
            if resp.status_code == 200:
                sev  = 'High'
                note = f'HTTP 200 – content length {len(resp.content)} bytes'
            elif resp.status_code in (301, 302):
                location = resp.headers.get('Location', '')
                if any(w in location.lower() for w in ('login', 'signin', 'auth')):
                    continue          # legitimate auth redirect
                sev  = 'Medium'
                note = f'HTTP {resp.status_code} → {location}'
            else:
                continue

            issues.append(BusinessLogicIssue(
                check_type='forced_browsing',
                severity=sev,
                endpoint_url=url,
                http_method='GET',
                parameter='',
                evidence=f'GET {url} → {note}',
                description=(
                    f'Sensitive path "{path}" is accessible without authentication. '
                    f'Response: {note}'
                ),
                impact=(
                    'Exposure of administrative interfaces, configuration files, or backup '
                    'archives can lead to full application compromise, credential theft, or '
                    'data leakage.'
                ),
                remediation=(
                    '1. Restrict access to sensitive paths with authentication middleware.\n'
                    '2. Remove backup files and debug endpoints from production.\n'
                    '3. Return 404 (not 403) for paths that should not exist to avoid enumeration.\n'
                    '4. Implement role-based access control (RBAC) on all admin routes.'
                ),
                references=[
                    'https://owasp.org/www-project-web-security-testing-guide/latest/'
                    '4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/'
                    '04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information',
                    'https://cwe.mitre.org/data/definitions/425.html',
                ],
            ))
        return issues

    # ── Check 1: IDOR ─────────────────────────────────────────────────────────

    def _check_idor(self, endpoint) -> List[BusinessLogicIssue]:
        """
        For each numeric query / path parameter, fetch the baseline response
        then probe id±1 and id=0.  If the response body changes substantially
        and stays 200, flag potential IDOR.
        """
        issues: List[BusinessLogicIssue] = []
        url    = endpoint.url
        method = endpoint.method.upper()

        # Collect numeric query params
        parsed    = urlparse(url)
        qs        = parse_qs(parsed.query, keep_blank_values=True)
        id_params = {k: v[0] for k, v in qs.items() if v[0].lstrip('-').isdigit()}

        if not id_params:
            return issues

        # Baseline
        try:
            baseline = self.session.request(method, url, timeout=self.timeout,
                                            allow_redirects=False)
            baseline_len = len(baseline.content)
        except Exception:
            return issues

        if baseline.status_code not in (200, 201):
            return issues

        for param_name, original_val in id_params.items():
            orig_int = int(original_val)
            probes   = [orig_int + 1, orig_int - 1, 0]

            for probe_val in probes:
                if probe_val == orig_int:
                    continue
                probe_qs = dict(qs)
                probe_qs[param_name] = [str(probe_val)]
                new_query = urlencode({k: v[0] for k, v in probe_qs.items()})
                probe_url = urlunparse(parsed._replace(query=new_query))

                try:
                    resp = self.session.request(method, probe_url,
                                                timeout=self.timeout,
                                                allow_redirects=False)
                except Exception:
                    continue

                if resp.status_code != 200:
                    continue

                # Substantial content change = different object returned
                delta = abs(len(resp.content) - baseline_len)
                if delta > 50 and len(resp.content) > 100:
                    issues.append(BusinessLogicIssue(
                        check_type='idor',
                        severity='High',
                        endpoint_url=url,
                        http_method=method,
                        parameter=param_name,
                        evidence=(
                            f'{method} {probe_url} → HTTP 200, '
                            f'body size {len(resp.content)}B '
                            f'(baseline {baseline_len}B, delta {delta}B)'
                        ),
                        description=(
                            f'Parameter "{param_name}" accepted value {probe_val} '
                            f'(original: {original_val}) and returned a 200 response '
                            f'with different content, indicating possible IDOR.'
                        ),
                        impact=(
                            'Attackers can enumerate and access other users\' records, orders, '
                            'or files by incrementing/decrementing object identifiers — without '
                            'any special privileges.'
                        ),
                        remediation=(
                            '1. Enforce server-side ownership checks: verify the requesting user '
                            'owns the requested object before returning data.\n'
                            '2. Use non-sequential UUIDs instead of integer IDs.\n'
                            '3. Implement ABAC (attribute-based access control).\n'
                            '4. Log and alert on unexpected object-ID enumeration patterns.'
                        ),
                        references=[
                            'https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control',
                            'https://cwe.mitre.org/data/definitions/639.html',
                            'https://portswigger.net/web-security/access-control/idor',
                        ],
                    ))
                    break  # one finding per param is enough

        return issues

    # ── Check 2: Parameter Tampering ─────────────────────────────────────────

    def _check_param_tamper(self, endpoint) -> List[BusinessLogicIssue]:
        """
        For parameters whose names suggest business-critical numeric values
        (price, amount, qty …), send boundary / negative values and flag if
        the server accepts them with a 200.
        """
        issues: List[BusinessLogicIssue] = []
        url    = endpoint.url
        method = endpoint.method.upper()

        # Collect candidate params from query string
        parsed = urlparse(url)
        qs     = parse_qs(parsed.query, keep_blank_values=True)
        candidates = [k for k in qs if _BUSINESS_PARAMS.search(k)]

        # Also check body / form params stored on the endpoint object
        body_params = []
        for loc in ('body_params', 'query_params', 'parameters'):
            for p in (getattr(endpoint, loc, None) or []):
                pname = getattr(p, 'name', '')
                if _BUSINESS_PARAMS.search(pname):
                    body_params.append(pname)

        all_candidates = list(set(candidates + body_params))
        if not all_candidates:
            return issues

        for param_name in all_candidates:
            for tamper_val in _TAMPER_VALUES:
                probe_qs  = {k: v[0] for k, v in qs.items()}
                probe_qs[param_name] = tamper_val
                new_query = urlencode(probe_qs)
                probe_url = urlunparse(parsed._replace(query=new_query))

                try:
                    resp = self.session.request(method, probe_url,
                                                timeout=self.timeout,
                                                allow_redirects=False)
                except Exception:
                    continue

                if resp.status_code in (200, 201, 302):
                    # A redirect to a success/confirmation page is also suspicious
                    location = resp.headers.get('Location', '')
                    is_success_redirect = (
                        resp.status_code in (301, 302)
                        and any(w in location.lower()
                                for w in ('success', 'confirm', 'thank', 'order'))
                    )
                    if resp.status_code in (200, 201) or is_success_redirect:
                        issues.append(BusinessLogicIssue(
                            check_type='param_tamper',
                            severity='High',
                            endpoint_url=url,
                            http_method=method,
                            parameter=param_name,
                            evidence=(
                                f'{method} {probe_url} with {param_name}={tamper_val} '
                                f'→ HTTP {resp.status_code}'
                            ),
                            description=(
                                f'Business-critical parameter "{param_name}" accepted '
                                f'the tampered value "{tamper_val}" (HTTP {resp.status_code}). '
                                'The server did not reject the invalid input.'
                            ),
                            impact=(
                                'Attackers can manipulate prices, quantities, or scores to their '
                                'advantage — e.g., purchasing items for negative/zero cost, '
                                'bypassing quotas, or gaining unearned credits.'
                            ),
                            remediation=(
                                '1. Validate all numeric inputs server-side: enforce min/max '
                                'bounds and reject negative values where inappropriate.\n'
                                '2. Never trust client-supplied prices or quantities; re-fetch '
                                'authoritative values from the database at order time.\n'
                                '3. Use signed/HMAC-protected tokens for sensitive values.\n'
                                '4. Implement rate-limiting and anomaly detection on order flows.'
                            ),
                            references=[
                                'https://owasp.org/www-project-web-security-testing-guide/latest/'
                                '4-Web_Application_Security_Testing/10-Business_Logic_Testing/'
                                '04-Test_for_Process_Timing',
                                'https://cwe.mitre.org/data/definitions/840.html',
                            ],
                        ))
                        break  # one finding per param

        return issues

    # ── Check 3: HTTP Method Override ────────────────────────────────────────

    def _check_method_override(self, endpoint) -> List[BusinessLogicIssue]:
        """
        Try PUT / DELETE / PATCH / TRACE on an endpoint that only expects GET/POST.
        Flag if the server returns 200/201/204 (not 405 Method Not Allowed).
        """
        issues: List[BusinessLogicIssue] = []
        url            = endpoint.url
        declared_method = endpoint.method.upper()

        for method in _PROBE_METHODS:
            if method == declared_method:
                continue
            try:
                resp = self.session.request(method, url, timeout=self.timeout,
                                            allow_redirects=False)
            except Exception:
                continue

            if resp.status_code in (200, 201, 204):
                sev = 'High' if method in ('DELETE', 'PUT', 'PATCH') else 'Medium'
                issues.append(BusinessLogicIssue(
                    check_type='method_override',
                    severity=sev,
                    endpoint_url=url,
                    http_method=method,
                    parameter='',
                    evidence=f'{method} {url} → HTTP {resp.status_code}',
                    description=(
                        f'Endpoint accepts {method} requests (expected: {declared_method}). '
                        f'Response: HTTP {resp.status_code}.'
                    ),
                    impact=(
                        f'Accepting {method} on an endpoint not designed for it can allow '
                        'unintended data modification, deletion, or server-side state changes '
                        'by any authenticated (or unauthenticated) user.'
                    ),
                    remediation=(
                        '1. Explicitly whitelist allowed HTTP methods per endpoint.\n'
                        '2. Return 405 Method Not Allowed for all other methods.\n'
                        '3. In frameworks: use method decorators/annotations '
                        '(@GET, @POST, etc.) and disable catch-all routing.\n'
                        '4. Disable TRACE globally — it enables XST attacks.'
                    ),
                    references=[
                        'https://owasp.org/www-project-web-security-testing-guide/latest/'
                        '4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/'
                        '06-Test_HTTP_Methods',
                        'https://cwe.mitre.org/data/definitions/650.html',
                    ],
                ))

        return issues
