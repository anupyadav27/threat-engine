"""
Attack Executor - Main orchestrator for attack execution
Manages the attack flow: endpoints → parameters → payloads → execution
"""

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional
from datetime import datetime
import sys
from pathlib import Path

# Add payloads directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'payloads'))

from payload_loader import PayloadLoader, PayloadCategory
from payload_encoder import PayloadEncoder
from .payload_injector import PayloadInjector
from .request_builder import RequestBuilder
from .response_recorder import ResponseRecorder
from .vulnerability_detector import VulnerabilityDetector
from .business_logic_detector import BusinessLogicDetector


class AttackExecutor:
    """
    Main attack execution engine.
    Orchestrates the attack flow across endpoints, parameters, and payloads.
    """
    
    def __init__(self, config, endpoints: List[Any], auth_manager=None):
        """
        Initialize attack executor.
        
        Args:
            config: DAST configuration object
            endpoints: List of discovered endpoints (from Step 2)
            auth_manager: Authentication manager (from Step 1)
        """
        self.config = config
        self.endpoints = endpoints
        self.auth_manager = auth_manager
        
        # Initialize components
        self.payload_loader = PayloadLoader()
        self.payload_encoder = PayloadEncoder()
        self.injector = PayloadInjector()
        # Build a flat config dict for RequestBuilder from the nested scan config
        _perf = (config.get('scan') or {}).get('performance') or {}
        _crawl = (config.get('scan') or {}).get('crawler') or {}
        # Attack timeout is separate from the crawler's request_timeout.
        # Use explicit attack_timeout if set, otherwise cap crawler timeout at 10s
        # so slow sites don't make the attack phase take hours.
        crawler_timeout = _perf.get('request_timeout', 30)
        attack_timeout = _perf.get('attack_timeout', min(crawler_timeout, 10))
        rb_config = {
            'timeout': attack_timeout,
            'retry_attempts': 1,          # attacks: 2 total attempts (1 retry)
            'retry_delay': 0.5,
            'ssl_verify': config.get('ssl_verify', True),
            'user_agent': _crawl.get('user_agent', 'DAST-Scanner/1.0'),
        }
        self.request_builder = RequestBuilder(auth_manager, rb_config)
        self.recorder = ResponseRecorder(config)
        self.detector = VulnerabilityDetector()
        self.detector.set_auth_manager(auth_manager)
        self._bl_detector: Optional[BusinessLogicDetector] = None
        self.logger = logging.getLogger('DASTScanner.Attack')

        # Statistics
        self.stats = {
            'total_attacks': 0,
            'completed': 0,
            'failed': 0,
            'vulnerabilities_found': 0,
            'start_time': None,
            'end_time': None
        }
        
        # Store vulnerabilities and deduplication set (protected by lock for threading)
        self.vulnerabilities = []
        self._vuln_seen = set()
        self._lock = threading.Lock()

        # Number of parallel worker threads for the attack phase
        self._threads = int((config.get('scan') or {}).get('performance', {}).get('threads', 5))
        
    def execute_attacks(self) -> Dict[str, Any]:
        """
        Main execution method.
        Executes attacks across all endpoints and parameters.
        
        Returns:
            Dictionary with attack results and statistics
        """
        self.stats['start_time'] = datetime.now()
        self._calculate_total_attacks()

        # Execute attacks in parallel across endpoints
        results = []
        workers = max(1, min(self._threads, len(self.endpoints)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(self._attack_endpoint, ep): ep
                       for ep in self.endpoints}
            for future in as_completed(futures):
                try:
                    results.extend(future.result())
                except Exception as exc:
                    self.logger.debug("Endpoint worker error: %s", exc)
        
        # ── Business Logic checks (run once per scan) ────────────────────────
        self._run_business_logic_checks()

        self.stats['end_time'] = datetime.now()

        # Finalize recorder
        self.recorder.finalize()

        self._print_summary()
        
        return {
            'results': results,
            'stats': self.stats,
            'vulnerabilities': self.vulnerabilities
        }
    
    def _attack_endpoint(self, endpoint) -> List[Dict[str, Any]]:
        """
        Attack a single endpoint across all its parameters.
        
        Args:
            endpoint: EnrichedEndpoint object with URL, method, and parameter lists
            
        Returns:
            List of attack results for this endpoint
        """
        results = []
        all_parameters = []
        
        # EnrichedEndpoint has separate lists for each parameter location
        if hasattr(endpoint, 'query_params'):
            all_parameters.extend(endpoint.query_params or [])
        if hasattr(endpoint, 'path_params'):
            all_parameters.extend(endpoint.path_params or [])
        if hasattr(endpoint, 'body_params'):
            all_parameters.extend(endpoint.body_params or [])
        if hasattr(endpoint, 'header_params'):
            all_parameters.extend(endpoint.header_params or [])
        if hasattr(endpoint, 'cookie_params'):
            all_parameters.extend(endpoint.cookie_params or [])
        
        # Fallback for old-style Endpoint objects with single parameters list
        if not all_parameters and hasattr(endpoint, 'parameters'):
            all_parameters = endpoint.parameters or []
        
        if not all_parameters:
            return results

        # Track vulns before this endpoint so we can print a per-endpoint summary
        _vuln_before = len(self.vulnerabilities)

        # Run per-endpoint checks (CSRF, open redirect, file upload) exactly once
        self._run_endpoint_level_checks(endpoint)

        for parameter in all_parameters:
            results.extend(self._attack_parameter(endpoint, parameter))

        # One-line summary per endpoint
        from urllib.parse import urlparse as _up
        _path   = _up(endpoint.url).path or '/'
        _method = str(endpoint.method)[:6].ljust(6)
        _new    = self.vulnerabilities[_vuln_before:]
        if _new:
            _names, _seen = [], set()
            for v in _new:
                n = ((v.get('header_name') or v.get('cookie_name') or v.get('type') or '?')
                     if isinstance(v, dict) else '?')
                s = (v.get('severity', 'I') if isinstance(v, dict) else 'I')[0]
                if n not in _seen:
                    _seen.add(n)
                    _names.append(f"{n[:16]}({s})")
            shown = ', '.join(_names[:2])
            extra = f' +{len(_names)-2}' if len(_names) > 2 else ''
            print(f"  {_method} {_path:<36} [{len(_new):2d}]  {shown}{extra}")
        else:
            print(f"  {_method} {_path:<36}       -")

        return results
    
    def _attack_parameter(self, endpoint, parameter) -> List[Dict[str, Any]]:
        """
        Attack a single parameter with relevant payloads.
        
        Args:
            endpoint: Endpoint object
            parameter: Parameter metadata object
            
        Returns:
            List of attack results for this parameter
        """
        results = []
        
        # Skip non-injectable parameters
        if hasattr(parameter, 'injectable') and not parameter.injectable:
            return results
        
        # Skip authentication/CSRF tokens
        if parameter.name.lower() in ['csrf_token', 'csrf', 'token', 'session_id', '_token']:
            return results
        
        payloads = self._get_relevant_payloads(parameter)
        if not payloads:
            return results

        for payload in payloads:
            category = self._infer_payload_category(payload)
            result = self._execute_attack(endpoint, parameter, payload, category)
            with self._lock:
                if result:
                    results.append(result)
                    self.stats['completed'] += 1
                else:
                    self.stats['failed'] += 1

        return results
    
    def _infer_payload_category(self, payload: str) -> str:
        """Infer the payload category from its content for targeted detection."""
        p = payload.lower()
        if any(x in p for x in ["sleep(", "waitfor", "pg_sleep", "benchmark(", "' or ", '" or ', "' and ", '" and ', " union ", "--", "/*"]):
            return 'sqli'
        if any(x in p for x in ["<script", "onerror=", "onload=", "alert(", "javascript:", "<img", "<svg"]):
            return 'xss'
        if any(x in p for x in ["../", "..\\", "%2e%2e", "etc/passwd", "boot.ini"]):
            return 'path'
        if any(x in p for x in ["169.254.169.254", "metadata.google", "localhost", "127.0.0.1"]):
            return 'ssrf'
        if any(x in p for x in ["{{", "${", "<%", "#{", "{{7*7}}"]):
            return 'ssti'
        if any(x in p for x in ["<!entity", "<!doctype", "system "]):
            return 'xxe'
        if any(x in p for x in [";", "&&", "||", "`", "$(", "| ls", "| id", "| whoami"]):
            return 'cmd'
        return ''

    def _execute_attack(self, endpoint, parameter, payload: str, category: str = '') -> Dict[str, Any]:
        """
        Execute a single attack: inject payload, send request, record response.

        Args:
            endpoint: Endpoint object
            parameter: Parameter object
            payload: Payload string to inject
            
        Returns:
            Attack result dictionary or None on failure
        """
        try:
            # 1. Inject payload into parameter
            injected_value = self.injector.inject(
                endpoint=endpoint,
                parameter=parameter,
                payload=payload
            )
            
            # 2. Build HTTP request
            request_data = self.request_builder.build_request(
                endpoint=endpoint,
                parameter=parameter,
                payload_value=injected_value
            )
            
            # 3. Send request
            start_time = time.time()
            response = self.request_builder.send_request(request_data)
            response_time = int((time.time() - start_time) * 1000)  # ms
            
            if not response:
                return None
            
            # 4. Record result (now includes headers)
            result = {
                'timestamp': datetime.now().isoformat(),
                'endpoint': {
                    'url': endpoint.url,
                    'method': endpoint.method
                },
                'parameter': {
                    'name': parameter.name,
                    'location': parameter.location,
                    'type': str(parameter.param_type.value) if hasattr(parameter.param_type, 'value') else 'unknown'
                },
                'payload': {
                    'original': payload,
                    'injected': injected_value,
                    'category': category,
                },
                'request': {
                    'url': request_data.get('url'),
                    'method': request_data.get('method')
                },
                'response': {
                    'status_code': getattr(response, 'status_code', None),
                    'headers': dict(getattr(response, 'headers', {})),
                    'time_ms': response_time,
                    'body_length': len(getattr(response, 'text', '')),
                    'body': getattr(response, 'text', '')[:10000]  # Store first 10KB
                }
            }
            
            # 5. Store result (thread-safe)
            with self._lock:
                self.recorder.record(result)

            # 6. Analyze for vulnerabilities
            vulnerabilities = self.detector.analyze_response(result)
            if vulnerabilities:
                with self._lock:
                    for vuln in vulnerabilities:
                        # Deduplication key: (type, endpoint, parameter)
                        if isinstance(vuln, dict):
                            _vtype = (vuln.get('header_name') or vuln.get('cookie_name')
                                      or vuln.get('type') or 'Security Finding')
                            ep = vuln.get('endpoint', {})
                            _eurl = ep.get('url', '') if isinstance(ep, dict) else str(ep)
                            prm = vuln.get('parameter', {})
                            _pname = prm.get('name', '') if isinstance(prm, dict) else str(prm)
                            _ploc = prm.get('location', '') if isinstance(prm, dict) else ''
                        else:
                            _vtype = getattr(getattr(vuln, 'type', None), 'value', None) or str(getattr(vuln, 'type', 'Unknown'))
                            _eurl = getattr(vuln, 'endpoint_url', '')
                            _pname = getattr(vuln, 'parameter_name', '')
                            _ploc = str(getattr(vuln, 'parameter_location', ''))
                        key = (_vtype, _eurl, _pname, _ploc)
                        if key not in self._vuln_seen:
                            self.vulnerabilities.append(vuln)
                            self._vuln_seen.add(key)
                            self.stats['vulnerabilities_found'] += 1

            return result

        except Exception as e:
            self.logger.debug(f"Attack error: {e}")
            return None
    
    def _get_relevant_payloads(self, parameter) -> List[str]:
        """
        Get context-aware payloads based on parameter metadata.
        
        Args:
            parameter: Parameter metadata object
            
        Returns:
            List of relevant payload strings
        """
        from dast_engine.parameters.parameter_types import ParameterType
        
        payloads = []
        
        # Get parameter type
        param_type = parameter.param_type
        param_format = getattr(parameter, 'format_hint', None)
        
        # Payload counts are tuned for speed vs coverage:
        # String/Email: 3 SQLi + 3 XSS = 6 payloads
        # Integer/Float: 3 SQLi
        # URL: 3 SSRF
        # Default: 2 SQLi + 2 XSS = 4 payloads
        if param_type in [ParameterType.STRING, ParameterType.EMAIL]:
            payloads.extend(self.payload_loader.get_sqli_payloads()[:3])
            payloads.extend(self.payload_loader.get_xss_payloads()[:3])

        elif param_type in [ParameterType.INTEGER, ParameterType.FLOAT]:
            payloads.extend(self.payload_loader.get_sqli_payloads()[:3])

        elif param_type == ParameterType.URL or param_format == 'url':
            payloads.extend(self.payload_loader.get_ssrf_payloads()[:3])

        else:
            payloads.extend(self.payload_loader.get_sqli_payloads()[:2])
            payloads.extend(self.payload_loader.get_xss_payloads()[:2])
        
        return payloads
    
    def _run_endpoint_level_checks(self, endpoint) -> None:
        """
        Run per-endpoint security checks exactly once per endpoint (not per payload).
        Covers CSRF, open redirect, and file upload tests via VulnerabilityDetector.
        """
        ep_dict = {
            'url': getattr(endpoint, 'url', ''),
            'method': str(getattr(endpoint, 'method', 'GET')),
        }
        for check in ('test_csrf_protection', 'test_open_redirect', 'test_file_upload_security'):
            fn = getattr(self.detector, check, None)
            if fn is None:
                continue
            try:
                results = fn(ep_dict)
                if results is None:
                    continue
                items = results if isinstance(results, list) else [results]
                for issue in items:
                    if issue is None:
                        continue
                    if isinstance(issue, dict):
                        ep = issue.get('endpoint', {})
                        prm = issue.get('parameter', {})
                        key = (
                            issue.get('type', ''),
                            ep.get('url', '') if isinstance(ep, dict) else str(ep),
                            ep.get('method', '') if isinstance(ep, dict) else '',
                            prm.get('name', '') if isinstance(prm, dict) else str(prm),
                        )
                    else:
                        key = (str(getattr(issue, 'type', '')), getattr(issue, 'endpoint_url', ''),
                               getattr(issue, 'endpoint_method', ''), getattr(issue, 'parameter_name', ''))
                    with self._lock:
                        if key not in self._vuln_seen:
                            self._vuln_seen.add(key)
                            self.vulnerabilities.append(issue)
                            self.stats['vulnerabilities_found'] += 1
            except Exception as exc:
                self.logger.debug("Endpoint-level check %s failed: %s", check, exc)

    def _run_business_logic_checks(self) -> None:
        """
        Run all four business-logic checks:
          - Forced browsing  (once, against base URL)
          - IDOR             (per endpoint)
          - Parameter tamper (per endpoint)
          - HTTP method override (per endpoint)
        Findings are deduplicated and added to self.vulnerabilities.
        """
        base_url = self.config.get('target', {}).get('url', '') if isinstance(self.config, dict) else getattr(self.config, 'target_url', '')
        if not base_url:
            return

        bl = BusinessLogicDetector(
            session=self.request_builder.session,
            base_url=base_url,
            timeout=8,
        )

        all_issues = []

        all_issues.extend(bl.run_forced_browsing())
        for endpoint in self.endpoints:
            all_issues.extend(bl.check_endpoint(endpoint))

        added = 0
        with self._lock:
            for issue in all_issues:
                d = issue.to_dict()
                ep = d.get('endpoint', {})
                prm = d.get('parameter', {})
                key = (d['type'], ep.get('url', ''), ep.get('method', ''),
                       prm.get('name', '') if isinstance(prm, dict) else '')
                if key not in self._vuln_seen:
                    self._vuln_seen.add(key)
                    self.vulnerabilities.append(d)
                    self.stats['vulnerabilities_found'] += 1
                    added += 1

        # One summary line for business logic (mirrors per-endpoint format)
        if added:
            sev_counts: Dict[str, int] = {}
            for issue in all_issues:
                d = issue.to_dict()
                sev_counts[d.get('severity', 'Info')] = sev_counts.get(d.get('severity', 'Info'), 0) + 1
            top = max(sev_counts, key=lambda k: ['Critical','High','Medium','Low','Info'].index(k) if k in ['Critical','High','Medium','Low','Info'] else 99)
            print(f"  {'[BizLogic]':<6} {'(scan-wide)':<36} [{added:2d}]  top sev: {top}")
        else:
            print(f"  {'[BizLogic]':<6} {'(scan-wide)':<36}       -")

    def _calculate_total_attacks(self):
        """Calculate total number of attacks to be executed."""
        total = 0
        for endpoint in self.endpoints:
            # Get all parameters across all locations
            all_parameters = []
            
            # EnrichedEndpoint has separate lists for each parameter location
            if hasattr(endpoint, 'query_params'):
                all_parameters.extend(endpoint.query_params or [])
            if hasattr(endpoint, 'path_params'):
                all_parameters.extend(endpoint.path_params or [])
            if hasattr(endpoint, 'body_params'):
                all_parameters.extend(endpoint.body_params or [])
            if hasattr(endpoint, 'header_params'):
                all_parameters.extend(endpoint.header_params or [])
            if hasattr(endpoint, 'cookie_params'):
                all_parameters.extend(endpoint.cookie_params or [])
            
            # Fallback for old-style Endpoint objects with single parameters list
            if not all_parameters and hasattr(endpoint, 'parameters'):
                all_parameters = endpoint.parameters or []
            
            # Count injectable parameters
            injectable_params = [
                p for p in all_parameters 
                if getattr(p, 'injectable', True)
            ]
            
            # Estimate payload count (will vary based on parameter type)
            total += len(injectable_params) * 10
        
        self.stats['total_attacks'] = total
    
    def _print_summary(self):
        """Print a single summary line after all attacks complete."""
        duration = (self.stats['end_time'] - self.stats['start_time']).total_seconds()
        m, s = divmod(int(duration), 60)
        sev_counts: Dict[str, int] = {}
        for v in self.vulnerabilities:
            sev = (v.get('severity', 'Info') if isinstance(v, dict)
                   else getattr(getattr(v, 'severity', None), 'value', 'Info'))
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        sev_parts = [f"{k[0]}:{sev_counts[k]}"
                     for k in ['Critical', 'High', 'Medium', 'Low', 'Info']
                     if sev_counts.get(k)]
        sev_str = '  '.join(sev_parts) or 'none'
        print(f"\n  {self.stats['completed']} requests  |  "
              f"{self.stats['vulnerabilities_found']} findings ({sev_str})  |  {m}m {s}s")


