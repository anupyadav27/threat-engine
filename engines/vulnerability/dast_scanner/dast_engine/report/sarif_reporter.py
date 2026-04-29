"""
SARIF 2.1.0 Reporter
Produces Static Analysis Results Interchange Format output for CI/CD pipelines.
Consumed by GitHub Code Scanning, Azure DevOps, and other SAST/DAST integrations.

Exit-code convention (set by __main__.py, not this module):
  0 = clean scan
  1 = --fail-on threshold breached
  2 = scan error
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from .json_reporter import _normalize_vuln, _compute_cvss

logger = logging.getLogger('DASTScanner.SARIF')

# SARIF level for each severity
_SARIF_LEVEL: Dict[str, str] = {
    'Critical': 'error',
    'High':     'error',
    'Medium':   'warning',
    'Low':      'note',
    'Info':     'none',
}

_TOOL_NAME    = 'DAST-Scanner'
_TOOL_VERSION = '1.0.0'
_SARIF_SCHEMA = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json'


class SARIFReporter:
    """Generate a SARIF 2.1.0 report file."""

    def __init__(self, output_dir: str = 'reports'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_report(
        self,
        vulnerabilities: List[Any],
        scan_config: Dict[str, Any] = None,
        scan_stats: Dict[str, Any] = None,
    ) -> str:
        """
        Build a SARIF 2.1.0 document and write it to disk.

        Returns:
            Absolute path to the written .sarif file.
        """
        normalised = [_normalize_vuln(v) for v in vulnerabilities]

        rules      = self._build_rules(normalised)
        results    = self._build_results(normalised)
        target_url = (scan_config or {}).get('target', {}).get('url', 'unknown')

        sarif_doc = {
            '$schema': _SARIF_SCHEMA,
            'version': '2.1.0',
            'runs': [
                {
                    'tool': {
                        'driver': {
                            'name':            _TOOL_NAME,
                            'version':         _TOOL_VERSION,
                            'informationUri':  'https://github.com/your-org/dast-scanner',
                            'rules':           rules,
                        }
                    },
                    'originalUriBaseIds': {
                        'WEBROOT': {'uri': target_url if target_url.endswith('/') else target_url + '/'}
                    },
                    'results':   results,
                    'invocations': [
                        {
                            'executionSuccessful': True,
                            'endTimeUtc': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                            'toolExecutionNotifications': [],
                        }
                    ],
                    'properties': {
                        'scanTarget':   target_url,
                        'totalFindings': len(normalised),
                        'scanStats':    scan_stats or {},
                    }
                }
            ]
        }

        timestamp  = datetime.now().strftime('%Y%m%d_%H%M%S')
        out_path   = self.output_dir / f'dast_report_{timestamp}.sarif'
        out_path.write_text(json.dumps(sarif_doc, indent=2, ensure_ascii=False), encoding='utf-8')

        logger.info('SARIF report saved to %s', out_path)
        print(f'\n[OK] SARIF report saved to: {out_path}')
        return str(out_path)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_rules(self, normalised: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """One SARIF rule per unique vulnerability type."""
        seen: Dict[str, Dict[str, Any]] = {}
        for vuln in normalised:
            vtype    = vuln.get('type', 'Unknown')
            rule_id  = self._type_to_rule_id(vtype)
            if rule_id in seen:
                continue

            severity = vuln.get('severity', 'Info')
            cvss     = _compute_cvss(vtype, severity)
            level    = _SARIF_LEVEL.get(severity, 'none')

            seen[rule_id] = {
                'id': rule_id,
                'name': vtype.replace(' ', ''),
                'shortDescription': {'text': vtype},
                'fullDescription': {
                    'text': (
                        f'{vtype} — {severity} severity. '
                        f'CVSS 3.1 base score: {cvss["base_score"]}'
                    )
                },
                'defaultConfiguration': {'level': level},
                'properties': {
                    'tags':      ['security', 'dast'],
                    'severity':  severity,
                    'cvss':      cvss,
                    'precision': 'medium',
                    'problem.severity': level,
                }
            }

        return list(seen.values())

    def _build_results(self, normalised: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """One SARIF result per finding."""
        results = []
        for vuln in normalised:
            vtype    = vuln.get('type', 'Unknown')
            rule_id  = self._type_to_rule_id(vtype)
            severity = vuln.get('severity', 'Info')
            level    = _SARIF_LEVEL.get(severity, 'none')

            endpoint = vuln.get('endpoint', {}) or {}
            url      = endpoint.get('url', '')
            method   = endpoint.get('method', 'GET')

            param    = vuln.get('parameter', {}) or {}
            param_name = param.get('name', '')

            evidence  = str(vuln.get('evidence', ''))
            payload   = str(vuln.get('payload',  ''))
            message   = (
                f'{vtype} found at {method} {url}'
                + (f' — parameter: {param_name}' if param_name else '')
                + (f'\nPayload: {payload[:200]}'  if payload   else '')
                + (f'\nEvidence: {evidence[:300]}' if evidence  else '')
            )

            result_entry: Dict[str, Any] = {
                'ruleId':  rule_id,
                'level':   level,
                'message': {'text': message},
                'locations': [
                    {
                        'physicalLocation': {
                            'artifactLocation': {
                                'uri':       url,
                                'uriBaseId': 'WEBROOT',
                            }
                        },
                        'logicalLocations': [
                            {
                                'name':         param_name or url,
                                'kind':         'parameter' if param_name else 'url',
                                'decoratedName': f'{method} {url}' + (f'?{param_name}' if param_name else ''),
                            }
                        ]
                    }
                ],
                'properties': {
                    'severity':   severity,
                    'confidence': vuln.get('confidence', 0.0),
                    'method':     method,
                    'parameter':  param_name,
                    'cvss':       _compute_cvss(vtype, severity),
                }
            }

            results.append(result_entry)

        return results

    @staticmethod
    def _type_to_rule_id(vuln_type: str) -> str:
        """Convert a vulnerability type string to a compact SARIF rule ID."""
        replacements = {
            ' ': '-', '/': '-', '(': '', ')': '',
            "'": '', '"': '', ',': '', '.': '',
        }
        rid = vuln_type
        for char, replacement in replacements.items():
            rid = rid.replace(char, replacement)
        # Collapse multiple hyphens
        while '--' in rid:
            rid = rid.replace('--', '-')
        return rid.strip('-').upper()
