"""
JSON Report Generator
Generates JSON reports with vulnerability classification by severity
"""

import json
from datetime import datetime
from typing import List, Dict, Any
from pathlib import Path
from collections import defaultdict


_CVSS_MAP: Dict[str, tuple] = {
    'SQL Injection':                   (9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
    'Blind SQL Injection':             (9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
    'OS Command Injection':            (9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
    'Server-Side Template Injection':  (9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
    'XML External Entity (XXE)':       (8.2, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L'),
    'Server-Side Request Forgery':     (8.6, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N'),
    'NoSQL Injection':                 (8.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'),
    'Cross-Site Scripting (XSS)':      (6.1, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'),
    'Path Traversal / LFI':            (7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'),
    'Open Redirect':                   (6.1, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'),
    'Missing Security Headers':        (5.3, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'),
}

_CVSS_SEVERITY_FALLBACK: Dict[str, tuple] = {
    'Critical': (9.0, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
    'High':     (7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'),
    'Medium':   (5.0, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N'),
    'Low':      (3.1, 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N'),
    'Info':     (0.0, ''),
}


def _compute_cvss(vuln_type: str, severity: str) -> Dict[str, Any]:
    """Return CVSS 3.1 base score and vector for a given vulnerability type/severity."""
    score, vector = _CVSS_MAP.get(
        vuln_type,
        _CVSS_SEVERITY_FALLBACK.get(severity, (0.0, ''))
    )
    return {'base_score': score, 'vector': vector, 'version': '3.1'}


def _vuln_attr(vuln: Any, attr: str, default: Any = '') -> Any:
    """
    Safely extract an attribute from either a Vulnerability dataclass or a dict.
    Handles enum values automatically (returns .value if present).
    """
    if isinstance(vuln, dict):
        value = vuln.get(attr, default)
    else:
        value = getattr(vuln, attr, default)
    # Unwrap enums
    if hasattr(value, 'value'):
        return value.value
    return value if value is not None else default


def _normalize_vuln(vuln: Any) -> Dict[str, Any]:
    """
    Normalise a vulnerability (dataclass or dict from security analysers) into
    a consistent flat dict for report generation.

    SecurityHeaderIssue / CookieSecurityIssue dicts have these keys:
        header_name / cookie_name, severity (str), status, current_value,
        recommended_value, description, impact, remediation, references

    Vulnerability dataclass fields:
        type, severity, confidence, endpoint_url, endpoint_method,
        parameter_name, parameter_location, payload, evidence,
        description, remediation, references
    """
    if isinstance(vuln, dict):
        # Derive a human-readable type label
        vuln_type = (
            vuln.get('header_name')
            or vuln.get('cookie_name')
            or vuln.get('type')
            or 'Security Finding'
        )
        severity = str(vuln.get('severity', 'Info'))
        # Capitalise first letter for consistency
        severity = severity.capitalize()

        endpoint_info = vuln.get('endpoint', {})
        if isinstance(endpoint_info, dict):
            endpoint_url = endpoint_info.get('url', '')
            endpoint_method = endpoint_info.get('method', '')
        else:
            endpoint_url = str(endpoint_info)
            endpoint_method = ''

        parameter_info = vuln.get('parameter', {})
        if isinstance(parameter_info, dict):
            parameter_name = parameter_info.get('name', '')
            parameter_location = parameter_info.get('location', '')
        else:
            parameter_name = str(parameter_info)
            parameter_location = ''

        # Build evidence from available fields
        evidence_parts = []
        if vuln.get('status'):
            evidence_parts.append(f"Status: {vuln['status']}")
        if vuln.get('current_value'):
            evidence_parts.append(f"Current: {vuln['current_value']}")
        if vuln.get('recommended_value'):
            evidence_parts.append(f"Recommended: {vuln['recommended_value']}")
        if vuln.get('evidence'):
            evidence_parts.append(str(vuln['evidence']))
        evidence = ' | '.join(evidence_parts) if evidence_parts else vuln.get('description', '')

        remediation = vuln.get('remediation', '')
        if isinstance(remediation, list):
            remediation = '; '.join(remediation)

        references = vuln.get('references', [])
        if isinstance(references, str):
            references = [references]

        return {
            'type': vuln_type,
            'severity': severity,
            'cvss': _compute_cvss(vuln_type, severity),
            'confidence': float(vuln.get('confidence', 0.9)),
            'endpoint_url': endpoint_url,
            'endpoint_method': endpoint_method,
            'parameter_name': parameter_name,
            'parameter_location': str(parameter_location),
            'payload': str(vuln.get('payload', '')),
            'evidence': evidence,
            'description': vuln.get('description', ''),
            'impact': vuln.get('impact', ''),
            'remediation': remediation,
            'references': references,
        }
    else:
        # Vulnerability dataclass
        remediation = getattr(vuln, 'remediation', '')
        if isinstance(remediation, list):
            remediation = '; '.join(remediation)
        references = getattr(vuln, 'references', [])
        if isinstance(references, str):
            references = [references]
        _type = _vuln_attr(vuln, 'type', 'Unknown')
        _sev = _vuln_attr(vuln, 'severity', 'Info')
        return {
            'type': _type,
            'severity': _sev,
            'cvss': _compute_cvss(_type, _sev),
            'confidence': float(getattr(vuln, 'confidence', 0.0)),
            'endpoint_url': getattr(vuln, 'endpoint_url', ''),
            'endpoint_method': getattr(vuln, 'endpoint_method', ''),
            'parameter_name': getattr(vuln, 'parameter_name', ''),
            'parameter_location': str(getattr(vuln, 'parameter_location', '')),
            'payload': str(getattr(vuln, 'payload', '')),
            'evidence': str(getattr(vuln, 'evidence', '')),
            'description': getattr(vuln, 'description', ''),
            'impact': getattr(vuln, 'impact', ''),
            'remediation': remediation,
            'references': references,
        }


class JSONReporter:
    """Generate JSON vulnerability reports with severity classification."""

    def __init__(self, output_dir: str = "reports"):
        """
        Initialize JSON reporter.

        Args:
            output_dir: Directory to save reports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(
        self,
        vulnerabilities: List[Any],
        scan_config: Dict[str, Any] = None,
        scan_stats: Dict[str, Any] = None,
        filename: str = None,
        endpoints: List[Any] = None,
        parameter_stats: Dict[str, Any] = None,
        module_summary: List[Any] = None,
    ) -> str:
        """
        Generate comprehensive JSON vulnerability report.

        Args:
            vulnerabilities: List of Vulnerability objects or dicts
            scan_config: Scan configuration details
            scan_stats: Scan statistics
            filename: Optional custom filename
            endpoints: List of enriched endpoint objects (optional)
            parameter_stats: Parameter identification statistics (optional)

        Returns:
            Path to generated report file
        """
        # Normalise all vulns once upfront
        normalised = [_normalize_vuln(v) for v in vulnerabilities]

        # Generate filename if not provided
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"dast_report_{timestamp}.json"

        filepath = self.output_dir / filename

        # Build report structure
        report = {
            "report_metadata": self._build_metadata(scan_config, scan_stats),
            "discovery_summary": self._build_discovery_summary(endpoints, scan_stats),
            "parameter_summary": self._build_parameter_summary(parameter_stats),
            "module_summary": module_summary or [],
            "executive_summary": self._build_executive_summary(normalised),
            "severity_classification": self._classify_by_severity(normalised),
            "vulnerability_details": self._build_vulnerability_details(normalised),
            "recommendations": self._build_recommendations(normalised),
            "compliance_mapping": self._build_compliance_mapping(normalised)
        }

        # Write to file
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print(f"\n[OK] Report saved to: {filepath}")
        return str(filepath)

    def _build_discovery_summary(self, endpoints: List[Any], scan_stats: Dict[str, Any]) -> Dict[str, Any]:
        """Build discovery summary section with endpoint list."""
        if not endpoints:
            return {
                "total_endpoints": 0,
                "pages_crawled": (scan_stats or {}).get('pages_crawled', 0),
                "endpoints": []
            }

        endpoint_list = []
        for ep in endpoints:
            if hasattr(ep, '__dict__') or hasattr(ep, 'url'):
                url = getattr(ep, 'url', '')
                method_raw = getattr(ep, 'method', 'GET')
                method = getattr(method_raw, 'value', str(method_raw)) if method_raw else 'GET'
                ep_type_raw = getattr(ep, 'endpoint_type', '')
                ep_type = getattr(ep_type_raw, 'value', str(ep_type_raw)) if ep_type_raw else ''
                params = getattr(ep, 'parameters', []) or []
                endpoint_list.append({
                    "url": url,
                    "method": method,
                    "type": ep_type,
                    "parameter_count": len(params),
                })
            elif isinstance(ep, dict):
                endpoint_list.append({
                    "url": ep.get('url', ''),
                    "method": ep.get('method', 'GET'),
                    "type": ep.get('endpoint_type', ''),
                    "parameter_count": len(ep.get('parameters', [])),
                })

        return {
            "total_endpoints": len(endpoint_list),
            "pages_crawled": (scan_stats or {}).get('pages_crawled', 0),
            "endpoints": endpoint_list,
        }

    def _build_parameter_summary(self, parameter_stats: Dict[str, Any]) -> Dict[str, Any]:
        """Build parameter identification summary."""
        if not parameter_stats:
            return {"total_parameters": 0, "injectable_parameters": 0}
        return {
            "total_parameters": parameter_stats.get('total_parameters', 0),
            "injectable_parameters": parameter_stats.get('injectable_parameters', 0),
            "by_location": parameter_stats.get('by_location', {}),
            "by_type": parameter_stats.get('by_type', {}),
        }

    def _build_metadata(self, config: Dict[str, Any], stats: Dict[str, Any]) -> Dict[str, Any]:
        """Build report metadata section."""
        metadata = {
            "report_generated": datetime.now().isoformat(),
            "scanner": "DAST Security Scanner",
            "version": "1.0.0",
            "report_format": "JSON",
        }

        if config:
            metadata["scan_target"] = config.get('target', {}).get('url', 'N/A')

        if stats:
            metadata["scan_statistics"] = {
                "total_attacks": stats.get('total_attacks', 0),
                "completed_attacks": stats.get('completed', 0),
                "failed_attacks": stats.get('failed', 0),
                "vulnerabilities_found": stats.get('vulnerabilities_found', 0),
                "scan_duration_seconds": self._calculate_duration(stats),
                "attack_rate_per_second": self._calculate_rate(stats)
            }

        return metadata

    def _build_executive_summary(self, normalised: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build executive summary with counts and risk assessment."""
        severity_counts: Dict[str, int] = defaultdict(int)
        for v in normalised:
            severity_counts[v['severity']] += 1

        risk_weights = {
            'Critical': 10,
            'High': 7,
            'Medium': 4,
            'Low': 2,
            'Info': 1
        }

        risk_score = sum(
            count * risk_weights.get(severity, 0)
            for severity, count in severity_counts.items()
        )

        if risk_score >= 50:
            risk_level = "Critical"
        elif risk_score >= 30:
            risk_level = "High"
        elif risk_score >= 15:
            risk_level = "Medium"
        elif risk_score > 0:
            risk_level = "Low"
        else:
            risk_level = "None"

        return {
            "total_vulnerabilities": len(normalised),
            "by_severity": {
                "critical": severity_counts.get('Critical', 0),
                "high": severity_counts.get('High', 0),
                "medium": severity_counts.get('Medium', 0),
                "low": severity_counts.get('Low', 0),
                "info": severity_counts.get('Info', 0)
            },
            "risk_assessment": {
                "overall_risk_level": risk_level,
                "risk_score": risk_score,
                "max_risk_score": 100
            },
            "top_vulnerability_types": self._get_top_vulnerability_types(normalised, limit=5)
        }

    def _classify_by_severity(self, normalised: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Classify vulnerabilities by severity level."""
        classification: Dict[str, list] = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": []
        }

        for v in normalised:
            severity_key = v['severity'].lower()
            if severity_key not in classification:
                severity_key = 'info'

            evidence = v['evidence']
            vuln_summary = {
                "id": self._generate_vuln_id(v),
                "type": v['type'],
                "endpoint": f"{v['endpoint_method']} {v['endpoint_url']}".strip(),
                "parameter": f"{v['parameter_name']} ({v['parameter_location']})".strip(' ()'),
                "confidence": round(v['confidence'], 2),
                "evidence_preview": evidence[:100] + "..." if len(evidence) > 100 else evidence
            }

            classification[severity_key].append(vuln_summary)

        return classification

    def _build_vulnerability_details(self, normalised: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build detailed vulnerability information."""
        details = []

        for i, v in enumerate(normalised, 1):
            detail = {
                "id": self._generate_vuln_id(v),
                "finding_number": i,
                "vulnerability_type": v['type'],
                "severity": v['severity'],
                "confidence": round(v['confidence'], 2),
                "location": {
                    "endpoint_url": v['endpoint_url'],
                    "http_method": v['endpoint_method'],
                    "parameter_name": v['parameter_name'],
                    "parameter_location": v['parameter_location']
                },
                "attack_details": {
                    "payload_used": v['payload'],
                    "evidence": v['evidence']
                },
                "description": v['description'],
                "impact": v['impact'] or self._assess_impact_by_type(v['type']),
                "remediation": v['remediation'],
                "references": v['references'],
                "cvss": v.get('cvss', _compute_cvss(v['type'], v['severity']))
            }
            details.append(detail)

        return details

    def _build_recommendations(self, normalised: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build prioritized remediation recommendations."""
        recommendations: Dict[str, list] = {
            "immediate_action_required": [],
            "high_priority": [],
            "medium_priority": [],
            "low_priority": []
        }

        for v in normalised:
            recommendation = {
                "vulnerability_type": v['type'],
                "affected_endpoints": [v['endpoint_url']] if v['endpoint_url'] else [],
                "remediation_steps": v['remediation']
            }

            sev = v['severity']
            if sev == 'Critical':
                recommendations["immediate_action_required"].append(recommendation)
            elif sev == 'High':
                recommendations["high_priority"].append(recommendation)
            elif sev == 'Medium':
                recommendations["medium_priority"].append(recommendation)
            else:
                recommendations["low_priority"].append(recommendation)

        for priority in recommendations:
            recommendations[priority] = self._deduplicate_recommendations(
                recommendations[priority]
            )

        return recommendations

    def _build_compliance_mapping(self, normalised: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Map vulnerabilities to compliance frameworks."""
        owasp_mapping: Dict[str, list] = defaultdict(list)
        cwe_mapping: Dict[str, list] = defaultdict(list)

        for v in normalised:
            for ref in v['references']:
                if 'OWASP' in str(ref):
                    owasp_mapping[ref].append(v['type'])
                elif 'CWE-' in str(ref):
                    cwe_mapping[ref].append(v['type'])

        return {
            "owasp_top_10_2021": {
                category: list(set(vulns))
                for category, vulns in owasp_mapping.items()
            },
            "cwe_coverage": {
                cwe: list(set(vulns))
                for cwe, vulns in cwe_mapping.items()
            }
        }

    def _get_top_vulnerability_types(self, normalised: List[Dict[str, Any]], limit: int = 5) -> List[Dict[str, Any]]:
        """Get most common vulnerability types."""
        type_counts: Dict[str, int] = defaultdict(int)
        for v in normalised:
            type_counts[v['type']] += 1

        sorted_types = sorted(
            type_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:limit]

        return [
            {"type": vuln_type, "count": count}
            for vuln_type, count in sorted_types
        ]

    def _assess_impact_by_type(self, vuln_type: str) -> str:
        """Assess vulnerability impact based on type label."""
        impact_map = {
            'SQL Injection': 'Complete database compromise, data theft, data manipulation',
            'Cross-Site Scripting (XSS)': 'Session hijacking, credential theft, malicious redirects',
            'OS Command Injection': 'Remote code execution, complete server compromise',
            'Path Traversal / LFI': 'Unauthorized file access, sensitive data disclosure',
            'XXE Injection': 'File disclosure, SSRF, denial of service',
            'Server-Side Request Forgery': 'Internal network access, cloud metadata theft',
            'Server-Side Template Injection': 'Remote code execution, server compromise',
            'NoSQL Injection': 'Database bypass, data theft, unauthorized access',
            'Open Redirect': 'Phishing attacks, credential theft',
            'Missing Security Headers': 'Increased attack surface, clickjacking, MIME sniffing'
        }
        return impact_map.get(vuln_type, 'Security risk requiring remediation')

    def _generate_vuln_id(self, v: Dict[str, Any]) -> str:
        """Generate unique vulnerability ID from normalised dict."""
        type_abbr = ''.join([c for c in str(v['type']) if c.isupper() or c.isdigit()]) or 'VLN'
        endpoint_hash = abs(hash(f"{v['endpoint_url']}{v['parameter_name']}")) % 10000
        return f"{type_abbr}-{endpoint_hash:04d}"

    def _calculate_duration(self, stats: Dict[str, Any]) -> float:
        """Calculate scan duration in seconds."""
        if 'start_time' in stats and 'end_time' in stats:
            start = stats['start_time']
            end = stats['end_time']
            if hasattr(start, 'timestamp') and hasattr(end, 'timestamp'):
                return round(end.timestamp() - start.timestamp(), 2)
        return 0.0

    def _calculate_rate(self, stats: Dict[str, Any]) -> float:
        """Calculate attack rate per second."""
        duration = self._calculate_duration(stats)
        if duration > 0:
            return round(stats.get('completed', 0) / duration, 2)
        return 0.0

    def _deduplicate_recommendations(self, recommendations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Deduplicate recommendations by vulnerability type."""
        unique_recs: Dict[str, Dict] = {}

        for rec in recommendations:
            vuln_type = rec['vulnerability_type']
            if vuln_type not in unique_recs:
                unique_recs[vuln_type] = rec
            else:
                unique_recs[vuln_type]['affected_endpoints'].extend(
                    rec['affected_endpoints']
                )

        for rec in unique_recs.values():
            rec['affected_endpoints'] = list(set(rec['affected_endpoints']))

        return list(unique_recs.values())

