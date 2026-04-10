"""
Report Generator
Unified interface for generating reports in multiple formats
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .json_reporter import JSONReporter
from .sarif_reporter import SARIFReporter

logger = logging.getLogger('DASTScanner.Report')

# Use unique tokens instead of {placeholders} so str.replace() is safe
# even when finding descriptions/evidence contain { } characters.
_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DAST Scan Report</title>
<style>
  body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; color: #333; }
  h1 { color: #c0392b; margin-bottom: 4px; }
  h2 { color: #2c3e50; border-bottom: 2px solid #bdc3c7; padding-bottom: 6px; margin-top: 32px; }
  .meta { color: #7f8c8d; font-size: 0.9em; margin-bottom: 24px; }
  table { border-collapse: collapse; width: 100%; background: #fff; margin-bottom: 20px; }
  th { background: #2c3e50; color: #fff; padding: 8px 12px; text-align: left; }
  td { border: 1px solid #bdc3c7; padding: 8px 12px; vertical-align: top; word-break: break-word; }
  tr:nth-child(even) { background: #ecf0f1; }
  .summary-box { background: #fff; border: 1px solid #bdc3c7; border-radius: 6px; padding: 16px 24px;
                 margin-bottom: 20px; display: inline-block; min-width: 100px; margin-right: 10px;
                 text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
  .summary-box .count { font-size: 2.2em; font-weight: bold; margin-top: 6px; }
  .sev-label { font-weight: bold; font-size: 0.9em; letter-spacing: 0.5px; }
  pre { background: #2c3e50; color: #ecf0f1; padding: 8px; border-radius: 4px; overflow-x: auto;
        font-size: 0.82em; white-space: pre-wrap; margin: 0; max-height: 120px; overflow-y: auto; }
</style>
</head>
<body>
<h1>DAST Scan Report</h1>
<p class="meta">Target: <strong>@@TARGET_URL@@</strong> &nbsp;|&nbsp;
  Pages crawled: @@PAGES_CRAWLED@@ &nbsp;|&nbsp; Generated: @@GENERATED_AT@@</p>

<h2>Severity Summary</h2>
@@SUMMARY_BOXES@@

<h2>Module Summary</h2>
@@MODULE_TABLE@@

<h2>Vulnerability Details (@@TOTAL@@ findings)</h2>
@@VULN_TABLE@@

</body>
</html>
"""


class ReportGenerator:
    """Unified report generation interface."""

    def __init__(self, output_dir: str = "reports"):
        """
        Initialize report generator.

        Args:
            output_dir: Directory to save reports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.json_reporter  = JSONReporter(output_dir)
        self.sarif_reporter = SARIFReporter(output_dir)

    def generate_all_reports(
        self,
        vulnerabilities: List[Any],
        scan_config: Optional[Dict[str, Any]] = None,
        scan_stats: Optional[Dict[str, Any]] = None,
        formats: List[str] = None,
        endpoints: Optional[List[Any]] = None,
        parameter_stats: Optional[Dict[str, Any]] = None,
        module_summary: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, str]:
        """
        Generate reports in the requested formats.

        Supported formats: 'json', 'summary', 'html', 'sarif'
        Unsupported formats are logged as warnings (not hard-errors).

        Args:
            vulnerabilities: List of Vulnerability objects
            scan_config: Scan configuration dict
            scan_stats: Scan statistics dict
            formats: List of formats to generate (default: ['json'])
            endpoints: Enriched endpoint list for discovery summary
            parameter_stats: Parameter identification statistics

        Returns:
            Dictionary mapping format name to file path
        """
        if formats is None:
            formats = ['json', 'html']

        generated_reports: Dict[str, str] = {}

        for fmt in formats:
          try:
            if fmt in ('json', 'summary'):
                # 'summary' is an alias for 'json' — everything is in dast_report_*.json
                if 'json' not in generated_reports:
                    path = self.json_reporter.generate_report(
                        vulnerabilities=vulnerabilities,
                        scan_config=scan_config,
                        scan_stats=scan_stats,
                        endpoints=endpoints,
                        parameter_stats=parameter_stats,
                        module_summary=module_summary,
                    )
                    generated_reports['json'] = path
                if fmt == 'summary':
                    generated_reports['summary'] = generated_reports['json']

            elif fmt == 'html':
                path = self._generate_html_report(
                    vulnerabilities, scan_stats,
                    module_summary=module_summary,
                    scan_config=scan_config,
                )
                generated_reports['html'] = path

            elif fmt == 'sarif':
                path = self.sarif_reporter.generate_report(
                    vulnerabilities=vulnerabilities,
                    scan_config=scan_config,
                    scan_stats=scan_stats,
                )
                generated_reports['sarif'] = path

            else:
                logger.warning(
                    "Report format '%s' is not supported. Supported formats: json, html, sarif.",
                    fmt,
                )
          except Exception as exc:
            logger.error("Failed to generate '%s' report: %s", fmt, exc, exc_info=True)

        return generated_reports

    def print_console_summary(self, vulnerabilities: List[Any]):
        """Print vulnerability summary to console."""
        from collections import defaultdict

        print("\n" + "=" * 70)
        print("VULNERABILITY CLASSIFICATION SUMMARY")
        print("=" * 70)

        by_severity = defaultdict(list)
        for vuln in vulnerabilities:
            by_severity[vuln.severity.value].append(vuln)

        print(f"\nTotal Vulnerabilities: {len(vulnerabilities)}")
        print("\nBy Severity:")
        for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            count = len(by_severity[severity])
            if count > 0:
                print(f"  {severity:10s}: {count:3d}")

        for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            vulns = by_severity[severity]
            if vulns:
                print(f"\n{severity} Severity Vulnerabilities:")
                print("-" * 70)
                for vuln in vulns:
                    print(f"  - {vuln.type.value}")
                    print(f"    Endpoint: {vuln.endpoint_method} {vuln.endpoint_url}")
                    print(f"    Parameter: {vuln.parameter_name} ({vuln.parameter_location})")
                    print(f"    Confidence: {vuln.confidence:.2f}")

        print("=" * 70)

    # ------------------------------------------------------------------
    # HTML report
    # ------------------------------------------------------------------

    def _generate_html_report(
        self,
        vulnerabilities: List[Any],
        scan_stats: Optional[Dict[str, Any]] = None,
        module_summary: Optional[List[Dict[str, Any]]] = None,
        scan_config: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Generate an HTML report and return the file path."""
        from .json_reporter import _normalize_vuln
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"dast_report_{timestamp}.html"

        severity_order = ['Critical', 'High', 'Medium', 'Low', 'Info']
        sev_colours = {
            'Critical': '#c0392b', 'High': '#e67e22',
            'Medium': '#f39c12', 'Low': '#27ae60', 'Info': '#3498db',
        }

        # Normalise all vulns to dicts once
        normalised = [_normalize_vuln(v) for v in vulnerabilities]

        counts: Dict[str, int] = {s: 0 for s in severity_order}
        for v in normalised:
            sev = v.get('severity', 'Info')
            counts[sev] = counts.get(sev, 0) + 1

        # ── Summary boxes ──────────────────────────────────────────────────
        summary_boxes = ""
        for sev in severity_order:
            c = counts.get(sev, 0)
            colour = sev_colours.get(sev, '#95a5a6')
            summary_boxes += (
                f'<div class="summary-box" style="border-top:4px solid {colour}">'
                f'<div class="sev-label" style="color:{colour}">{sev}</div>'
                f'<div class="count">{c}</div>'
                f'</div>'
            )

        # ── Module summary table ───────────────────────────────────────────
        if module_summary:
            mod_rows = ""
            for m in module_summary:
                fc = m.get('finding_count', 0)
                hs = m.get('highest_severity', 'None')
                colour = sev_colours.get(hs, '#95a5a6') if fc else '#7f8c8d'
                badge = (f'<span style="background:{colour};color:#fff;padding:2px 8px;'
                         f'border-radius:4px;font-size:0.85em">{hs} ({fc})</span>'
                         if fc else '<span style="color:#aaa">None detected</span>')
                mod_rows += (
                    f"<tr>"
                    f"<td>{m.get('module','')}</td>"
                    f"<td>{m.get('input_used','')}</td>"
                    f"<td>{badge}</td>"
                    f"<td>{m.get('features','')}</td>"
                    f"</tr>\n"
                )
            module_table = (
                "<table>"
                "<thead><tr>"
                "<th>Module</th><th>Input Tested</th>"
                "<th>Findings</th><th>Features</th>"
                "</tr></thead>"
                f"<tbody>{mod_rows}</tbody>"
                "</table>"
            )
        else:
            module_table = "<p>No module summary available.</p>"

        # ── Vulnerability table ────────────────────────────────────────────
        sorted_vulns = sorted(
            normalised,
            key=lambda v: severity_order.index(v['severity'])
            if v['severity'] in severity_order else 99
        )
        rows = ""
        for v in sorted_vulns:
            sev = v['severity']
            colour = sev_colours.get(sev, '#95a5a6')
            badge = (f'<span style="background:{colour};color:#fff;padding:2px 6px;'
                     f'border-radius:4px">{sev}</span>')
            evidence = str(v.get('evidence', '')).replace('<', '&lt;').replace('>', '&gt;')
            payload = str(v.get('payload', '')).replace('<', '&lt;').replace('>', '&gt;')
            ep_url = v.get('endpoint_url', '')
            ep_method = v.get('endpoint_method', '')
            param = v.get('parameter_name', '')
            rows += (
                f"<tr>"
                f"<td>{badge}</td>"
                f"<td>{v.get('type','')}</td>"
                f"<td>{ep_method} {ep_url}</td>"
                f"<td>{param}</td>"
                f"<td><pre>{payload[:200]}</pre></td>"
                f"<td><pre>{evidence[:400]}</pre></td>"
                f"</tr>\n"
            )

        vuln_table = (
            "<table>"
            "<thead><tr>"
            "<th>Severity</th><th>Type</th><th>Endpoint</th>"
            "<th>Parameter</th><th>Payload</th><th>Evidence</th>"
            "</tr></thead>"
            f"<tbody>{rows or '<tr><td colspan=6>No vulnerabilities found.</td></tr>'}</tbody>"
            "</table>"
        )

        # ── Target info ───────────────────────────────────────────────────
        target_url = (scan_config or {}).get('target', {}).get('url', 'N/A')
        pages = (scan_stats or {}).get('pages_crawled', 0)
        endpoints = (scan_stats or {}).get('total_attacks', 0)

        html = (
            _HTML_TEMPLATE
            .replace('@@GENERATED_AT@@', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            .replace('@@TARGET_URL@@', str(target_url))
            .replace('@@PAGES_CRAWLED@@', str(pages))
            .replace('@@SUMMARY_BOXES@@', summary_boxes)
            .replace('@@MODULE_TABLE@@', module_table)
            .replace('@@TOTAL@@', str(len(normalised)))
            .replace('@@VULN_TABLE@@', vuln_table)
        )

        output_file.write_text(html, encoding='utf-8')
        logger.info("HTML report saved to %s", output_file)
        print(f"\n[OK] HTML report saved to: {output_file}")
        return str(output_file)
