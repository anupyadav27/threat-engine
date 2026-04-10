"""
CIS Benchmark HTML Parser

Parses CIS benchmark HTML files (from pdftohtml) into structured JSON controls.
Handles AWS, Azure, GCP, OCI, IBM, AliCloud benchmarks.

Usage:
    python scripts/parse_cis_html.py [--output data/cis_parsed/]
"""

import os
import re
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# CLI/Console split markers per CSP
CLI_MARKERS = {
    'aws': [r'From Command Line', r'AWS CLI', r'aws\s+\w+'],
    'azure': [r'From Azure CLI', r'Azure CLI', r'Using Azure CLI', r'az\s+\w+'],
    'gcp': [r'From Command Line', r'gcloud\s+\w+', r'Using gcloud'],
    'oci': [r'From Command Line', r'OCI CLI', r'oci\s+\w+'],
    'ibm': [r'From Command Line', r'IBM Cloud CLI', r'ibmcloud\s+\w+'],
    'alicloud': [r'From Command Line', r'aliyun\s+\w+'],
}

CONSOLE_MARKERS = {
    'aws': [r'From Console', r'AWS Console', r'AWS Management Console'],
    'azure': [r'From Azure Portal', r'Azure Portal', r'Using Azure Portal'],
    'gcp': [r'From Console', r'Google Cloud Console', r'Cloud Console'],
    'oci': [r'From Console', r'OCI Console'],
    'ibm': [r'From Console', r'IBM Cloud Console'],
    'alicloud': [r'From Console', r'Alibaba Cloud Console'],
}

CONTROL_START = re.compile(
    r'(\d+\.\d+(?:\.\d+)?)\s+'
    r'((?:Ensure|Verify|Check|Set|Configure|Enable|Disable|Restrict|'
    r'Do not|Avoid|Use|Implement|Maintain|Review|Remove|Rotate|Require|'
    r'Minimize|Maximize|Monitor|Create|Prohibit|Manage|Protect|Encrypt|'
    r'Limit|Prevent|Deny|Allow|Audit|Log|Track|Alert|Define|Enforce|'
    r'Establish|Apply|Assign|Grant|Revoke|Delete|Terminate|Suspend|'
    r'Block|Filter|Scan|Test|Validate|Approve|Authorize|Document|'
    r'Inventory|Classify|Label|Tag|Backup|Archive|Retain|Purge|'
    r'Segregat|Separat|Isolat|Harden)\b.+?)'
    r'(?:\s*\((?:Automated|Manual|Level \d|Scored|Not Scored)\))',
    re.IGNORECASE
)

SECTION_MARKERS = [
    'Profile Applicability', 'Description', 'Rationale',
    'Audit', 'Remediation', 'Default Value', 'Impact',
    'References', 'CIS Controls', 'Additional Information',
]


def detect_csp(filename: str) -> str:
    """Detect CSP from filename."""
    fn = filename.lower()
    if 'aws' in fn or 'amazon' in fn: return 'aws'
    if 'azure' in fn or 'microsoft' in fn: return 'azure'
    if 'gcp' in fn or 'google' in fn: return 'gcp'
    if 'oci' in fn or 'oracle' in fn: return 'oci'
    if 'ibm' in fn: return 'ibm'
    if 'alibaba' in fn or 'alicloud' in fn: return 'alicloud'
    return 'unknown'


def strip_html(html: str) -> str:
    """Strip HTML tags, normalize whitespace."""
    text = re.sub(r'<style[^>]*>.*?</style>', ' ', html, flags=re.DOTALL)
    text = re.sub(r'<[^>]+>', ' ', text)
    text = re.sub(r'&nbsp;', ' ', text)
    text = re.sub(r'&amp;', '&', text)
    text = re.sub(r'&lt;', '<', text)
    text = re.sub(r'&gt;', '>', text)
    text = re.sub(r'&#\d+;', ' ', text)
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


def extract_section(block: str, marker: str, next_markers: List[str]) -> str:
    """Extract text between marker and the next marker."""
    idx = block.find(marker)
    if idx < 0:
        return ''
    start = idx + len(marker)
    end = len(block)
    for nm in next_markers:
        ni = block.find(nm, start + 5)  # +5 to avoid matching within the marker itself
        if 0 < ni < end:
            end = ni
    result = block[start:end].strip()
    # Clean up leading colons, dots, whitespace
    result = re.sub(r'^[\s:.\-]+', '', result)
    return result


def split_console_cli(text: str, csp: str) -> Tuple[str, str]:
    """Split text into console and CLI sections based on CSP markers."""
    if not text:
        return '', ''

    console_pats = CONSOLE_MARKERS.get(csp, CONSOLE_MARKERS['aws'])
    cli_pats = CLI_MARKERS.get(csp, CLI_MARKERS['aws'])

    # Find first console marker
    console_pos = len(text)
    for pat in console_pats:
        m = re.search(pat, text, re.IGNORECASE)
        if m and m.start() < console_pos:
            console_pos = m.start()

    # Find first CLI marker
    cli_pos = len(text)
    for pat in cli_pats:
        m = re.search(pat, text, re.IGNORECASE)
        if m and m.start() < cli_pos:
            cli_pos = m.start()

    if console_pos == len(text) and cli_pos == len(text):
        # No markers found — return all as console
        return text, ''

    if console_pos < cli_pos:
        console = text[console_pos:cli_pos].strip()
        cli = text[cli_pos:].strip()
    else:
        cli = text[cli_pos:console_pos].strip()
        console = text[console_pos:].strip()

    return console, cli


def parse_cis_html(filepath: Path) -> List[Dict]:
    """Parse a CIS benchmark HTML file into structured controls."""
    content = filepath.read_text(errors='ignore')
    csp = detect_csp(filepath.name)
    text = strip_html(content)

    # Split into control blocks
    blocks = CONTROL_START.split(text)

    controls = []
    seen_ids = set()

    i = 1  # blocks[0] is preamble
    while i < len(blocks) - 1:
        ctrl_id = blocks[i].strip()
        title_plus = blocks[i + 1] if i + 1 < len(blocks) else ''
        i += 2

        # Get the full block until next control
        block = title_plus
        while i < len(blocks):
            next_text = blocks[i] if i < len(blocks) else ''
            # Check if this is a new control ID
            if re.match(r'^\d+\.\d+', next_text.strip()):
                break
            block += ' ' + next_text
            i += 1

        # Skip duplicates (TOC references)
        key = f"{ctrl_id}_{len(block)}"
        if ctrl_id in seen_ids and len(block) < 200:
            continue

        # Extract title (first sentence before assessment type)
        title_match = re.match(r'(.+?)(?:\s*\((?:Automated|Manual|Level|Scored|Not))', title_plus)
        title = title_match.group(1).strip() if title_match else title_plus[:200].strip()

        assessment = 'Automated' if re.search(r'\(Automated\)', block[:200]) else 'Manual'
        profile = 'Level 1' if 'Level 1' in block[:500] else ('Level 2' if 'Level 2' in block[:500] else '')

        # Extract sections
        ordered_markers = SECTION_MARKERS
        desc = extract_section(block, 'Description', ['Rationale', 'Audit', 'Impact'])
        rationale = extract_section(block, 'Rationale', ['Audit', 'Impact', 'Remediation'])
        audit_raw = extract_section(block, 'Audit', ['Remediation', 'Default Value', 'References', 'CIS Controls'])
        rem_raw = extract_section(block, 'Remediation', ['Default Value', 'Impact', 'References', 'CIS Controls'])
        default_val = extract_section(block, 'Default Value', ['References', 'CIS Controls', 'Additional Information'])
        impact = extract_section(block, 'Impact', ['Remediation', 'References', 'CIS Controls', 'Default Value', 'Audit'])
        refs_text = extract_section(block, 'References', ['CIS Controls', 'Additional Information'])

        # Split audit and remediation into console/cli
        audit_console, audit_cli = split_console_cli(audit_raw, csp)
        rem_console, rem_cli = split_console_cli(rem_raw, csp)

        # Extract reference URLs
        refs = re.findall(r'https?://\S+', refs_text)

        # Only keep controls with meaningful content
        if len(desc) < 10 and len(audit_raw) < 10 and len(rem_raw) < 10:
            continue

        seen_ids.add(ctrl_id)

        # Section ID = first number
        section_id = ctrl_id.split('.')[0]

        controls.append({
            'control_id': ctrl_id,
            'title': title,
            'assessment_type': assessment,
            'profile_level': profile,
            'section_id': section_id,
            'csp': csp,
            'description': desc[:2000] if desc else None,
            'rationale': rationale[:2000] if rationale else None,
            'audit_raw': audit_raw[:3000] if audit_raw else None,
            'audit_console': audit_console[:3000] if audit_console else None,
            'audit_cli': audit_cli[:3000] if audit_cli else None,
            'remediation_raw': rem_raw[:3000] if rem_raw else None,
            'remediation_console': rem_console[:3000] if rem_console else None,
            'remediation_cli': rem_cli[:3000] if rem_cli else None,
            'default_value': default_val[:1000] if default_val else None,
            'impact': impact[:1000] if impact else None,
            'references': refs if refs else None,
            'source_file': filepath.name,
        })

    return controls


def main():
    base = Path('/Users/apple/Desktop/compliance_doc/cis')
    output_dir = Path('/Users/apple/Desktop/threat-engine/data/cis_parsed')
    output_dir.mkdir(parents=True, exist_ok=True)

    html_files = sorted(base.rglob('*.html'))
    print(f'Found {len(html_files)} HTML files')

    all_controls = []
    stats = {}

    for html_file in html_files:
        try:
            controls = parse_cis_html(html_file)
            csp = detect_csp(html_file.name)
            if controls:
                all_controls.extend(controls)
                stats[html_file.name] = {
                    'controls': len(controls),
                    'csp': csp,
                    'with_desc': sum(1 for c in controls if c.get('description')),
                    'with_audit': sum(1 for c in controls if c.get('audit_raw')),
                    'with_remediation': sum(1 for c in controls if c.get('remediation_raw')),
                    'with_audit_cli': sum(1 for c in controls if c.get('audit_cli')),
                    'with_rem_cli': sum(1 for c in controls if c.get('remediation_cli')),
                }
                print(f'  {html_file.name}: {len(controls)} controls ({csp})')
        except Exception as e:
            print(f'  ERROR {html_file.name}: {e}')

    # Save all controls
    with open(output_dir / 'all_cis_controls.json', 'w') as f:
        json.dump(all_controls, f, indent=2, default=str)

    # Save stats
    with open(output_dir / 'parsing_stats.json', 'w') as f:
        json.dump(stats, f, indent=2)

    # Summary
    print(f'\n=== SUMMARY ===')
    print(f'Total controls parsed: {len(all_controls)}')
    print(f'Files processed: {len(stats)}')
    by_csp = {}
    for c in all_controls:
        csp = c.get('csp', 'unknown')
        by_csp[csp] = by_csp.get(csp, 0) + 1
    for csp, count in sorted(by_csp.items(), key=lambda x: -x[1]):
        print(f'  {csp}: {count} controls')

    print(f'\nField coverage:')
    for field in ['description', 'rationale', 'audit_raw', 'audit_console', 'audit_cli',
                  'remediation_raw', 'remediation_console', 'remediation_cli', 'default_value', 'impact', 'references']:
        count = sum(1 for c in all_controls if c.get(field))
        print(f'  {field}: {count}/{len(all_controls)} ({100*count//max(len(all_controls),1)}%)')


if __name__ == '__main__':
    main()
