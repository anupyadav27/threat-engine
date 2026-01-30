import uuid
import random
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand
from django.utils import timezone

from threats_management.models import Threat, ThreatRemediationStep, ThreatRelatedFinding
from tenant_management.models import Tenants


class Command(BaseCommand):
    help = 'Populates the database with realistic threat data with proper references'

    def add_arguments(self, parser):
        parser.add_argument(
            '--count',
            type=int,
            default=50,
            help='Number of threats to create (default: 50)'
        )
        parser.add_argument(
            '--clear',
            action='store_true',
            help='Delete existing threats before populating'
        )

    def handle(self, *args, **options):
        count = options['count']
        clear = options['clear']

        tenants = list(Tenants.objects.all())
        if not tenants:
            self.stdout.write(
                self.style.ERROR('No tenants found! Create tenants first.')
            )
            return

        if clear:
            ThreatRelatedFinding.objects.all().delete()
            ThreatRemediationStep.objects.all().delete()
            Threat.objects.all().delete()
            self.stdout.write(self.style.SUCCESS('Cleared existing threat data'))

        threat_names = [
            "Phishing Campaign Targeting Finance Team",
            "Ransomware Attack via Compromised RDP",
            "Data Exfiltration Through Misconfigured S3 Bucket",
            "Credential Stuffing Attack on Admin Portal",
            "Supply Chain Compromise via NPM Package",
            "Zero-Day Exploit in Web Application Framework",
            "Insider Threat - Unauthorized Data Access",
            "DDoS Attack on Customer-Facing API",
            "Malware Distribution Through Fake Software Updates",
            "Social Engineering Attack on HR Department",
            "Cloud Account Takeover via Stolen API Keys",
            "SQL Injection Vulnerability in Legacy System",
            "Cross-Site Scripting (XSS) in Customer Portal",
            "Man-in-the-Middle Attack on Internal Network",
            "Brute Force Attack on SSH Services"
        ]

        severities = ['critical', 'high', 'medium', 'low']
        statuses = ['active', 'mitigated', 'false_positive', 'under_investigation', 'resolved']

        remediation_templates = {
            'phishing': [
                "Isolate affected user accounts",
                "Reset compromised credentials",
                "Block malicious email domains",
                "Conduct security awareness training",
                "Implement email filtering rules"
            ],
            'ransomware': [
                "Isolate infected systems from network",
                "Restore data from clean backups",
                "Patch vulnerable RDP configurations",
                "Implement multi-factor authentication",
                "Deploy endpoint detection and response (EDR)"
            ],
            'data_exfiltration': [
                "Fix S3 bucket permissions immediately",
                "Audit all cloud storage configurations",
                "Implement data loss prevention (DLP)",
                "Rotate all compromised credentials",
                "Monitor for unusual data access patterns"
            ],
            'credential_stuffing': [
                "Enforce strong password policies",
                "Implement account lockout mechanisms",
                "Deploy CAPTCHA on login pages",
                "Enable multi-factor authentication",
                "Monitor for credential reuse attempts"
            ],
            'supply_chain': [
                "Audit third-party dependencies",
                "Implement software bill of materials (SBOM)",
                "Verify package integrity with checksums",
                "Use private package repositories",
                "Implement dependency vulnerability scanning"
            ],
            'zero_day': [
                "Apply vendor security patches immediately",
                "Implement network segmentation",
                "Deploy web application firewall (WAF)",
                "Monitor for exploitation attempts",
                "Conduct code review and security testing"
            ],
            'insider_threat': [
                "Revoke unauthorized access privileges",
                "Implement principle of least privilege",
                "Enable detailed audit logging",
                "Conduct employee background checks",
                "Deploy user behavior analytics (UBA)"
            ],
            'ddos': [
                "Engage DDoS mitigation service",
                "Implement rate limiting on APIs",
                "Configure CDN with DDoS protection",
                "Scale infrastructure to absorb traffic",
                "Block malicious IP addresses"
            ]
        }

        threats_created = 0
        remediation_steps_created = 0
        findings_created = 0

        for i in range(count):
            tenant = random.choice(tenants)

            threat_name = random.choice(threat_names)
            severity = random.choices(severities, weights=[3, 4, 2, 1], k=1)[0]
            status = random.choice(statuses)

            descriptions = {
                "Phishing Campaign": "Sophisticated phishing emails targeting finance team members with fake invoice attachments leading to credential harvesting.",
                "Ransomware Attack": "Ransomware deployed through brute-forced RDP credentials, encrypting critical business data and demanding cryptocurrency payment.",
                "Data Exfiltration": "Sensitive customer data exposed due to publicly accessible S3 bucket with write permissions enabled.",
                "Credential Stuffing": "Automated attacks using credential pairs from previous breaches to gain unauthorized access to admin portal.",
                "Supply Chain Compromise": "Malicious code injected into legitimate NPM package used by internal applications, creating backdoor access.",
                "Zero-Day Exploit": "Previously unknown vulnerability in web framework exploited to execute arbitrary code on production servers.",
                "Insider Threat": "Employee accessing and downloading sensitive customer data beyond their job requirements without authorization.",
                "DDoS Attack": "Coordinated distributed denial-of-service attack overwhelming customer-facing APIs with millions of requests per second.",
                "Malware Distribution": "Fake software update notifications distributing trojan malware to employee workstations.",
                "Social Engineering": "Attackers impersonating IT support to trick HR employees into revealing system credentials.",
                "Cloud Account Takeover": "Stolen API keys from GitHub repository used to gain full access to cloud infrastructure and deploy cryptominers.",
                "SQL Injection": "Unsanitized user input in legacy search functionality allowing attackers to extract database contents.",
                "Cross-Site Scripting": "Stored XSS vulnerability in customer comment section allowing session hijacking of authenticated users.",
                "Man-in-the-Middle": "ARP spoofing attack on internal network intercepting sensitive communications between departments.",
                "Brute Force Attack": "Automated SSH brute force attempts targeting weak passwords on internet-facing servers."
            }

            description = "No description available"
            for key, desc in descriptions.items():
                if key in threat_name:
                    description = desc
                    break

            threat = Threat.objects.create(
                id=str(uuid.uuid4()),
                tenant=tenant,
                name=threat_name,
                severity=severity,
                status=status,
                description=description,
                created_at=timezone.now() - timedelta(days=random.randint(1, 90)),
                updated_at=timezone.now() - timedelta(hours=random.randint(1, 48))
            )
            threats_created += 1

            threat_type = 'phishing'
            if 'Ransomware' in threat_name:
                threat_type = 'ransomware'
            elif 'S3 Bucket' in threat_name or 'Data Exfiltration' in threat_name:
                threat_type = 'data_exfiltration'
            elif 'Credential Stuffing' in threat_name:
                threat_type = 'credential_stuffing'
            elif 'Supply Chain' in threat_name:
                threat_type = 'supply_chain'
            elif 'Zero-Day' in threat_name:
                threat_type = 'zero_day'
            elif 'Insider Threat' in threat_name:
                threat_type = 'insider_threat'
            elif 'DDoS' in threat_name:
                threat_type = 'ddos'
            else:
                threat_type = random.choice(list(remediation_templates.keys()))

            steps = remediation_templates[threat_type]
            num_steps = random.randint(2, min(5, len(steps)))
            selected_steps = random.sample(steps, num_steps)

            for order, step_desc in enumerate(selected_steps, 1):
                ThreatRemediationStep.objects.create(
                    id=str(uuid.uuid4()),
                    threat=threat,
                    step_order=order,
                    step_description=step_desc,
                    created_at=threat.created_at,
                    updated_at=threat.updated_at
                )
                remediation_steps_created += 1

            num_findings = random.randint(0, 3)
            for _ in range(num_findings):
                finding_types = ['scan_vuln_', 'compliance_issue_', 'audit_alert_']
                finding_prefix = random.choice(finding_types)
                finding_id = f"{finding_prefix}{str(uuid.uuid4())}"

                ThreatRelatedFinding.objects.create(
                    id=str(uuid.uuid4()),
                    threat=threat,
                    finding_id=finding_id,
                    created_at=threat.created_at + timedelta(hours=random.randint(1, 24)),
                    updated_at=threat.updated_at
                )
                findings_created += 1

            if (i + 1) % 10 == 0:
                self.stdout.write(f'Created {i + 1}/{count} threats...')

        self.stdout.write(
            self.style.SUCCESS(
                f'Successfully created:\n'
                f'  • {threats_created} threats\n'
                f'  • {remediation_steps_created} remediation steps\n'
                f'  • {findings_created} related findings'
            )
        )