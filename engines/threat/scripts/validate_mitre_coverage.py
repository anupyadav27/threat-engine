"""
MITRE ATT&CK Coverage Validator

Validates threat rules against official MITRE ATT&CK for Cloud techniques.
Compares our coverage with official MITRE documentation.
"""

import yaml
import json
import argparse
from pathlib import Path
from typing import Dict, List, Set, Any
from collections import defaultdict


class MITRECoverageValidator:
    """Validates MITRE ATT&CK coverage"""
    
    def __init__(self, rules_path: str):
        self.rules_path = Path(rules_path)
        self.rules = self._load_rules()
        
        # Official MITRE ATT&CK for Cloud techniques (as of 2024)
        # Source: https://attack.mitre.org/matrices/enterprise/cloud/
        self.official_cloud_techniques = self._load_official_techniques()
    
    def _load_rules(self) -> List[Dict[str, Any]]:
        """Load threat rules from YAML"""
        with open(self.rules_path, 'r') as f:
            data = yaml.safe_load(f)
            return data.get("threat_rules", [])
    
    def _load_official_techniques(self) -> Dict[str, Dict[str, Any]]:
        """
        Official MITRE ATT&CK for Cloud techniques
        Based on: https://attack.mitre.org/matrices/enterprise/cloud/
        """
        return {
            # Initial Access
            "T1078": {
                "name": "Valid Accounts",
                "tactic": "Initial Access",
                "sub_techniques": ["T1078.001", "T1078.002", "T1078.003", "T1078.004", "T1078.005"]
            },
            "T1078.001": {"name": "Valid Accounts: Default Accounts", "tactic": "Initial Access"},
            "T1078.002": {"name": "Valid Accounts: Domain Accounts", "tactic": "Initial Access"},
            "T1078.003": {"name": "Valid Accounts: Local Accounts", "tactic": "Initial Access"},
            "T1078.004": {"name": "Valid Accounts: Cloud Accounts", "tactic": "Initial Access"},
            "T1078.005": {"name": "Valid Accounts: Cloud Accounts: AWS IAM roles", "tactic": "Initial Access"},
            "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
            "T1566": {"name": "Phishing", "tactic": "Initial Access"},
            "T1566.001": {"name": "Phishing: Spearphishing Attachment", "tactic": "Initial Access"},
            "T1566.002": {"name": "Phishing: Spearphishing Link", "tactic": "Initial Access"},
            "T1566.003": {"name": "Phishing: Spearphishing via Service", "tactic": "Initial Access"},
            "T1078.006": {"name": "Valid Accounts: Cloud Accounts: Azure AD", "tactic": "Initial Access"},
            "T1078.007": {"name": "Valid Accounts: Cloud Accounts: Google Workspace", "tactic": "Initial Access"},
            
            # Execution
            "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
            "T1059.009": {"name": "Command and Scripting Interpreter: Cloud API", "tactic": "Execution"},
            "T1650": {"name": "Container Administration Command", "tactic": "Execution"},
            "T1651": {"name": "Cloud Administration Command", "tactic": "Execution"},
            
            # Persistence
            "T1098": {"name": "Account Manipulation", "tactic": "Persistence"},
            "T1098.001": {"name": "Account Manipulation: Additional Cloud Credentials", "tactic": "Persistence"},
            "T1098.003": {"name": "Account Manipulation: Additional Cloud Roles", "tactic": "Persistence"},
            "T1098.004": {"name": "Account Manipulation: SSH Authorized Keys", "tactic": "Persistence"},
            "T1098.005": {"name": "Account Manipulation: Device Registration", "tactic": "Persistence"},
            "T1136": {"name": "Create Account", "tactic": "Persistence"},
            "T1136.003": {"name": "Create Account: Cloud Account", "tactic": "Persistence"},
            "T1543": {"name": "Create or Modify System Process", "tactic": "Persistence"},
            "T1543.003": {"name": "Create or Modify System Process: Windows Service", "tactic": "Persistence"},
            "T1574": {"name": "Hijack Execution Flow", "tactic": "Persistence"},
            "T1574.012": {"name": "Hijack Execution Flow: COR_PROFILER", "tactic": "Persistence"},
            "T1525": {"name": "Implant Container Image", "tactic": "Persistence"},
            "T1078.005": {"name": "Valid Accounts: Cloud Accounts: AWS IAM roles", "tactic": "Persistence"},
            
            # Privilege Escalation
            "T1078": {"name": "Valid Accounts", "tactic": "Privilege Escalation"},
            "T1078.004": {"name": "Valid Accounts: Cloud Accounts", "tactic": "Privilege Escalation"},
            "T1078.005": {"name": "Valid Accounts: Cloud Accounts: AWS IAM roles", "tactic": "Privilege Escalation"},
            "T1134": {"name": "Access Token Manipulation", "tactic": "Privilege Escalation"},
            "T1134.001": {"name": "Access Token Manipulation: Token Impersonation/Theft", "tactic": "Privilege Escalation"},
            "T1134.002": {"name": "Access Token Manipulation: Create Process with Token", "tactic": "Privilege Escalation"},
            "T1134.003": {"name": "Access Token Manipulation: Make and Impersonate Token", "tactic": "Privilege Escalation"},
            "T1134.004": {"name": "Access Token Manipulation: Parent PID Spoofing", "tactic": "Privilege Escalation"},
            "T1134.005": {"name": "Access Token Manipulation: SID-History Injection", "tactic": "Privilege Escalation"},
            "T1531": {"name": "Account Access Removal", "tactic": "Privilege Escalation"},
            "T1484": {"name": "Domain Policy Modification", "tactic": "Privilege Escalation"},
            "T1484.002": {"name": "Domain Policy Modification: Domain Trust Modification", "tactic": "Privilege Escalation"},
            
            # Defense Evasion
            "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion"},
            "T1078.004": {"name": "Valid Accounts: Cloud Accounts", "tactic": "Defense Evasion"},
            "T1078.005": {"name": "Valid Accounts: Cloud Accounts: AWS IAM roles", "tactic": "Defense Evasion"},
            "T1562": {"name": "Impair Defenses", "tactic": "Defense Evasion"},
            "T1562.001": {"name": "Impair Defenses: Disable or Modify Tools", "tactic": "Defense Evasion"},
            "T1562.008": {"name": "Impair Defenses: Disable Cloud Logs", "tactic": "Defense Evasion"},
            "T1562.010": {"name": "Impair Defenses: Disable or Modify System Firewall", "tactic": "Defense Evasion"},
            "T1070": {"name": "Indicator Removal on Host", "tactic": "Defense Evasion"},
            "T1070.004": {"name": "Indicator Removal on Host: File Deletion", "tactic": "Defense Evasion"},
            "T1070.005": {"name": "Indicator Removal on Host: Network Share Connection Removal", "tactic": "Defense Evasion"},
            "T1070.006": {"name": "Indicator Removal on Host: Timestomping", "tactic": "Defense Evasion"},
            "T1140": {"name": "Deobfuscate/Decode Files or Information", "tactic": "Defense Evasion"},
            "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
            "T1036": {"name": "Masquerading", "tactic": "Defense Evasion"},
            "T1036.005": {"name": "Masquerading: Match Legitimate Name or Location", "tactic": "Defense Evasion"},
            "T1112": {"name": "Modify Registry", "tactic": "Defense Evasion"},
            "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "Defense Evasion"},
            "T1548.003": {"name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "tactic": "Defense Evasion"},
            "T1550": {"name": "Use Alternate Authentication Material", "tactic": "Defense Evasion"},
            "T1550.003": {"name": "Use Alternate Authentication Material: Pass the Ticket", "tactic": "Defense Evasion"},
            "T1550.004": {"name": "Use Alternate Authentication Material: Web Session Cookie", "tactic": "Defense Evasion"},
            "T1622": {"name": "Debugger Evasion", "tactic": "Defense Evasion"},
            
            # Credential Access
            "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
            "T1110.001": {"name": "Brute Force: Password Guessing", "tactic": "Credential Access"},
            "T1110.002": {"name": "Brute Force: Password Cracking", "tactic": "Credential Access"},
            "T1110.003": {"name": "Brute Force: Password Spraying", "tactic": "Credential Access"},
            "T1110.004": {"name": "Brute Force: Credential Stuffing", "tactic": "Credential Access"},
            "T1555": {"name": "Credentials from Password Stores", "tactic": "Credential Access"},
            "T1555.001": {"name": "Credentials from Password Stores: Keychain", "tactic": "Credential Access"},
            "T1555.003": {"name": "Credentials from Password Stores: Credentials from Web Browsers", "tactic": "Credential Access"},
            "T1555.004": {"name": "Credentials from Password Stores: Windows Credential Manager", "tactic": "Credential Access"},
            "T1552": {"name": "Unsecured Credentials", "tactic": "Credential Access"},
            "T1552.001": {"name": "Unsecured Credentials: Credentials In Files", "tactic": "Credential Access"},
            "T1552.002": {"name": "Unsecured Credentials: Credentials in Registry", "tactic": "Credential Access"},
            "T1552.003": {"name": "Unsecured Credentials: Bash History", "tactic": "Credential Access"},
            "T1552.004": {"name": "Unsecured Credentials: Private Keys", "tactic": "Credential Access"},
            "T1552.005": {"name": "Unsecured Credentials: Cloud Instance Metadata API", "tactic": "Credential Access"},
            "T1552.006": {"name": "Unsecured Credentials: Group Policy Preferences", "tactic": "Credential Access"},
            "T1552.007": {"name": "Unsecured Credentials: Container API", "tactic": "Credential Access"},
            "T1556": {"name": "Modify Authentication Process", "tactic": "Credential Access"},
            "T1556.001": {"name": "Modify Authentication Process: Domain Controller Authentication", "tactic": "Credential Access"},
            "T1556.002": {"name": "Modify Authentication Process: Password Filter DLL", "tactic": "Credential Access"},
            "T1556.003": {"name": "Modify Authentication Process: Pluggable Authentication Modules", "tactic": "Credential Access"},
            "T1556.004": {"name": "Modify Authentication Process: Network Device Authentication", "tactic": "Credential Access"},
            "T1556.005": {"name": "Modify Authentication Process: Reversible Encryption", "tactic": "Credential Access"},
            "T1556.006": {"name": "Modify Authentication Process: Multi-Factor Authentication", "tactic": "Credential Access"},
            "T1558": {"name": "Steal or Forge Kerberos Tickets", "tactic": "Credential Access"},
            "T1558.001": {"name": "Steal or Forge Kerberos Tickets: Golden Ticket", "tactic": "Credential Access"},
            "T1558.002": {"name": "Steal or Forge Kerberos Tickets: Silver Ticket", "tactic": "Credential Access"},
            "T1558.003": {"name": "Steal or Forge Kerberos Tickets: Kerberoasting", "tactic": "Credential Access"},
            "T1558.004": {"name": "Steal or Forge Kerberos Tickets: AS-REP Roasting", "tactic": "Credential Access"},
            "T1621": {"name": "Multi-Factor Authentication Request Generation", "tactic": "Credential Access"},
            "T1606": {"name": "Forge Web Credentials", "tactic": "Credential Access"},
            "T1606.001": {"name": "Forge Web Credentials: Web Cookies", "tactic": "Credential Access"},
            "T1606.002": {"name": "Forge Web Credentials: SAML Tokens", "tactic": "Credential Access"},
            "T1528": {"name": "Steal Application Access Token", "tactic": "Credential Access"},
            "T1528.001": {"name": "Steal Application Access Token: Cloud Accounts", "tactic": "Credential Access"},
            "T1528.002": {"name": "Steal Application Access Token: API Keys", "tactic": "Credential Access"},
            "T1528.003": {"name": "Steal Application Access Token: OAuth Tokens", "tactic": "Credential Access"},
            
            # Discovery
            "T1087": {"name": "Account Discovery", "tactic": "Discovery"},
            "T1087.004": {"name": "Account Discovery: Cloud Account", "tactic": "Discovery"},
            "T1580": {"name": "Cloud Infrastructure Discovery", "tactic": "Discovery"},
            "T1580.001": {"name": "Cloud Infrastructure Discovery: AWS", "tactic": "Discovery"},
            "T1580.002": {"name": "Cloud Infrastructure Discovery: Azure", "tactic": "Discovery"},
            "T1580.003": {"name": "Cloud Infrastructure Discovery: GCP", "tactic": "Discovery"},
            "T1018": {"name": "Remote System Discovery", "tactic": "Discovery"},
            "T1046": {"name": "Network Service Scanning", "tactic": "Discovery"},
            "T1040": {"name": "Network Sniffing", "tactic": "Discovery"},
            "T1057": {"name": "Process Discovery", "tactic": "Discovery"},
            "T1082": {"name": "System Information Discovery", "tactic": "Discovery"},
            "T1083": {"name": "File and Directory Discovery", "tactic": "Discovery"},
            "T1135": {"name": "Network Share Discovery", "tactic": "Discovery"},
            "T1201": {"name": "Password Policy Discovery", "tactic": "Discovery"},
            "T1069": {"name": "Permission Groups Discovery", "tactic": "Discovery"},
            "T1069.001": {"name": "Permission Groups Discovery: Local Groups", "tactic": "Discovery"},
            "T1069.002": {"name": "Permission Groups Discovery: Domain Groups", "tactic": "Discovery"},
            "T1069.003": {"name": "Permission Groups Discovery: Cloud Groups", "tactic": "Discovery"},
            "T1482": {"name": "Domain Trust Discovery", "tactic": "Discovery"},
            "T1613": {"name": "Container and Resource Discovery", "tactic": "Discovery"},
            "T1613.001": {"name": "Container and Resource Discovery: Cloud Resources", "tactic": "Discovery"},
            "T1613.002": {"name": "Container and Resource Discovery: Container Resources", "tactic": "Discovery"},
            "T1614": {"name": "System Location Discovery", "tactic": "Discovery"},
            "T1614.001": {"name": "System Location Discovery: System Language Discovery", "tactic": "Discovery"},
            "T1614.002": {"name": "System Location Discovery: Time Zone Discovery", "tactic": "Discovery"},
            
            # Lateral Movement
            "T1021": {"name": "Remote Services", "tactic": "Lateral Movement"},
            "T1021.001": {"name": "Remote Services: Remote Desktop Protocol", "tactic": "Lateral Movement"},
            "T1021.002": {"name": "Remote Services: SMB/Windows Admin Shares", "tactic": "Lateral Movement"},
            "T1021.003": {"name": "Remote Services: Distributed Component Object Model", "tactic": "Lateral Movement"},
            "T1021.004": {"name": "Remote Services: SSH", "tactic": "Lateral Movement"},
            "T1021.005": {"name": "Remote Services: VNC", "tactic": "Lateral Movement"},
            "T1071": {"name": "Application Layer Protocol", "tactic": "Lateral Movement"},
            "T1071.001": {"name": "Application Layer Protocol: Web Protocols", "tactic": "Lateral Movement"},
            "T1071.002": {"name": "Application Layer Protocol: File Transfer Protocols", "tactic": "Lateral Movement"},
            "T1071.003": {"name": "Application Layer Protocol: Mail Protocols", "tactic": "Lateral Movement"},
            "T1071.004": {"name": "Application Layer Protocol: DNS", "tactic": "Lateral Movement"},
            "T1534": {"name": "Internal Spearphishing", "tactic": "Lateral Movement"},
            "T1570": {"name": "Lateral Tool Transfer", "tactic": "Lateral Movement"},
            "T1021.006": {"name": "Remote Services: Windows Remote Management", "tactic": "Lateral Movement"},
            
            # Collection
            "T1119": {"name": "Automated Collection", "tactic": "Collection"},
            "T1115": {"name": "Clipboard Data", "tactic": "Collection"},
            "T1005": {"name": "Data from Local System", "tactic": "Collection"},
            "T1039": {"name": "Data from Network Shared Drive", "tactic": "Collection"},
            "T1074": {"name": "Data Staged", "tactic": "Collection"},
            "T1074.001": {"name": "Data Staged: Local Data Staging", "tactic": "Collection"},
            "T1074.002": {"name": "Data Staged: Remote Data Staging", "tactic": "Collection"},
            "T1213": {"name": "Data from Information Repositories", "tactic": "Collection"},
            "T1213.001": {"name": "Data from Information Repositories: Confluence", "tactic": "Collection"},
            "T1213.002": {"name": "Data from Information Repositories: Sharepoint", "tactic": "Collection"},
            "T1213.003": {"name": "Data from Information Repositories: Code Repositories", "tactic": "Collection"},
            "T1530": {"name": "Data from Cloud Storage Object", "tactic": "Collection"},
            "T1530.001": {"name": "Data from Cloud Storage Object: S3", "tactic": "Collection"},
            "T1530.002": {"name": "Data from Cloud Storage Object: Azure Blob", "tactic": "Collection"},
            "T1530.003": {"name": "Data from Cloud Storage Object: Google Cloud Storage", "tactic": "Collection"},
            "T1602": {"name": "Data from Configuration Repository", "tactic": "Collection"},
            "T1602.001": {"name": "Data from Configuration Repository: SNMP (MIB Dump)", "tactic": "Collection"},
            "T1602.002": {"name": "Data from Configuration Repository: Network Device Configuration Dump", "tactic": "Collection"},
            "T1602.003": {"name": "Data from Configuration Repository: Container Orchestration Configuration", "tactic": "Collection"},
            
            # Exfiltration
            "T1020": {"name": "Automated Exfiltration", "tactic": "Exfiltration"},
            "T1020.001": {"name": "Automated Exfiltration: Traffic Duplication", "tactic": "Exfiltration"},
            "T1020.002": {"name": "Automated Exfiltration: Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
            "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
            "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
            "T1048.001": {"name": "Exfiltration Over Alternative Protocol: Exfiltration Over Symmetric Encrypted Non-C2 Protocol", "tactic": "Exfiltration"},
            "T1048.002": {"name": "Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol", "tactic": "Exfiltration"},
            "T1048.003": {"name": "Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol", "tactic": "Exfiltration"},
            "T1537": {"name": "Transfer Data to Cloud Account", "tactic": "Exfiltration"},
            "T1567": {"name": "Exfiltration Over Web Service", "tactic": "Exfiltration"},
            "T1567.001": {"name": "Exfiltration Over Web Service: Exfiltration to Code Repository", "tactic": "Exfiltration"},
            "T1567.002": {"name": "Exfiltration Over Web Service: Exfiltration to Cloud Storage", "tactic": "Exfiltration"},
            "T1567.003": {"name": "Exfiltration Over Web Service: Exfiltration to Text Storage Sites", "tactic": "Exfiltration"},
            
            # Impact
            "T1485": {"name": "Data Destruction", "tactic": "Impact"},
            "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact"},
            "T1490": {"name": "Inhibit System Recovery", "tactic": "Impact"},
            "T1491": {"name": "Defacement", "tactic": "Impact"},
            "T1491.001": {"name": "Defacement: Internal Defacement", "tactic": "Impact"},
            "T1491.002": {"name": "Defacement: External Defacement", "tactic": "Impact"},
            "T1495": {"name": "Firmware Corruption", "tactic": "Impact"},
            "T1496": {"name": "Resource Hijacking", "tactic": "Impact"},
            "T1498": {"name": "Network Denial of Service", "tactic": "Impact"},
            "T1499": {"name": "Endpoint Denial of Service", "tactic": "Impact"},
            "T1499.001": {"name": "Endpoint Denial of Service: OS Exhaustion Flood", "tactic": "Impact"},
            "T1499.002": {"name": "Endpoint Denial of Service: Service Exhaustion Flood", "tactic": "Impact"},
            "T1499.003": {"name": "Endpoint Denial of Service: Application Exhaustion Flood", "tactic": "Impact"},
            "T1499.004": {"name": "Endpoint Denial of Service: Application or System Exploitation", "tactic": "Impact"},
            "T1565": {"name": "Data Manipulation", "tactic": "Impact"},
            "T1565.001": {"name": "Data Manipulation: Stored Data Manipulation", "tactic": "Impact"},
            "T1565.002": {"name": "Data Manipulation: Transmitted Data Manipulation", "tactic": "Impact"},
            "T1565.003": {"name": "Data Manipulation: Runtime Data Manipulation", "tactic": "Impact"},
            "T1578": {"name": "Modify Cloud Compute Infrastructure", "tactic": "Impact"},
            "T1578.001": {"name": "Modify Cloud Compute Infrastructure: Create Snapshot", "tactic": "Impact"},
            "T1578.002": {"name": "Modify Cloud Compute Infrastructure: Create Cloud Instance", "tactic": "Impact"},
            "T1578.003": {"name": "Modify Cloud Compute Infrastructure: Delete Cloud Instance", "tactic": "Impact"},
            "T1578.004": {"name": "Modify Cloud Compute Infrastructure: Revert Cloud Instance", "tactic": "Impact"},
            "T1578.005": {"name": "Modify Cloud Compute Infrastructure: Start Cloud Instance", "tactic": "Impact"},
            "T1578.006": {"name": "Modify Cloud Compute Infrastructure: Stop Cloud Instance", "tactic": "Impact"},
        }
    
    def get_covered_techniques(self) -> Set[str]:
        """Get all MITRE techniques covered in our rules"""
        covered = set()
        for rule in self.rules:
            covered.update(rule.get("mitre_techniques", []))
        return covered
    
    def get_missing_techniques(self) -> Dict[str, List[str]]:
        """Get missing MITRE techniques by tactic"""
        covered = self.get_covered_techniques()
        official = set(self.official_cloud_techniques.keys())
        missing = official - covered
        
        # Group by tactic
        missing_by_tactic = defaultdict(list)
        for tech_id in missing:
            tech_info = self.official_cloud_techniques.get(tech_id, {})
            tactic = tech_info.get("tactic", "Unknown")
            missing_by_tactic[tactic].append({
                "id": tech_id,
                "name": tech_info.get("name", "Unknown")
            })
        
        return dict(missing_by_tactic)
    
    def validate_coverage(self) -> Dict[str, Any]:
        """Validate MITRE coverage"""
        covered = self.get_covered_techniques()
        official = set(self.official_cloud_techniques.keys())
        
        # Count by tactic
        covered_by_tactic = defaultdict(set)
        for tech_id in covered:
            if tech_id in self.official_cloud_techniques:
                tactic = self.official_cloud_techniques[tech_id].get("tactic", "Unknown")
                covered_by_tactic[tactic].add(tech_id)
        
        missing = official - covered
        
        return {
            "summary": {
                "total_official_techniques": len(official),
                "covered_techniques": len(covered),
                "missing_techniques": len(missing),
                "coverage_percentage": round((len(covered) / len(official)) * 100, 2) if official else 0
            },
            "covered_by_tactic": {k: len(v) for k, v in covered_by_tactic.items()},
            "missing_by_tactic": self.get_missing_techniques(),
            "covered_techniques": sorted(list(covered)),
            "missing_techniques": sorted(list(missing))
        }
    
    def print_validation_report(self, validation: Dict[str, Any]):
        """Print validation report"""
        print("\n" + "="*80)
        print("MITRE ATT&CK FOR CLOUD - COVERAGE VALIDATION REPORT")
        print("="*80)
        
        summary = validation["summary"]
        print(f"\n📊 Coverage Summary:")
        print(f"  Official Techniques: {summary['total_official_techniques']}")
        print(f"  Covered Techniques: {summary['covered_techniques']}")
        print(f"  Missing Techniques: {summary['missing_techniques']}")
        print(f"  Coverage: {summary['coverage_percentage']}%")
        
        print(f"\n✅ Covered by Tactic:")
        for tactic, count in sorted(validation["covered_by_tactic"].items()):
            print(f"  {tactic:25s}: {count:3d} techniques")
        
        print(f"\n⚠️  Missing by Tactic:")
        missing_by_tactic = validation["missing_by_tactic"]
        if missing_by_tactic:
            for tactic, techniques in sorted(missing_by_tactic.items()):
                print(f"\n  {tactic}:")
                for tech in techniques[:10]:  # Show first 10
                    print(f"    - {tech['id']:15s}: {tech['name']}")
                if len(techniques) > 10:
                    print(f"    ... and {len(techniques) - 10} more")
        else:
            print("  ✅ No missing techniques!")
        
        print("\n" + "="*80)


def main():
    parser = argparse.ArgumentParser(description="Validate MITRE ATT&CK coverage")
    parser.add_argument("rules_file", help="Path to threat rules YAML file")
    parser.add_argument("--output", help="Output JSON report file")
    
    args = parser.parse_args()
    
    validator = MITRECoverageValidator(args.rules_file)
    validation = validator.validate_coverage()
    
    validator.print_validation_report(validation)
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(validation, f, indent=2)
        print(f"\n✅ Report saved to {args.output}")


if __name__ == "__main__":
    main()
