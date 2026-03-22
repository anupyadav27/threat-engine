"""
Threat Rule Coverage Analyzer

Analyzes coverage of threat rules across:
- Threat types
- Services
- Relationship types
- MITRE ATT&CK techniques
- Misconfig patterns

Usage:
    python analyze_threat_rule_coverage.py threat_rules.yaml
"""

import yaml
import json
import argparse
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Any, Set


class CoverageAnalyzer:
    """Analyzes threat rule coverage"""
    
    def __init__(self, rules_path: str):
        self.rules_path = Path(rules_path)
        self.rules = self._load_rules()
    
    def _load_rules(self) -> List[Dict[str, Any]]:
        """Load threat rules from YAML"""
        with open(self.rules_path, 'r') as f:
            data = yaml.safe_load(f)
            return data.get("threat_rules", [])
    
    def analyze_coverage(self) -> Dict[str, Any]:
        """Analyze coverage across all dimensions"""
        coverage = {
            "summary": {
                "total_rules": len(self.rules),
                "threat_types": len(set(r.get("threat_type") for r in self.rules)),
                "unique_services": len(set(r.get("service") for r in self.rules if r.get("service"))),
                "unique_misconfig_patterns": len(self._get_unique_patterns()),
                "unique_relationship_types": len(self._get_unique_relations()),
                "unique_resource_types": len(self._get_unique_resource_types()),
                "mitre_techniques": len(self._get_unique_mitre_techniques())
            },
            "by_threat_type": self._analyze_by_threat_type(),
            "by_service": self._analyze_by_service(),
            "by_service_category": self._analyze_by_service_category(),
            "by_relationship_type": self._analyze_by_relationship_type(),
            "by_resource_type": self._analyze_by_resource_type(),
            "by_mitre_technique": self._analyze_by_mitre_technique(),
            "gaps": self._identify_gaps()
        }
        
        return coverage
    
    def _get_unique_patterns(self) -> Set[str]:
        """Get unique misconfig patterns"""
        patterns = set()
        for rule in self.rules:
            patterns.update(rule.get("misconfig_patterns", []))
        return patterns
    
    def _get_unique_relations(self) -> Set[str]:
        """Get unique relationship types"""
        relations = set()
        for rule in self.rules:
            conditions = rule.get("relationship_conditions", {})
            for req_rel in conditions.get("required_relations", []):
                relations.add(req_rel.get("relation_type", ""))
        return relations - {""}
    
    def _get_unique_resource_types(self) -> Set[str]:
        """Get unique resource types"""
        resource_types = set()
        for rule in self.rules:
            conditions = rule.get("relationship_conditions", {})
            for req_rel in conditions.get("required_relations", []):
                resource_types.add(req_rel.get("target_resource_type", ""))
        return resource_types - {""}
    
    def _get_unique_mitre_techniques(self) -> Set[str]:
        """Get unique MITRE techniques"""
        techniques = set()
        for rule in self.rules:
            techniques.update(rule.get("mitre_techniques", []))
        return techniques
    
    def _analyze_by_threat_type(self) -> Dict[str, int]:
        """Count rules by threat type"""
        counts = defaultdict(int)
        for rule in self.rules:
            threat_type = rule.get("threat_type", "unknown")
            counts[threat_type] += 1
        return dict(counts)
    
    def _analyze_by_service(self) -> Dict[str, int]:
        """Count rules by service"""
        counts = defaultdict(int)
        for rule in self.rules:
            service = rule.get("service", "unknown")
            if service:
                counts[service] += 1
        return dict(counts)
    
    def _analyze_by_service_category(self) -> Dict[str, int]:
        """Count rules by service category"""
        counts = defaultdict(int)
        for rule in self.rules:
            category = rule.get("service_category")
            if category:
                counts[category] += 1
        return dict(counts)
    
    def _analyze_by_relationship_type(self) -> Dict[str, int]:
        """Count rules by relationship type"""
        counts = defaultdict(int)
        for rule in self.rules:
            conditions = rule.get("relationship_conditions", {})
            for req_rel in conditions.get("required_relations", []):
                rel_type = req_rel.get("relation_type", "")
                if rel_type:
                    counts[rel_type] += 1
        return dict(counts)
    
    def _analyze_by_resource_type(self) -> Dict[str, int]:
        """Count rules by resource type"""
        counts = defaultdict(int)
        for rule in self.rules:
            conditions = rule.get("relationship_conditions", {})
            for req_rel in conditions.get("required_relations", []):
                resource_type = req_rel.get("target_resource_type", "")
                if resource_type:
                    # Normalize patterns
                    base_type = resource_type.split(".")[0] if "." in resource_type else resource_type
                    counts[base_type] += 1
        return dict(counts)
    
    def _analyze_by_mitre_technique(self) -> Dict[str, int]:
        """Count rules by MITRE technique"""
        counts = defaultdict(int)
        for rule in self.rules:
            for technique in rule.get("mitre_techniques", []):
                counts[technique] += 1
        return dict(counts)
    
    def _identify_gaps(self) -> Dict[str, List[str]]:
        """Identify coverage gaps"""
        gaps = {
            "missing_threat_types": [],
            "missing_services": [],
            "missing_relationship_types": [],
            "missing_mitre_techniques": []
        }
        
        # Expected threat types
        expected_threats = ["exposure", "identity", "lateral_movement", 
                           "data_exfiltration", "privilege_escalation", "data_breach"]
        actual_threats = set(r.get("threat_type") for r in self.rules)
        gaps["missing_threat_types"] = [t for t in expected_threats if t not in actual_threats]
        
        # Expected relationship types
        expected_relations = [
            "uses", "assumes", "connected_to", "internet_connected",
            "encrypted_by", "grants_access_to", "routes_to", "attached_to"
        ]
        actual_relations = self._get_unique_relations()
        gaps["missing_relationship_types"] = [r for r in expected_relations if r not in actual_relations]
        
        # Expected MITRE techniques (key ones)
        expected_mitre = ["T1078", "T1078.004", "T1134", "T1021", "T1048", "T1190"]
        actual_mitre = self._get_unique_mitre_techniques()
        gaps["missing_mitre_techniques"] = [t for t in expected_mitre if t not in actual_mitre]
        
        return gaps
    
    def print_report(self, coverage: Dict[str, Any]):
        """Print coverage report"""
        print("\n" + "="*80)
        print("THREAT RULE COVERAGE REPORT")
        print("="*80)
        
        summary = coverage["summary"]
        print(f"\n📊 Summary:")
        print(f"  Total Rules: {summary['total_rules']}")
        print(f"  Threat Types: {summary['threat_types']}")
        print(f"  Services Covered: {summary['unique_services']}")
        print(f"  Service Categories: {len(coverage['by_service_category'])}")
        print(f"  Unique Misconfig Patterns: {summary['unique_misconfig_patterns']}")
        print(f"  Unique Relationship Types: {summary['unique_relationship_types']}")
        print(f"  Unique Resource Types: {summary['unique_resource_types']}")
        print(f"  MITRE Techniques Covered: {summary['mitre_techniques']}")
        
        print(f"\n🎯 By Threat Type:")
        for threat_type, count in sorted(coverage["by_threat_type"].items(), key=lambda x: x[1], reverse=True):
            print(f"  {threat_type:25s}: {count:4d} rules")
        
        print(f"\n🏢 By Service Category (Top 10):")
        sorted_cats = sorted(coverage["by_service_category"].items(), 
                           key=lambda x: x[1], reverse=True)[:10]
        for category, count in sorted_cats:
            print(f"  {category:25s}: {count:4d} rules")
        
        print(f"\n🔗 By Relationship Type (Top 10):")
        sorted_rels = sorted(coverage["by_relationship_type"].items(), 
                           key=lambda x: x[1], reverse=True)[:10]
        for rel_type, count in sorted_rels:
            print(f"  {rel_type:25s}: {count:4d} rules")
        
        print(f"\n🎯 By MITRE Technique (Top 15):")
        sorted_mitre = sorted(coverage["by_mitre_technique"].items(), 
                            key=lambda x: x[1], reverse=True)[:15]
        for technique, count in sorted_mitre:
            print(f"  {technique:15s}: {count:4d} rules")
        
        gaps = coverage["gaps"]
        print(f"\n⚠️  Coverage Gaps:")
        if gaps["missing_threat_types"]:
            print(f"  Missing Threat Types: {', '.join(gaps['missing_threat_types'])}")
        if gaps["missing_relationship_types"]:
            print(f"  Missing Relationship Types: {', '.join(gaps['missing_relationship_types'])}")
        if gaps["missing_mitre_techniques"]:
            print(f"  Missing MITRE Techniques: {', '.join(gaps['missing_mitre_techniques'])}")
        
        print("\n" + "="*80)


def main():
    parser = argparse.ArgumentParser(description="Analyze threat rule coverage")
    parser.add_argument("rules_file", help="Path to threat rules YAML file")
    parser.add_argument("--output", help="Output JSON report file")
    
    args = parser.parse_args()
    
    analyzer = CoverageAnalyzer(args.rules_file)
    coverage = analyzer.analyze_coverage()
    
    analyzer.print_report(coverage)
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(coverage, f, indent=2)
        print(f"\n✅ Report saved to {args.output}")


if __name__ == "__main__":
    main()
