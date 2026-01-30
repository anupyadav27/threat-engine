"""
JSON Exporter

Exports compliance reports as JSON (default format).
"""

from typing import Dict, Any
import json


class JSONExporter:
    """Exports compliance reports as JSON."""
    
    @staticmethod
    def export(report: Dict[str, Any], pretty: bool = True) -> str:
        """
        Export compliance report as JSON string.
        
        Args:
            report: Compliance report dictionary
            pretty: Whether to format with indentation
        
        Returns:
            JSON string
        """
        if pretty:
            return json.dumps(report, indent=2, default=str)
        else:
            return json.dumps(report, default=str)
    
    @staticmethod
    def save(report: Dict[str, Any], filepath: str, pretty: bool = True) -> None:
        """
        Save compliance report to JSON file.
        
        Args:
            report: Compliance report dictionary
            filepath: Output file path
            pretty: Whether to format with indentation
        """
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2 if pretty else None, default=str)

