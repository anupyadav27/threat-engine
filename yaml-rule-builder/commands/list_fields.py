"""
List fields for a service command
"""

from typing import List, Dict
try:
    from ..core.data_loader import DataLoader
    from ..core.field_mapper import FieldMapper
    from ..config import Config
except ImportError:
    from core.data_loader import DataLoader
    from core.field_mapper import FieldMapper
    from config import Config

def list_fields(service_name: str, config: Config) -> Dict:
    """List all available fields for a service"""
    loader = DataLoader(config)
    service_data = loader.load_service_data(service_name)
    
    mapper = FieldMapper(service_data)
    fields = mapper.get_available_fields()
    
    result = {}
    for field_name in fields:
        field_info = mapper.get_field_info(field_name)
        result[field_name] = {
            "operators": field_info.get("operators", []),
            "type": field_info.get("type", "string"),
            "enum": field_info.get("enum", False),
            "possible_values": field_info.get("possible_values"),
            "operations": field_info.get("operations", [])
        }
    
    return result

