"""
Parameter Identification Module - Step 3
Identifies and analyzes user-controlled inputs for security testing
"""

from dast_engine.parameters.parameter_enricher import ParameterEnricher, enrich_endpoints
from dast_engine.parameters.parameter_extractor import ParameterExtractor
from dast_engine.parameters.parameter_analyzer import ParameterAnalyzer
from dast_engine.parameters.parameter_types import ParameterType, ParameterMetadata
from dast_engine.parameters.value_generator import ValueGenerator

__all__ = [
    'ParameterEnricher',
    'enrich_endpoints',
    'ParameterExtractor',
    'ParameterAnalyzer',
    'ParameterType',
    'ParameterMetadata',
    'ValueGenerator',
]
