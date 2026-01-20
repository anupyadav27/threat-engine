"""
Result Aggregator Module

Groups scan results by framework/control and calculates compliance scores.
"""

from .result_aggregator import ResultAggregator
from .score_calculator import ScoreCalculator

__all__ = ["ResultAggregator", "ScoreCalculator"]

