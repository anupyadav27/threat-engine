"""
Trend Tracker

Tracks compliance scores over time for trend analysis.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta, timezone
from collections import defaultdict


class TrendTracker:
    """Tracks compliance trends over time."""
    
    def __init__(self):
        """Initialize trend tracker."""
        # In-memory storage (use database in production)
        self._trends: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    
    def record_score(
        self,
        csp: str,
        account_id: str,
        framework: str,
        score: float,
        scanned_at: Optional[str] = None
    ) -> None:
        """
        Record a compliance score for trend tracking.
        
        Args:
            csp: Cloud service provider
            account_id: Account/subscription ID
            framework: Framework name
            score: Compliance score (0-100)
            scanned_at: Timestamp (ISO format, defaults to now)
        """
        if scanned_at is None:
            scanned_at = datetime.now(timezone.utc).isoformat() + 'Z'
        
        key = f"{csp}:{account_id}:{framework}"
        
        self._trends[key].append({
            'score': score,
            'scanned_at': scanned_at,
            'recorded_at': datetime.now(timezone.utc).isoformat() + 'Z'
        })
        
        # Keep only last 365 days of data
        cutoff = (datetime.now(timezone.utc) - timedelta(days=365)).isoformat() + 'Z'
        self._trends[key] = [
            t for t in self._trends[key]
            if t['scanned_at'] >= cutoff
        ]
    
    def get_trends(
        self,
        csp: str,
        account_id: str,
        framework: str,
        days: int = 30
    ) -> List[Dict[str, Any]]:
        """
        Get compliance trends for a framework.
        
        Args:
            csp: Cloud service provider
            account_id: Account/subscription ID
            framework: Framework name
            days: Number of days to look back
        
        Returns:
            List of trend data points
        """
        key = f"{csp}:{account_id}:{framework}"
        
        if key not in self._trends:
            return []
        
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat() + 'Z'
        
        trends = [
            t for t in self._trends[key]
            if t['scanned_at'] >= cutoff
        ]
        
        # Sort by scanned_at
        trends.sort(key=lambda x: x['scanned_at'])
        
        return trends
    
    def calculate_trend_direction(
        self,
        csp: str,
        account_id: str,
        framework: str,
        days: int = 30
    ) -> Dict[str, Any]:
        """
        Calculate trend direction (improving/degrading/stable).
        
        Args:
            csp: Cloud service provider
            account_id: Account/subscription ID
            framework: Framework name
            days: Number of days to analyze
        
        Returns:
            Trend direction data
        """
        trends = self.get_trends(csp, account_id, framework, days)
        
        if len(trends) < 2:
            return {
                'direction': 'insufficient_data',
                'current_score': trends[0]['score'] if trends else None,
                'previous_score': None,
                'change': 0.0
            }
        
        current_score = trends[-1]['score']
        previous_score = trends[0]['score']
        change = current_score - previous_score
        
        if change > 2.0:
            direction = 'improving'
        elif change < -2.0:
            direction = 'degrading'
        else:
            direction = 'stable'
        
        return {
            'direction': direction,
            'current_score': current_score,
            'previous_score': previous_score,
            'change': round(change, 2),
            'data_points': len(trends)
        }

