"""
Data Activity Monitoring Analyzer - Detects anomalies in data access patterns.

Analyzes CloudTrail and CloudWatch logs for unusual access patterns.
"""

import boto3
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from datetime import datetime, timedelta
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


@dataclass
class ActivityEvent:
    """Data access activity event."""
    event_id: str
    timestamp: datetime
    resource_id: str
    resource_arn: str
    principal: str
    action: str
    ip_address: Optional[str] = None
    location: Optional[str] = None
    anomaly_score: float = 0.0
    risk_level: str = "low"  # low, medium, high
    alert_triggered: bool = False


class ActivityAnalyzer:
    """Analyzes data access activity for anomalies."""
    
    def __init__(self, aws_session: Optional[boto3.Session] = None):
        """
        Initialize activity analyzer.
        
        Args:
            aws_session: Optional boto3 session
        """
        import os
        region = os.getenv('AWS_REGION', os.getenv('AWS_DEFAULT_REGION', 'ap-south-1'))
        self.session = aws_session or boto3.Session(region_name=region)
        self.cloudtrail = self.session.client('cloudtrail')
    
    def get_s3_access_events(self, bucket: str, days_back: int = 7) -> List[ActivityEvent]:
        """
        Get S3 access events from CloudTrail.
        
        Args:
            bucket: S3 bucket name
            days_back: Number of days to look back
            
        Returns:
            List of ActivityEvent objects
        """
        events = []
        
        try:
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=days_back)
            
            # Query CloudTrail for S3 events
            # This is simplified - actual implementation would use CloudTrail Insights or log parsing
            # response = self.cloudtrail.lookup_events(
            #     LookupAttributes=[
            #         {'AttributeKey': 'ResourceName', 'AttributeValue': bucket}
            #     ],
            #     StartTime=start_time,
            #     EndTime=end_time
            # )
            
            # Parse events into ActivityEvent objects
            # for event in response.get('Events', []):
            #     events.append(ActivityEvent(...))
        
        except Exception as e:
            logger.error(f"Error getting S3 access events for {bucket}: {e}")
        
        return events
    
    def detect_anomalies(self, events: List[ActivityEvent]) -> List[ActivityEvent]:
        """
        Detect anomalous access patterns.
        
        Args:
            events: List of activity events
            
        Returns:
            List of events with anomaly scores and alerts
        """
        if not events:
            return []
        
        # Calculate baseline statistics
        access_counts = defaultdict(int)
        ip_addresses = defaultdict(int)
        time_of_day = defaultdict(int)
        
        for event in events:
            access_counts[event.principal] += 1
            if event.ip_address:
                ip_addresses[event.ip_address] += 1
            hour = event.timestamp.hour
            time_of_day[hour] += 1
        
        # Detect anomalies
        for event in events:
            anomaly_score = 0.0
            
            # Check for unusual access volume
            if access_counts[event.principal] > len(events) * 0.5:  # More than 50% of events
                anomaly_score += 0.3
            
            # Check for unusual IP address
            if event.ip_address and ip_addresses[event.ip_address] == 1:
                anomaly_score += 0.2
            
            # Check for off-hours access (e.g., outside 9 AM - 5 PM)
            hour = event.timestamp.hour
            if hour < 9 or hour > 17:
                anomaly_score += 0.2
            
            # Determine risk level
            if anomaly_score >= 0.7:
                event.risk_level = "high"
                event.alert_triggered = True
            elif anomaly_score >= 0.4:
                event.risk_level = "medium"
            else:
                event.risk_level = "low"
            
            event.anomaly_score = anomaly_score
        
        return events
    
    def monitor_data_access(self, data_stores: List[Dict], days_back: int = 7) -> Dict[str, List[ActivityEvent]]:
        """
        Monitor access to data stores.
        
        Args:
            data_stores: List of data store assets
            days_back: Number of days to analyze
            
        Returns:
            Dictionary mapping resource_id to list of activity events
        """
        results = {}
        
        for store in data_stores:
            resource_id = store.get("resource_id", "")
            resource_type = store.get("resource_type", "").lower()
            
            events = []
            
            # Handle S3 buckets
            if "s3:bucket" in resource_type:
                events = self.get_s3_access_events(resource_id, days_back)
                events = self.detect_anomalies(events)
            
            if events:
                results[resource_id] = events
        
        return results


# Convenience function
def analyze_activity(data_stores: List[Dict], days_back: int = 7, aws_session: Optional[boto3.Session] = None) -> Dict[str, List[ActivityEvent]]:
    """Analyze activity for data stores."""
    analyzer = ActivityAnalyzer(aws_session)
    return analyzer.monitor_data_access(data_stores, days_back)

