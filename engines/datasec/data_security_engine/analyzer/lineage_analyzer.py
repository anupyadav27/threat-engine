"""
Data Lineage Analyzer - Tracks data flows across services.

Uses CloudTrail logs and service relationships to map data lineage.
"""

import boto3
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import logging

logger = logging.getLogger(__name__)


@dataclass
class DataFlow:
    """Represents a data flow between resources."""
    source_resource_id: str
    source_resource_type: str
    target_resource_id: str
    target_resource_type: str
    transformation: Optional[str] = None  # e.g., "ETL job: glue-job-123"
    relationship_type: str = "transformed_from"  # or "consumed_by", "copied_from"
    timestamp: Optional[datetime] = None


class LineageAnalyzer:
    """Analyzes data flows and builds lineage graphs."""
    
    def __init__(self, aws_session: Optional[boto3.Session] = None):
        """
        Initialize lineage analyzer.
        
        Args:
            aws_session: Optional boto3 session
        """
        import os
        region = os.getenv('AWS_REGION', os.getenv('AWS_DEFAULT_REGION', 'ap-south-1'))
        self.session = aws_session or boto3.Session(region_name=region)
        self.cloudtrail = self.session.client('cloudtrail')
        self.glue = self.session.client('glue') if self.session.region_name else None
    
    def analyze_s3_to_redshift_flows(self, s3_buckets: List[str], redshift_clusters: List[str], days_back: int = 30) -> List[DataFlow]:
        """
        Analyze data flows from S3 to Redshift using CloudTrail.
        
        Args:
            s3_buckets: List of S3 bucket names
            redshift_clusters: List of Redshift cluster identifiers
            days_back: Number of days to look back in CloudTrail
            
        Returns:
            List of DataFlow objects
        """
        flows = []
        
        try:
            # Look for COPY commands from S3 to Redshift
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days_back)
            
            for bucket in s3_buckets:
                # Query CloudTrail for S3 access events
                # This is a simplified example - actual implementation would parse CloudTrail logs
                # to find COPY commands and other data transformation operations
                pass
        
        except Exception as e:
            logger.error(f"Error analyzing S3 to Redshift flows: {e}")
        
        return flows
    
    def analyze_glue_job_lineage(self, glue_jobs: List[str]) -> List[DataFlow]:
        """
        Analyze data lineage from AWS Glue jobs.
        
        Args:
            glue_jobs: List of Glue job names
            
        Returns:
            List of DataFlow objects
        """
        flows = []
        
        if not self.glue:
            logger.warning("Glue client not available")
            return flows
        
        try:
            for job_name in glue_jobs:
                # Get job details
                response = self.glue.get_job(JobName=job_name)
                job = response.get('Job', {})
                
                # Extract source and target from job definition
                # This is simplified - actual implementation would parse job script
                command = job.get('Command', {})
                script_location = command.get('ScriptLocation', '')
                
                # Parse for data sources and targets
                # Example: Extract S3 paths from job script
                # flows.append(DataFlow(...))
        
        except Exception as e:
            logger.error(f"Error analyzing Glue job lineage: {e}")
        
        return flows
    
    def build_lineage_graph(self, data_stores: List[Dict], cloudtrail_events: Optional[List[Dict]] = None) -> Dict[str, List[DataFlow]]:
        """
        Build lineage graph for data stores.
        
        Args:
            data_stores: List of data store assets
            cloudtrail_events: Optional pre-fetched CloudTrail events
            
        Returns:
            Dictionary mapping resource_id to list of flows
        """
        lineage_graph = {}
        
        # Extract S3 buckets and other resources
        s3_buckets = [ds.get("resource_id") for ds in data_stores if "s3:bucket" in ds.get("resource_type", "")]
        
        # Analyze flows (simplified - would use actual CloudTrail log parsing)
        # flows = self.analyze_s3_to_redshift_flows(s3_buckets, [])
        
        # Build graph structure
        for store in data_stores:
            resource_id = store.get("resource_uid") or store.get("resource_arn")
            if resource_id:
                lineage_graph[resource_id] = []
        
        return lineage_graph


# Convenience function
def build_data_lineage(data_stores: List[Dict], aws_session: Optional[boto3.Session] = None) -> Dict[str, List[DataFlow]]:
    """Build data lineage graph for data stores."""
    analyzer = LineageAnalyzer(aws_session)
    return analyzer.build_lineage_graph(data_stores)

