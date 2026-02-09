"""
Data Classification Analyzer - Detects PII, PCI, PHI in data content.

This analyzer complements configScan rules by actually scanning object content
for sensitive data patterns. It's Python-based, not YAML rules.
"""

import re
import boto3
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class DataClassification(Enum):
    """Data classification types."""
    PII = "pii"  # Personally Identifiable Information
    PCI = "pci"  # Payment Card Industry data
    PHI = "phi"  # Protected Health Information
    FINANCIAL = "financial"  # Financial data
    CREDENTIALS = "credentials"  # Passwords, API keys
    CUSTOM = "custom"  # Custom patterns


@dataclass
class ClassificationResult:
    """Result of data classification scan."""
    resource_id: str
    resource_arn: str
    resource_type: str
    classification: List[DataClassification]
    confidence: float  # 0.0 to 1.0
    matched_patterns: List[Dict[str, Any]]
    sample_data: Optional[str] = None


class DataClassificationPatterns:
    """Pattern definitions for sensitive data detection."""
    
    # PII Patterns
    PII_PATTERNS = {
        "ssn": re.compile(r'\b\d{3}-?\d{2}-?\d{4}\b'),  # Social Security Number
        "email": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        "phone_us": re.compile(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'),
        "credit_card": re.compile(r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'),
        "passport": re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'),
        "driver_license": re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'),
    }
    
    # PCI Patterns
    PCI_PATTERNS = {
        "credit_card": re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),
        "cvv": re.compile(r'\b\d{3,4}\b'),  # In context of credit card
        "track_data": re.compile(r'%[BT]\d+\^'),
    }
    
    # PHI Patterns
    PHI_PATTERNS = {
        "medical_record": re.compile(r'\bMRN[:\s]?\d+\b', re.IGNORECASE),
        "patient_id": re.compile(r'\bPID[:\s]?\d+\b', re.IGNORECASE),
        "icd_code": re.compile(r'\b[A-Z]\d{2}(?:\.\d+)?\b'),  # ICD-10 codes
        "ndc": re.compile(r'\b\d{4}-?\d{4}-?\d{2}\b'),  # National Drug Code
    }
    
    # Credentials
    CREDENTIAL_PATTERNS = {
        "api_key": re.compile(r'\bAKIA[0-9A-Z]{16}\b'),  # AWS Access Key
        "password": re.compile(r'(?:password|pwd|pass)[:=]\s*["\']?[^\s"\']{6,}["\']?', re.IGNORECASE),
        "token": re.compile(r'\b(?:token|bearer)[:=]\s*[A-Za-z0-9_-]{20,}\b', re.IGNORECASE),
    }


class ClassificationAnalyzer:
    """Analyzes data content for sensitive data classification."""
    
    def __init__(self, aws_session: Optional[boto3.Session] = None):
        """
        Initialize classification analyzer.
        
        Args:
            aws_session: Optional boto3 session (uses default if not provided)
        """
        import os
        region = os.getenv('AWS_REGION', os.getenv('AWS_DEFAULT_REGION', 'ap-south-1'))
        self.session = aws_session or boto3.Session(region_name=region)
        self.s3_client = self.session.client('s3')
        self.patterns = DataClassificationPatterns()
    
    def classify_s3_object(self, bucket: str, key: str, sample_size: int = 1024) -> ClassificationResult:
        """
        Classify an S3 object by sampling its content.
        
        Args:
            bucket: S3 bucket name
            key: Object key
            sample_size: Number of bytes to sample (default: 1KB)
            
        Returns:
            ClassificationResult
        """
        resource_arn = f"arn:aws:s3:::{bucket}/{key}"
        matched_patterns = []
        classifications = set()
        
        try:
            # Get object (sample first N bytes)
            response = self.s3_client.get_object(
                Bucket=bucket,
                Key=key,
                Range=f'bytes=0-{sample_size}'
            )
            
            content = response['Body'].read().decode('utf-8', errors='ignore')
            sample_data = content[:sample_size]
            
            # Check PII patterns
            for pattern_name, pattern in self.patterns.PII_PATTERNS.items():
                if pattern.search(content):
                    matched_patterns.append({
                        "type": "pii",
                        "pattern": pattern_name,
                        "confidence": 0.8 if pattern_name in ["ssn", "email"] else 0.6
                    })
                    classifications.add(DataClassification.PII)
            
            # Check PCI patterns
            for pattern_name, pattern in self.patterns.PCI_PATTERNS.items():
                if pattern.search(content):
                    matched_patterns.append({
                        "type": "pci",
                        "pattern": pattern_name,
                        "confidence": 0.9 if pattern_name == "credit_card" else 0.7
                    })
                    classifications.add(DataClassification.PCI)
            
            # Check PHI patterns
            for pattern_name, pattern in self.patterns.PHI_PATTERNS.items():
                if pattern.search(content):
                    matched_patterns.append({
                        "type": "phi",
                        "pattern": pattern_name,
                        "confidence": 0.75
                    })
                    classifications.add(DataClassification.PHI)
            
            # Check credentials
            for pattern_name, pattern in self.patterns.CREDENTIAL_PATTERNS.items():
                if pattern.search(content):
                    matched_patterns.append({
                        "type": "credentials",
                        "pattern": pattern_name,
                        "confidence": 0.85
                    })
                    classifications.add(DataClassification.CREDENTIALS)
            
            # Calculate overall confidence
            confidence = max([p.get("confidence", 0.5) for p in matched_patterns], default=0.0)
            
        except Exception as e:
            logger.warning(f"Error classifying S3 object {bucket}/{key}: {e}")
            matched_patterns = []
            classifications = set()
            confidence = 0.0
            sample_data = None
        
        return ClassificationResult(
            resource_id=key,
            resource_arn=resource_arn,
            resource_type="s3:object",
            classification=list(classifications),
            confidence=confidence,
            matched_patterns=matched_patterns,
            sample_data=sample_data
        )
    
    def classify_s3_bucket(self, bucket: str, max_objects: int = 10) -> List[ClassificationResult]:
        """
        Classify objects in an S3 bucket by sampling.
        
        Args:
            bucket: S3 bucket name
            max_objects: Maximum number of objects to sample
            
        Returns:
            List of ClassificationResult objects
        """
        results = []
        
        try:
            # List objects in bucket
            paginator = self.s3_client.get_paginator('list_objects_v2')
            pages = paginator.paginate(Bucket=bucket, MaxKeys=max_objects)
            
            for page in pages:
                for obj in page.get('Contents', []):
                    key = obj['Key']
                    
                    # Skip if it's likely binary or very large
                    if obj['Size'] > 10 * 1024 * 1024:  # Skip files > 10MB
                        continue
                    
                    # Classify object
                    result = self.classify_s3_object(bucket, key)
                    if result.classification:  # Only include if classified
                        results.append(result)
        
        except Exception as e:
            logger.error(f"Error classifying S3 bucket {bucket}: {e}")
        
        return results
    
    def classify_resources(self, data_stores: List[Dict]) -> List[ClassificationResult]:
        """
        Classify multiple data stores from inventory.
        
        Args:
            data_stores: List of data store assets from inventory
            
        Returns:
            List of ClassificationResult objects
        """
        results = []
        
        for store in data_stores:
            resource_type = store.get("resource_type", "").lower()
            resource_id = store.get("resource_id", "")
            
            # Handle S3 buckets
            if "s3:bucket" in resource_type or store.get("service", "").lower() == "s3":
                bucket_results = self.classify_s3_bucket(resource_id)
                results.extend(bucket_results)
            # TODO: Add support for RDS, DynamoDB, etc.
        
        return results


# Convenience function
def classify_data_store(resource_arn: str, resource_type: str, aws_session: Optional[boto3.Session] = None) -> ClassificationResult:
    """Classify a data store resource."""
    analyzer = ClassificationAnalyzer(aws_session)
    
    # Parse S3 ARN: arn:aws:s3:::bucket/key
    if resource_type == "s3:object" and resource_arn.startswith("arn:aws:s3:::"):
        parts = resource_arn.replace("arn:aws:s3:::", "").split("/", 1)
        bucket = parts[0]
        key = parts[1] if len(parts) > 1 else ""
        return analyzer.classify_s3_object(bucket, key)
    
    # TODO: Handle other resource types
    raise NotImplementedError(f"Classification not implemented for {resource_type}")

