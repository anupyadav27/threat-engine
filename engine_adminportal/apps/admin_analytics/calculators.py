"""
Analytics calculation logic.
"""
import logging
from typing import Dict, List, Any
from django.db import connection
from django.core.cache import cache
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class AnalyticsCalculator:
    """Calculate various analytics metrics."""
    
    def calculate_overview(self) -> Dict[str, Any]:
        """Calculate platform-wide overview analytics."""
        cache_key = 'analytics_overview'
        cached = cache.get(cache_key)
        if cached:
            return cached
        
        with connection.cursor() as cursor:
            # Tenant counts
            cursor.execute("SELECT COUNT(*) FROM tenants")
            total_tenants = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM tenants WHERE status = 'active'")
            active_tenants = cursor.fetchone()[0]
            inactive_tenants = total_tenants - active_tenants
            
            # Scan counts
            cursor.execute("""
                SELECT 
                    COUNT(*) FILTER (WHERE started_at >= NOW() - INTERVAL '24 hours') as scans_24h,
                    COUNT(*) FILTER (WHERE started_at >= NOW() - INTERVAL '7 days') as scans_7d,
                    COUNT(*) FILTER (WHERE started_at >= NOW() - INTERVAL '30 days') as scans_30d
                FROM onboarding_executions
            """)
            scan_stats = cursor.fetchone()
            
            # Compliance scores
            cursor.execute("""
                SELECT AVG(score) 
                FROM compliance_summary 
                WHERE created_at >= NOW() - INTERVAL '30 days'
            """)
            avg_compliance = cursor.fetchone()[0] or 0.0
            
            # Top failing rules
            cursor.execute("""
                SELECT rule_id, COUNT(*) as failure_count
                FROM scan_findings
                WHERE status = 'failed' AND created_at >= NOW() - INTERVAL '30 days'
                GROUP BY rule_id
                ORDER BY failure_count DESC
                LIMIT 10
            """)
            top_failing_rules = [{'rule_id': row[0], 'failures': row[1]} for row in cursor.fetchall()]
            
            # Resource distribution by provider
            cursor.execute("""
                SELECT provider_type, COUNT(*) as count
                FROM onboarding_accounts
                GROUP BY provider_type
            """)
            resource_distribution = {row[0]: row[1] for row in cursor.fetchall()}
            
            # Scan success rate
            cursor.execute("""
                SELECT 
                    COUNT(*) FILTER (WHERE status = 'completed') as successful,
                    COUNT(*) as total
                FROM onboarding_executions
                WHERE started_at >= NOW() - INTERVAL '30 days'
            """)
            success_stats = cursor.fetchone()
            success_rate = (success_stats[0] / success_stats[1] * 100) if success_stats[1] > 0 else 0.0
            
            # Findings distribution
            cursor.execute("""
                SELECT severity, COUNT(*) as count
                FROM scan_findings
                WHERE created_at >= NOW() - INTERVAL '30 days'
                GROUP BY severity
            """)
            findings_distribution = {row[0]: row[1] for row in cursor.fetchall()}
        
        overview = {
            'total_tenants': total_tenants,
            'active_tenants': active_tenants,
            'inactive_tenants': inactive_tenants,
            'total_scans_24h': scan_stats[0] or 0,
            'total_scans_7d': scan_stats[1] or 0,
            'total_scans_30d': scan_stats[2] or 0,
            'average_compliance_score': round(float(avg_compliance), 2),
            'top_failing_rules': top_failing_rules,
            'resource_distribution': resource_distribution,
            'scan_success_rate': round(success_rate, 2),
            'findings_distribution': findings_distribution
        }
        
        cache.set(cache_key, overview, 300)  # Cache for 5 minutes
        return overview
    
    def calculate_compliance_analytics(self) -> Dict[str, Any]:
        """Calculate compliance analytics."""
        cache_key = 'analytics_compliance'
        cached = cache.get(cache_key)
        if cached:
            return cached
        
        with connection.cursor() as cursor:
            # Overall average
            cursor.execute("""
                SELECT AVG(score) 
                FROM compliance_summary 
                WHERE created_at >= NOW() - INTERVAL '30 days'
            """)
            overall_avg = cursor.fetchone()[0] or 0.0
            
            # By framework
            cursor.execute("""
                SELECT framework, AVG(score) as avg_score
                FROM compliance_summary
                WHERE created_at >= NOW() - INTERVAL '30 days'
                GROUP BY framework
            """)
            by_framework = {row[0]: round(float(row[1]), 2) for row in cursor.fetchall()}
            
            # By tenant
            cursor.execute("""
                SELECT tenant_id, AVG(score) as avg_score
                FROM compliance_summary
                WHERE created_at >= NOW() - INTERVAL '30 days'
                GROUP BY tenant_id
                ORDER BY avg_score DESC
                LIMIT 20
            """)
            by_tenant = [{'tenant_id': row[0], 'score': round(float(row[1]), 2)} for row in cursor.fetchall()]
            
            # Trends (last 7 days)
            cursor.execute("""
                SELECT 
                    DATE(created_at) as date,
                    AVG(score) as avg_score
                FROM compliance_summary
                WHERE created_at >= NOW() - INTERVAL '7 days'
                GROUP BY DATE(created_at)
                ORDER BY date
            """)
            trends = [{'date': str(row[0]), 'score': round(float(row[1]), 2)} for row in cursor.fetchall()]
        
        analytics = {
            'overall_average': round(float(overall_avg), 2),
            'by_framework': by_framework,
            'by_tenant': by_tenant,
            'trends': trends
        }
        
        cache.set(cache_key, analytics, 300)
        return analytics
    
    def calculate_scan_analytics(self) -> Dict[str, Any]:
        """Calculate scan statistics."""
        cache_key = 'analytics_scans'
        cached = cache.get(cache_key)
        if cached:
            return cached
        
        with connection.cursor() as cursor:
            # Total scans
            cursor.execute("""
                SELECT 
                    COUNT(*) as total,
                    COUNT(*) FILTER (WHERE status = 'completed') as successful,
                    COUNT(*) FILTER (WHERE status = 'failed') as failed
                FROM onboarding_executions
                WHERE started_at >= NOW() - INTERVAL '30 days'
            """)
            scan_stats = cursor.fetchone()
            total = scan_stats[0] or 0
            successful = scan_stats[1] or 0
            failed = scan_stats[2] or 0
            success_rate = (successful / total * 100) if total > 0 else 0.0
            
            # Average duration
            cursor.execute("""
                SELECT AVG(EXTRACT(EPOCH FROM (completed_at - started_at)))
                FROM onboarding_executions
                WHERE status = 'completed' AND completed_at IS NOT NULL
                AND started_at >= NOW() - INTERVAL '30 days'
            """)
            avg_duration = cursor.fetchone()[0] or 0.0
            
            # Scans by provider
            cursor.execute("""
                SELECT provider_type, COUNT(*) as count
                FROM onboarding_executions e
                JOIN onboarding_accounts a ON e.account_id = a.account_id
                WHERE e.started_at >= NOW() - INTERVAL '30 days'
                GROUP BY provider_type
            """)
            scans_by_provider = {row[0]: row[1] for row in cursor.fetchall()}
            
            # Scans by tenant
            cursor.execute("""
                SELECT tenant_id, COUNT(*) as count
                FROM onboarding_executions
                WHERE started_at >= NOW() - INTERVAL '30 days'
                GROUP BY tenant_id
                ORDER BY count DESC
                LIMIT 20
            """)
            scans_by_tenant = [{'tenant_id': row[0], 'count': row[1]} for row in cursor.fetchall()]
        
        analytics = {
            'total_scans': total,
            'successful_scans': successful,
            'failed_scans': failed,
            'success_rate': round(success_rate, 2),
            'average_duration': round(float(avg_duration), 2),
            'scans_by_provider': scans_by_provider,
            'scans_by_tenant': scans_by_tenant
        }
        
        cache.set(cache_key, analytics, 300)
        return analytics
    
    def calculate_trends(self, metric_name: str, days: int = 30) -> Dict[str, Any]:
        """Calculate time-series trends."""
        cache_key = f'analytics_trends_{metric_name}_{days}'
        cached = cache.get(cache_key)
        if cached:
            return cached
        
        # This is a simplified version - can be extended for different metrics
        with connection.cursor() as cursor:
            if metric_name == 'scans':
                cursor.execute("""
                    SELECT 
                        DATE(started_at) as date,
                        COUNT(*) as count
                    FROM onboarding_executions
                    WHERE started_at >= NOW() - INTERVAL '%s days'
                    GROUP BY DATE(started_at)
                    ORDER BY date
                """, [days])
                data_points = [{'date': str(row[0]), 'value': row[1]} for row in cursor.fetchall()]
            elif metric_name == 'compliance':
                cursor.execute("""
                    SELECT 
                        DATE(created_at) as date,
                        AVG(score) as avg_score
                    FROM compliance_summary
                    WHERE created_at >= NOW() - INTERVAL '%s days'
                    GROUP BY DATE(created_at)
                    ORDER BY date
                """, [days])
                data_points = [{'date': str(row[0]), 'value': round(float(row[1]), 2)} for row in cursor.fetchall()]
            else:
                data_points = []
        
        trends = {
            'metric_name': metric_name,
            'data_points': data_points,
            'period': f'{days} days'
        }
        
        cache.set(cache_key, trends, 300)
        return trends
    
    def compare_tenants(self, tenant_ids: List[str]) -> Dict[str, Any]:
        """Compare metrics across tenants."""
        comparison_data = []
        
        for tenant_id in tenant_ids:
            with connection.cursor() as cursor:
                # Get compliance scores
                cursor.execute("""
                    SELECT AVG(score) 
                    FROM compliance_summary 
                    WHERE tenant_id = %s AND created_at >= NOW() - INTERVAL '30 days'
                """, [tenant_id])
                compliance_score = cursor.fetchone()[0] or 0.0
                
                # Get scan counts
                cursor.execute("""
                    SELECT COUNT(*) 
                    FROM onboarding_executions
                    WHERE tenant_id = %s AND started_at >= NOW() - INTERVAL '30 days'
                """, [tenant_id])
                scan_count = cursor.fetchone()[0] or 0
                
                # Get findings
                cursor.execute("""
                    SELECT COUNT(*) 
                    FROM scan_findings
                    WHERE tenant_id = %s AND created_at >= NOW() - INTERVAL '30 days'
                """, [tenant_id])
                findings_count = cursor.fetchone()[0] or 0
            
            comparison_data.append({
                'tenant_id': tenant_id,
                'compliance_score': round(float(compliance_score), 2),
                'scan_count': scan_count,
                'findings_count': findings_count
            })
        
        return {
            'tenants': tenant_ids,
            'metrics': ['compliance_score', 'scan_count', 'findings_count'],
            'comparison_data': comparison_data
        }


# Global instance
analytics_calculator = AnalyticsCalculator()
