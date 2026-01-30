"""
Views for engine integration and health monitoring.
"""
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.db import connection
from common.permissions import IsAdmin
from .health_checker import health_checker
from .clients import engine_manager


class HealthCheckView(APIView):
    """Basic health check endpoint."""
    permission_classes = []  # Public endpoint
    
    def get(self, request):
        return Response({
            'status': 'healthy',
            'service': 'admin-portal-backend'
        })


class EngineHealthView(APIView):
    """Get health status of all engines."""
    permission_classes = [IsAdmin]
    
    def get(self, request):
        results = health_checker.check_all_engines()
        return Response(results)


class DatabaseHealthView(APIView):
    """Get database health status."""
    permission_classes = [IsAdmin]
    
    def get(self, request):
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                cursor.fetchone()
            
            return Response({
                'status': 'healthy',
                'database': 'connected',
                'engine': connection.vendor
            })
        except Exception as e:
            return Response({
                'status': 'unhealthy',
                'database': 'disconnected',
                'error': str(e)
            }, status=status.HTTP_503_SERVICE_UNAVAILABLE)


class ServicesHealthView(APIView):
    """Get health status of all services."""
    permission_classes = [IsAdmin]
    
    def get(self, request):
        services = {
            'engines': health_checker.check_all_engines(),
            'database': self._check_database(),
        }
        
        overall_status = 'healthy'
        for service_name, service_data in services.items():
            if isinstance(service_data, dict) and service_data.get('status') != 'healthy':
                overall_status = 'degraded'
        
        return Response({
            'status': overall_status,
            'services': services
        })
    
    def _check_database(self):
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
            return {'status': 'healthy', 'database': 'connected'}
        except Exception as e:
            return {'status': 'unhealthy', 'error': str(e)}


class HealthSummaryView(APIView):
    """Get overall system health summary."""
    permission_classes = [IsAdmin]
    
    def get(self, request):
        engine_health = health_checker.check_all_engines()
        db_health = self._check_database()
        
        healthy_engines = sum(1 for h in engine_health.values() if h.get('status') == 'healthy')
        total_engines = len(engine_health)
        
        overall_status = 'healthy'
        if db_health.get('status') != 'healthy':
            overall_status = 'unhealthy'
        elif healthy_engines < total_engines:
            overall_status = 'degraded'
        
        return Response({
            'status': overall_status,
            'engines': {
                'healthy': healthy_engines,
                'total': total_engines,
                'details': engine_health
            },
            'database': db_health
        })
    
    def _check_database(self):
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
            return {'status': 'healthy', 'database': 'connected'}
        except Exception as e:
            return {'status': 'unhealthy', 'error': str(e)}
