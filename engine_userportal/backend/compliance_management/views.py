"""
Views for Compliance Management
Proxies to Compliance Engine API
"""
import hashlib
import json
from django.http import HttpResponseNotModified
from django.utils.encoding import force_bytes
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.exceptions import ValidationError

from utils.engine_clients import ComplianceEngineClient
from .serializers import (
    ComplianceFrameworkSerializer,
    ComplianceControlSerializer,
    ComplianceFindingSerializer,
    ComplianceTrendSerializer
)


class ComplianceViewSet(viewsets.ViewSet):
    """ViewSet for Compliance - proxies to Compliance Engine API"""

    @action(detail=False, methods=['post'])
    def generate(self, request):
        """Generate compliance report"""
        scan_id = request.data.get('scan_id')
        csp = request.data.get('csp')
        frameworks = request.data.get('frameworks')
        
        if not scan_id or not csp:
            raise ValidationError({"scan_id": "This field is required", "csp": "This field is required"})

        client = ComplianceEngineClient()
        
        try:
            report = client.generate_report(
                scan_id=scan_id,
                csp=csp,
                frameworks=frameworks
            )
            
            return Response({
                "success": True,
                "message": "Compliance report generated successfully",
                "data": report
            })
        except Exception as e:
            return Response({
                "success": False,
                "message": f"Failed to generate report: {str(e)}"
            }, status=500)

    @action(detail=False, methods=['get'], url_path='framework/(?P<framework>[^/.]+)/status')
    def framework_status(self, request, framework=None):
        """Get framework compliance status"""
        scan_id = request.query_params.get('scan_id')
        csp = request.query_params.get('csp')
        
        if not scan_id or not csp:
            raise ValidationError({"scan_id": "This field is required", "csp": "This field is required"})

        client = ComplianceEngineClient()
        
        try:
            framework_data = client.get_framework_status(
                framework=framework,
                scan_id=scan_id,
                csp=csp
            )
            
            serializer = ComplianceFrameworkSerializer(framework_data)
            return Response({
                "success": True,
                "message": "Framework status fetched successfully",
                "data": serializer.data
            })
        except Exception as e:
            return Response({
                "success": False,
                "message": f"Failed to fetch framework status: {str(e)}"
            }, status=500)

    @action(detail=False, methods=['get'], url_path='framework/(?P<framework>[^/.]+)/control/(?P<control_id>[^/.]+)')
    def control_detail(self, request, framework=None, control_id=None):
        """Get control detail"""
        scan_id = request.query_params.get('scan_id')
        csp = request.query_params.get('csp')
        
        if not scan_id or not csp:
            raise ValidationError({"scan_id": "This field is required", "csp": "This field is required"})

        client = ComplianceEngineClient()
        
        try:
            control = client.get_control_detail(
                framework=framework,
                control_id=control_id,
                scan_id=scan_id,
                csp=csp
            )
            
            serializer = ComplianceControlSerializer(control)
            return Response({
                "success": True,
                "message": "Control detail fetched successfully",
                "data": serializer.data
            })
        except Exception as e:
            return Response({
                "success": False,
                "message": f"Failed to fetch control detail: {str(e)}"
            }, status=500)

    @action(detail=False, methods=['get'])
    def trends(self, request):
        """Get compliance trends"""
        csp = request.query_params.get('csp')
        if not csp:
            raise ValidationError({"csp": "This field is required"})

        client = ComplianceEngineClient()
        
        try:
            trend_data = client.get_trends(
                csp=csp,
                account_id=request.query_params.get('account_id'),
                days=int(request.query_params.get('days', 30)),
                framework=request.query_params.get('framework')
            )
            
            trends = trend_data.get('trend_data', [])
            serializer = ComplianceTrendSerializer(trends, many=True)
            return Response({
                "success": True,
                "message": "Trends fetched successfully",
                "data": serializer.data
            })
        except Exception as e:
            return Response({
                "success": False,
                "message": f"Failed to fetch trends: {str(e)}"
            }, status=500)

    @action(detail=False, methods=['get'], url_path='accounts/(?P<account_id>[^/.]+)')
    def account_compliance(self, request, account_id=None):
        """Get account compliance"""
        scan_id = request.query_params.get('scan_id')
        csp = request.query_params.get('csp')
        
        if not scan_id or not csp:
            raise ValidationError({"scan_id": "This field is required", "csp": "This field is required"})

        client = ComplianceEngineClient()
        
        try:
            compliance = client.get_account_compliance(
                account_id=account_id,
                scan_id=scan_id,
                csp=csp
            )
            
            return Response({
                "success": True,
                "message": "Account compliance fetched successfully",
                "data": compliance
            })
        except Exception as e:
            return Response({
                "success": False,
                "message": f"Failed to fetch account compliance: {str(e)}"
            }, status=500)
