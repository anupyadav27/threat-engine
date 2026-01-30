"""
Views for DataSec Management
Proxies to DataSec Engine API
"""
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.exceptions import ValidationError

from utils.engine_clients import DataSecEngineClient
from .serializers import (
    DataCatalogSerializer,
    DataSecurityFindingSerializer,
    DataClassificationSerializer,
    DataResidencySerializer
)


class DataSecViewSet(viewsets.ViewSet):
    """ViewSet for DataSec - proxies to DataSec Engine API"""

    @action(detail=False, methods=['post'])
    def scan(self, request):
        """Generate data security scan"""
        scan_id = request.data.get('scan_id')
        csp = request.data.get('csp')
        
        if not scan_id or not csp:
            raise ValidationError({"scan_id": "This field is required", "csp": "This field is required"})

        client = DataSecEngineClient()
        
        try:
            report = client.generate_scan(
                scan_id=scan_id,
                csp=csp
            )
            
            return Response({
                "success": True,
                "message": "Data security scan generated successfully",
                "data": report
            })
        except Exception as e:
            return Response({
                "success": False,
                "message": f"Failed to generate scan: {str(e)}"
            }, status=500)

    @action(detail=False, methods=['get'])
    def catalog(self, request):
        """Get data catalog"""
        csp = request.query_params.get('csp')
        if not csp:
            raise ValidationError({"csp": "This field is required"})

        client = DataSecEngineClient()
        
        try:
            catalog_data = client.get_catalog(
                csp=csp,
                scan_id=request.query_params.get('scan_id', 'latest'),
                account_id=request.query_params.get('account_id'),
                service=request.query_params.get('service'),
                region=request.query_params.get('region')
            )
            
            catalog_items = catalog_data.get('catalog', [])
            serializer = DataCatalogSerializer(catalog_items, many=True)
            return Response({
                "success": True,
                "message": "Catalog fetched successfully",
                "data": serializer.data
            })
        except Exception as e:
            return Response({
                "success": False,
                "message": f"Failed to fetch catalog: {str(e)}"
            }, status=500)

    @action(detail=False, methods=['get'])
    def findings(self, request):
        """Get data security findings"""
        csp = request.query_params.get('csp')
        if not csp:
            raise ValidationError({"csp": "This field is required"})

        client = DataSecEngineClient()
        
        try:
            findings_data = client.get_findings(
                csp=csp,
                scan_id=request.query_params.get('scan_id', 'latest')
            )
            
            findings = findings_data.get('findings', [])
            serializer = DataSecurityFindingSerializer(findings, many=True)
            return Response({
                "success": True,
                "message": "Findings fetched successfully",
                "data": serializer.data
            })
        except Exception as e:
            return Response({
                "success": False,
                "message": f"Failed to fetch findings: {str(e)}"
            }, status=500)

    @action(detail=False, methods=['get'])
    def classification(self, request):
        """Get data classification"""
        resource_arn = request.query_params.get('resource_arn')
        if not resource_arn:
            raise ValidationError({"resource_arn": "This field is required"})

        client = DataSecEngineClient()
        
        try:
            classification = client.get_classification(resource_arn=resource_arn)
            serializer = DataClassificationSerializer(classification)
            return Response({
                "success": True,
                "message": "Classification fetched successfully",
                "data": serializer.data
            })
        except Exception as e:
            return Response({
                "success": False,
                "message": f"Failed to fetch classification: {str(e)}"
            }, status=500)

    @action(detail=False, methods=['get'])
    def residency(self, request):
        """Get data residency"""
        resource_arn = request.query_params.get('resource_arn')
        if not resource_arn:
            raise ValidationError({"resource_arn": "This field is required"})

        client = DataSecEngineClient()
        
        try:
            residency = client.get_residency(resource_arn=resource_arn)
            serializer = DataResidencySerializer(residency)
            return Response({
                "success": True,
                "message": "Residency fetched successfully",
                "data": serializer.data
            })
        except Exception as e:
            return Response({
                "success": False,
                "message": f"Failed to fetch residency: {str(e)}"
            }, status=500)
