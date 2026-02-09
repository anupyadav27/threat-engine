from rest_framework import status
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response

from user_auth.auth import CookieTokenAuthentication
from user_auth.permissions import TenantScoped
from utils.engine_clients import SecOpsEngineClient


@api_view(["GET"])
@authentication_classes([CookieTokenAuthentication])
@permission_classes([TenantScoped])
def list_scans(request: Request):
    """List SecOps scans. Query params: tenant_id, customer_id, scan_id, limit."""
    client = SecOpsEngineClient()
    tenant_id = getattr(request, "tenant_id", None) or request.query_params.get("tenant_id")
    customer_id = getattr(request, "customer_id", None) or request.query_params.get("customer_id")
    scan_id = request.query_params.get("scan_id")
    limit = int(request.query_params.get("limit", 50))
    data = client.list_scans(
        tenant_id=tenant_id,
        customer_id=customer_id,
        scan_id=scan_id,
        limit=limit,
    )
    return Response(data)


@api_view(["GET"])
@authentication_classes([CookieTokenAuthentication])
@permission_classes([IsAuthenticated])
def get_scan(request: Request, scan_id: str):
    """Get a single SecOps scan by scan_id."""
    client = SecOpsEngineClient()
    data = client.get_scan(scan_id)
    if data is None:
        return Response({"detail": "Scan not found"}, status=status.HTTP_404_NOT_FOUND)
    return Response(data)


@api_view(["GET"])
@authentication_classes([CookieTokenAuthentication])
@permission_classes([IsAuthenticated])
def get_findings(request: Request, scan_id: str):
    """Get findings for a SecOps scan. Query params: limit."""
    client = SecOpsEngineClient()
    limit = int(request.query_params.get("limit", 500))
    data = client.get_findings(scan_id=scan_id, limit=limit)
    return Response(data)
