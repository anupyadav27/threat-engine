"""
Views for admin management app.
"""
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django.db import connection, transaction
from django.contrib.auth.hashers import make_password
from common.permissions import IsAdmin, IsSuperAdmin
from .serializers import (
    UserSerializer,
    TenantSerializer,
    CreateUserSerializer,
    UpdateUserSerializer,
    CreateTenantSerializer,
    UpdateTenantSerializer,
    AssignTenantSerializer
)
from apps.admin_audit.models import AdminAuditLog


class UserViewSet(viewsets.ViewSet):
    """ViewSet for user management."""
    permission_classes = [IsAdmin]
    
    def list(self, request):
        """List all users."""
        page = int(request.query_params.get('page', 1))
        page_size = int(request.query_params.get('page_size', 50))
        offset = (page - 1) * page_size
        
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT user_id, email, first_name, last_name, is_active, is_superuser, created_at, last_login
                FROM users
                ORDER BY created_at DESC
                LIMIT %s OFFSET %s
            """, [page_size, offset])
            columns = [col[0] for col in cursor.description]
            users = [dict(zip(columns, row)) for row in cursor.fetchall()]
            
            cursor.execute("SELECT COUNT(*) FROM users")
            total = cursor.fetchone()[0]
        
        serializer = UserSerializer(users, many=True)
        return Response({
            'results': serializer.data,
            'count': total,
            'page': page,
            'page_size': page_size
        })
    
    def create(self, request):
        """Create a new user."""
        if not request.user.is_superuser:
            return Response(
                {'error': 'Only super admins can create users'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        serializer = CreateUserSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        data = serializer.validated_data
        
        with transaction.atomic():
            with connection.cursor() as cursor:
                import uuid
                user_id = str(uuid.uuid4())
                password_hash = make_password(data['password'])
                
                cursor.execute("""
                    INSERT INTO users (user_id, email, password, first_name, last_name, is_active, is_superuser, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
                    RETURNING user_id, email, first_name, last_name, is_active, is_superuser, created_at, last_login
                """, [
                    user_id,
                    data['email'],
                    password_hash,
                    data.get('first_name', ''),
                    data.get('last_name', ''),
                    data.get('is_active', True),
                    False  # is_superuser
                ])
                
                columns = [col[0] for col in cursor.description]
                user = dict(zip(columns, cursor.fetchone()))
                
                # Assign roles if provided
                if data.get('roles'):
                    for role_name in data['roles']:
                        cursor.execute("""
                            SELECT role_id FROM roles WHERE name = %s
                        """, [role_name])
                        role_result = cursor.fetchone()
                        if role_result:
                            role_id = role_result[0]
                            cursor.execute("""
                                INSERT INTO user_roles (user_id, role_id)
                                VALUES (%s, %s)
                                ON CONFLICT DO NOTHING
                            """, [user_id, role_id])
        
        # Audit log
        AdminAuditLog.objects.create(
            admin_user_id=str(request.user.id),
            action_type='user_create',
            resource_type='user',
            resource_id=user_id,
            details={'email': data['email']},
            ip_address=self._get_client_ip(request)
        )
        
        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    
    def retrieve(self, request, pk=None):
        """Get user details."""
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT user_id, email, first_name, last_name, is_active, is_superuser, created_at, last_login
                FROM users
                WHERE user_id = %s
            """, [pk])
            columns = [col[0] for col in cursor.description]
            row = cursor.fetchone()
            if not row:
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
            user = dict(zip(columns, row))
        
        serializer = UserSerializer(user)
        return Response(serializer.data)
    
    def update(self, request, pk=None):
        """Update user."""
        if not request.user.is_superuser:
            return Response(
                {'error': 'Only super admins can update users'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        serializer = UpdateUserSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        data = serializer.validated_data
        
        with transaction.atomic():
            with connection.cursor() as cursor:
                updates = []
                values = []
                
                if 'email' in data:
                    updates.append("email = %s")
                    values.append(data['email'])
                if 'first_name' in data:
                    updates.append("first_name = %s")
                    values.append(data.get('first_name', ''))
                if 'last_name' in data:
                    updates.append("last_name = %s")
                    values.append(data.get('last_name', ''))
                if 'is_active' in data:
                    updates.append("is_active = %s")
                    values.append(data['is_active'])
                
                if updates:
                    values.append(pk)
                    cursor.execute(f"""
                        UPDATE users
                        SET {', '.join(updates)}, updated_at = NOW()
                        WHERE user_id = %s
                        RETURNING user_id, email, first_name, last_name, is_active, is_superuser, created_at, last_login
                    """, values)
                    
                    columns = [col[0] for col in cursor.description]
                    user = dict(zip(columns, cursor.fetchone()))
                else:
                    # Just fetch existing user
                    cursor.execute("""
                        SELECT user_id, email, first_name, last_name, is_active, is_superuser, created_at, last_login
                        FROM users WHERE user_id = %s
                    """, [pk])
                    columns = [col[0] for col in cursor.description]
                    user = dict(zip(columns, cursor.fetchone()))
                
                # Update roles if provided
                if 'roles' in data:
                    # Remove existing roles
                    cursor.execute("DELETE FROM user_roles WHERE user_id = %s", [pk])
                    # Add new roles
                    for role_name in data['roles']:
                        cursor.execute("SELECT role_id FROM roles WHERE name = %s", [role_name])
                        role_result = cursor.fetchone()
                        if role_result:
                            role_id = role_result[0]
                            cursor.execute("""
                                INSERT INTO user_roles (user_id, role_id)
                                VALUES (%s, %s)
                            """, [pk, role_id])
        
        # Audit log
        AdminAuditLog.objects.create(
            admin_user_id=str(request.user.id),
            action_type='user_update',
            resource_type='user',
            resource_id=pk,
            details=data,
            ip_address=self._get_client_ip(request)
        )
        
        serializer = UserSerializer(user)
        return Response(serializer.data)
    
    def destroy(self, request, pk=None):
        """Deactivate user (soft delete)."""
        if not request.user.is_superuser:
            return Response(
                {'error': 'Only super admins can deactivate users'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        with transaction.atomic():
            with connection.cursor() as cursor:
                cursor.execute("""
                    UPDATE users
                    SET is_active = FALSE, updated_at = NOW()
                    WHERE user_id = %s
                """, [pk])
        
        # Audit log
        AdminAuditLog.objects.create(
            admin_user_id=str(request.user.id),
            action_type='user_delete',
            resource_type='user',
            resource_id=pk,
            ip_address=self._get_client_ip(request)
        )
        
        return Response(status=status.HTTP_204_NO_CONTENT)
    
    @action(detail=True, methods=['get'])
    def tenants(self, request, pk=None):
        """Get user's tenants."""
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT t.tenant_id, t.tenant_name, t.status, tu.role
                FROM tenants t
                JOIN tenant_users tu ON t.tenant_id = tu.tenant_id
                WHERE tu.user_id = %s
            """, [pk])
            columns = [col[0] for col in cursor.description]
            tenants = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        serializer = TenantSerializer(tenants, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def assign_tenant(self, request, pk=None):
        """Assign tenant to user."""
        serializer = AssignTenantSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        data = serializer.validated_data
        
        with transaction.atomic():
            with connection.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO tenant_users (user_id, tenant_id, role)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (user_id, tenant_id) DO UPDATE SET role = %s
                """, [pk, data['tenant_id'], data.get('role', 'member'), data.get('role', 'member')])
        
        # Audit log
        AdminAuditLog.objects.create(
            admin_user_id=str(request.user.id),
            action_type='role_assign',
            resource_type='tenant_user',
            resource_id=f"{pk}:{data['tenant_id']}",
            details=data,
            ip_address=self._get_client_ip(request)
        )
        
        return Response({'message': 'Tenant assigned successfully'}, status=status.HTTP_200_OK)
    
    def _get_client_ip(self, request):
        """Get client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class TenantManagementViewSet(viewsets.ViewSet):
    """ViewSet for tenant management."""
    permission_classes = [IsAdmin]
    
    def list(self, request):
        """List all tenants."""
        page = int(request.query_params.get('page', 1))
        page_size = int(request.query_params.get('page_size', 50))
        offset = (page - 1) * page_size
        
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT tenant_id, tenant_name, status, created_at, updated_at
                FROM tenants
                ORDER BY created_at DESC
                LIMIT %s OFFSET %s
            """, [page_size, offset])
            columns = [col[0] for col in cursor.description]
            tenants = [dict(zip(columns, row)) for row in cursor.fetchall()]
            
            cursor.execute("SELECT COUNT(*) FROM tenants")
            total = cursor.fetchone()[0]
        
        serializer = TenantSerializer(tenants, many=True)
        return Response({
            'results': serializer.data,
            'count': total,
            'page': page,
            'page_size': page_size
        })
    
    def create(self, request):
        """Create a new tenant."""
        if not request.user.is_superuser:
            return Response(
                {'error': 'Only super admins can create tenants'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        serializer = CreateTenantSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        data = serializer.validated_data
        
        with transaction.atomic():
            with connection.cursor() as cursor:
                import uuid
                tenant_id = str(uuid.uuid4())
                
                cursor.execute("""
                    INSERT INTO tenants (tenant_id, tenant_name, status, created_at, updated_at)
                    VALUES (%s, %s, %s, NOW(), NOW())
                    RETURNING tenant_id, tenant_name, status, created_at, updated_at
                """, [tenant_id, data['tenant_name'], data.get('status', 'active')])
                
                columns = [col[0] for col in cursor.description]
                tenant = dict(zip(columns, cursor.fetchone()))
        
        # Audit log
        AdminAuditLog.objects.create(
            admin_user_id=str(request.user.id),
            action_type='tenant_create',
            resource_type='tenant',
            resource_id=tenant_id,
            details={'tenant_name': data['tenant_name']},
            ip_address=self._get_client_ip(request)
        )
        
        serializer = TenantSerializer(tenant)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    
    def update(self, request, pk=None):
        """Update tenant."""
        if not request.user.is_superuser:
            return Response(
                {'error': 'Only super admins can update tenants'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        serializer = UpdateTenantSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        data = serializer.validated_data
        
        with transaction.atomic():
            with connection.cursor() as cursor:
                updates = []
                values = []
                
                if 'tenant_name' in data:
                    updates.append("tenant_name = %s")
                    values.append(data['tenant_name'])
                if 'status' in data:
                    updates.append("status = %s")
                    values.append(data['status'])
                
                if updates:
                    values.append(pk)
                    cursor.execute(f"""
                        UPDATE tenants
                        SET {', '.join(updates)}, updated_at = NOW()
                        WHERE tenant_id = %s
                        RETURNING tenant_id, tenant_name, status, created_at, updated_at
                    """, values)
                    
                    columns = [col[0] for col in cursor.description]
                    tenant = dict(zip(columns, cursor.fetchone()))
                else:
                    cursor.execute("""
                        SELECT tenant_id, tenant_name, status, created_at, updated_at
                        FROM tenants WHERE tenant_id = %s
                    """, [pk])
                    columns = [col[0] for col in cursor.description]
                    tenant = dict(zip(columns, cursor.fetchone()))
        
        # Audit log
        AdminAuditLog.objects.create(
            admin_user_id=str(request.user.id),
            action_type='tenant_update',
            resource_type='tenant',
            resource_id=pk,
            details=data,
            ip_address=self._get_client_ip(request)
        )
        
        serializer = TenantSerializer(tenant)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def suspend(self, request, pk=None):
        """Suspend tenant."""
        if not request.user.is_superuser:
            return Response(
                {'error': 'Only super admins can suspend tenants'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        with transaction.atomic():
            with connection.cursor() as cursor:
                cursor.execute("""
                    UPDATE tenants
                    SET status = 'suspended', updated_at = NOW()
                    WHERE tenant_id = %s
                """, [pk])
        
        # Audit log
        AdminAuditLog.objects.create(
            admin_user_id=str(request.user.id),
            action_type='tenant_suspend',
            resource_type='tenant',
            resource_id=pk,
            ip_address=self._get_client_ip(request)
        )
        
        return Response({'message': 'Tenant suspended'}, status=status.HTTP_200_OK)
    
    @action(detail=True, methods=['post'])
    def activate(self, request, pk=None):
        """Activate tenant."""
        if not request.user.is_superuser:
            return Response(
                {'error': 'Only super admins can activate tenants'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        with transaction.atomic():
            with connection.cursor() as cursor:
                cursor.execute("""
                    UPDATE tenants
                    SET status = 'active', updated_at = NOW()
                    WHERE tenant_id = %s
                """, [pk])
        
        # Audit log
        AdminAuditLog.objects.create(
            admin_user_id=str(request.user.id),
            action_type='tenant_activate',
            resource_type='tenant',
            resource_id=pk,
            ip_address=self._get_client_ip(request)
        )
        
        return Response({'message': 'Tenant activated'}, status=status.HTTP_200_OK)
    
    @action(detail=True, methods=['get'])
    def users(self, request, pk=None):
        """Get tenant's users."""
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT u.user_id, u.email, u.first_name, u.last_name, tu.role
                FROM users u
                JOIN tenant_users tu ON u.user_id = tu.user_id
                WHERE tu.tenant_id = %s
            """, [pk])
            columns = [col[0] for col in cursor.description]
            users = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        return Response(users)
    
    @action(detail=True, methods=['get'])
    def accounts(self, request, pk=None):
        """Get tenant's cloud accounts."""
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT account_id, account_name, provider_type, status, onboarding_status
                FROM onboarding_accounts
                WHERE tenant_id = %s
            """, [pk])
            columns = [col[0] for col in cursor.description]
            accounts = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        return Response(accounts)
    
    def _get_client_ip(self, request):
        """Get client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
