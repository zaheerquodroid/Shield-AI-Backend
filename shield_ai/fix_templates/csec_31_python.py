"""
Fix templates for CSEC-31: Missing Audit Logging Infrastructure (Python/Django)
"""

# ============================================================================
# COMPONENT 1: AUDITLOG MODEL
# ============================================================================

AUDIT_LOG_MODEL = '''
# Shield AI: AuditLog Model
# File: models.py or audit/models.py

import uuid
from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone

User = get_user_model()


class AuditLog(models.Model):
    """
    Audit log for tracking security-relevant actions.

    Records all authentication events, authorization failures,
    and data modifications for compliance and security monitoring.
    """

    # Action types
    ACTION_CHOICES = [
        # Authentication
        ('login_success', 'Login Success'),
        ('login_failed', 'Login Failed'),
        ('logout', 'Logout'),
        ('signup', 'Signup'),
        ('password_reset', 'Password Reset'),
        ('password_changed', 'Password Changed'),
        ('mfa_enabled', 'MFA Enabled'),
        ('mfa_disabled', 'MFA Disabled'),
        ('session_revoked', 'Session Revoked'),

        # Authorization
        ('permission_denied', 'Permission Denied'),
        ('role_changed', 'Role Changed'),
        ('access_granted', 'Access Granted'),

        # Data operations
        ('create', 'Create'),
        ('update', 'Update'),
        ('delete', 'Delete'),
        ('bulk_delete', 'Bulk Delete'),
        ('export', 'Export'),
        ('import', 'Import'),

        # Security
        ('suspicious_activity', 'Suspicious Activity'),
        ('rate_limit_exceeded', 'Rate Limit Exceeded'),
        ('account_locked', 'Account Locked'),
        ('account_unlocked', 'Account Unlocked'),
        ('user_impersonation', 'User Impersonation'),

        # System
        ('configuration_changed', 'Configuration Changed'),
        ('admin_action', 'Admin Action'),
    ]

    # Primary fields
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)

    # User context
    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='audit_logs',
        help_text='User who performed the action (null for anonymous)',
    )
    username = models.CharField(
        max_length=150,
        blank=True,
        help_text='Username snapshot (preserved even if user deleted)',
    )

    # Action details
    action = models.CharField(
        max_length=50,
        choices=ACTION_CHOICES,
        db_index=True,
        help_text='Type of action performed',
    )

    # Resource context
    resource_type = models.CharField(
        max_length=100,
        blank=True,
        db_index=True,
        help_text='Type of resource affected (e.g., User, Order, Product)',
    )
    resource_id = models.CharField(
        max_length=255,
        blank=True,
        help_text='ID of resource affected',
    )

    # Request context
    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text='Client IP address',
    )
    user_agent = models.TextField(
        blank=True,
        help_text='Browser/client user agent string',
    )
    request_id = models.UUIDField(
        null=True,
        blank=True,
        help_text='Request correlation ID for tracing',
    )

    # Additional details
    details = models.JSONField(
        default=dict,
        blank=True,
        help_text='Additional context (before/after values, error messages, etc.)',
    )

    # Optional: Multi-tenancy
    tenant_id = models.CharField(
        max_length=100,
        blank=True,
        db_index=True,
        help_text='Tenant identifier for multi-tenant applications',
    )

    # Status
    success = models.BooleanField(
        default=True,
        help_text='Whether the action succeeded',
    )
    error_message = models.TextField(
        blank=True,
        help_text='Error message if action failed',
    )

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['-timestamp']),
            models.Index(fields=['user', '-timestamp']),
            models.Index(fields=['action', '-timestamp']),
            models.Index(fields=['resource_type', 'resource_id']),
            models.Index(fields=['ip_address', '-timestamp']),
        ]
        verbose_name = 'Audit Log'
        verbose_name_plural = 'Audit Logs'

    def __str__(self):
        return f"{self.timestamp} - {self.username or 'Anonymous'} - {self.action}"

    def save(self, *args, **kwargs):
        # Snapshot username for preservation
        if self.user and not self.username:
            self.username = self.user.username
        super().save(*args, **kwargs)
'''

# ============================================================================
# COMPONENT 2: AUDIT UTILITY FUNCTIONS
# ============================================================================

AUDIT_UTILITY = '''
# Shield AI: Audit Logging Utility
# File: utils/audit.py

import logging
from typing import Optional, Dict, Any
from django.contrib.auth import get_user_model
from django.http import HttpRequest
# Import your AuditLog model (adjust path as needed)
# from myapp.models import AuditLog

logger = logging.getLogger(__name__)
User = get_user_model()


def log_audit_event(
    action: str,
    request: Optional[HttpRequest] = None,
    user: Optional[User] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    success: bool = True,
    error_message: str = '',
    tenant_id: str = '',
) -> 'AuditLog':
    """
    Log an audit event.

    Args:
        action: Action type (login_success, create, update, delete, etc.)
        request: HttpRequest object (to extract IP, user agent, user)
        user: User who performed action (overrides request.user)
        resource_type: Type of resource affected (e.g., 'User', 'Order')
        resource_id: ID of resource affected
        details: Additional context as dictionary
        success: Whether action succeeded
        error_message: Error message if action failed
        tenant_id: Tenant identifier for multi-tenant apps

    Returns:
        AuditLog: Created audit log entry

    Example:
        # In a view
        log_audit_event(
            action='login_success',
            request=request,
            details={'login_method': 'password'}
        )

        # In a signal or service
        log_audit_event(
            action='delete',
            user=request.user,
            resource_type='Order',
            resource_id=str(order.id),
            details={'order_total': str(order.total)}
        )
    """
    from myapp.models import AuditLog  # Adjust import path

    # Extract user from request if not provided
    if user is None and request and hasattr(request, 'user'):
        user = request.user if request.user.is_authenticated else None

    # Extract IP address
    ip_address = None
    if request:
        ip_address = get_client_ip(request)

    # Extract user agent
    user_agent = ''
    if request and request.META:
        user_agent = request.META.get('HTTP_USER_AGENT', '')[:500]

    # Extract request ID if available
    request_id = None
    if request and hasattr(request, 'request_id'):
        request_id = request.request_id

    # Create audit log
    try:
        audit_log = AuditLog.objects.create(
            user=user,
            action=action,
            resource_type=resource_type or '',
            resource_id=resource_id or '',
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            details=details or {},
            success=success,
            error_message=error_message,
            tenant_id=tenant_id,
        )

        logger.info(
            f"Audit log created: {action} by {user.username if user else 'anonymous'}",
            extra={
                'audit_log_id': str(audit_log.id),
                'action': action,
                'user_id': user.id if user else None,
            }
        )

        return audit_log

    except Exception as e:
        # Log error but don't fail the request
        logger.error(f"Failed to create audit log: {e}", exc_info=True)
        raise


def get_client_ip(request: HttpRequest) -> Optional[str]:
    """
    Extract client IP address from request.

    Handles X-Forwarded-For header for proxied requests.

    Args:
        request: HttpRequest object

    Returns:
        str: Client IP address or None
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        # Get first IP in chain
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')

    return ip


def log_authentication_event(
    action: str,
    request: HttpRequest,
    user: Optional[User] = None,
    username: str = '',
    success: bool = True,
    error_message: str = '',
) -> 'AuditLog':
    """
    Log authentication events (login, logout, signup, etc.).

    Args:
        action: Authentication action (login_success, login_failed, logout, etc.)
        request: HttpRequest object
        user: User object (if authenticated)
        username: Username for failed attempts
        success: Whether authentication succeeded
        error_message: Error message for failed attempts

    Returns:
        AuditLog: Created audit log entry

    Example:
        # Successful login
        log_authentication_event(
            action='login_success',
            request=request,
            user=user
        )

        # Failed login
        log_authentication_event(
            action='login_failed',
            request=request,
            username=attempted_username,
            success=False,
            error_message='Invalid credentials'
        )
    """
    details = {}
    if username and not user:
        details['attempted_username'] = username

    return log_audit_event(
        action=action,
        request=request,
        user=user,
        details=details,
        success=success,
        error_message=error_message,
    )


def log_data_change(
    action: str,
    request: HttpRequest,
    resource_type: str,
    resource_id: str,
    before: Optional[Dict] = None,
    after: Optional[Dict] = None,
) -> 'AuditLog':
    """
    Log data modification events (create, update, delete).

    Args:
        action: Data action (create, update, delete)
        request: HttpRequest object
        resource_type: Type of resource (e.g., 'User', 'Order', 'Product')
        resource_id: ID of resource
        before: Snapshot of resource before change (for update/delete)
        after: Snapshot of resource after change (for create/update)

    Returns:
        AuditLog: Created audit log entry

    Example:
        # Create
        log_data_change(
            action='create',
            request=request,
            resource_type='Order',
            resource_id=str(order.id),
            after={'total': order.total, 'status': order.status}
        )

        # Update
        log_data_change(
            action='update',
            request=request,
            resource_type='Order',
            resource_id=str(order.id),
            before={'status': 'pending'},
            after={'status': 'completed'}
        )

        # Delete
        log_data_change(
            action='delete',
            request=request,
            resource_type='Order',
            resource_id=str(order.id),
            before={'total': order.total, 'status': order.status}
        )
    """
    details = {}
    if before:
        details['before'] = before
    if after:
        details['after'] = after

    return log_audit_event(
        action=action,
        request=request,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
    )
'''

# ============================================================================
# COMPONENT 3: AUDIT MIDDLEWARE
# ============================================================================

AUDIT_MIDDLEWARE = '''
# Shield AI: Audit Middleware
# File: middleware.py

import logging
from django.utils.deprecation import MiddlewareMixin
from utils.audit import log_audit_event

logger = logging.getLogger(__name__)


class AuditMiddleware(MiddlewareMixin):
    """
    Middleware to automatically log authenticated requests.

    Logs all authenticated user actions for audit trail.
    Excludes static files, media files, and health check endpoints.
    """

    # Paths to exclude from audit logging
    EXCLUDED_PATHS = [
        '/static/',
        '/media/',
        '/health/',
        '/api/health/',
        '/__debug__/',
        '/favicon.ico',
    ]

    # Methods to exclude (typically GET requests for viewing)
    EXCLUDED_METHODS = ['OPTIONS', 'HEAD']

    def process_response(self, request, response):
        """
        Log request after response is ready.

        Only logs authenticated requests that modify data (POST, PUT, PATCH, DELETE)
        or access sensitive endpoints.
        """
        # Skip excluded paths
        if any(request.path.startswith(path) for path in self.EXCLUDED_PATHS):
            return response

        # Skip excluded methods
        if request.method in self.EXCLUDED_METHODS:
            return response

        # Only log authenticated users
        if not hasattr(request, 'user') or not request.user.is_authenticated:
            return response

        # Log data-modifying requests
        if request.method in ['POST', 'PUT', 'PATCH', 'DELETE']:
            action = self._get_action_from_request(request)

            try:
                log_audit_event(
                    action=action,
                    request=request,
                    details={
                        'path': request.path,
                        'method': request.method,
                        'status_code': response.status_code,
                    },
                    success=(200 <= response.status_code < 400),
                )
            except Exception as e:
                # Don't fail request if audit logging fails
                logger.error(f"Audit logging failed: {e}", exc_info=True)

        return response

    def _get_action_from_request(self, request):
        """
        Determine action type from request method.

        Args:
            request: HttpRequest object

        Returns:
            str: Action type
        """
        method_action_map = {
            'POST': 'create',
            'PUT': 'update',
            'PATCH': 'update',
            'DELETE': 'delete',
        }

        return method_action_map.get(request.method, 'admin_action')
'''

# ============================================================================
# COMPONENT 4: MANAGEMENT COMMANDS
# ============================================================================

CLEANUP_COMMAND = '''
# Shield AI: Audit Log Cleanup Management Command
# File: management/commands/cleanup_audit_logs.py

from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
# Adjust import path as needed
# from myapp.models import AuditLog


class Command(BaseCommand):
    help = 'Delete audit logs older than specified retention period (default: 90 days)'

    def add_arguments(self, parser):
        parser.add_argument(
            '--days',
            type=int,
            default=90,
            help='Number of days to retain logs (default: 90)',
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be deleted without actually deleting',
        )

    def handle(self, *args, **options):
        from myapp.models import AuditLog  # Adjust import path

        retention_days = options['days']
        dry_run = options['dry_run']

        # Calculate cutoff date
        cutoff_date = timezone.now() - timedelta(days=retention_days)

        # Query old logs
        old_logs = AuditLog.objects.filter(timestamp__lt=cutoff_date)
        count = old_logs.count()

        if dry_run:
            self.stdout.write(
                self.style.WARNING(
                    f'DRY RUN: Would delete {count} audit logs older than {retention_days} days '
                    f'(before {cutoff_date.strftime("%Y-%m-%d")})'
                )
            )
        else:
            # Delete old logs
            deleted_count, _ = old_logs.delete()

            self.stdout.write(
                self.style.SUCCESS(
                    f'Successfully deleted {deleted_count} audit logs older than {retention_days} days'
                )
            )
'''

EXPORT_COMMAND = '''
# Shield AI: Export Audit Logs Management Command
# File: management/commands/export_audit_logs.py

import csv
import json
from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import datetime
# Adjust import path as needed
# from myapp.models import AuditLog


class Command(BaseCommand):
    help = 'Export audit logs to CSV or JSON file'

    def add_arguments(self, parser):
        parser.add_argument(
            '--output',
            type=str,
            required=True,
            help='Output file path (e.g., audit_logs.csv or audit_logs.json)',
        )
        parser.add_argument(
            '--start-date',
            type=str,
            help='Start date (YYYY-MM-DD)',
        )
        parser.add_argument(
            '--end-date',
            type=str,
            help='End date (YYYY-MM-DD)',
        )
        parser.add_argument(
            '--format',
            type=str,
            choices=['csv', 'json'],
            default='csv',
            help='Export format (default: csv)',
        )

    def handle(self, *args, **options):
        from myapp.models import AuditLog  # Adjust import path

        output_file = options['output']
        export_format = options['format']

        # Build queryset
        queryset = AuditLog.objects.all()

        # Apply date filters
        if options['start_date']:
            start_date = datetime.strptime(options['start_date'], '%Y-%m-%d')
            queryset = queryset.filter(timestamp__gte=start_date)

        if options['end_date']:
            end_date = datetime.strptime(options['end_date'], '%Y-%m-%d')
            queryset = queryset.filter(timestamp__lte=end_date)

        # Export
        count = queryset.count()
        self.stdout.write(f'Exporting {count} audit logs...')

        if export_format == 'csv':
            self._export_csv(queryset, output_file)
        else:
            self._export_json(queryset, output_file)

        self.stdout.write(
            self.style.SUCCESS(f'Successfully exported {count} logs to {output_file}')
        )

    def _export_csv(self, queryset, output_file):
        """Export to CSV format."""
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)

            # Write header
            writer.writerow([
                'ID', 'Timestamp', 'User', 'Action', 'Resource Type',
                'Resource ID', 'IP Address', 'Success', 'Details'
            ])

            # Write rows
            for log in queryset.iterator():
                writer.writerow([
                    str(log.id),
                    log.timestamp.isoformat(),
                    log.username or 'Anonymous',
                    log.action,
                    log.resource_type,
                    log.resource_id,
                    log.ip_address,
                    log.success,
                    json.dumps(log.details),
                ])

    def _export_json(self, queryset, output_file):
        """Export to JSON format."""
        logs_data = []

        for log in queryset.iterator():
            logs_data.append({
                'id': str(log.id),
                'timestamp': log.timestamp.isoformat(),
                'user_id': log.user_id,
                'username': log.username,
                'action': log.action,
                'resource_type': log.resource_type,
                'resource_id': log.resource_id,
                'ip_address': log.ip_address,
                'user_agent': log.user_agent,
                'success': log.success,
                'error_message': log.error_message,
                'details': log.details,
            })

        with open(output_file, 'w', encoding='utf-8') as jsonfile:
            json.dump(logs_data, jsonfile, indent=2)
'''

# ============================================================================
# COMPONENT 5: ADMIN API
# ============================================================================

AUDIT_SERIALIZER = '''
# Shield AI: AuditLog Serializer
# File: serializers/audit.py

from rest_framework import serializers
# Adjust import path as needed
# from myapp.models import AuditLog


class AuditLogSerializer(serializers.ModelSerializer):
    """Serializer for AuditLog model."""

    username = serializers.CharField(read_only=True)

    class Meta:
        model = AuditLog
        fields = [
            'id', 'timestamp', 'user', 'username', 'action',
            'resource_type', 'resource_id', 'ip_address',
            'user_agent', 'request_id', 'details', 'success',
            'error_message', 'tenant_id',
        ]
        read_only_fields = fields  # All fields are read-only
'''

AUDIT_VIEWS = '''
# Shield AI: Audit Log API Views
# File: views/audit.py

from rest_framework import viewsets, filters
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAdminUser
from django_filters.rest_framework import DjangoFilterBackend
import csv
from django.http import HttpResponse
# Adjust import paths as needed
# from myapp.models import AuditLog
# from myapp.serializers import AuditLogSerializer


class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint for viewing audit logs.

    Only accessible to admin users.
    Supports filtering by user, action, resource_type, date range.
    """

    queryset = AuditLog.objects.all().select_related('user')
    serializer_class = AuditLogSerializer
    permission_classes = [IsAdminUser]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]

    filterset_fields = ['action', 'resource_type', 'user', 'success']
    search_fields = ['username', 'ip_address', 'resource_id']
    ordering_fields = ['timestamp', 'action']
    ordering = ['-timestamp']

    @action(detail=False, methods=['get'])
    def export_csv(self, request):
        """
        Export audit logs to CSV.

        GET /api/audit-logs/export_csv/
        """
        queryset = self.filter_queryset(self.get_queryset())

        # Create CSV response
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="audit_logs.csv"'

        writer = csv.writer(response)
        writer.writerow([
            'ID', 'Timestamp', 'User', 'Action', 'Resource Type',
            'Resource ID', 'IP Address', 'Success'
        ])

        for log in queryset.iterator():
            writer.writerow([
                str(log.id),
                log.timestamp.isoformat(),
                log.username or 'Anonymous',
                log.action,
                log.resource_type,
                log.resource_id,
                log.ip_address,
                log.success,
            ])

        return response
'''

AUDIT_URLS = '''
# Shield AI: Audit Log URLs
# Add to urls.py

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from myapp.views import AuditLogViewSet  # Adjust import path

router = DefaultRouter()
router.register(r'audit-logs', AuditLogViewSet, basename='auditlog')

urlpatterns = [
    path('api/', include(router.urls)),
]
'''

# ============================================================================
# COMPONENT 6: INTEGRATION EXAMPLES
# ============================================================================

AUTH_VIEW_INTEGRATION = '''
# Shield AI: Integration Example - Authentication Views
# File: views/auth.py

from django.contrib.auth import authenticate, login, logout
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from utils.audit import log_authentication_event


class LoginView(APIView):
    """Login view with audit logging."""

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        # Authenticate user
        user = authenticate(request, username=username, password=password)

        if user is not None:
            # Login successful
            login(request, user)

            # Shield AI: Log successful login
            log_authentication_event(
                action='login_success',
                request=request,
                user=user,
            )

            return Response({'message': 'Login successful'})
        else:
            # Login failed
            # Shield AI: Log failed login attempt
            log_authentication_event(
                action='login_failed',
                request=request,
                username=username,
                success=False,
                error_message='Invalid credentials',
            )

            return Response(
                {'error': 'Invalid credentials'},
                status=status.HTTP_401_UNAUTHORIZED
            )


class LogoutView(APIView):
    """Logout view with audit logging."""

    def post(self, request):
        # Shield AI: Log logout
        log_authentication_event(
            action='logout',
            request=request,
            user=request.user,
        )

        logout(request)

        return Response({'message': 'Logout successful'})
'''

CRUD_VIEW_INTEGRATION = '''
# Shield AI: Integration Example - CRUD Views
# File: views/orders.py

from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework import status
from utils.audit import log_data_change
from myapp.models import Order
from myapp.serializers import OrderSerializer


class OrderViewSet(viewsets.ModelViewSet):
    """Order CRUD views with audit logging."""

    queryset = Order.objects.all()
    serializer_class = OrderSerializer

    def perform_create(self, serializer):
        """Create order with audit logging."""
        instance = serializer.save()

        # Shield AI: Log creation
        log_data_change(
            action='create',
            request=self.request,
            resource_type='Order',
            resource_id=str(instance.id),
            after={
                'total': str(instance.total),
                'status': instance.status,
                'customer_id': instance.customer_id,
            }
        )

    def perform_update(self, serializer):
        """Update order with audit logging."""
        # Capture before state
        old_instance = self.get_object()
        before = {
            'total': str(old_instance.total),
            'status': old_instance.status,
        }

        # Update
        instance = serializer.save()

        # Capture after state
        after = {
            'total': str(instance.total),
            'status': instance.status,
        }

        # Shield AI: Log update
        log_data_change(
            action='update',
            request=self.request,
            resource_type='Order',
            resource_id=str(instance.id),
            before=before,
            after=after,
        )

    def perform_destroy(self, instance):
        """Delete order with audit logging."""
        # Capture snapshot before deletion
        before = {
            'total': str(instance.total),
            'status': instance.status,
            'customer_id': instance.customer_id,
        }

        # Shield AI: Log deletion
        log_data_change(
            action='delete',
            request=self.request,
            resource_type='Order',
            resource_id=str(instance.id),
            before=before,
        )

        # Delete
        instance.delete()
'''

# ============================================================================
# MIGRATIONS
# ============================================================================

MIGRATION_TEMPLATE = '''
# Shield AI: AuditLog Model Migration
# File: migrations/000X_auditlog.py

from django.db import migrations, models
import django.db.models.deletion
import uuid
from django.conf import settings
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        # Add your app's last migration here
        ('myapp', '000X_previous_migration'),
    ]

    operations = [
        migrations.CreateModel(
            name='AuditLog',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('timestamp', models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ('username', models.CharField(blank=True, help_text='Username snapshot', max_length=150)),
                ('action', models.CharField(choices=[...], db_index=True, help_text='Type of action performed', max_length=50)),
                ('resource_type', models.CharField(blank=True, db_index=True, help_text='Type of resource affected', max_length=100)),
                ('resource_id', models.CharField(blank=True, help_text='ID of resource affected', max_length=255)),
                ('ip_address', models.GenericIPAddressField(blank=True, help_text='Client IP address', null=True)),
                ('user_agent', models.TextField(blank=True, help_text='Browser/client user agent string')),
                ('request_id', models.UUIDField(blank=True, help_text='Request correlation ID', null=True)),
                ('details', models.JSONField(blank=True, default=dict, help_text='Additional context')),
                ('tenant_id', models.CharField(blank=True, db_index=True, help_text='Tenant identifier', max_length=100)),
                ('success', models.BooleanField(default=True, help_text='Whether the action succeeded')),
                ('error_message', models.TextField(blank=True, help_text='Error message if action failed')),
                ('user', models.ForeignKey(blank=True, help_text='User who performed the action', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='audit_logs', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Audit Log',
                'verbose_name_plural': 'Audit Logs',
                'ordering': ['-timestamp'],
            },
        ),
        migrations.AddIndex(
            model_name='auditlog',
            index=models.Index(fields=['-timestamp'], name='audit_timestamp_idx'),
        ),
        migrations.AddIndex(
            model_name='auditlog',
            index=models.Index(fields=['user', '-timestamp'], name='audit_user_timestamp_idx'),
        ),
        migrations.AddIndex(
            model_name='auditlog',
            index=models.Index(fields=['action', '-timestamp'], name='audit_action_timestamp_idx'),
        ),
        migrations.AddIndex(
            model_name='auditlog',
            index=models.Index(fields=['resource_type', 'resource_id'], name='audit_resource_idx'),
        ),
        migrations.AddIndex(
            model_name='auditlog',
            index=models.Index(fields=['ip_address', '-timestamp'], name='audit_ip_timestamp_idx'),
        ),
    ]
'''

# ============================================================================
# REQUIREMENTS
# ============================================================================

REQUIREMENTS_ENTRY = '''# Shield AI: Audit Logging
django-filter>=23.2  # For API filtering
djangorestframework>=3.14.0  # For admin API
'''

# ============================================================================
# SETTINGS ADDITIONS
# ============================================================================

SETTINGS_ADDITIONS = '''
# Shield AI: Audit Logging Settings

# Add middleware
MIDDLEWARE = [
    # ... other middleware ...
    'myapp.middleware.AuditMiddleware',  # Shield AI: Audit logging
]

# Add to INSTALLED_APPS if audit is a separate app
INSTALLED_APPS = [
    # ... other apps ...
    'django_filters',  # For audit log filtering
]

# Audit log retention (days)
AUDIT_LOG_RETENTION_DAYS = 90
'''

# ============================================================================
# CELERY BEAT SCHEDULE (OPTIONAL)
# ============================================================================

CELERY_BEAT_SCHEDULE = '''
# Shield AI: Celery Beat Schedule for Audit Log Cleanup
# File: celerybeat_schedule.py or settings.py

from celery.schedules import crontab

CELERY_BEAT_SCHEDULE = {
    'cleanup-audit-logs-daily': {
        'task': 'myapp.tasks.cleanup_audit_logs',
        'schedule': crontab(hour=2, minute=0),  # 2 AM daily
    },
}
'''

CELERY_TASK = '''
# Shield AI: Celery Task for Audit Log Cleanup
# File: tasks.py

from celery import shared_task
from django.core.management import call_command


@shared_task
def cleanup_audit_logs():
    """Run audit log cleanup command."""
    call_command('cleanup_audit_logs', days=90)
'''


def get_audit_logging_components():
    """
    Get all audit logging components.

    Returns:
        dict: All templates needed for audit logging
    """
    return {
        'model': AUDIT_LOG_MODEL,
        'utility': AUDIT_UTILITY,
        'middleware': AUDIT_MIDDLEWARE,
        'cleanup_command': CLEANUP_COMMAND,
        'export_command': EXPORT_COMMAND,
        'serializer': AUDIT_SERIALIZER,
        'views': AUDIT_VIEWS,
        'urls': AUDIT_URLS,
        'auth_integration': AUTH_VIEW_INTEGRATION,
        'crud_integration': CRUD_VIEW_INTEGRATION,
        'migration': MIGRATION_TEMPLATE,
        'requirements': REQUIREMENTS_ENTRY,
        'settings': SETTINGS_ADDITIONS,
        'celery_beat': CELERY_BEAT_SCHEDULE,
        'celery_task': CELERY_TASK,
    }
