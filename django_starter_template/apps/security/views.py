from rest_framework import viewsets, status, generics
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from django.db.models import Count, Q
from django.utils.translation import gettext_lazy as _
from datetime import timedelta
from drf_spectacular.utils import extend_schema, OpenApiTypes
from .models import AuditLog, RateLimit, SecurityEvent, SecuritySettings, APIKey
from .serializers import (
    AuditLogSerializer, RateLimitSerializer, SecurityEventSerializer,
    SecuritySettingsSerializer, APIKeySerializer, APIKeyCreateSerializer,
    SecurityDashboardSerializer
)
from .permissions import (
    IsSecurityAdmin, CanViewAuditLogs, CanManageSecurityEvents,
    CanManageSecuritySettings, CanManageAPIKeys, IsOwnerOrSecurityAdmin
)


@extend_schema(
    tags=["Security"],
    summary="Audit log management",
    description="Read-only operations for viewing audit logs and security events."
)
class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for audit logs"""

    serializer_class = AuditLogSerializer
    permission_classes = [CanViewAuditLogs]
    filterset_fields = ['event_type', 'severity', 'user', 'ip_address']
    search_fields = ['description', 'request_path', 'user__username']
    ordering_fields = ['timestamp', 'severity']
    ordering = ['-timestamp']
    queryset = AuditLog.objects.none()  # Provide empty queryset for schema generation

    def get_queryset(self):
        queryset = AuditLog.objects.all()

        # Filter by date range
        start_date = self.request.query_params.get('start_date')
        end_date = self.request.query_params.get('end_date')

        if start_date:
            queryset = queryset.filter(timestamp__gte=start_date)
        if end_date:
            queryset = queryset.filter(timestamp__lte=end_date)

        # Users can only see their own logs unless they're security admins
        if not self.request.user.has_perm('security.view_auditlog'):
            queryset = queryset.filter(user=self.request.user)

        return queryset


@extend_schema(
    tags=["Security"],
    summary="Rate limit management",
    description="Read-only operations for viewing rate limits and blocking abusive requests."
)
class RateLimitViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for rate limits"""

    serializer_class = RateLimitSerializer
    permission_classes = [IsSecurityAdmin]
    filterset_fields = ['limit_type', 'is_blocked', 'endpoint']
    search_fields = ['identifier', 'endpoint']
    ordering_fields = ['window_start', 'request_count']
    ordering = ['-window_start']

    def get_queryset(self):
        now = timezone.now()
        return RateLimit.objects.filter(window_end__gt=now)

    @action(detail=True, methods=['post'])
    def unblock(self, request, pk=None):
        """Unblock a rate limit"""
        rate_limit = self.get_object()
        rate_limit.is_blocked = False
        rate_limit.blocked_until = None
        rate_limit.save()
        return Response({'status': 'unblocked'})


@extend_schema(
    tags=["Security"],
    summary="Security event management",
    description="Complete CRUD operations for security events including incident tracking and resolution."
)
class SecurityEventViewSet(viewsets.ModelViewSet):
    """ViewSet for security events"""

    serializer_class = SecurityEventSerializer
    permission_classes = [CanManageSecurityEvents]
    filterset_fields = ['event_type', 'status', 'severity', 'user']
    search_fields = ['title', 'description', 'ip_address']
    ordering_fields = ['created_at', 'severity', 'status']
    ordering = ['-created_at']

    def get_queryset(self):
        return SecurityEvent.objects.all()

    @action(detail=True, methods=['post'])
    def resolve(self, request, pk=None):
        """Resolve a security event"""
        security_event = self.get_object()
        notes = request.data.get('notes', '')
        security_event.resolve(request.user, notes)
        serializer = self.get_serializer(security_event)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def mark_false_positive(self, request, pk=None):
        """Mark security event as false positive"""
        security_event = self.get_object()
        security_event.status = SecurityEvent.Status.FALSE_POSITIVE
        security_event.save()
        serializer = self.get_serializer(security_event)
        return Response(serializer.data)


@extend_schema(
    tags=["Security"],
    summary="Security settings management",
    description="Complete CRUD operations for security configuration and policy settings."
)
class SecuritySettingsViewSet(viewsets.ModelViewSet):
    """ViewSet for security settings"""

    serializer_class = SecuritySettingsSerializer
    permission_classes = [CanManageSecuritySettings]
    filterset_fields = ['setting_type', 'is_enabled']
    search_fields = ['name', 'description']
    ordering_fields = ['setting_type', 'updated_at']
    ordering = ['setting_type']

    def get_queryset(self):
        return SecuritySettings.objects.all()


@extend_schema(
    tags=["Security"],
    summary="API key management",
    description="Complete CRUD operations for API key management and access control."
)
class APIKeyViewSet(viewsets.ModelViewSet):
    """ViewSet for API keys"""

    serializer_class = APIKeySerializer
    permission_classes = [CanManageAPIKeys]
    filterset_fields = ['key_type', 'is_active']
    search_fields = ['name', 'user__username']
    ordering_fields = ['created_at', 'last_used_at']
    ordering = ['-created_at']
    queryset = APIKey.objects.none()  # Provide empty queryset for schema generation

    def get_queryset(self):
        # Users can see their own keys, security admins can see all
        if self.request.user.has_perm('security.view_apikey'):
            return APIKey.objects.all()
        return APIKey.objects.filter(user=self.request.user)

    def get_serializer_class(self):
        if self.action == 'create':
            return APIKeyCreateSerializer
        return APIKeySerializer

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    @action(detail=True, methods=['post'])
    def regenerate(self, request, pk=None):
        """Regenerate API key"""
        api_key = self.get_object()
        api_key.generate_key()
        api_key.save()
        serializer = self.get_serializer(api_key)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def deactivate(self, request, pk=None):
        """Deactivate API key"""
        api_key = self.get_object()
        api_key.is_active = False
        api_key.save()
        return Response({'status': 'deactivated'})

    @action(detail=True, methods=['post'])
    def activate(self, request, pk=None):
        """Activate API key"""
        api_key = self.get_object()
        api_key.is_active = True
        api_key.save()
        return Response({'status': 'activated'})


@extend_schema(
    tags=["Security"],
    summary="Get security dashboard",
    description="Returns security dashboard data including audit logs, security events, and rate limiting statistics.",
    responses={200: SecurityDashboardSerializer}
)
@api_view(['GET'])
@permission_classes([IsSecurityAdmin])
def security_dashboard(request):
    """Get security dashboard data"""

    # Calculate metrics
    now = timezone.now()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    last_24h = now - timedelta(hours=24)

    data = {
        'total_audit_logs': AuditLog.objects.count(),
        'critical_events': SecurityEvent.objects.filter(
            severity=AuditLog.Severity.CRITICAL,
            status=SecurityEvent.Status.ACTIVE
        ).count(),
        'active_rate_limits': RateLimit.objects.filter(
            is_blocked=True,
            blocked_until__gt=now
        ).count(),
        'recent_security_events': SecurityEventSerializer(
            SecurityEvent.objects.filter(created_at__gte=last_24h)[:10],
            many=True
        ).data,
        'audit_logs_today': AuditLog.objects.filter(timestamp__gte=today_start).count(),
        'blocked_ips': RateLimit.objects.filter(
            limit_type=RateLimit.LimitType.IP,
            is_blocked=True,
            blocked_until__gt=now
        ).values('identifier').distinct().count()
    }

    serializer = SecurityDashboardSerializer(data=data)
    serializer.is_valid(raise_exception=True)
    return Response(serializer.validated_data)


@extend_schema(
    tags=["Security"],
    summary="Log security event",
    description="Log a security event with the specified details.",
    request=OpenApiTypes.OBJECT,
    responses={201: SecurityEventSerializer, 400: OpenApiTypes.OBJECT}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def log_security_event(request):
    """Log a security event (for internal use)"""

    event_type = request.data.get('event_type')
    title = request.data.get('title')
    description = request.data.get('description')
    severity = request.data.get('severity', AuditLog.Severity.MEDIUM)
    detection_data = request.data.get('detection_data', {})

    if not all([event_type, title, description]):
        return Response(
            {'error': 'event_type, title, and description are required'},
            status=status.HTTP_400_BAD_REQUEST
        )

    security_event = SecurityEvent.objects.create(
        event_type=event_type,
        title=title,
        description=description,
        severity=severity,
        user=request.user,
        ip_address=request.META.get('REMOTE_ADDR'),
        detection_data=detection_data
    )

    serializer = SecurityEventSerializer(security_event)
    return Response(serializer.data, status=status.HTTP_201_CREATED)
