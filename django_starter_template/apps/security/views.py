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
from apps.accounts.models import User, UserSession, LoginAttempt


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
    description="Returns comprehensive security dashboard data including audit logs, security events, rate limiting, 2FA statistics, session data, and threat intelligence.",
    responses={200: SecurityDashboardSerializer}
)
@api_view(['GET'])
@permission_classes([IsSecurityAdmin])
def security_dashboard(request):
    """Get comprehensive security dashboard data"""

    # Time periods
    now = timezone.now()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)
    last_30d = now - timedelta(days=30)

    # Basic security metrics
    data = {
        'total_audit_logs': AuditLog.objects.count(),
        'audit_logs_today': AuditLog.objects.filter(timestamp__gte=today_start).count(),
        'audit_logs_24h': AuditLog.objects.filter(timestamp__gte=last_24h).count(),
        'audit_logs_7d': AuditLog.objects.filter(timestamp__gte=last_7d).count(),
    }

    # Security events analysis
    security_events = SecurityEvent.objects.all()
    data.update({
        'total_security_events': security_events.count(),
        'active_security_events': security_events.filter(status=SecurityEvent.Status.ACTIVE).count(),
        'critical_events': security_events.filter(
            severity=AuditLog.Severity.CRITICAL,
            status=SecurityEvent.Status.ACTIVE
        ).count(),
        'high_severity_events': security_events.filter(
            severity=AuditLog.Severity.HIGH,
            status=SecurityEvent.Status.ACTIVE
        ).count(),
        'resolved_events_24h': security_events.filter(
            status=SecurityEvent.Status.RESOLVED,
            updated_at__gte=last_24h
        ).count(),
    })

    # Rate limiting statistics
    rate_limits = RateLimit.objects.filter(window_end__gt=now)
    data.update({
        'active_rate_limits': rate_limits.filter(is_blocked=True).count(),
        'total_rate_limit_entries': rate_limits.count(),
        'blocked_ips': rate_limits.filter(
            limit_type=RateLimit.LimitType.IP,
            is_blocked=True
        ).values('identifier').distinct().count(),
        'blocked_users': rate_limits.filter(
            limit_type=RateLimit.LimitType.USER,
            is_blocked=True
        ).values('identifier').distinct().count(),
    })

    # User and authentication statistics
    users = User.objects.all()
    data.update({
        'total_users': users.count(),
        'active_users': users.filter(is_active=True).count(),
        'users_with_2fa': users.filter(otp_device__isnull=False).count(),
        'locked_accounts': users.filter(account_locked_until__gt=now).count(),
        'users_with_failed_attempts': users.filter(failed_login_attempts__gt=0).count(),
    })

    # Session statistics
    sessions = UserSession.objects.all()
    data.update({
        'total_sessions': sessions.count(),
        'active_sessions': sessions.filter(is_active=True).count(),
        'expired_sessions': sessions.filter(is_expired=True).count(),
        'high_risk_sessions': sessions.filter(risk_score__gte=70).count(),
        'sessions_with_device_info': sessions.filter(device_info__isnull=False).count(),
    })

    # Login attempt analysis
    login_attempts = LoginAttempt.objects.all()
    data.update({
        'total_login_attempts': login_attempts.count(),
        'failed_login_attempts_24h': login_attempts.filter(
            success=False,
            created_at__gte=last_24h
        ).count(),
        'successful_login_attempts_24h': login_attempts.filter(
            success=True,
            created_at__gte=last_24h
        ).count(),
        'login_attempts_today': login_attempts.filter(created_at__gte=today_start).count(),
    })

    # API key statistics
    api_keys = APIKey.objects.all()
    data.update({
        'total_api_keys': api_keys.count(),
        'active_api_keys': api_keys.filter(is_active=True).count(),
        'api_keys_used_today': api_keys.filter(last_used_at__gte=today_start).count(),
    })

    # Recent activity (last 10 items each)
    data.update({
        'recent_security_events': SecurityEventSerializer(
            security_events.filter(created_at__gte=last_24h).order_by('-created_at')[:10],
            many=True
        ).data,
        'recent_audit_logs': AuditLogSerializer(
            AuditLog.objects.filter(timestamp__gte=last_24h).order_by('-timestamp')[:10],
            many=True
        ).data,
        'recent_failed_logins': list(
            LoginAttempt.objects.filter(
                success=False,
                created_at__gte=last_24h
            ).values('email', 'failure_reason', 'created_at').order_by('-created_at')[:10]
        ),
    })

    # Geographic threat analysis (if location_info exists)
    audit_logs_with_location = AuditLog.objects.filter(
        timestamp__gte=last_7d
    ).exclude(location_info__isnull=True)

    if audit_logs_with_location.exists():
        # Get top countries by suspicious activity
        suspicious_countries = audit_logs_with_location.filter(
            event_type__in=[
                AuditLog.EventType.FAILED_LOGIN,
                AuditLog.EventType.SECURITY_VIOLATION,
                AuditLog.EventType.UNAUTHORIZED_ACCESS
            ]
        ).values('location_info').annotate(
            count=Count('id')
        ).order_by('-count')[:5]

        data['top_suspicious_countries'] = list(suspicious_countries)

    # Security health score (0-100, higher is better)
    health_score = 100

    # Deduct points for various security issues
    if data['critical_events'] > 0:
        health_score -= min(data['critical_events'] * 10, 30)
    if data['active_rate_limits'] > 10:
        health_score -= min((data['active_rate_limits'] - 10) * 2, 20)
    if data['locked_accounts'] > 5:
        health_score -= min((data['locked_accounts'] - 5) * 3, 15)
    if data['high_risk_sessions'] > 20:
        health_score -= min((data['high_risk_sessions'] - 20) * 1, 15)
    if data['failed_login_attempts_24h'] > 50:
        health_score -= min((data['failed_login_attempts_24h'] - 50) // 10, 20)

    data['security_health_score'] = max(0, health_score)

    # Security trends (comparing last 7 days vs previous 7 days)
    prev_7d_start = last_7d - timedelta(days=7)
    prev_7d_end = last_7d

    prev_failed_logins = LoginAttempt.objects.filter(
        success=False,
        created_at__range=(prev_7d_start, prev_7d_end)
    ).count()

    current_failed_logins = data['failed_login_attempts_24h'] * 7  # Approximate for 7 days

    data['failed_login_trend'] = {
        'previous_7d': prev_failed_logins,
        'current_7d': current_failed_logins,
        'change_percent': ((current_failed_logins - prev_failed_logins) / max(prev_failed_logins, 1)) * 100
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
