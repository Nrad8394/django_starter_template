from rest_framework import viewsets, status, mixins
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import get_object_or_404
from django.utils.translation import gettext_lazy as _
from django.db import transaction, models
from django.utils import timezone
from django.contrib.auth import get_user_model
from drf_spectacular.utils import extend_schema, OpenApiParameter, OpenApiTypes
from .models import (
    NotificationTemplate,
    Notification,
    NotificationDelivery,
    NotificationPreference,
    NotificationEvent
)
from .serializers import (
    NotificationTemplateSerializer,
    NotificationSerializer,
    NotificationDeliverySerializer,
    NotificationPreferenceSerializer,
    NotificationEventSerializer,
    SendNotificationSerializer,
    BulkNotificationSerializer
)
from .permissions import (
    CanManageNotifications,
    CanManageTemplates,
    CanViewAnalytics,
    NotificationPreferencesPermission
)

User = get_user_model()


@extend_schema(
    tags=["Notifications"],
    summary="Notification template management",
    description="Complete CRUD operations for notification templates and message formatting."
)
class NotificationTemplateViewSet(viewsets.ModelViewSet):
    """ViewSet for managing notification templates"""

    queryset = NotificationTemplate.objects.all()
    serializer_class = NotificationTemplateSerializer
    permission_classes = [CanManageTemplates]

    def get_queryset(self):
        queryset = super().get_queryset()
        template_type = self.request.query_params.get('type')
        if template_type:
            queryset = queryset.filter(template_type=template_type)
        return queryset.filter(is_active=True)

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name='type',
                type=str,
                description='Filter by template type (email, sms, push, in_app)',
                required=False
            )
        ]
    )
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)


@extend_schema(
    tags=["Notifications"],
    summary="Notification management",
    description="Complete CRUD operations for notifications including sending, status updates, and delivery tracking."
)
class NotificationViewSet(viewsets.ModelViewSet):
    """ViewSet for managing notifications"""

    serializer_class = NotificationSerializer
    permission_classes = [CanManageNotifications]
    queryset = Notification.objects.none()  # Provide empty queryset for schema generation

    def get_queryset(self):
        queryset = Notification.objects.select_related('recipient', 'template')

        # Filter by current user if not staff
        if not self.request.user.is_staff and not self.request.user.is_superuser:
            queryset = queryset.filter(recipient=self.request.user)

        # Apply filters
        status_filter = self.request.query_params.get('status')
        priority_filter = self.request.query_params.get('priority')
        template_type = self.request.query_params.get('template_type')

        if status_filter:
            queryset = queryset.filter(status=status_filter)
        if priority_filter:
            queryset = queryset.filter(priority=priority_filter)
        if template_type:
            queryset = queryset.filter(template__template_type=template_type)

        return queryset.order_by('-created_at')

    @extend_schema(
        parameters=[
            OpenApiParameter(name='status', type=str, required=False),
            OpenApiParameter(name='priority', type=str, required=False),
            OpenApiParameter(name='template_type', type=str, required=False),
        ]
    )
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)

    @action(detail=True, methods=['post'])
    def mark_read(self, request, pk=None):
        """Mark a notification as read"""
        notification = self.get_object()
        notification.status = Notification.STATUS_DELIVERED
        notification.delivered_at = timezone.now()
        notification.save()
        serializer = self.get_serializer(notification)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def retry(self, request, pk=None):
        """Retry sending a failed notification"""
        notification = self.get_object()
        if notification.status != Notification.STATUS_FAILED:
            return Response(
                {'error': _('Only failed notifications can be retried')},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Reset status and increment retry count
        notification.status = Notification.STATUS_PENDING
        notification.retry_count += 1
        notification.last_error = ''
        notification.save()

        try:
            from .tasks import send_notification
            send_notification.delay(str(notification.id))
        except Exception as e:
            logger.error(f"Failed to schedule notification {notification.id}: {str(e)}")
        serializer = self.get_serializer(notification)
        return Response(serializer.data)

    @action(detail=False, methods=['post'])
    def bulk_action(self, request):
        """Perform bulk actions on notifications"""
        serializer = BulkNotificationSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        notification_ids = serializer.validated_data['notification_ids']
        action = serializer.validated_data['action']

        notifications = Notification.objects.filter(id__in=notification_ids)

        if action == 'cancel':
            notifications.filter(status=Notification.STATUS_PENDING).update(
                status=Notification.STATUS_CANCELLED
            )
        elif action == 'retry':
            notifications.filter(status=Notification.STATUS_FAILED).update(
                status=Notification.STATUS_PENDING,
                retry_count=models.F('retry_count') + 1,
                last_error=''
            )
        elif action == 'mark_delivered':
            notifications.filter(status__in=[Notification.STATUS_SENT, Notification.STATUS_PENDING]).update(
                status=Notification.STATUS_DELIVERED,
                delivered_at=timezone.now()
            )

        return Response({'message': _(f'Bulk {action} completed')})

    @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated])
    def stats(self, request):
        """Get notification statistics for the current user"""

        total = Notification.objects.count()
        sent = Notification.objects.filter(status=Notification.STATUS_SENT).count()
        pending = Notification.objects.filter(status=Notification.STATUS_PENDING).count()
        unread = Notification.objects.filter(status__in=[Notification.STATUS_SENT, Notification.STATUS_PENDING]).count()
        delivered = Notification.objects.filter(status=Notification.STATUS_DELIVERED).count()
        failed = Notification.objects.filter(status=Notification.STATUS_FAILED).count()

        return Response({
            'total': total,
            'sent': sent,
            'delivered': delivered,
            'failed': failed,
            'pending': pending,
            'unread': unread
        })


@extend_schema(
    tags=["Notifications"],
    summary="Notification delivery management",
    description="Read-only operations for viewing notification delivery records and tracking status."
)
class NotificationDeliveryViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for viewing notification delivery records"""

    queryset = NotificationDelivery.objects.select_related('notification__recipient')
    serializer_class = NotificationDeliverySerializer
    permission_classes = [CanViewAnalytics]

    def get_queryset(self):
        queryset = super().get_queryset()

        # Filter by notification if provided
        notification_id = self.request.query_params.get('notification_id')
        if notification_id:
            queryset = queryset.filter(notification_id=notification_id)

        # Filter by delivery method
        method = self.request.query_params.get('method')
        if method:
            queryset = queryset.filter(delivery_method=method)

        return queryset.order_by('-created_at')


@extend_schema(
    tags=["Notifications"],
    summary="Notification preference management",
    description="Operations for managing user notification preferences and delivery settings."
)
class NotificationPreferenceViewSet(mixins.RetrieveModelMixin,
                                   mixins.UpdateModelMixin,
                                   viewsets.GenericViewSet):
    """ViewSet for managing notification preferences"""

    serializer_class = NotificationPreferenceSerializer
    permission_classes = [NotificationPreferencesPermission]
    queryset = NotificationPreference.objects.none()  # Provide empty queryset for schema generation

    def get_queryset(self):
        return NotificationPreference.objects.filter(user=self.request.user)

    def get_object(self):
        """Get or create preferences for the current user"""
        obj, created = NotificationPreference.objects.get_or_create(
            user=self.request.user,
            defaults={
                'email_enabled': True,
                'sms_enabled': False,
                'push_enabled': True,
                'in_app_enabled': True,
                'exam_notifications': True,
                'moderation_notifications': True,
                'system_notifications': True,
                'deadline_notifications': True,
            }
        )
        return obj


@extend_schema(
    tags=["Notifications"],
    summary="Notification event management",
    description="Read-only operations for viewing notification events and system activity logs."
)
class NotificationEventViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for viewing notification events"""

    queryset = NotificationEvent.objects.filter(is_active=True)
    serializer_class = NotificationEventSerializer
    permission_classes = [CanManageTemplates]


@extend_schema(
    tags=["Notifications"],
    summary="Send notification",
    description="Send notifications to multiple recipients using a notification template.",
    request=SendNotificationSerializer,
    responses={201: OpenApiTypes.OBJECT, 400: OpenApiTypes.OBJECT}
)
@api_view(['POST'])
@permission_classes([CanManageNotifications])
def send_notification(request):
    """Send a notification using a template"""
    serializer = SendNotificationSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    data = serializer.validated_data
    template = get_object_or_404(NotificationTemplate, id=data['template_id'])

    notifications_created = []

    with transaction.atomic():
        for recipient_id in data['recipient_ids']:
            recipient = get_object_or_404(User, id=recipient_id)

            # Create notification
            notification = Notification.objects.create(
                recipient=recipient,
                template=template,
                subject=data.get('subject', template.subject),
                body=template.body,  # Would be processed with template variables
                data=data['data'],
                scheduled_at=data.get('scheduled_at'),
                priority=data.get('priority', 'medium')
            )
            notifications_created.append(notification.id)

    return Response({
        'message': _(f'Created {len(notifications_created)} notifications'),
        'notification_ids': notifications_created
    }, status=status.HTTP_201_CREATED)


@extend_schema(
    tags=["Notifications"],
    summary="Get user notifications",
    description="Get current user's notifications with optional filtering and pagination.",
    parameters=[
        OpenApiParameter(name='status', type=str, location=OpenApiParameter.QUERY, description='Filter by notification status'),
        OpenApiParameter(name='unread_only', type=bool, location=OpenApiParameter.QUERY, description='Show only unread notifications'),
        OpenApiParameter(name='page', type=int, location=OpenApiParameter.QUERY, description='Page number'),
        OpenApiParameter(name='page_size', type=int, location=OpenApiParameter.QUERY, description='Items per page (max 100)')
    ],
    responses={200: OpenApiTypes.OBJECT}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_notifications(request):
    """Get current user's notifications"""
    notifications = Notification.objects.filter(
        recipient=request.user
    ).select_related('template').order_by('-created_at')

    # Apply filters
    status_filter = request.query_params.get('status')
    unread_only = request.query_params.get('unread_only', 'false').lower() == 'true'

    if status_filter:
        notifications = notifications.filter(status=status_filter)
    if unread_only:
        notifications = notifications.exclude(status=Notification.STATUS_DELIVERED)

    # Pagination
    page = request.query_params.get('page', 1)
    page_size = min(int(request.query_params.get('page_size', 20)), 100)

    start = (int(page) - 1) * page_size
    end = start + page_size

    serializer = NotificationSerializer(notifications[start:end], many=True)
    return Response({
        'count': notifications.count(),
        'results': serializer.data
    })


@extend_schema(
    tags=["Notifications"],
    summary="Get notification statistics",
    description="Returns statistics about notifications including totals and recent activity.",
    responses={200: OpenApiTypes.OBJECT}
)
@api_view(['GET'])
@permission_classes([CanViewAnalytics])
def notification_stats(request):
    """Get notification statistics"""
    # Basic stats
    total_notifications = Notification.objects.count()
    sent_notifications = Notification.objects.filter(status=Notification.STATUS_SENT).count()
    delivered_notifications = Notification.objects.filter(status=Notification.STATUS_DELIVERED).count()
    failed_notifications = Notification.objects.filter(status=Notification.STATUS_FAILED).count()

    # Recent activity (last 30 days)
    from django.utils import timezone
    thirty_days_ago = timezone.now() - timezone.timedelta(days=30)

    recent_notifications = Notification.objects.filter(created_at__gte=thirty_days_ago)
    recent_sent = recent_notifications.filter(status=Notification.STATUS_SENT).count()
    recent_delivered = recent_notifications.filter(status=Notification.STATUS_DELIVERED).count()
    recent_failed = recent_notifications.filter(status=Notification.STATUS_FAILED).count()

    return Response({
        'total': total_notifications,
        'sent': sent_notifications,
        'delivered': delivered_notifications,
        'failed': failed_notifications,
        'recent': {
            'total': recent_notifications.count(),
            'sent': recent_sent,
            'delivered': recent_delivered,
            'failed': recent_failed,
        }
    })


@extend_schema(
    tags=["Notifications"],
    summary="Mark notifications as read",
    description="Mark multiple notifications as read for the current user.",
    request=OpenApiTypes.OBJECT,
    responses={200: OpenApiTypes.OBJECT, 400: OpenApiTypes.OBJECT}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def mark_notifications_read(request):
    """Mark multiple notifications as read"""
    notification_ids = request.data.get('notification_ids', [])
    if not notification_ids:
        return Response(
            {'error': _('notification_ids is required')},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Only allow users to mark their own notifications as read
    updated_count = Notification.objects.filter(
        id__in=notification_ids,
        recipient=request.user,
        status__in=[Notification.STATUS_SENT, Notification.STATUS_PENDING]
    ).update(
        status=Notification.STATUS_DELIVERED,
        delivered_at=timezone.now()
    )

    return Response({
        'message': _(f'Marked {updated_count} notifications as read')
    })
