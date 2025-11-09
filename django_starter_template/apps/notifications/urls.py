from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

# Create a router for ViewSets
router = DefaultRouter()
router.register(r'templates', views.NotificationTemplateViewSet, basename='notification-template')
router.register(r'notifications', views.NotificationViewSet, basename='notification')
router.register(r'deliveries', views.NotificationDeliveryViewSet, basename='notification-delivery')
router.register(r'preferences', views.NotificationPreferenceViewSet, basename='notification-preference')
router.register(r'events', views.NotificationEventViewSet, basename='notification-event')

# URL patterns
urlpatterns = [
    # Include router URLs
    path('', include(router.urls)),

    # Custom API endpoints
    path('send/', views.send_notification, name='send-notification'),
    path('user/notifications/', views.user_notifications, name='user-notifications'),
    path('stats/', views.notification_stats, name='notification-stats'),
    path('mark-read/', views.mark_notifications_read, name='mark-notifications-read'),
]