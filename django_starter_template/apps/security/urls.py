from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

app_name = 'security'

router = DefaultRouter()
router.register(r'audit-logs', views.AuditLogViewSet, basename='auditlog')
router.register(r'rate-limits', views.RateLimitViewSet, basename='ratelimit')
router.register(r'security-events', views.SecurityEventViewSet, basename='securityevent')
router.register(r'security-settings', views.SecuritySettingsViewSet, basename='securitysettings')
router.register(r'api-keys', views.APIKeyViewSet, basename='apikey')

urlpatterns = [
    path('', include(router.urls)),
    path('dashboard/', views.security_dashboard, name='security-dashboard'),
    path('statistics/', views.security_dashboard, name='security-statistics'),
    path('log-event/', views.log_security_event, name='log-security-event'),
]