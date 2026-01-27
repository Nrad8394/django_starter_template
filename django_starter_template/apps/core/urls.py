from django.urls import path, include
from . import views

app_name = "core"

urlpatterns = [
    # Health check
    path("health/", views.health_check, name="health_check"),
    # Dashboard
    path("dashboard/statistics/", views.dashboard_statistics, name="dashboard_statistics"),
    # CSRF token endpoints
    path("csrf-token/", views.get_csrf_token, name="csrf_token"),
    path("csrf/", views.csrf_token_view, name="csrf_token_alt"),
    # Task status endpoint
    path("tasks/<uuid:task_id>/status/", views.task_status, name="task_status"),
    # User-specific data endpoints
    path("my-classes/", views.my_classes, name="my_classes"),
    path("pending-approvals/", views.pending_approvals, name="pending_approvals"),
    path("notifications/", views.user_notifications, name="user_notifications"),
    path(
        "notifications/<uuid:notification_id>/mark-read/",
        views.mark_notification_read,
        name="mark_notification_read",
    ),
    # System settings (admin only)
    path("settings/", views.system_settings, name="system_settings"),
    # Custom authentication endpoints with proper tags
    path("auth/", include("apps.core.auth_urls")),
]
