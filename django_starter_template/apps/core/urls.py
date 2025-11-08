from django.urls import path, include
from . import views

app_name = 'core'

urlpatterns = [
    # Health check
    path('health/', views.health_check, name='health_check'),

    # CSRF token endpoints
    path('csrf-token/', views.get_csrf_token, name='csrf_token'),
    path('csrf/', views.csrf_token_view, name='csrf_token_alt'),

    # Task status endpoint
    path('tasks/<uuid:task_id>/status/', views.task_status, name='task_status'),

    # Dashboard statistics
    path('dashboard/statistics/', views.dashboard_statistics, name='dashboard_statistics'),

    # Custom authentication endpoints with proper tags
    path('auth/', include('apps.core.auth_urls')),
]