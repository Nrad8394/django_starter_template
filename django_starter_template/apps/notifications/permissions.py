from rest_framework import permissions
from django.utils.translation import gettext_lazy as _


class IsOwnerOrAdmin(permissions.BasePermission):
    """
    Custom permission to only allow owners of an object or admins to access it.
    """

    def has_object_permission(self, request, view, obj):
        # Allow admins to access any object
        if request.user.is_staff or request.user.is_superuser:
            return True

        # Allow users to access their own notifications/preferences
        if hasattr(obj, 'user'):
            return obj.user == request.user
        elif hasattr(obj, 'recipient'):
            return obj.recipient == request.user

        return False


class CanManageNotifications(permissions.BasePermission):
    """
    Permission to manage notifications (send, update status, etc.)
    """

    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            # Allow authenticated users to view their own notifications
            return request.user and request.user.is_authenticated

        # For write operations, require staff or specific roles
        if request.user.is_staff or request.user.is_superuser:
            return True

        # Check for specific permissions based on user roles
        user_permissions = getattr(request.user, 'get_all_permissions', lambda: set())()
        return any(perm in user_permissions for perm in [
            'notifications.can_send_notifications',
            'notifications.can_manage_notifications'
        ])


class CanManageTemplates(permissions.BasePermission):
    """
    Permission to manage notification templates
    """

    def has_permission(self, request, view):
        # Only staff and superusers can manage templates
        return request.user.is_staff or request.user.is_superuser


class CanViewAnalytics(permissions.BasePermission):
    """
    Permission to view notification analytics and reports
    """

    def has_permission(self, request, view):
        # Allow staff and users with analytics permission
        if request.user.is_staff or request.user.is_superuser:
            return True

        user_permissions = getattr(request.user, 'get_all_permissions', lambda: set())()
        return 'notifications.can_view_analytics' in user_permissions


class NotificationPreferencesPermission(permissions.BasePermission):
    """
    Permission for notification preferences - users can only manage their own
    """

    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated

    def has_object_permission(self, request, view, obj):
        # Users can only access their own preferences
        return obj.user == request.user