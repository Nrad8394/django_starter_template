from rest_framework import permissions
from django.utils.translation import gettext_lazy as _


class IsSecurityAdmin(permissions.BasePermission):
    """Permission for security administrators"""

    message = _('You do not have permission to access security features.')

    def has_permission(self, request, view):
        return (
            request.user and
            request.user.is_authenticated and
            request.user.has_perm('security.view_auditlog')
        )


class CanViewAuditLogs(permissions.BasePermission):
    """Permission to view audit logs"""

    message = _('You do not have permission to view audit logs.')

    def has_permission(self, request, view):
        return (
            request.user and
            request.user.is_authenticated
        )


class CanManageSecurityEvents(permissions.BasePermission):
    """Permission to manage security events"""

    message = _('You do not have permission to manage security events.')

    def has_permission(self, request, view):
        return (
            request.user and
            request.user.is_authenticated and
            request.user.has_perm('security.change_securityevent')
        )


class CanManageSecuritySettings(permissions.BasePermission):
    """Permission to manage security settings"""

    message = _('You do not have permission to manage security settings.')

    def has_permission(self, request, view):
        return (
            request.user and
            request.user.is_authenticated and
            request.user.has_perm('security.change_securitysettings')
        )


class CanManageAPIKeys(permissions.BasePermission):
    """Permission to manage API keys"""

    message = _('You do not have permission to manage API keys.')

    def has_object_permission(self, request, view, obj):
        # Users can manage their own API keys
        if request.user == obj.user:
            return True
        # Security admins can manage all API keys
        return (
            request.user and
            request.user.is_authenticated and
            request.user.has_perm('security.change_apikey')
        )


class IsOwnerOrSecurityAdmin(permissions.BasePermission):
    """Permission for owners or security admins"""

    message = _('You do not have permission to access this resource.')

    def has_object_permission(self, request, view, obj):
        # Check if user owns the object
        if hasattr(obj, 'user') and obj.user == request.user:
            return True
        # Check if user is security admin
        return (
            request.user and
            request.user.is_authenticated and
            request.user.has_perm('security.view_auditlog')
        )