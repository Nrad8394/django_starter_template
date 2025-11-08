"""
Core permissions for Django Starter Template
"""
from rest_framework import permissions


class IsStaffOrReadOnly(permissions.BasePermission):
    """
    Custom permission to only allow staff users to edit objects.
    """

    def has_permission(self, request, view):
        # Read permissions are allowed to any authenticated user
        if request.method in permissions.SAFE_METHODS:
            return request.user and request.user.is_authenticated

        # Write permissions are only allowed to staff users
        return request.user and request.user.is_authenticated and request.user.is_staff_member


class IsOwnerOrStaff(permissions.BasePermission):
    """
    Custom permission to only allow owners of an object or staff to edit it.
    """

    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated

    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any authenticated user
        if request.method in permissions.SAFE_METHODS:
            return True

        # Write permissions are only allowed to the owner or staff
        if hasattr(obj, 'created_by'):
            return obj.created_by == request.user or request.user.is_staff_member

        # Fallback for objects without created_by field
        return request.user.is_staff_member


class IsAdminOrReadOnly(permissions.BasePermission):
    """
    Custom permission to only allow admin users to edit objects.
    """

    def has_permission(self, request, view):
        # Read permissions are allowed to any authenticated user
        if request.method in permissions.SAFE_METHODS:
            return request.user and request.user.is_authenticated

        # Write permissions are only allowed to admin users
        return request.user and request.user.is_authenticated and request.user.is_admin_or_above


class IsSupervisorOrAbove(permissions.BasePermission):
    """
    Permission for supervisor level and above.
    """

    def has_permission(self, request, view):
        return (
            request.user and
            request.user.is_authenticated and
            request.user.is_supervisor_or_above
        )


class IsStaffMember(permissions.BasePermission):
    """
    Permission for staff members and above.
    """

    def has_permission(self, request, view):
        return (
            request.user and
            request.user.is_authenticated and
            request.user.is_staff_member
        )


class CanManageIncidents(permissions.BasePermission):
    """
    Custom permission for incident management based on user role and assignment.
    """

    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated

    def has_object_permission(self, request, view, obj):
        user = request.user

        # Admin and supervisors can manage all incidents
        if user.is_admin_or_above or user.is_supervisor_or_above:
            return True

        # Staff can manage assigned incidents or their own created incidents
        if user.is_staff_member:
            if hasattr(obj, 'assigned_to') and obj.assigned_to == user:
                return True
            if hasattr(obj, 'created_by') and obj.created_by == user:
                return True

        # Regular users can only view/edit their own incidents in limited ways
        if hasattr(obj, 'created_by') and obj.created_by == user:
            # Residents can only edit new incidents
            if request.method in permissions.SAFE_METHODS:
                return True
            return obj.status == 'new'

        return False