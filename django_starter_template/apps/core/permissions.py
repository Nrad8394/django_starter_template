"""
Reusable DRF permission classes.

Scope rule for this module: nothing here may know anything about your domain.
A permission class that mentions an entity type belongs next to that entity,
not in ``core``.

(The version this replaces contained a ``CanManageIncidents`` class with rules
about residents editing incidents in the ``new`` state — a whole domain model
smuggled into a starter template, unusable by anyone not building an incident
tracker, and confusing for everyone who is not.)

Second scope rule: prefer Django's own permission framework over bespoke role
checks. ``DjangoModelPermissions`` reads ``app.add_model`` / ``change_model``
/ ``delete_model`` from the database, so permissions are data an administrator
can grant at runtime. A hand-rolled ``user.role == "manager"`` check is code,
and changing who can do what means a deploy. Reach for the role-based classes
at the bottom only when Django's model-level granularity genuinely is not
enough.
"""

from rest_framework import permissions

# Methods that do not modify state. DRF exposes these as ``SAFE_METHODS``;
# aliased here so the intent reads clearly at each call site.
SAFE_METHODS = permissions.SAFE_METHODS


class FullDjangoModelPermissions(permissions.DjangoModelPermissions):
    """
    ``DjangoModelPermissions`` that also guards reads.

    DRF's stock class deliberately leaves ``GET`` unguarded — it assumes read
    access is public and only writes need a permission. That is the wrong
    default for a private API: it means any authenticated user can list every
    model in the system unless each view remembers to say otherwise.

    This class requires ``view_<model>`` for reads, so access is deny-by-
    default and granted explicitly.
    """

    perms_map = {
        "GET": ["%(app_label)s.view_%(model_name)s"],
        "OPTIONS": [],
        "HEAD": [],
        "POST": ["%(app_label)s.add_%(model_name)s"],
        "PUT": ["%(app_label)s.change_%(model_name)s"],
        "PATCH": ["%(app_label)s.change_%(model_name)s"],
        "DELETE": ["%(app_label)s.delete_%(model_name)s"],
    }


class IsAuthenticatedReadOnly(permissions.BasePermission):
    """Any authenticated user may read; nobody may write."""

    def has_permission(self, request, view):
        return bool(
            request.method in SAFE_METHODS
            and request.user
            and request.user.is_authenticated
        )


class IsStaffOrReadOnly(permissions.BasePermission):
    """Authenticated users read; Django staff write."""

    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        if request.method in SAFE_METHODS:
            return True
        return bool(request.user.is_staff)


class IsAdminOrReadOnly(permissions.BasePermission):
    """Authenticated users read; superusers write."""

    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        if request.method in SAFE_METHODS:
            return True
        return bool(request.user.is_superuser)


class IsOwnerOrStaff(permissions.BasePermission):
    """
    Object-level: only the record's owner (or staff) may touch it.

    ``owner_field`` is read from the view so one class serves models that name
    the column differently::

        class InvoiceViewSet(BaseModelViewSet):
            permission_classes = [IsOwnerOrStaff]
            owner_field = "customer"     # defaults to "created_by"

    Important: object-level permissions run only on detail routes, because
    that is the only time DRF has an object. They do **not** filter list
    responses. Scope the queryset as well::

        def get_queryset(self):
            qs = super().get_queryset()
            if self.request.user.is_staff:
                return qs
            return qs.filter(created_by=self.request.user)

    Forgetting that half is the single most common way a "secured" API leaks
    every row to every user.
    """

    owner_field = "created_by"

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated)

    def has_object_permission(self, request, view, obj):
        if request.user.is_staff:
            return True

        owner_field = getattr(view, "owner_field", self.owner_field)
        owner = getattr(obj, owner_field, None)
        return owner is not None and owner == request.user


class IsOwnerOrReadOnly(permissions.BasePermission):
    """Everyone authenticated reads; only the owner writes."""

    owner_field = "created_by"

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated)

    def has_object_permission(self, request, view, obj):
        if request.method in SAFE_METHODS:
            return True

        owner_field = getattr(view, "owner_field", self.owner_field)
        owner = getattr(obj, owner_field, None)
        return owner is not None and owner == request.user


class HasRole(permissions.BasePermission):
    """
    Grant access when the user holds one of the roles a view names.

    Only reach for this when Django's model permissions cannot express the
    rule — typically for action endpoints that are not CRUD on one model
    (``POST /reports/reconcile/``), where there is no ``change_<model>``
    permission that means the right thing.

    Usage::

        class ReportViewSet(BaseModelViewSet):
            permission_classes = [HasRole]
            allowed_roles = ["manager", "auditor"]

    The role is read via ``ROLE_ATTRIBUTE`` so this works whether your user
    model stores a single ``role`` string, or something richer. Override
    ``get_user_roles`` for a many-to-many role table.

    Note the class does not hard-code any role name. A template that shipped
    ``IsSupervisorOrAbove`` would be asserting that every project built from
    it has supervisors, and would break at import time on any project whose
    user model lacks the matching property.
    """

    #: Attribute on the user model holding the role.
    ROLE_ATTRIBUTE = "role"

    def get_user_roles(self, user) -> set:
        value = getattr(user, self.ROLE_ATTRIBUTE, None)
        if value is None:
            return set()
        if isinstance(value, str):
            return {value}
        try:
            return set(value)
        except TypeError:
            return {str(value)}

    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False

        allowed = getattr(view, "allowed_roles", None)
        if not allowed:
            # A view that opts into HasRole but names no roles is almost
            # certainly a mistake. Deny rather than silently allow everyone.
            return False

        if request.user.is_superuser:
            return True

        return bool(self.get_user_roles(request.user) & set(allowed))


class ReadOnly(permissions.BasePermission):
    """
    Allow safe methods only. Compose with ``|`` to build "X, or read"::

        permission_classes = [IsAdminUser | ReadOnly]
    """

    def has_permission(self, request, view):
        return request.method in SAFE_METHODS
