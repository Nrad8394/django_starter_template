"""
Additional authentication views for user permissions
"""

from rest_framework import permissions, views
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema, OpenApiResponse


@extend_schema(
    tags=["Authentication"],
    summary="Get user permissions",
    description="Get current authenticated user's permissions as codenames array for frontend permission checking.",
    responses={
        200: OpenApiResponse(
            description="User permissions",
            response={
                "type": "object",
                "properties": {
                    "permissions": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Array of permission codenames",
                    },
                    "role": {"type": "string", "description": "User role name"},
                    "role_display": {
                        "type": "string",
                        "description": "User role display name",
                    },
                },
            },
        ),
        401: {"description": "Not authenticated"},
    },
)
class UserPermissionsView(views.APIView):
    """
    Return the current user's permissions as an array of codenames.
    This endpoint is called by the frontend usePermissions hook to fetch
    actual permissions from the backend instead of using static role mappings.
    """

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        """Get user's permissions as codenames array"""
        user = request.user

        # Get all permissions from user's role
        permission_codenames = []
        if user.role and user.role.is_active:
            # Include both the codename and the full app_label.codename format
            for perm in user.role.permissions.all():
                permission_codenames.append(perm.codename)
                # Also add the full format for module permissions
                permission_codenames.append(f"{perm.content_type.app_label}.{perm.codename}")

        return Response(
            {
                "permissions": permission_codenames,
                "role": user.role.name if user.role else None,
                "role_display": user.role.display_name if user.role else None,
            }
        )
