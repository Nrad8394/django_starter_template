"""
Custom authentication views with proper API documentation tags
"""
from rest_framework import serializers
from dj_rest_auth.views import (
    LoginView as BaseLoginView,
    LogoutView as BaseLogoutView,
    UserDetailsView as BaseUserDetailsView,
    PasswordChangeView as BasePasswordChangeView,
    PasswordResetView as BasePasswordResetView,
    PasswordResetConfirmView as BasePasswordResetConfirmView,
)
from dj_rest_auth.registration.views import (
    RegisterView as BaseRegisterView,
    VerifyEmailView as BaseVerifyEmailView,
    ResendEmailVerificationView as BaseResendEmailVerificationView,
)
from drf_spectacular.utils import extend_schema, OpenApiParameter
from drf_spectacular.types import OpenApiTypes
from .serializers import (
    PasswordResetConfirmSerializer,
    PasswordResetConfirmResponseSerializer,
    PasswordResetSerializer
)


# Simple response serializers for API documentation
class LogoutResponseSerializer(serializers.Serializer):
    """Serializer for logout response"""
    detail = serializers.CharField(default="Successfully logged out.")


class MessageResponseSerializer(serializers.Serializer):
    """Generic message response serializer"""
    detail = serializers.CharField()
    message = serializers.CharField(required=False)


@extend_schema(
    tags=['Authentication'],
    summary="User authentication",
    description="User login with email and password authentication."
)
class LoginView(BaseLoginView):
    """
    Custom login view with proper API documentation
    """
    authentication_classes = []  # Allow unauthenticated access

    @extend_schema(
        auth=[],
        summary="User login",
        description="Authenticate user with email and password. Returns JWT tokens for API access.",
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)


@extend_schema(
    tags=['Authentication'],
    summary="User logout",
    description="Logout user and invalidate authentication tokens."
)
class LogoutView(BaseLogoutView):
    """
    Custom logout view with proper API documentation
    """
    serializer_class = LogoutResponseSerializer
    allowed_methods = ['POST']

    @extend_schema(
        tags=['Authentication'],
        summary="User logout",
        description="Logout user and invalidate JWT tokens.",
        responses={200: LogoutResponseSerializer}
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)


@extend_schema(
    tags=['Authentication'],
    summary="User registration",
    description="Register new user accounts with email verification."
)
class RegisterView(BaseRegisterView):
    """
    Custom registration view with proper API documentation
    """
    serializer_class = None  # Will be determined by dj-rest-auth

    @extend_schema(
        tags=['Authentication'],
        summary="User registration",
        description="Register a new user account. Creates user profile and assigns appropriate role.",
        request=OpenApiTypes.OBJECT,
        responses={201: OpenApiTypes.OBJECT, 400: OpenApiTypes.OBJECT}
    )
    def post(self, request, *args, **kwargs):
        from django.db import IntegrityError
        from rest_framework.response import Response
        from rest_framework import status
        import logging
        logger = logging.getLogger(__name__)
        try:
            response = super().post(request, *args, **kwargs)
            # If the response is already an error, just return it
            if hasattr(response, 'data') and response.status_code == 400 and 'non_field_errors' in response.data:
                return Response(response.data, status=status.HTTP_400_BAD_REQUEST)
            return response
        except Exception as e:
            logger.error(f"Registration error: {e}")
            if isinstance(e, IntegrityError) or 'UNIQUE constraint failed' in str(e):
                if 'auth_user.email' in str(e):
                    return Response(
                        {'email': ['A user with this email address already exists.']},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                else:
                    return Response(
                        {'error': ['Registration failed due to a data conflict. Please try again.']},
                        status=status.HTTP_400_BAD_REQUEST
                    )
            # If the exception has a 'detail' or 'args' with serializer errors, return them
            if hasattr(e, 'detail'):
                return Response(e.detail, status=status.HTTP_400_BAD_REQUEST)
            if hasattr(e, 'args') and e.args and isinstance(e.args[0], dict):
                return Response(e.args[0], status=status.HTTP_400_BAD_REQUEST)
            return Response(
                {'error': ['Registration failed. Please check your information and try again.']},
                status=status.HTTP_400_BAD_REQUEST
            )


@extend_schema(
    tags=['Users'],
    summary="User profile management",
    description="Get and update current user's profile information."
)
class UserDetailsView(BaseUserDetailsView):
    """
    Custom user details view with proper API documentation
    """

    @extend_schema(
        tags=['Users'],
        summary="Get user details",
        description="Get current authenticated user's profile information.",
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    @extend_schema(
        tags=['Users'],
        summary="Update user details",
        description="Update current authenticated user's profile information.",
    )
    def put(self, request, *args, **kwargs):
        return super().put(request, *args, **kwargs)

    @extend_schema(
        tags=['Users'],
        summary="Partially update user details",
        description="Partially update current authenticated user's profile information.",
    )
    def patch(self, request, *args, **kwargs):
        return super().patch(request, *args, **kwargs)


@extend_schema(
    tags=['Authentication'],
    summary="Password management",
    description="Change user password with current password verification."
)
class PasswordChangeView(BasePasswordChangeView):
    """
    Custom password change view with proper API documentation
    """

    @extend_schema(
        tags=['Authentication'],
        summary="Change password",
        description="Change user's password. Requires current password for verification.",
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)


@extend_schema(
    tags=['Authentication'],
    summary="Password reset",
    description="Request password reset via email."
)
class PasswordResetView(BasePasswordResetView):
    """
    Custom password reset view with proper API documentation and custom form
    """

    def get_serializer_class(self):
        """
        Return the custom password reset serializer
        """
        return PasswordResetSerializer

    @extend_schema(
        tags=['Authentication'],
        summary="Request password reset",
        description="Send password reset email to user.",
        responses={200: MessageResponseSerializer}
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)


@extend_schema(
    tags=['Authentication'],
    summary="Password reset confirmation",
    description="Confirm password reset with token and set new password."
)
class PasswordResetConfirmView(BasePasswordResetConfirmView):
    """
    Custom password reset confirm view with proper API documentation

    Accepts the following POST parameters:
    - uid: User ID (base36 encoded)
    - token: Password reset token
    - new_password1: New password
    - new_password2: New password confirmation

    Returns success message when password is reset successfully.
    """
    serializer_class = PasswordResetConfirmSerializer

    def get_serializer(self, *args, **kwargs):
        data = self.request.data.copy()
        data['uid'] = self.kwargs.get('uid')
        data['token'] = self.kwargs.get('token')
        kwargs['data'] = data
        return super().get_serializer(*args, **kwargs)

    @extend_schema(
        tags=['Authentication'],
        summary="Confirm password reset",
        description="Confirm password reset with token and set new password. "
                   "This endpoint validates the reset token and sets a new password for the user.",
        request=PasswordResetConfirmSerializer,
        parameters=[
            OpenApiParameter("uid", OpenApiTypes.STR, location=OpenApiParameter.PATH, description="User ID (base36 encoded)"),
            OpenApiParameter("token", OpenApiTypes.STR, location=OpenApiParameter.PATH, description="Password reset token"),
        ],
        responses={
            200: PasswordResetConfirmResponseSerializer,
            400: OpenApiTypes.OBJECT,  # Use OpenApiTypes.OBJECT for generic error responses
        }
    )
    def post(self, request, *args, **kwargs):
        """
        Confirm password reset and set new password.

        This method handles the password reset confirmation process by:
        1. Validating the provided uid and token
        2. Checking the new password meets requirements
        3. Setting the new password for the user
        4. Returning a success response
        """
        return super().post(request, *args, **kwargs)


@extend_schema(
    tags=['Authentication'],
    summary="Email verification",
    description="Verify user email addresses with verification tokens."
)
class VerifyEmailView(BaseVerifyEmailView):
    """
    Custom email verification view with proper API documentation
    """

    @extend_schema(
        tags=['Authentication'],
        summary="Verify email",
        description="Verify user's email address with verification token.",
        responses={200: MessageResponseSerializer}
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)


@extend_schema(
    tags=['Authentication'],
    summary="Email verification resend",
    description="Resend email verification tokens to users."
)
class ResendEmailVerificationView(BaseResendEmailVerificationView):
    """
    Custom resend email verification view with proper API documentation
    """

    @extend_schema(
        tags=['Authentication'],
        summary="Resend email verification",
        description="Resend email verification token to user.",
        responses={200: MessageResponseSerializer}
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)