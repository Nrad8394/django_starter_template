"""
Custom authentication URLs with properly tagged views
"""

from django.urls import path, include
from . import auth_views
from .views import HistoryListView
from .auth_permissions_view import UserPermissionsView

urlpatterns = [
    # Custom authentication endpoints with proper tags
    path("login/", auth_views.LoginView.as_view(), name="rest_login"),
    path("logout/", auth_views.LogoutView.as_view(), name="rest_logout"),
    path("user/", auth_views.UserDetailsView.as_view(), name="rest_user_details"),
    path("user/permissions/", UserPermissionsView.as_view(), name="user_permissions"),
    path(
        "password/change/",
        auth_views.PasswordChangeView.as_view(),
        name="rest_password_change",
    ),
    path(
        "password/reset/",
        auth_views.PasswordResetView.as_view(),
        name="rest_password_reset",
    ),
    # Support both path-based and body-based password reset confirmation requests.
    # Some frontends POST the uid/token in the request body instead of the URL.
    path(
        "password/reset/confirm/<uid>/<token>/",
        auth_views.PasswordResetConfirmView.as_view(),
        name="password_reset_confirm",
    ),
    path(
        "password/reset/confirm/",
        auth_views.PasswordResetConfirmView.as_view(),
        name="password_reset_confirm_body",
    ),
    # JWT token endpoints
    path(
        "token/refresh/",
        auth_views.CustomTokenRefreshView.as_view(),
        name="token_refresh",
    ),
    # NOTE: Registration endpoints removed - users are created via UserViewSet by admins
    # Email verification endpoints removed as well
    # Two-Factor Authentication
    path("2fa/setup/", auth_views.TwoFactorSetupView.as_view(), name="2fa-setup"),
    path(
        "2fa/verify-setup/",
        auth_views.TwoFactorVerifySetupView.as_view(),
        name="2fa-verify-setup",
    ),
    path(
        "2fa/verify-login/",
        auth_views.TwoFactorVerifyLoginView.as_view(),
        name="2fa-verify-login",
    ),
    path("2fa/disable/", auth_views.TwoFactorDisableView.as_view(), name="2fa-disable"),
    path(
        "2fa/regenerate-backup-codes/",
        auth_views.TwoFactorRegenerateBackupCodesView.as_view(),
        name="2fa-regenerate-backup-codes",
    ),
    path("2fa/status/", auth_views.TwoFactorStatusView.as_view(), name="2fa-status"),
    # User setup endpoints
    path("user/setup-status/", auth_views.UserSetupStatusView.as_view(), name="user-setup-status"),
    path("profile/complete/", auth_views.CompleteProfileView.as_view(), name="complete-profile"),
    path("enroll-face/", auth_views.EnrollFaceView.as_view(), name="enroll-face"),
]

urlpatterns += [
    path("history/", HistoryListView.as_view(), name="history-list"),
]
