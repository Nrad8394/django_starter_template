# Middleware stack - Consistent across all environments
MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "apps.core.middleware.APICSRFMiddleware",  # Custom CSRF middleware for API
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django_otp.middleware.OTPMiddleware",
    "apps.core.middleware.CurrentUserMiddleware",  # Set current user in thread locals for audit fields
    "apps.accounts.middleware.LoginSecurityMiddleware",  # Login security enforcement
    "apps.accounts.middleware.SessionActivityMiddleware",  # Track session activity
    "apps.security.middleware.RateLimitMiddleware",  # Rate limiting
    "apps.security.middleware.AuditLogMiddleware",  # Audit logging
    "allauth.account.middleware.AccountMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "apps.core.middleware.RequestTracingMiddleware",
    "apps.core.middleware.PerformanceMiddleware",
    "apps.core.middleware.ErrorHandlingMiddleware",
]