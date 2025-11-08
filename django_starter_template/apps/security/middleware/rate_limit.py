import time
from django.core.cache import cache
from django.http import JsonResponse
from django.utils import timezone
from django.conf import settings
from ..models import RateLimit, AuditLog
from datetime import timedelta


class RateLimitMiddleware:
    """Middleware for rate limiting requests"""

    def __init__(self, get_response):
        self.get_response = get_response
        self.rate_limits = getattr(settings, 'RATE_LIMITS', {
            'default': {'requests': 100, 'window': 60},  # 100 requests per minute
            'api': {'requests': 1000, 'window': 3600},   # 1000 requests per hour
            'auth': {'requests': 5, 'window': 300},      # 5 auth attempts per 5 minutes
        })

    def __call__(self, request):
        # Skip rate limiting for certain paths
        exempt_paths = getattr(settings, 'RATE_LIMIT_EXEMPT_PATHS', [
            '/admin/', '/static/', '/media/', '/api/v1/core/health/'
        ])

        if any(request.path.startswith(path) for path in exempt_paths):
            return self.get_response(request)

        # Determine rate limit category
        category = self._get_rate_limit_category(request)

        # Check rate limits
        if not self._check_rate_limit(request, category):
            return self._rate_limit_exceeded_response(request)

        response = self.get_response(request)
        return response

    def _get_rate_limit_category(self, request):
        """Determine which rate limit category to use"""
        if request.path.startswith('/api/auth/'):
            return 'auth'
        elif request.path.startswith('/api/'):
            return 'api'
        return 'default'

    def _check_rate_limit(self, request, category):
        """Check if request is within rate limits"""
        limits = self.rate_limits.get(category, self.rate_limits['default'])

        # Get identifiers
        ip = self._get_client_ip(request)
        user_id = request.user.id if request.user.is_authenticated else None

        # Check if IP is blocked
        if self._is_identifier_blocked(ip, 'ip'):
            return False

        # Check if user is blocked
        if user_id and self._is_identifier_blocked(str(user_id), 'user'):
            return False

        # Check IP-based rate limit
        if not self._check_identifier_rate_limit(ip, request.path, limits, 'ip'):
            return False

        # Check user-based rate limit if authenticated
        if user_id and not self._check_identifier_rate_limit(str(user_id), request.path, limits, 'user'):
            return False

        return True

    def _is_identifier_blocked(self, identifier, limit_type):
        """Check if identifier is currently blocked"""
        now = timezone.now()
        return RateLimit.objects.filter(
            limit_type=limit_type,
            identifier=identifier,
            is_blocked=True,
            blocked_until__gt=now
        ).exists()

    def _check_identifier_rate_limit(self, identifier, endpoint, limits, limit_type):
        """Check rate limit for a specific identifier"""
        cache_key = f"ratelimit:{limit_type}:{identifier}:{endpoint}"
        window_seconds = limits['window']

        # Get current window data
        now = time.time()
        window_start = now - window_seconds

        # Get existing requests in window
        cached_data = cache.get(cache_key, [])
        # Filter out requests outside current window
        cached_data = [req_time for req_time in cached_data if req_time > window_start]

        # Check if limit exceeded
        if len(cached_data) >= limits['requests']:
            # Create or update rate limit record
            self._create_rate_limit_record(identifier, endpoint, limit_type, len(cached_data) + 1, window_seconds)
            return False

        # Add current request
        cached_data.append(now)
        cache.set(cache_key, cached_data, window_seconds)

        return True

    def _create_rate_limit_record(self, identifier, endpoint, limit_type, request_count, window_seconds):
        """Create a rate limit record in database"""
        now = timezone.now()
        window_start = now - timedelta(seconds=window_seconds)

        rate_limit, created = RateLimit.objects.get_or_create(
            limit_type=limit_type,
            identifier=identifier,
            endpoint=endpoint,
            window_start__gte=window_start,
            defaults={
                'window_start': window_start,
                'window_end': now + timedelta(seconds=window_seconds),
                'request_count': request_count,
                'is_blocked': True,
                'blocked_until': now + timedelta(minutes=15)  # Block for 15 minutes
            }
        )

        if not created:
            rate_limit.request_count = request_count
            rate_limit.is_blocked = True
            rate_limit.blocked_until = now + timedelta(minutes=15)
            rate_limit.save()

    def _get_client_ip(self, request):
        """Get the client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def _rate_limit_exceeded_response(self, request):
        """Return rate limit exceeded response"""
        # Log the rate limit violation
        AuditLog.objects.create(
            user=request.user if request.user.is_authenticated else None,
            event_type=AuditLog.EventType.SECURITY_VIOLATION,
            severity=AuditLog.Severity.MEDIUM,
            description=f"Rate limit exceeded for {request.path}",
            ip_address=self._get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT'),
            request_path=request.path,
            request_method=request.method,
        )

        return JsonResponse(
            {
                'error': 'Rate limit exceeded',
                'message': 'Too many requests. Please try again later.',
                'retry_after': 900  # 15 minutes
            },
            status=429
        )