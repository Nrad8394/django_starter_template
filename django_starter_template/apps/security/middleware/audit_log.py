import json
import time
from django.utils import timezone
from django.conf import settings
from ..models import AuditLog


class AuditLogMiddleware:
    """Middleware for logging security and audit events"""

    def __init__(self, get_response):
        self.get_response = get_response
        self.audit_paths = getattr(settings, 'AUDIT_LOG_PATHS', [
            '/api/',
        ])
        self.sensitive_fields = getattr(settings, 'AUDIT_SENSITIVE_FIELDS', [
            'password', 'token', 'key', 'secret', 'api_key'
        ])

    def __call__(self, request):
        # Store request data for logging
        self._store_request_data(request)

        start_time = time.time()
        response = self.get_response(request)
        duration = time.time() - start_time

        # Log the request if it matches audit criteria
        if self._should_audit_request(request, response):
            self._log_request(request, response, duration)

        return response

    def _store_request_data(self, request):
        """Store request data for later use"""
        # Store request body for POST/PUT/PATCH requests
        if request.method in ['POST', 'PUT', 'PATCH']:
            try:
                if hasattr(request, 'body') and request.body:
                    request._audit_body = request.body.decode('utf-8')
                    # Sanitize sensitive data
                    request._audit_body = self._sanitize_data(request._audit_body)
            except:
                request._audit_body = None

    def _should_audit_request(self, request, response):
        """Determine if request should be audited"""
        # Always audit authentication requests
        if any(request.path.startswith(path) for path in self.audit_paths):
            return True

        # Audit failed requests (4xx, 5xx)
        if response.status_code >= 400:
            return True

        # Audit suspicious activities
        if self._is_suspicious_request(request):
            return True

        return False

    def _is_suspicious_request(self, request):
        """Check if request appears suspicious"""
        # Check for SQL injection patterns
        sql_patterns = ['union', 'select', 'insert', 'update', 'delete', 'drop', 'exec', 'script']
        query_string = request.META.get('QUERY_STRING', '').lower()

        if any(pattern in query_string for pattern in sql_patterns):
            return True

        # Check for XSS patterns
        xss_patterns = ['<script', 'javascript:', 'onload=', 'onerror=']
        if hasattr(request, '_audit_body') and request._audit_body:
            body_lower = request._audit_body.lower()
            if any(pattern in body_lower for pattern in xss_patterns):
                return True

        return False

    def _log_request(self, request, response, duration):
        """Log the request details"""
        event_type = self._determine_event_type(request, response)
        severity = self._determine_severity(request, response)

        # Prepare request data
        request_data = None
        if hasattr(request, '_audit_body') and request._audit_body is not None:
            try:
                request_data = json.loads(request._audit_body)
            except:
                request_data = {'raw_body': request._audit_body[:500]}  # Truncate long bodies

        # Create audit log entry
        AuditLog.objects.create(
            user=request.user if request.user.is_authenticated else None,
            event_type=event_type,
            severity=severity,
            description=self._generate_description(request, response),
            ip_address=self._get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT'),
            session_key=request.session.session_key if hasattr(request, 'session') and request.session else None,
            request_path=request.path,
            request_method=request.method,
            request_data=request_data,
            response_status=response.status_code,
            additional_data={
                'duration': round(duration, 3),
                'query_params': dict(request.GET),
                'user_agent': request.META.get('HTTP_USER_AGENT'),
                'referer': request.META.get('HTTP_REFERER'),
            }
        )

    def _determine_event_type(self, request, response):
        """Determine the audit event type"""
        if request.path.startswith('/api/auth/login'):
            return AuditLog.EventType.LOGIN if response.status_code == 200 else AuditLog.EventType.FAILED_LOGIN
        elif request.path.startswith('/api/auth/logout'):
            return AuditLog.EventType.LOGOUT
        elif 'password' in request.path:
            return AuditLog.EventType.PASSWORD_CHANGE
        elif response.status_code >= 500:
            return AuditLog.EventType.SECURITY_VIOLATION
        elif response.status_code == 403:
            return AuditLog.EventType.UNAUTHORIZED_ACCESS
        elif self._is_suspicious_request(request):
            return AuditLog.EventType.SUSPICIOUS_ACTIVITY
        else:
            return AuditLog.EventType.API_ACCESS

    def _determine_severity(self, request, response):
        """Determine the severity level"""
        if response.status_code >= 500:
            return AuditLog.Severity.CRITICAL
        elif response.status_code == 403 or response.status_code == 401:
            return AuditLog.Severity.HIGH
        elif self._is_suspicious_request(request):
            return AuditLog.Severity.HIGH
        elif response.status_code >= 400:
            return AuditLog.Severity.MEDIUM
        else:
            return AuditLog.Severity.LOW

    def _generate_description(self, request, response):
        """Generate a human-readable description"""
        if request.path.startswith('/api/auth/login'):
            if response.status_code == 200:
                return f"Successful login for user {request.user.get_username() if request.user.is_authenticated else 'unknown'}"
            else:
                return "Failed login attempt"
        elif request.path.startswith('/api/auth/logout'):
            return "User logout"
        elif response.status_code >= 500:
            return f"Server error: {response.status_code}"
        elif response.status_code == 403:
            return "Access forbidden"
        elif self._is_suspicious_request(request):
            return "Suspicious request detected"
        else:
            return f"API access: {request.method} {request.path}"

    def _sanitize_data(self, data):
        """Remove sensitive information from data"""
        if isinstance(data, str):
            try:
                data_dict = json.loads(data)
                self._sanitize_dict(data_dict)
                return json.dumps(data_dict)
            except:
                return data
        elif isinstance(data, dict):
            self._sanitize_dict(data)
            return data
        return data

    def _sanitize_dict(self, data_dict):
        """Sanitize a dictionary by removing sensitive fields"""
        for field in self.sensitive_fields:
            for key in list(data_dict.keys()):
                if field.lower() in key.lower():
                    data_dict[key] = '***REDACTED***'

    def _get_client_ip(self, request):
        """Get the client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip