import re
import logging
from typing import Dict, Any
from django.core.cache import cache
from django.conf import settings

logger = logging.getLogger(__name__)

def mask_pii(text: str) -> str:
    """Mask personally identifiable information in text"""
    if not text:
        return text

    # Email masking
    text = re.sub(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '***@***.***', text)

    # Phone number masking
    text = re.sub(r'\+?[\d\s\-\(\)]{8,}', '***-***-****', text)

    # ID number masking (Kenyan format)
    text = re.sub(r'\b\d{8}\b', '********', text)

    return text

def log_with_trace(request, level: int, message: str, **kwargs):
    """Log with trace ID and additional context"""
    extra = {
        'trace_id': getattr(request, 'trace_id', 'unknown'),
        'user_id': getattr(request.user, 'id', 'anonymous') if hasattr(request, 'user') else 'anonymous',
        'path': getattr(request, 'path', 'unknown'),
        'method': getattr(request, 'method', 'unknown'),
        **kwargs
    }

    logger.log(level, mask_pii(message), extra=extra)

def cache_key(prefix: str, *args) -> str:
    """Generate consistent cache keys"""
    key_parts = [prefix] + [str(arg) for arg in args]
    return ':'.join(key_parts)

def get_client_ip(request) -> str:
    """Get client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

class ServiceResult:
    """Standardized service result wrapper"""

    def __init__(self, success: bool = True, data: Any = None,
                 error: str = None, error_code: str = None):
        self.success = success
        self.data = data
        self.error = error
        self.error_code = error_code

    @classmethod
    def success_result(cls, data: Any = None):
        return cls(success=True, data=data)

    @classmethod
    def error_result(cls, error: str, error_code: str = None):
        return cls(success=False, error=error, error_code=error_code)