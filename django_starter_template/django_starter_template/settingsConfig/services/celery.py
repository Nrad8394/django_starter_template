"""
Celery background task get_envuration.

This file centralizes Celery settings for task queuing, scheduling,
and worker get_envuration.

Reference: https://docs.celeryproject.io/
"""
from ..env import get_env
from ..base import TIME_ZONE
# ============================================================================
# CELERY BROKER SETTINGS
# ============================================================================

# Broker URL (Message broker - Redis or RabbitMQ)
CELERY_BROKER_URL = get_env(
    'CELERY_BROKER_URL',
    default='redis://localhost:6379/0'
)

# Read and write URLs (for redundancy)
CELERY_BROKER_READ_URL = get_env('CELERY_BROKER_READ_URL', default=None)
CELERY_BROKER_WRITE_URL = get_env('CELERY_BROKER_WRITE_URL', default=None)

# Connection pooling for Redis
CELERY_BROKER_POOL_LIMIT = get_env('CELERY_BROKER_POOL_LIMIT', default=10, cast=int)

# Broker connection options
CELERY_BROKER_CONNECTION_RETRY = get_env('CELERY_BROKER_CONNECTION_RETRY', default=True, cast=bool)
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = get_env('CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP', default=True, cast=bool)
CELERY_BROKER_CONNECTION_MAX_RETRIES = get_env('CELERY_BROKER_CONNECTION_MAX_RETRIES', default=10, cast=int)

# ============================================================================
# CELERY RESULT BACKEND SETTINGS
# ============================================================================

# Result backend (Where task results are stored)
CELERY_RESULT_BACKEND = get_env(
    'CELERY_RESULT_BACKEND',
    default='redis://localhost:6379/1'
)
CELERY_RESULT_BACKEND = get_env('CELERY_RESULT_BACKEND', default='django-db')  # Use Django database for results
# Result backend options
CELERY_RESULT_EXPIRES = get_env('CELERY_RESULT_EXPIRES', default=3600, cast=int)  # 1 hour
CELERY_RESULT_EXTENDED = get_env('CELERY_RESULT_EXTENDED', default=True, cast=bool)
CELERY_RESULT_PERSISTENT = get_env('CELERY_RESULT_PERSISTENT', default=True, cast=bool)

# ============================================================================
# CELERY TASK SETTINGS
# ============================================================================

# Default queue name
CELERY_TASK_DEFAULT_QUEUE = get_env('CELERY_TASK_DEFAULT_QUEUE', default='celery')

# Task serialization
CELERY_TASK_SERIALIZER = get_env('CELERY_TASK_SERIALIZER', default='json')
CELERY_ACCEPT_CONTENT = ['json']
CELERY_RESULT_SERIALIZER = get_env('CELERY_RESULT_SERIALIZER', default='json')

# Always eager execution (for testing/development)
CELERY_TASK_ALWAYS_EAGER = get_env('CELERY_TASK_ALWAYS_EAGER', default=False, cast=bool)

# Store task results eagerly
CELERY_TASK_EAGER_PROPAGATES = get_env('CELERY_TASK_EAGER_PROPAGATES', default=False, cast=bool)

# Task acknowledgment (Late acknowledgment - task ack after completion)
CELERY_TASK_ACKS_LATE = get_env('CELERY_TASK_ACKS_LATE', default=True, cast=bool)

# Task soft/hard time limits
CELERY_TASK_SOFT_TIME_LIMIT = get_env('CELERY_TASK_SOFT_TIME_LIMIT', default=300, cast=int)  # 5 minutes
CELERY_TASK_TIME_LIMIT = get_env('CELERY_TASK_TIME_LIMIT', default=600, cast=int)  # 10 minutes

# Ignore results from tasks (reduce storage)
CELERY_TASK_IGNORE_RESULT = get_env('CELERY_TASK_IGNORE_RESULT', default=False, cast=bool)

# Store task results even for eager tasks
CELERY_TASK_STORE_EAGER_RESULT = get_env('CELERY_TASK_STORE_EAGER_RESULT', default=False, cast=bool)

# Default task compression
CELERY_TASK_COMPRESSION = get_env('CELERY_TASK_COMPRESSION', default='gzip')

# ============================================================================
# CELERY WORKER SETTINGS
# ============================================================================

# Worker prefetch multiplier (Number of messages the worker can reserve)
CELERY_WORKER_PREFETCH_MULTIPLIER = get_env('CELERY_WORKER_PREFETCH_MULTIPLIER', default=4, cast=int)

# Max tasks per child process (prevents memory leaks)
CELERY_WORKER_MAX_TASKS_PER_CHILD = get_env('CELERY_WORKER_MAX_TASKS_PER_CHILD', default=1000, cast=int)

# Worker event logging
CELERY_WORKER_SEND_TASK_EVENTS = get_env('CELERY_WORKER_SEND_TASK_EVENTS', default=False, cast=bool)

# Disable heartbeat to reduce network traffic
CELERY_WORKER_DISABLE_RATE_LIMITS = get_env('CELERY_WORKER_DISABLE_RATE_LIMITS', default=False, cast=bool)

# ============================================================================
# CELERY BEAT SCHEDULER (Periodic Tasks)
# ============================================================================

# Beat scheduler implementation
CELERY_BEAT_SCHEDULER = 'django_celery_beat.schedulers:DatabaseScheduler'

# ============================================================================
# CELERY TIMEZONE & TIMEZONE HANDLING
# ============================================================================

# Use UTC for task scheduling
CELERY_ENABLE_UTC = get_env('CELERY_ENABLE_UTC', default=True, cast=bool)

# Timezone for interpreting crontab times
CELERY_TIMEZONE = TIME_ZONE
# ============================================================================
# CELERY LOGGING
# ============================================================================

# Log format
CELERY_TASK_LOG_FORMAT = '[%(asctime)s: %(levelname)s/%(processName)s] %(task_name)s[%(task_id)s]: %(message)s'
CELERY_WORKER_LOG_FORMAT = '[%(asctime)s: %(levelname)s/%(processName)s] %(message)s'

# Task event logging
CELERY_TASK_TRACK_STARTED = get_env('CELERY_TASK_TRACK_STARTED', default=True, cast=bool)

# Send task started events
CELERY_TASK_SEND_SENT_EVENT = get_env('CELERY_TASK_SEND_SENT_EVENT', default=False, cast=bool)

# ============================================================================
# CELERY MONITORING & SECURITY
# ============================================================================

# Secrets to hide in logs
CELERY_SECURITY_DIGEST = get_env('CELERY_SECURITY_DIGEST', default='sha256')

# Redis connection options (if using Redis broker)
CELERY_REDIS_DB = get_env('CELERY_REDIS_DB', default=0, cast=int)
CELERY_REDIS_HOST = get_env('CELERY_REDIS_HOST', default='localhost')
CELERY_REDIS_PORT = get_env('CELERY_REDIS_PORT', default=6379, cast=int)
CELERY_REDIS_PASSWORD = get_env('CELERY_REDIS_PASSWORD', default=None)

# ============================================================================
# CELERY ENABLE EAGER MODE
# ============================================================================

# Disable by setting environment variable CELERY_ALWAYS_EAGER=true for testing
CELERY_ALWAYS_EAGER = get_env('CELERY_ALWAYS_EAGER', default=False, cast=bool)