from decouple import config

# Import shared settings
try:
    from .performance import REDIS_URL
except ImportError:
    # Fallback if performance module not available
    REDIS_URL = config('REDIS_URL', default='redis://localhost:6379/0')

# Celery Configuration
CELERY_BROKER_URL = config('CELERY_BROKER_URL', default=REDIS_URL)
CELERY_RESULT_BACKEND = config('CELERY_RESULT_BACKEND', default=REDIS_URL)
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = 'Africa/Nairobi'  # Match settings.TIME_ZONE
CELERY_TASK_TRACK_STARTED = True

# Task Persistence and Recovery Configuration
CELERY_TASK_PUBLISH_RETRY = True
CELERY_TASK_PUBLISH_RETRY_POLICY = {
    'max_retries': 3,
    'interval_start': 0,
    'interval_step': 0.2,
    'interval_max': 0.5,
}

# Worker restart and task recovery
CELERY_WORKER_DISABLE_RATE_LIMITS = True
CELERY_WORKER_PREFETCH_MULTIPLIER = 1  # Process one task at a time for better control
CELERY_WORKER_MAX_TASKS_PER_CHILD = 100  # Restart worker after tasks to prevent memory issues
CELERY_WORKER_CONCURRENCY = 4  # Adjust per CPU cores

# Task time limits
CELERY_TASK_TIME_LIMIT = 600  # hard timeout (will kill the task)
CELERY_TASK_SOFT_TIME_LIMIT = 300  # soft timeout

# Result backend settings for better persistence
CELERY_RESULT_EXPIRES = 3600  # Clean old results (1 hour default)
CELERY_RESULT_CACHE_MAX = 10000

# Task acknowledgment and visibility timeout
CELERY_TASK_ACKS_LATE = True  # Tasks acknowledged after completion
CELERY_TASK_REJECT_ON_WORKER_LOST = True  # Requeue tasks if worker dies
CELERY_WORKER_LOST_WAIT = 10.0  # Wait 10 seconds before requeuing lost tasks

# Broker settings
CELERY_BROKER_HEARTBEAT = 10  # Helps detect dead connections faster
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True

# Task settings
CELERY_TASK_DEFAULT_RETRY_DELAY = 10  # 10 seconds before retry
CELERY_TASK_DEFAULT_RATE_LIMIT = None

# Event monitoring for better debugging
CELERY_SEND_EVENTS = True
CELERY_SEND_TASK_EVENTS = True

# Task Routing Configuration
CELERY_TASK_DEFAULT_QUEUE = 'default'
CELERY_TASK_QUEUES = {
    'high_priority': {
        'exchange': 'high_priority',
        'routing_key': 'high_priority',
    },
    'default': {
        'exchange': 'default',
        'routing_key': 'default',
    },
    'low_priority': {
        'exchange': 'low_priority',
        'routing_key': 'low_priority',
    },
}

# CELERY_TASK_ROUTES = {
# ,
# }



# Django Celery Beat - Database Scheduler Configuration
# This allows dynamic schedule management through Django Admin
CELERY_BEAT_SCHEDULER = 'django_celery_beat.schedulers:DatabaseScheduler'
