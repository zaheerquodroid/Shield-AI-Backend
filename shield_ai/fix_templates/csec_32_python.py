"""
Fix templates for CSEC-32: Missing Structured JSON Logging (Python/Django)
"""

# ============================================================================
# OPTION 1: python-json-logger (Recommended - Lightweight)
# ============================================================================

PYTHON_JSON_LOGGER_CONFIG = '''
# Shield AI: Structured JSON Logging Configuration (python-json-logger)

import os
from pythonjsonlogger import jsonlogger

# Determine log level from environment
LOG_LEVEL = os.environ.get('DJANGO_LOG_LEVEL', 'INFO')

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,

    # JSON Formatters
    'formatters': {
        'json': {
            '()': 'pythonjsonlogger.jsonlogger.JsonFormatter',
            'format': '%(asctime)s %(levelname)s %(name)s %(message)s %(pathname)s %(lineno)d',
            'datefmt': '%Y-%m-%dT%H:%M:%S',
            # Add custom fields
            'rename_fields': {
                'levelname': 'level',
                'name': 'logger',
                'pathname': 'file',
                'lineno': 'line',
            },
        },
        # Fallback for console in development
        'verbose': {
            'format': '{levelname} {asctime} {name} {message}',
            'style': '{',
        },
    },

    # Filters
    'filters': {
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse',
        },
        'require_debug_true': {
            '()': 'django.utils.log.RequireDebugTrue',
        },
    },

    # Handlers
    'handlers': {
        # Console handler with JSON format
        'console_json': {
            'level': LOG_LEVEL,
            'class': 'logging.StreamHandler',
            'formatter': 'json',
        },
        # Console handler for development (human-readable)
        'console': {
            'level': 'DEBUG',
            'filters': ['require_debug_true'],
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
        # File handler for production logs
        'file_json': {
            'level': 'INFO',
            'filters': ['require_debug_false'],
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': 'logs/app.log',
            'maxBytes': 10485760,  # 10 MB
            'backupCount': 10,
            'formatter': 'json',
        },
        # Error log file
        'file_errors': {
            'level': 'ERROR',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': 'logs/errors.log',
            'maxBytes': 10485760,  # 10 MB
            'backupCount': 5,
            'formatter': 'json',
        },
    },

    # Loggers
    'loggers': {
        # Django request logger
        'django.request': {
            'handlers': ['console_json', 'file_json', 'file_errors'],
            'level': 'INFO',
            'propagate': False,
        },
        # Django server logger
        'django.server': {
            'handlers': ['console_json', 'file_json'],
            'level': 'INFO',
            'propagate': False,
        },
        # Security logger
        'django.security': {
            'handlers': ['console_json', 'file_json', 'file_errors'],
            'level': 'WARNING',
            'propagate': False,
        },
        # Application logger
        '': {  # Root logger
            'handlers': ['console_json', 'file_json'],
            'level': LOG_LEVEL,
        },
    },
}
'''

# ============================================================================
# OPTION 2: structlog (Advanced - Rich Features)
# ============================================================================

STRUCTLOG_CONFIG = '''
# Shield AI: Structured JSON Logging Configuration (structlog)

import os
import logging
import structlog
from structlog.stdlib import BoundLogger

# Determine log level from environment
LOG_LEVEL = os.environ.get('DJANGO_LOG_LEVEL', 'INFO')

# Configure structlog
structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.filter_by_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=BoundLogger,
    context_class=dict,
    cache_logger_on_first_use=True,
)

# Django LOGGING configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,

    # Formatters
    'formatters': {
        'json': {
            '()': structlog.stdlib.ProcessorFormatter,
            'processor': structlog.processors.JSONRenderer(),
        },
        'console': {
            '()': structlog.stdlib.ProcessorFormatter,
            'processor': structlog.dev.ConsoleRenderer(),
        },
    },

    # Filters
    'filters': {
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse',
        },
        'require_debug_true': {
            '()': 'django.utils.log.RequireDebugTrue',
        },
    },

    # Handlers
    'handlers': {
        'console_json': {
            'level': LOG_LEVEL,
            'class': 'logging.StreamHandler',
            'formatter': 'json',
        },
        'console': {
            'level': 'DEBUG',
            'filters': ['require_debug_true'],
            'class': 'logging.StreamHandler',
            'formatter': 'console',
        },
        'file_json': {
            'level': 'INFO',
            'filters': ['require_debug_false'],
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': 'logs/app.log',
            'maxBytes': 10485760,  # 10 MB
            'backupCount': 10,
            'formatter': 'json',
        },
    },

    # Loggers
    'loggers': {
        'django': {
            'handlers': ['console_json', 'file_json'],
            'level': 'INFO',
        },
        'django.request': {
            'handlers': ['console_json', 'file_json'],
            'level': 'INFO',
            'propagate': False,
        },
        '': {
            'handlers': ['console_json', 'file_json'],
            'level': LOG_LEVEL,
        },
    },
}
'''

# ============================================================================
# REQUEST CONTEXT MIDDLEWARE (Option 1: python-json-logger)
# ============================================================================

REQUEST_CONTEXT_MIDDLEWARE_JSON_LOGGER = '''
# Shield AI: Request Context Middleware for JSON Logging
# File: utils/middleware.py

import uuid
import logging
import time
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger(__name__)


class RequestContextLoggingMiddleware(MiddlewareMixin):
    """
    Adds request context to log records and logs each request.

    Adds the following to log context:
    - request_id: Unique identifier for request tracing
    - user_id: Authenticated user ID
    - username: Authenticated username
    - ip_address: Client IP address
    - path: Request path
    - method: HTTP method
    - user_agent: User agent string
    """

    def process_request(self, request):
        """Add context at request start."""
        # Generate unique request ID
        request.request_id = str(uuid.uuid4())
        request.start_time = time.time()

        # Add to all log records
        self._add_log_context(request)

    def process_response(self, request, response):
        """Log request completion."""
        if hasattr(request, 'start_time'):
            duration_ms = int((time.time() - request.start_time) * 1000)
        else:
            duration_ms = 0

        # Log the request
        logger.info(
            "Request completed",
            extra={
                'request_id': getattr(request, 'request_id', 'unknown'),
                'user_id': request.user.id if request.user.is_authenticated else None,
                'username': request.user.username if request.user.is_authenticated else 'anonymous',
                'ip_address': self._get_client_ip(request),
                'path': request.path,
                'method': request.method,
                'status_code': response.status_code,
                'duration_ms': duration_ms,
                'user_agent': request.META.get('HTTP_USER_AGENT', '')[:200],
                'referer': request.META.get('HTTP_REFERER', '')[:200],
            }
        )

        return response

    def process_exception(self, request, exception):
        """Log exceptions with context."""
        logger.error(
            f"Request exception: {exception}",
            exc_info=True,
            extra={
                'request_id': getattr(request, 'request_id', 'unknown'),
                'user_id': request.user.id if request.user.is_authenticated else None,
                'username': request.user.username if request.user.is_authenticated else 'anonymous',
                'ip_address': self._get_client_ip(request),
                'path': request.path,
                'method': request.method,
                'exception_type': type(exception).__name__,
            }
        )

    def _add_log_context(self, request):
        """Add request context to log filter."""
        # Note: This is simplified. In production, use contextvars or thread locals
        pass

    def _get_client_ip(self, request):
        """Get client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
'''

# ============================================================================
# REQUEST CONTEXT MIDDLEWARE (Option 2: structlog)
# ============================================================================

REQUEST_CONTEXT_MIDDLEWARE_STRUCTLOG = '''
# Shield AI: Request Context Middleware for structlog
# File: utils/middleware.py

import uuid
import time
import structlog
from django.utils.deprecation import MiddlewareMixin

logger = structlog.get_logger(__name__)


class RequestContextLoggingMiddleware(MiddlewareMixin):
    """
    Adds request context to structlog and logs each request.

    Uses structlog's context binding for automatic inclusion of
    request context in all log messages during request processing.
    """

    def process_request(self, request):
        """Bind request context."""
        # Generate unique request ID
        request.request_id = str(uuid.uuid4())
        request.start_time = time.time()

        # Bind context to structlog
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(
            request_id=request.request_id,
            user_id=request.user.id if request.user.is_authenticated else None,
            username=request.user.username if request.user.is_authenticated else 'anonymous',
            ip_address=self._get_client_ip(request),
            path=request.path,
            method=request.method,
        )

    def process_response(self, request, response):
        """Log request completion."""
        if hasattr(request, 'start_time'):
            duration_ms = int((time.time() - request.start_time) * 1000)
        else:
            duration_ms = 0

        # Log the request with bound context
        logger.info(
            "request_completed",
            status_code=response.status_code,
            duration_ms=duration_ms,
            user_agent=request.META.get('HTTP_USER_AGENT', '')[:200],
        )

        # Clear context
        structlog.contextvars.clear_contextvars()

        return response

    def process_exception(self, request, exception):
        """Log exceptions with context."""
        logger.error(
            "request_exception",
            exception_type=type(exception).__name__,
            exception_message=str(exception),
            exc_info=True,
        )

    def _get_client_ip(self, request):
        """Get client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
'''

# ============================================================================
# MIDDLEWARE SETTINGS ADDITION
# ============================================================================

ADD_LOGGING_MIDDLEWARE = '''    # Shield AI: Request context logging middleware
    'utils.middleware.RequestContextLoggingMiddleware','''

MIDDLEWARE_WITH_LOGGING = '''
# Shield AI: MIDDLEWARE with request context logging
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',

    # Shield AI: Request context logging
    'utils.middleware.RequestContextLoggingMiddleware',
]
'''

# ============================================================================
# EXAMPLE USAGE IN APPLICATION CODE
# ============================================================================

USAGE_EXAMPLE_STANDARD = '''
# Shield AI: Example logging usage with JSON logger

import logging

logger = logging.getLogger(__name__)

def process_payment(order_id, amount):
    """Process payment with structured logging."""
    logger.info(
        "Processing payment",
        extra={
            'order_id': order_id,
            'amount': amount,
            'currency': 'USD',
        }
    )

    try:
        # Process payment
        result = payment_gateway.charge(amount)

        logger.info(
            "Payment successful",
            extra={
                'order_id': order_id,
                'transaction_id': result.transaction_id,
                'amount': amount,
            }
        )

        return result

    except PaymentError as e:
        logger.error(
            "Payment failed",
            exc_info=True,
            extra={
                'order_id': order_id,
                'amount': amount,
                'error_code': e.code,
            }
        )
        raise
'''

USAGE_EXAMPLE_STRUCTLOG = '''
# Shield AI: Example logging usage with structlog

import structlog

logger = structlog.get_logger(__name__)

def process_payment(order_id, amount):
    """Process payment with structured logging."""
    log = logger.bind(order_id=order_id, amount=amount)

    log.info("processing_payment", currency="USD")

    try:
        # Process payment
        result = payment_gateway.charge(amount)

        log.info(
            "payment_successful",
            transaction_id=result.transaction_id,
        )

        return result

    except PaymentError as e:
        log.error(
            "payment_failed",
            error_code=e.code,
            exc_info=True,
        )
        raise
'''

# ============================================================================
# REQUIREMENTS & DEPENDENCIES
# ============================================================================

REQUIREMENTS_JSON_LOGGER = '''# Shield AI: Structured JSON Logging
python-json-logger>=2.0.7  # JSON log formatting
'''

REQUIREMENTS_STRUCTLOG = '''# Shield AI: Structured JSON Logging (Advanced)
structlog>=23.1.0  # Structured logging
django-structlog>=6.0.0  # Django integration for structlog
'''

# ============================================================================
# LOG DIRECTORY SETUP
# ============================================================================

CREATE_LOG_DIRECTORY = '''
# Shield AI: Create logs directory
# Add to .gitignore

logs/
*.log
'''

GITIGNORE_ENTRY = '''# Shield AI: Ignore log files
logs/
*.log
*.log.*
'''

# ============================================================================
# CLOUDWATCH CONFIGURATION (AWS)
# ============================================================================

CLOUDWATCH_CONFIG = '''
# Shield AI: CloudWatch Logs Agent Configuration
# File: /opt/aws/amazon-cloudwatch-agent/etc/config.json

{
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/log/django/app.log",
            "log_group_name": "/aws/django/application",
            "log_stream_name": "{instance_id}",
            "timestamp_format": "%Y-%m-%dT%H:%M:%S",
            "timezone": "UTC",
            "multi_line_start_pattern": "{",
            "encoding": "utf-8"
          },
          {
            "file_path": "/var/log/django/errors.log",
            "log_group_name": "/aws/django/errors",
            "log_stream_name": "{instance_id}",
            "timestamp_format": "%Y-%m-%dT%H:%M:%S",
            "timezone": "UTC"
          }
        ]
      }
    }
  }
}
'''

# ============================================================================
# ELASTICSEARCH/ELK CONFIGURATION
# ============================================================================

FILEBEAT_CONFIG = '''
# Shield AI: Filebeat Configuration for ELK Stack
# File: filebeat.yml

filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/django/app.log
    json.keys_under_root: true
    json.add_error_key: true
    fields:
      service: django-app
      environment: production

  - type: log
    enabled: true
    paths:
      - /var/log/django/errors.log
    json.keys_under_root: true
    json.add_error_key: true
    fields:
      service: django-app
      environment: production
      log_type: error

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "django-logs-%{+yyyy.MM.dd}"

logging.level: info
logging.to_files: true
'''

# ============================================================================
# DOCUMENTATION TEMPLATE
# ============================================================================

DOCUMENTATION_TEMPLATE = '''## Structured JSON Logging Added

Shield AI has converted plain text logging to structured JSON format for
better log parsing, analysis, and monitoring.

### What Was Added?

**JSON Log Format:**
- All logs now output in JSON format
- Structured fields for easy parsing
- Request context automatically included
- Compatible with CloudWatch, ELK, Splunk, Datadog

**Example Log Output:**
```json
{
  "timestamp": "2024-01-15T10:30:45.123Z",
  "level": "INFO",
  "logger": "django.request",
  "message": "Request completed",
  "request_id": "abc123-def456",
  "user_id": 42,
  "username": "john.doe",
  "ip_address": "192.168.1.100",
  "path": "/api/auth/login",
  "method": "POST",
  "status_code": 200,
  "duration_ms": 145
}
```

### Implementation Options

**Option 1: python-json-logger (Recommended)**
```bash
# Install dependency
pip install python-json-logger

# Already configured in settings.py:
LOGGING = {
    'formatters': {
        'json': {
            '()': 'pythonjsonlogger.jsonlogger.JsonFormatter',
            ...
        }
    }
}
```

**Option 2: structlog (Advanced)**
```bash
# Install dependencies
pip install structlog django-structlog

# Already configured in settings.py with context binding
```

### How It Works

**Request Logging Flow:**

1. **Request arrives** → Middleware generates request_id
2. **Context bound** → request_id, user_id, ip_address added to context
3. **Application logs** → All logs include request context automatically
4. **Response sent** → Request logged with status_code, duration_ms
5. **JSON output** → Logs written in structured JSON format

**Log Fields:**

| Field | Description | Example |
|-------|-------------|---------|
| timestamp | ISO 8601 timestamp | 2024-01-15T10:30:45.123Z |
| level | Log level | INFO, ERROR, WARNING |
| logger | Logger name | django.request |
| message | Log message | Request completed |
| request_id | Unique request ID | abc123-def456 |
| user_id | User ID | 42 |
| username | Username | john.doe |
| ip_address | Client IP | 192.168.1.100 |
| path | Request path | /api/auth/login |
| method | HTTP method | POST |
| status_code | Response status | 200 |
| duration_ms | Request duration | 145 |

### Configuration

**Logging Settings (settings.py):**
```python
# Log level from environment variable
LOG_LEVEL = os.environ.get('DJANGO_LOG_LEVEL', 'INFO')

# Handlers configured for:
# - Console output (JSON in production)
# - File rotation (10 MB per file, 10 backups)
# - Separate error log file
```

**Middleware Added:**
```python
# Request context automatically added to all logs
'utils.middleware.RequestContextLoggingMiddleware',
```

**Log Directory:**
```
logs/
├── app.log       # All application logs
└── errors.log    # Error logs only
```

### Integration with Log Aggregation

**CloudWatch Logs:**
```bash
# CloudWatch Insights query examples:

# Find all failed login attempts
fields @timestamp, username, ip_address
| filter message = "Login failed"
| sort @timestamp desc

# Track slow requests
fields @timestamp, path, duration_ms
| filter duration_ms > 1000
| stats avg(duration_ms) by path
```

**Elasticsearch/Kibana:**
```json
// Kibana query examples:

// Failed authentication attempts
{
  "query": {
    "bool": {
      "must": [
        { "match": { "logger": "django.security" }},
        { "match": { "level": "WARNING" }}
      ]
    }
  }
}
```

**Splunk:**
```spl
# Splunk query examples

# User activity by IP
index=django_logs | stats count by ip_address, username

# Error rate by endpoint
index=django_logs level=ERROR | stats count by path
```

### Security Benefits

**Audit Trail:**
- Complete request/response logging
- User activity tracking
- IP address logging
- Timestamp precision

**Incident Response:**
- Correlate events via request_id
- Track user actions
- Identify attack patterns
- Forensic analysis

**Threat Detection:**
- Brute force attempts
- Suspicious IP patterns
- Privilege escalation
- Data access anomalies

### Usage in Application Code

**Standard Logging:**
```python
import logging
logger = logging.getLogger(__name__)

# Logs automatically include request context
logger.info(
    "Payment processed",
    extra={
        'order_id': 12345,
        'amount': 99.99,
        'currency': 'USD',
    }
)
```

**Structlog (if using Option 2):**
```python
import structlog
logger = structlog.get_logger(__name__)

# Context binding
log = logger.bind(order_id=12345)
log.info("payment_processed", amount=99.99)
```

### Monitoring & Alerts

**Set up alerts for:**
- Error rate spikes
- Slow request duration
- Failed authentication attempts
- Unusual user activity patterns
- Security events

**Metrics to track:**
- Request count by endpoint
- Average response time
- Error rate by status code
- User activity by time of day

### Compliance

**Meets audit requirements:**
- PCI DSS Requirement 10 - Audit logging
- SOC 2 CC7.2 - System operations logging
- GDPR Article 30 - Records of processing
- HIPAA §164.312(b) - Audit controls
- ISO 27001 A.12.4.1 - Event logging

### Troubleshooting

**Issue 1: Logs not in JSON format**
```python
# Check LOGGING configuration
# Ensure 'json' formatter is used in handlers
```

**Issue 2: Missing request context**
```python
# Verify middleware is installed:
# 'utils.middleware.RequestContextLoggingMiddleware'
```

**Issue 3: Log file permissions**
```bash
# Ensure logs directory exists and is writable
mkdir -p logs
chmod 755 logs
```

### References

- [python-json-logger Documentation](https://github.com/madzak/python-json-logger)
- [structlog Documentation](https://www.structlog.org/)
- [CloudWatch Logs Insights](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/AnalyzingLogData.html)
- [ELK Stack Documentation](https://www.elastic.co/guide/index.html)

**Pattern:** CSEC-32 - Missing Structured JSON Logging
**Severity:** Medium
**Status:** Fixed

For more information, see: [Shield AI Documentation](https://github.com/zaheerquodroid/Shield-AI-Backend)
'''


def get_logging_option(option='json_logger'):
    """
    Get the appropriate logging configuration based on option.

    Args:
        option: 'json_logger' for python-json-logger or 'structlog' for structlog

    Returns:
        dict: Configuration details
    """
    if option == 'json_logger':
        return {
            'config': PYTHON_JSON_LOGGER_CONFIG,
            'middleware': REQUEST_CONTEXT_MIDDLEWARE_JSON_LOGGER,
            'requirements': REQUIREMENTS_JSON_LOGGER,
            'usage_example': USAGE_EXAMPLE_STANDARD,
        }
    else:  # structlog
        return {
            'config': STRUCTLOG_CONFIG,
            'middleware': REQUEST_CONTEXT_MIDDLEWARE_STRUCTLOG,
            'requirements': REQUIREMENTS_STRUCTLOG,
            'usage_example': USAGE_EXAMPLE_STRUCTLOG,
        }


def format_template(template, **kwargs):
    """
    Format a template with given variables.

    Args:
        template: Template string
        **kwargs: Variables to substitute

    Returns:
        str: Formatted template
    """
    return template.format(**kwargs)
