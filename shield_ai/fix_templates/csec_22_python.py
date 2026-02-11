"""
Fix templates for CSEC-22: Unsanitized WebSocket Error Messages (Python/Django Channels)
"""

# Generic error wrapper template for WebSocket consumers
WEBSOCKET_ERROR_WRAPPER = '''import logging
import uuid

# Shield AI: Error sanitization for WebSocket
logger = logging.getLogger(__name__)

# In your exception handler, replace raw exception with this:
try:
    # Original code that might raise exception
    pass
except {exception_type} as {exception_var}:
    # Generate unique error ID for correlation
    error_id = str(uuid.uuid4())[:8]

    # Log full exception details server-side
    logger.error(
        f"WebSocket error [{{error_id}}]: {{str({exception_var})}}",
        exc_info=True,
        extra={{
            'error_id': error_id,
            'consumer': self.__class__.__name__,
            'user': getattr(self.scope.get('user'), 'username', 'anonymous') if hasattr(self, 'scope') else 'unknown'
        }}
    )

    # Send generic error message to client
    await self.send(text_data=json.dumps({{
        'error': 'An error occurred while processing your request. Please try again.',
        'error_id': error_id
    }}))
'''

# Template for text_data send with str(e)
FIX_TEMPLATE_TEXT_DATA = '''try:
    # Original code
    pass
except {exception_type} as {exception_var}:
    error_id = str(uuid.uuid4())[:8]
    logger.error(
        f"WebSocket error [{{error_id}}]: {{str({exception_var})}}",
        exc_info=True,
        extra={{'error_id': error_id, 'consumer': self.__class__.__name__}}
    )
    await self.send(text_data=json.dumps({{
        'error': 'An error occurred while processing your request. Please try again.',
        'error_id': error_id
    }}))'''

# Template for specific exception types with context-aware messages
CONTEXTUAL_ERROR_MESSAGES = {
    'ValidationError': 'Invalid input provided. Please check your data and try again.',
    'PermissionError': 'You do not have permission to perform this action.',
    'PermissionDenied': 'You do not have permission to perform this action.',
    'AuthenticationFailed': 'Authentication required. Please log in and try again.',
    'ObjectDoesNotExist': 'The requested resource was not found.',
    'DoesNotExist': 'The requested resource was not found.',
    'ConnectionError': 'Connection issue. Please check your network and try again.',
    'TimeoutError': 'Request timed out. Please try again.',
    'ValueError': 'Invalid input provided. Please check your data and try again.',
    'KeyError': 'Required field is missing. Please check your request.',
    'JSONDecodeError': 'Invalid data format. Please check your request.',
    'Exception': 'An error occurred while processing your request. Please try again.'
}

# Module-level imports to add
MODULE_IMPORTS = '''import logging
import uuid
import json
'''

# Logger initialization to add at module level
LOGGER_INIT = '''
# Shield AI: Error sanitization logger
logger = logging.getLogger(__name__)
'''

def get_error_message(exception_type):
    """
    Get appropriate generic error message based on exception type

    Args:
        exception_type: The type of exception (e.g., 'ValidationError')

    Returns:
        str: Generic error message appropriate for the exception type
    """
    return CONTEXTUAL_ERROR_MESSAGES.get(
        exception_type,
        CONTEXTUAL_ERROR_MESSAGES['Exception']
    )

def generate_fix(exception_var='e', exception_type='Exception', send_method='await self.send'):
    """
    Generate fix code for sanitizing WebSocket error messages

    Args:
        exception_var: Variable name of the exception (default: 'e')
        exception_type: Type of exception being caught (default: 'Exception')
        send_method: The send method being used (default: 'await self.send')

    Returns:
        str: Fix code to replace the vulnerable pattern
    """
    generic_message = get_error_message(exception_type)

    fix_code = f'''error_id = str(uuid.uuid4())[:8]
logger.error(
    f"WebSocket error [{{error_id}}]: {{str({exception_var})}}",
    exc_info=True,
    extra={{'error_id': error_id, 'consumer': self.__class__.__name__}}
)
{send_method}(text_data=json.dumps({{
    'error': '{generic_message}',
    'error_id': error_id
}}))'''

    return fix_code

# Template for adding imports if not present
def get_missing_imports(file_content):
    """
    Determine which imports are missing from the file

    Args:
        file_content: Content of the file being fixed

    Returns:
        str: Import statements to add
    """
    imports_to_add = []

    if 'import logging' not in file_content:
        imports_to_add.append('import logging')

    if 'import uuid' not in file_content:
        imports_to_add.append('import uuid')

    if 'import json' not in file_content:
        imports_to_add.append('import json')

    return '\n'.join(imports_to_add)

def get_logger_init(file_content):
    """
    Get logger initialization code if not present

    Args:
        file_content: Content of the file being fixed

    Returns:
        str: Logger initialization code
    """
    if 'logger = logging.getLogger' not in file_content:
        return '\n# Shield AI: Error sanitization logger\nlogger = logging.getLogger(__name__)\n'
    return ''

# .env.example template (not needed for CSEC-22, but included for consistency)
ENV_EXAMPLE_ENTRY = '''# LOGGING - Configure logging for error tracking
# Development: DEBUG
# Production: INFO or WARNING
LOG_LEVEL=INFO

# Optional: Sentry/error tracking service
# SENTRY_DSN=https://your-sentry-dsn
'''

# Documentation template
DOCUMENTATION_TEMPLATE = '''## WebSocket Error Message Sanitization

Shield AI has identified and fixed unsanitized error messages in WebSocket handlers
that could expose sensitive system information to clients.

### What Was Fixed?

**BEFORE (Insecure):**
```python
except Exception as e:
    await self.send(text_data=json.dumps({{
        'error': str(e)  # ❌ Exposes internal details!
    }}))
```

**AFTER (Secure):**
```python
except Exception as e:
    error_id = str(uuid.uuid4())[:8]
    logger.error(
        f"WebSocket error [{{error_id}}]: {{str(e)}}",
        exc_info=True,
        extra={{'error_id': error_id, 'consumer': self.__class__.__name__}}
    )
    await self.send(text_data=json.dumps({{
        'error': 'An error occurred while processing your request. Please try again.',
        'error_id': error_id
    }}))
```

### Security Benefits

**Prevents Information Disclosure:**
- ✅ No file paths or stack traces sent to clients
- ✅ No database schema details exposed
- ✅ No internal configuration revealed
- ✅ No library versions disclosed

**Maintains Observability:**
- ✅ Full exception details logged server-side
- ✅ Stack traces preserved in logs
- ✅ Error correlation via unique error IDs
- ✅ User context included in logs

### What Changed?

1. **Client-Side (WebSocket Response):**
   - Generic, user-friendly error messages
   - Unique error ID for support/debugging
   - No technical details exposed

2. **Server-Side (Logs):**
   - Full exception message and stack trace
   - Error correlation ID
   - User and consumer context
   - Timestamp and severity level

### Error Messages by Type

| Exception Type | Client Message |
|----------------|----------------|
| `ValidationError` | "Invalid input provided. Please check your data and try again." |
| `PermissionError` | "You do not have permission to perform this action." |
| `ObjectDoesNotExist` | "The requested resource was not found." |
| `ConnectionError` | "Connection issue. Please check your network and try again." |
| `TimeoutError` | "Request timed out. Please try again." |
| `Exception` (generic) | "An error occurred while processing your request. Please try again." |

### Debugging with Error IDs

**Client sees:**
```json
{{
  "error": "An error occurred while processing your request. Please try again.",
  "error_id": "a3f7b2c1"
}}
```

**Server logs:**
```
[ERROR] WebSocket error [a3f7b2c1]: division by zero
Traceback (most recent call last):
  File "/app/consumers.py", line 142, in receive
    result = calculate(data['value'])
ZeroDivisionError: division by zero
Extra: {{'error_id': 'a3f7b2c1', 'consumer': 'InterpreterConsumer', 'user': 'john@example.com'}}
```

### Logging Configuration

Ensure your Django settings include proper logging configuration:

```python
LOGGING = {{
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {{
        'verbose': {{
            'format': '[{{levelname}}] {{asctime}} {{name}} {{message}}',
            'style': '{{',
        }},
    }},
    'handlers': {{
        'console': {{
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        }},
        'file': {{
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': 'logs/websocket_errors.log',
            'maxBytes': 1024 * 1024 * 15,  # 15MB
            'backupCount': 10,
            'formatter': 'verbose',
        }},
    }},
    'loggers': {{
        '__name__': {{
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': False,
        }},
    }},
}}
```

### Testing

**Test that errors are sanitized:**
```python
# In your WebSocket consumer, trigger an error
# Check client receives generic message
# Check server logs contain full details

# Example test:
async def test_error_sanitization(self):
    # Trigger an error condition
    await self.communicate(invalid_data)

    # Client should receive generic message
    response = await self.receive_json_from()
    assert 'error_id' in response
    assert 'An error occurred' in response['error']
    assert 'ZeroDivisionError' not in response['error']

    # Server logs should contain full details
    # (Check your logging output)
```

### Security Impact

**OWASP Compliance:**
- ✅ Addresses A01:2021 - Broken Access Control
- ✅ Addresses A04:2021 - Insecure Design
- ✅ Follows OWASP Error Handling best practices

**Attack Prevention:**
- ✅ Prevents reconnaissance attacks
- ✅ Blocks information gathering
- ✅ Reduces attack surface
- ✅ Protects sensitive infrastructure details

### Support & Debugging

When users report errors:
1. Ask for the `error_id` from the error message
2. Search server logs for that error ID
3. Full exception context available for debugging
4. User context (username, timestamp) included

**Pattern:** CSEC-22 - Unsanitized WebSocket Error Messages
**Severity:** Critical
**Status:** Fixed
**References:**
- [OWASP Error Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)
- [CWE-209: Information Exposure Through Error Messages](https://cwe.mitre.org/data/definitions/209.html)

For more information, see: [Shield AI Documentation](https://github.com/zaheerquodroid/Shield-AI-Backend)
'''

def format_template(template, **kwargs):
    """
    Format a template with given variables

    Args:
        template: Template string
        **kwargs: Variables to substitute

    Returns:
        str: Formatted template
    """
    return template.format(**kwargs)
