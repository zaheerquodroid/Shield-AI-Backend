"""
Fix templates for CSEC-18: Hardcoded Secret with Fallback (Python)
"""

# Phase 1: Warning Template
PHASE_1_WARNING = '''import os
import warnings

# Shield AI: Phase 1 - Warning stage for {env_var_name}
{variable_name} = os.environ.get('{env_var_name}')
if not {variable_name}:
    warnings.warn(
        "\\n" + "="*80 + "\\n"
        "⚠️  SECURITY WARNING: {env_var_name} environment variable is not set!\\n"
        "Using insecure fallback key for development only.\\n"
        "This will be REQUIRED in production after {deadline}.\\n\\n"
        "To fix this:\\n"
        "  1. Generate a secure key:\\n"
        "     python -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())'\\n"
        "  2. Add to your .env file:\\n"
        "     {env_var_name}=<generated-key>\\n"
        "\\n"
        "Shield AI Security Remediation - Pattern: CSEC-18\\n"
        "="*80,
        DeprecationWarning,
        stacklevel=2
    )
    {variable_name} = {original_fallback}  # Temporary fallback

    # Optional: Track fallback usage for compliance monitoring
    import os as _os
    _os.environ['SHIELD_AI_USING_FALLBACK_{env_var_name}'] = 'true'
'''

# Phase 2: Enforcement Template
PHASE_2_ENFORCEMENT = '''import os

# Shield AI: Phase 2 - Enforcement for {env_var_name}
{variable_name} = os.environ.get('{env_var_name}')
if not {variable_name}:
    raise RuntimeError(
        "\\n" + "="*80 + "\\n"
        "❌ CONFIGURATION ERROR: {env_var_name} environment variable is REQUIRED\\n"
        "\\n"
        "The application cannot start without a secure {env_var_name}.\\n"
        "\\n"
        "To fix this:\\n"
        "  1. Generate a secure key:\\n"
        "     python -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())'\\n"
        "  2. Add to your .env file:\\n"
        "     {env_var_name}=<generated-key>\\n"
        "  3. Or set as environment variable:\\n"
        "     export {env_var_name}=<generated-key>\\n"
        "\\n"
        "Shield AI Security Remediation - Pattern: CSEC-18\\n"
        "="*80
    )
'''

# Phase 1: Django-specific Warning Template (with ImproperlyConfigured)
PHASE_1_DJANGO_WARNING = '''import os
import warnings
from django.core.exceptions import ImproperlyConfigured

# Shield AI: Phase 1 - Warning stage for {env_var_name}
{variable_name} = os.environ.get('{env_var_name}')
if not {variable_name}:
    warnings.warn(
        "\\n" + "="*80 + "\\n"
        "⚠️  SECURITY WARNING: {env_var_name} environment variable is not set!\\n"
        "Using insecure fallback key for development only.\\n"
        "This will raise ImproperlyConfigured after {deadline}.\\n\\n"
        "To fix this:\\n"
        "  1. Generate a secure key:\\n"
        "     python manage.py shell -c \\"from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())\\"\\n"
        "  2. Add to your .env file:\\n"
        "     {env_var_name}=<generated-key>\\n"
        "\\n"
        "Shield AI Security Remediation - Pattern: CSEC-18\\n"
        "="*80,
        DeprecationWarning,
        stacklevel=2
    )
    {variable_name} = {original_fallback}  # Temporary fallback
'''

# Phase 2: Django-specific Enforcement Template
PHASE_2_DJANGO_ENFORCEMENT = '''import os
from django.core.exceptions import ImproperlyConfigured

# Shield AI: Phase 2 - Enforcement for {env_var_name}
{variable_name} = os.environ.get('{env_var_name}')
if not {variable_name}:
    raise ImproperlyConfigured(
        "\\n" + "="*80 + "\\n"
        "❌ {env_var_name} environment variable is REQUIRED\\n"
        "\\n"
        "The Django application cannot start without a secure {env_var_name}.\\n"
        "\\n"
        "To fix this:\\n"
        "  1. Generate a secure key:\\n"
        "     python manage.py shell -c \\"from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())\\"\\n"
        "  2. Add to your .env file:\\n"
        "     {env_var_name}=<generated-key>\\n"
        "  3. Or set as environment variable:\\n"
        "     export {env_var_name}=<generated-key>\\n"
        "\\n"
        "Shield AI Security Remediation - Pattern: CSEC-18\\n"
        "Documentation: https://docs.djangoproject.com/en/stable/ref/settings/#secret-key\\n"
        "="*80
    )
'''

# .env.example template
ENV_EXAMPLE_ENTRY = '''# {env_var_name} - REQUIRED for security
# Generate with: python -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())'
# Keep this secret! Never commit the actual value to git.
{env_var_name}=your-secret-key-here-CHANGE-ME
'''

# Documentation template
DOCUMENTATION_TEMPLATE = '''## Security Configuration Required

Shield AI has identified that `{env_var_name}` needs to be configured via environment variable.

### Setup Instructions

1. **Generate a secure key:**
   ```bash
   python -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())'
   ```

2. **Add to your `.env` file:**
   ```bash
   {env_var_name}=<your-generated-key>
   ```

3. **Restart your application**

### Current Status
- **Phase:** {phase}
- **Enforcement Date:** {deadline}
- **Pattern:** CSEC-18 (Hardcoded Secret with Fallback)
- **Severity:** Critical

### What Changed?
- Removed hardcoded fallback value from settings
- Application now requires `{env_var_name}` to be set explicitly
- {phase_description}

### Troubleshooting
If you see warnings or errors about `{env_var_name}`:
1. Check your `.env` file exists and contains `{env_var_name}`
2. Verify your virtual environment is activated
3. Ensure `.env` file is in the project root
4. Check file permissions (should be readable)

For more information, see: [Shield AI Documentation](https://github.com/zaheerquodroid/Shield-AI-Backend)
'''

def get_template(phase, framework='generic'):
    """
    Get the appropriate template based on phase and framework

    Args:
        phase: 'warning' or 'enforcement'
        framework: 'generic', 'django', 'flask', etc.

    Returns:
        str: The template code
    """
    if framework == 'django':
        if phase == 'warning':
            return PHASE_1_DJANGO_WARNING
        else:
            return PHASE_2_DJANGO_ENFORCEMENT
    else:
        if phase == 'warning':
            return PHASE_1_WARNING
        else:
            return PHASE_2_ENFORCEMENT

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
