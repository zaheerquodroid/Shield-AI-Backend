"""
Fix templates for CSEC-19: DEBUG Defaults to True (Python)
"""

# Single Phase Fix Template (No phases needed - safe immediate change)
FIX_TEMPLATE = '''# Shield AI: CSEC-19 - DEBUG defaults to False (secure)
# Convert string to boolean, default to False for security
{variable_name} = os.environ.get('{env_var_name}', 'False').lower() in ('true', '1', 'yes')
'''

# Alternative Fix Template (More explicit)
FIX_TEMPLATE_EXPLICIT = '''# Shield AI: CSEC-19 - DEBUG defaults to False (secure)
{variable_name} = os.environ.get('{env_var_name}', 'False')
if isinstance({variable_name}, str):
    {variable_name} = {variable_name}.lower() in ('true', '1', 'yes')
'''

# Minimal Fix Template (Django-style)
FIX_TEMPLATE_MINIMAL = '''# Shield AI: CSEC-19 - Secure default (DEBUG=False)
{variable_name} = os.environ.get('{env_var_name}', 'False') == 'True'
'''

# .env.dev.example template
ENV_DEV_EXAMPLE_ENTRY = '''# DEBUG - Enable debug mode for development
# Set to True for local development, False for production
# WARNING: Never set DEBUG=True in production!
{env_var_name}=True
'''

# .env.prod.example template
ENV_PROD_EXAMPLE_ENTRY = '''# DEBUG - Disable debug mode in production (REQUIRED)
# Must be False or omitted in production environments
# Setting to True exposes sensitive information!
{env_var_name}=False
'''

# Documentation template
DOCUMENTATION_TEMPLATE = '''## Security Configuration: DEBUG Setting

Shield AI has updated the DEBUG setting to default to False for security.

### What Changed

**Before (INSECURE):**
```python
{before_code}
```
- If DEBUG env var is missing → DEBUG=True (DANGEROUS!)
- Exposes stack traces, SQL queries, and internal details in production

**After (SECURE):**
```python
{after_code}
```
- If DEBUG env var is missing → DEBUG=False (SAFE!)
- Production is secure by default
- Developers explicitly set DEBUG=True for local development

### Why This Matters

Running Django with DEBUG=True in production exposes:
- 🔴 Full stack traces with code snippets
- 🔴 SQL queries and database structure
- 🔴 Environment variables and secrets
- 🔴 Internal file paths
- 🔴 Django Debug Toolbar with sensitive info

### Setup Instructions

#### For Development (Local)
1. Create/update your `.env` file:
   ```bash
   DEBUG=True
   ```

2. Restart your development server

#### For Production
1. **Option A:** Set explicitly to False
   ```bash
   DEBUG=False
   ```

2. **Option B:** Don't set DEBUG at all (defaults to False)
   ```bash
   # DEBUG is not set - will default to False ✓
   ```

### Testing

```bash
# Test with DEBUG=True (development)
export DEBUG=True
python manage.py check
# Should see: DEBUG mode enabled

# Test with DEBUG=False (production)
export DEBUG=False
python manage.py check
# Should see: DEBUG mode disabled

# Test with DEBUG not set (should default to False)
unset DEBUG
python manage.py check
# Should see: DEBUG mode disabled (secure default)
```

### Current Status
- **Pattern:** CSEC-19 (DEBUG Defaults to True)
- **Severity:** Critical
- **Fix Applied:** Secure default (DEBUG=False)
- **Breaking Change:** No - safe for all environments

### Troubleshooting

If you see "Page not found (404)" or generic error pages:
1. Check your `.env` file has `DEBUG=True` for local development
2. Verify your virtual environment is activated
3. Restart your development server

For more information, see: [Shield AI Documentation](https://github.com/zaheerquodroid/Shield-AI-Backend)
'''

def get_template(phase='fix', framework='generic'):
    """
    Get the appropriate template based on framework

    Args:
        phase: Not used for CSEC-19 (single phase fix)
        framework: 'generic', 'django', 'flask', etc.

    Returns:
        str: The template code
    """
    # CSEC-19 is a single-phase fix, no warning period needed
    # Defaulting to False is always safe
    return FIX_TEMPLATE

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

def get_env_example_dev():
    """Get .env.dev.example template"""
    return ENV_DEV_EXAMPLE_ENTRY

def get_env_example_prod():
    """Get .env.prod.example template"""
    return ENV_PROD_EXAMPLE_ENTRY

def generate_documentation(before_code, after_code):
    """
    Generate documentation for DEBUG fix

    Args:
        before_code: Original vulnerable code
        after_code: Fixed secure code

    Returns:
        str: Documentation markdown
    """
    return DOCUMENTATION_TEMPLATE.format(
        before_code=before_code,
        after_code=after_code
    )
