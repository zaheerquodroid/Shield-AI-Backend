# Shield AI Backend - Quick Start Guide

## Installation

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Verify installation:**
   ```bash
   python -m shield_ai --help
   ```

## Usage Examples

### 1. Scan a Codebase (Coco TestAI)

```bash
# Scan entire codebase
python -m shield_ai scan /path/to/coco-testai

# Scan for specific pattern (CSEC-18)
python -m shield_ai scan /path/to/coco-testai --pattern csec_18_hardcoded_secret

# Scan for CSEC-19 (DEBUG defaults to True)
python -m shield_ai scan /path/to/coco-testai --pattern csec_19_debug_default_true

# Save findings to JSON
python -m shield_ai scan /path/to/coco-testai --output findings.json
```

### 2. Preview Fixes (Dry Run)

```bash
# Preview what changes will be made
python -m shield_ai fix /path/to/coco-testai --dry-run
```

### 3. Apply Phase 1 Fixes (Warning Mode - NON-BREAKING)

```bash
# Apply fixes with warnings (keeps existing code working)
python -m shield_ai fix /path/to/coco-testai --phase warning --deadline-days 30

# For Django specifically
python -m shield_ai fix /path/to/coco-testai --phase warning --framework django
```

**What happens:**
- ✅ Adds deprecation warnings when SECRET_KEY is not set
- ✅ Keeps fallback value (backwards compatible)
- ✅ Generates `.env.example` file
- ✅ Creates `SECURITY_UPDATES.md` documentation
- ✅ Creates backups of modified files

### 4. Apply Phase 2 Fixes (Enforcement Mode - BREAKING)

⚠️ **Only run after team has migrated (30 days later)**

```bash
# Enforce environment variable requirement
python -m shield_ai fix /path/to/coco-testai --phase enforcement
```

**What happens:**
- ❌ Application will fail to start if SECRET_KEY is not set
- ✅ Removes fallback value
- ✅ Forces secure configuration

### 5. Generate Reports

```bash
# Text report
python -m shield_ai report /path/to/coco-testai

# Markdown report
python -m shield_ai report /path/to/coco-testai --format markdown --output SECURITY_REPORT.md

# JSON report
python -m shield_ai report /path/to/coco-testai --format json --output report.json
```

## Workflow for CSEC-18 (Coco TestAI)

### Step 1: Scan
```bash
python -m shield_ai scan ../coco-testai --pattern csec_18_hardcoded_secret
```

**Expected output:**
```
🔍 Scanning ../coco-testai...
📋 Patterns to check: 1

  ⚠️  Found 1 issues for csec_18_hardcoded_secret

📊 SCAN RESULTS
Total findings: 1

Findings by severity:
  CRITICAL: 1

1. Hardcoded Secret Key with Fallback (csec_18_hardcoded_secret)
   File: ../coco-testai/coco_backend/settings.py:36
   Severity: CRITICAL
   Code: SECRET_KEY = os.environ.get('SECRET_KEY', 'insecure-default-key')...
   Env Var: SECRET_KEY
```

### Step 2: Preview Fixes
```bash
python -m shield_ai fix ../coco-testai --pattern csec_18_hardcoded_secret --dry-run
```

### Step 3: Apply Phase 1 (Non-Breaking)
```bash
python -m shield_ai fix ../coco-testai --pattern csec_18_hardcoded_secret --phase warning --framework django
```

**Files modified:**
- `coco_backend/settings.py` - Adds warning logic
- `.env.example` - Created with SECRET_KEY placeholder
- `SECURITY_UPDATES.md` - Documentation for developers
- `coco_backend/settings.py.shield_ai_backup` - Backup of original

### Step 4: Team Migration (30 days)
1. All developers update their `.env` files
2. CI/CD pipelines updated with SECRET_KEY
3. Monitor compliance

### Step 5: Apply Phase 2 (Enforcement)
```bash
# After 30 days and 100% migration
python -m shield_ai fix ../coco-testai --pattern csec_18_hardcoded_secret --phase enforcement --framework django
```

## Workflow for CSEC-19 (DEBUG Defaults to True)

### Step 1: Scan
```bash
python -m shield_ai scan ../coco-testai --pattern csec_19_debug_default_true
```

**Expected output:**
```
🔍 Scanning ../coco-testai...

  ⚠️  Found 1 issues for csec_19_debug_default_true

1. DEBUG Defaults to True (csec_19_debug_default_true)
   File: ../coco-testai/coco_backend/settings.py:39
   Severity: CRITICAL
   Code: DEBUG = os.environ.get('DEBUG', 'True')...
   Env Var: DEBUG
```

### Step 2: Preview Fixes
```bash
python -m shield_ai fix ../coco-testai --pattern csec_19_debug_default_true --dry-run
```

### Step 3: Apply Fix (Single Phase - Immediate)

⚠️ **CSEC-19 is simpler than CSEC-18 - single phase, no migration needed!**

```bash
# Apply the fix immediately (safe, non-breaking)
python -m shield_ai fix ../coco-testai --pattern csec_19_debug_default_true --framework django
```

**What happens:**
```python
# BEFORE:
DEBUG = os.environ.get('DEBUG', 'True')  # INSECURE!

# AFTER:
DEBUG = os.environ.get('DEBUG', 'False').lower() in ('true', '1', 'yes')  # SECURE!
```

**Files modified:**
- `coco_backend/settings.py` - DEBUG defaults to False
- `.env.dev.example` - Created with DEBUG=True for development
- `.env.prod.example` - Created with DEBUG=False for production
- `SECURITY_UPDATES.md` - Documentation
- `coco_backend/settings.py.shield_ai_backup` - Backup

### Step 4: Test Immediately

```bash
cd /path/to/coco-testai

# Test without DEBUG env var (should default to False - secure!)
python manage.py check
# App starts with DEBUG=False ✓

# Test with DEBUG=True (development)
export DEBUG=True
python manage.py check
# App starts with DEBUG=True ✓

# Test with DEBUG=False (production)
export DEBUG=False
python manage.py check
# App starts with DEBUG=False ✓
```

### Why CSEC-19 is Simpler

| Aspect | CSEC-18 | CSEC-19 |
|--------|---------|---------|
| **Phases** | 2 (warning → enforcement) | 1 (immediate fix) |
| **Migration period** | 30 days | None |
| **Breaking change** | Yes (Phase 2) | No |
| **Default behavior** | Fail if missing | False if missing |
| **Deployment** | Staged rollout | Immediate |

---

## File Structure After Running Shield AI

```
coco-testai/
├── .env.example                              # ✨ Generated by Shield AI
├── SECURITY_UPDATES.md                       # ✨ Generated by Shield AI
├── coco_backend/
│   ├── settings.py                          # ✅ Fixed by Shield AI
│   └── settings.py.shield_ai_backup         # 💾 Backup created
└── ... (rest of codebase)
```

## Rollback

If something goes wrong:

```bash
# Restore from backup
cp coco_backend/settings.py.shield_ai_backup coco_backend/settings.py
```

## Testing After Fix

```bash
# Test Phase 1 (should work with or without SECRET_KEY)
cd ../coco-testai
python manage.py check

# Test Phase 2 (should fail without SECRET_KEY)
unset SECRET_KEY
python manage.py check  # Should raise ImproperlyConfigured
```

## Support

For issues or questions:
- GitHub: https://github.com/zaheerquodroid/Shield-AI-Backend
- Jira:
  - CSEC-18 (Hardcoded SECRET_KEY)
  - CSEC-19 (DEBUG defaults to True)
