# Shield AI Backend

A security vulnerability remediation tool that automatically detects and fixes security issues in codebases with minimal breaking changes.

## Features

- Pattern-based vulnerability detection
- Non-breaking phased fixes
- Python support (Django, Flask, FastAPI)
- Jira integration for tracking
- Compliance monitoring

## Current Patterns

- **CSEC-22**: Unsanitized WebSocket error messages - prevents information disclosure (wrapper fix)
- **CSEC-23**: Bare except clauses and missing DRF exception handler - prevents information disclosure and improves error handling (context-aware fix)
- **CSEC-26**: Missing DRF rate limiting configuration - prevents brute force attacks and API abuse (phased rollout fix)
- **CSEC-27**: Missing breached password validation - prevents credential stuffing attacks (configuration addition)
- **CSEC-28**: Missing or insecure Django security headers - prevents clickjacking, MIME sniffing, protocol downgrade attacks (configuration addition)
- **CSEC-29**: Missing Content-Security-Policy header - prevents XSS attacks (configuration addition)
- **CSEC-30**: Missing Permissions-Policy header - prevents unauthorized browser feature access (middleware addition)
- **CSEC-31**: Missing audit logging infrastructure - enables compliance and security incident tracking (feature addition)
- **CSEC-32**: Missing structured JSON logging - enables log aggregation and security monitoring (configuration addition)
- **CSEC-33**: Missing PostgreSQL Row-Level Security (RLS) - prevents cross-tenant data leaks (database-level isolation)
- **CSEC-34**: Missing AWS Secrets Manager integration - centralized secret management with rotation and audit trail (wrapper utility)
- **CSEC-35**: LLM prompt injection vulnerability - prevents manipulation of AI models via crafted inputs (wrapper utility)
- **CSEC-36**: Missing static code analysis for AI-generated scripts - prevents code injection from LLMs (AST-based validation)

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Scan a codebase
python -m shield_ai scan /path/to/codebase

# Apply fixes (Phase 1: Warning mode)
python -m shield_ai fix /path/to/codebase --phase warning

# Apply fixes (Phase 2: Enforcement mode)
python -m shield_ai fix /path/to/codebase --phase enforcement

# Generate report
python -m shield_ai report /path/to/codebase --format markdown
```

## Project Structure

```
shield_ai/
├── core/              # Core scanning and fixing logic
├── patterns/          # Vulnerability pattern definitions
├── fix_templates/     # Language-specific fix templates
├── utils/             # Utility functions
└── integrations/      # Third-party integrations (Jira, etc.)
```

## License

MIT
