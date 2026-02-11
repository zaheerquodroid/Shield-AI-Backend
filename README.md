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
