"""
Shield AI Backend - Security Vulnerability Remediation Tool
"""

__version__ = "0.1.0"
__author__ = "Shield AI Team"

from shield_ai.core.scanner import SecurityScanner
from shield_ai.core.fixer import SecurityFixer

__all__ = ['SecurityScanner', 'SecurityFixer']
