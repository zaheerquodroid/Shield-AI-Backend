"""
Test file for CSEC-36: Safe code execution with validation
This file shows the correct pattern with code analysis - should NOT trigger warnings.
"""

# This file demonstrates the SECURE pattern with code analysis


# Secure pattern: Code analysis before execution
def execute_ai_script_safe(script_code):
    """Executes AI-generated code WITH validation - SECURE"""
    from code_analyzer import analyze_script

    # Analyze before execution
    analysis = analyze_script(script_code)

    if not analysis['is_safe']:
        raise SecurityError(
            f"Unsafe code detected: {analysis['violations']}"
        )

    # Safe to execute
    exec(script_code)


# Secure pattern: Validation wrapper
def safe_eval(expression):
    """Evaluates expression WITH validation"""
    from code_analyzer import analyze_script

    analysis = analyze_script(f"result = {expression}")

    if not analysis['is_safe']:
        raise ValueError(f"Unsafe expression: {expression}")

    return eval(expression)


# Secure pattern: Using safe_exec wrapper
def run_validated_code(code):
    """Uses the safe_exec wrapper"""
    from code_analyzer import safe_exec

    safe_exec(code)


# Safe usage: Only safe imports
def safe_calculation():
    """Uses only safe, allowed imports"""
    import math
    import json

    data = {"radius": 5}
    area = math.pi * data["radius"] ** 2
    return area


class SecurityError(Exception):
    """Security validation error"""
    pass
