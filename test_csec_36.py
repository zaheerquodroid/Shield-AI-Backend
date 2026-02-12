"""
Direct test script for CSEC-36 implementation
Tests static code analysis pattern detection
"""
import sys
import json
from pathlib import Path
from shield_ai.core.scanner import SecurityScanner


def main():
    """Test CSEC-36 patterns"""
    print("=" * 80)
    print("SHIELD AI - CSEC-36 IMPLEMENTATION TEST")
    print("Static Code Analysis for AI-Generated Scripts")
    print("=" * 80)

    scanner = SecurityScanner()

    # Test: Missing code analysis detection
    print("\nTest: Missing Static Code Analysis Detection")
    print("-" * 80)
    findings = scanner.scan_codebase('tests', pattern_id='csec_36_missing_code_analysis')

    print(f"Found {len(findings)} code analysis issues")

    # Categorize findings
    exec_findings = []
    eval_findings = []
    compile_findings = []
    subprocess_findings = []
    import_findings = []
    other_findings = []

    for finding in findings:
        desc = finding['description'].lower()
        if 'exec()' in desc:
            exec_findings.append(finding)
        elif 'eval()' in desc:
            eval_findings.append(finding)
        elif 'compile()' in desc:
            compile_findings.append(finding)
        elif 'subprocess' in desc:
            subprocess_findings.append(finding)
        elif '__import__' in desc:
            import_findings.append(finding)
        else:
            other_findings.append(finding)

    print(f"\nBreakdown:")
    print(f"  exec() without validation: {len(exec_findings)}")
    print(f"  eval() without validation: {len(eval_findings)}")
    print(f"  compile() without validation: {len(compile_findings)}")
    print(f"  subprocess without validation: {len(subprocess_findings)}")
    print(f"  __import__() without validation: {len(import_findings)}")
    print(f"  Other dangerous patterns: {len(other_findings)}")

    # Display findings
    print("\nDetailed Findings (first 15):")
    for i, finding in enumerate(findings[:15], 1):
        print(f"\n{i}. {finding['pattern_name']}")
        print(f"   File: {finding['file']}:{finding['line']}")
        print(f"   Severity: {finding['severity'].upper()}")
        print(f"   Description: {finding['description']}")
        if len(finding['matched_code']) > 60:
            print(f"   Code: {finding['matched_code'][:60]}...")
        else:
            print(f"   Code: {finding['matched_code']}")

    # Summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    print(f"Total Issues: {len(findings)}")
    print(f"exec() calls: {len(exec_findings)}")
    print(f"eval() calls: {len(eval_findings)}")
    print(f"compile() calls: {len(compile_findings)}")
    print(f"subprocess calls: {len(subprocess_findings)}")

    # Expected results
    print("\n" + "=" * 80)
    print("EXPECTED VS ACTUAL")
    print("=" * 80)
    print(f"Expected: 5+ issues (exec, eval, compile, subprocess, __import__)")
    print(f"Actual: {len(findings)} issues")
    print(f"exec() detected: {len(exec_findings)} (expected: 3+)")
    print(f"eval() detected: {len(eval_findings)} (expected: 2+)")

    # Validation
    success = True
    if len(findings) < 5:
        print("\n[ERROR] Expected at least 5 dangerous code patterns")
        success = False
    if len(exec_findings) < 3:
        print("\n[ERROR] Expected at least 3 exec() calls")
        success = False
    if len(eval_findings) < 2:
        print("\n[ERROR] Expected at least 2 eval() calls")
        success = False

    if success:
        print("\nMatch: YES [OK]")
    else:
        print("\nMatch: NO [ERROR]")

    # Save detailed findings
    with open('csec_36_test_results.json', 'w', encoding='utf-8') as f:
        json.dump({
            'findings': findings,
            'summary': {
                'total_count': len(findings),
                'exec_findings': len(exec_findings),
                'eval_findings': len(eval_findings),
                'compile_findings': len(compile_findings),
                'subprocess_findings': len(subprocess_findings),
                'import_findings': len(import_findings),
                'other_findings': len(other_findings),
            }
        }, f, indent=2)

    print("\nDetailed results saved to csec_36_test_results.json")
    print("=" * 80)

    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
