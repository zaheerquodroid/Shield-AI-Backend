"""
Direct test script for CSEC-23 implementation
Bypasses CLI to avoid Unicode encoding issues on Windows
"""
import sys
import json
from pathlib import Path
from shield_ai.core.scanner import SecurityScanner


def main():
    """Test CSEC-23 patterns"""
    print("=" * 80)
    print("SHIELD AI - CSEC-23 IMPLEMENTATION TEST")
    print("=" * 80)

    scanner = SecurityScanner()

    # Test 1: Bare except detection
    print("\nTest 1: Bare Except Detection")
    print("-" * 80)
    findings_bare_except = scanner.scan_codebase('tests', pattern_id='csec_23_bare_except')

    print(f"Found {len(findings_bare_except)} bare except issues")
    for i, finding in enumerate(findings_bare_except, 1):
        print(f"\n{i}. {finding['pattern_name']}")
        print(f"   File: {finding['file']}:{finding['line']}")
        print(f"   Code: {finding['matched_code'].strip()}")

        # Print context analysis if available
        context = finding['metadata'].get('context_analysis', {})
        if context:
            print(f"   Suggested Exception: {context.get('suggested_exception', 'N/A')}")
            print(f"   Confidence: {context.get('confidence', 'N/A')}")
            print(f"   Reason: {context.get('reason', 'N/A')}")
            print(f"   Context Type: {context.get('context_type', 'N/A')}")

    # Test 2: DRF exception handler detection
    print("\n" + "=" * 80)
    print("Test 2: DRF Exception Handler Detection")
    print("-" * 80)
    findings_drf = scanner.scan_codebase('tests', pattern_id='csec_23_drf_exception_handler')

    print(f"Found {len(findings_drf)} DRF config issues")
    for i, finding in enumerate(findings_drf, 1):
        print(f"\n{i}. {finding['pattern_name']}")
        print(f"   File: {finding['file']}:{finding['line']}")
        print(f"   Description: {finding['description']}")

    # Summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    print(f"Bare Except Issues: {len(findings_bare_except)}")
    print(f"DRF Handler Issues: {len(findings_drf)}")
    print(f"Total Issues: {len(findings_bare_except) + len(findings_drf)}")

    # Expected results
    print("\n" + "=" * 80)
    print("EXPECTED VS ACTUAL")
    print("=" * 80)
    print(f"Expected bare except: 8")
    print(f"Actual bare except: {len(findings_bare_except)}")
    print(f"Match: {'YES' if len(findings_bare_except) == 8 else 'NO'}")

    print(f"\nExpected DRF issues: 1")
    print(f"Actual DRF issues: {len(findings_drf)}")
    print(f"Match: {'YES' if len(findings_drf) >= 1 else 'NO'}")

    # Save detailed findings
    with open('csec_23_test_results.json', 'w', encoding='utf-8') as f:
        json.dump({
            'bare_except_findings': findings_bare_except,
            'drf_handler_findings': findings_drf,
            'summary': {
                'bare_except_count': len(findings_bare_except),
                'drf_handler_count': len(findings_drf),
                'total_count': len(findings_bare_except) + len(findings_drf)
            }
        }, f, indent=2)

    print("\nDetailed results saved to csec_23_test_results.json")
    print("=" * 80)

    return 0


if __name__ == '__main__':
    sys.exit(main())
