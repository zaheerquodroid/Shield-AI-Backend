"""
Direct test script for CSEC-30 implementation
Tests Permissions-Policy header detection
"""
import sys
import json
from pathlib import Path
from shield_ai.core.scanner import SecurityScanner


def main():
    """Test CSEC-30 patterns"""
    print("=" * 80)
    print("SHIELD AI - CSEC-30 IMPLEMENTATION TEST")
    print("=" * 80)

    scanner = SecurityScanner()

    # Test: Missing Permissions-Policy detection
    print("\nTest: Missing Permissions-Policy Header Detection")
    print("-" * 80)
    findings = scanner.scan_codebase('tests', pattern_id='csec_30_missing_permissions_policy')

    print(f"Found {len(findings)} Permissions-Policy issues")

    for i, finding in enumerate(findings, 1):
        print(f"\n{i}. {finding['pattern_name']}")
        print(f"   File: {finding['file']}:{finding['line']}")
        print(f"   Description: {finding['description']}")
        print(f"   Code: {finding['matched_code'][:80]}...")

    # Summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    print(f"Permissions-Policy Issues: {len(findings)}")

    # Expected results
    print("\n" + "=" * 80)
    print("EXPECTED VS ACTUAL")
    print("=" * 80)
    print(f"Expected issues: 1+")
    print(f"Actual issues: {len(findings)}")
    print(f"Match: {'YES' if len(findings) >= 1 else 'NO'}")

    # Save detailed findings
    with open('csec_30_test_results.json', 'w', encoding='utf-8') as f:
        json.dump({
            'findings': findings,
            'summary': {
                'total_count': len(findings)
            }
        }, f, indent=2)

    print("\nDetailed results saved to csec_30_test_results.json")
    print("=" * 80)

    return 0


if __name__ == '__main__':
    sys.exit(main())
