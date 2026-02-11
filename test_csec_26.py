"""
Direct test script for CSEC-26 implementation
Tests rate limiting detection patterns
"""
import sys
import json
from pathlib import Path
from shield_ai.core.scanner import SecurityScanner


def main():
    """Test CSEC-26 patterns"""
    print("=" * 80)
    print("SHIELD AI - CSEC-26 IMPLEMENTATION TEST")
    print("=" * 80)

    scanner = SecurityScanner()

    # Test: Missing rate limiting detection
    print("\nTest: Missing Rate Limiting Detection")
    print("-" * 80)
    findings = scanner.scan_codebase('tests', pattern_id='csec_26_missing_rate_limiting')

    print(f"Found {len(findings)} rate limiting issues")

    # Group findings by type
    settings_findings = []
    view_findings = []

    for finding in findings:
        if 'settings' in finding['file'].lower():
            settings_findings.append(finding)
        elif 'views' in finding['file'].lower() or 'view' in finding['description'].lower():
            view_findings.append(finding)

    print(f"\nSettings issues: {len(settings_findings)}")
    for i, finding in enumerate(settings_findings, 1):
        print(f"\n{i}. {finding['pattern_name']}")
        print(f"   File: {finding['file']}:{finding['line']}")
        print(f"   Description: {finding['description']}")
        print(f"   Code: {finding['matched_code'][:80]}...")

    print(f"\nView issues: {len(view_findings)}")
    for i, finding in enumerate(view_findings, 1):
        print(f"\n{i}. {finding['pattern_name']}")
        print(f"   File: {finding['file']}:{finding['line']}")
        print(f"   Description: {finding['description']}")
        print(f"   Code: {finding['matched_code'][:80]}...")

    # Summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    print(f"Settings Issues: {len(settings_findings)}")
    print(f"View Issues: {len(view_findings)}")
    print(f"Total Issues: {len(findings)}")

    # Expected results
    print("\n" + "=" * 80)
    print("EXPECTED VS ACTUAL")
    print("=" * 80)
    print(f"Expected settings issues: 1")
    print(f"Actual settings issues: {len(settings_findings)}")
    print(f"Match: {'YES' if len(settings_findings) >= 1 else 'NO'}")

    print(f"\nExpected view issues: 7")
    print(f"Actual view issues: {len(view_findings)}")
    print(f"Match: {'YES' if len(view_findings) >= 7 else 'NO'}")

    print(f"\nTotal expected: 8")
    print(f"Total actual: {len(findings)}")
    print(f"Match: {'YES' if len(findings) >= 8 else 'NO'}")

    # Save detailed findings
    with open('csec_26_test_results.json', 'w', encoding='utf-8') as f:
        json.dump({
            'settings_findings': settings_findings,
            'view_findings': view_findings,
            'summary': {
                'settings_count': len(settings_findings),
                'view_count': len(view_findings),
                'total_count': len(findings)
            }
        }, f, indent=2)

    print("\nDetailed results saved to csec_26_test_results.json")
    print("=" * 80)

    return 0


if __name__ == '__main__':
    sys.exit(main())
