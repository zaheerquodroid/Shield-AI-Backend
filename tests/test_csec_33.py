"""
Direct test script for CSEC-33 implementation
Tests PostgreSQL RLS pattern detection
"""
import sys
import json
from pathlib import Path
from shield_ai.core.scanner import SecurityScanner


def main():
    """Test CSEC-33 patterns"""
    print("=" * 80)
    print("SHIELD AI - CSEC-33 IMPLEMENTATION TEST")
    print("PostgreSQL Row-Level Security (RLS) Detection")
    print("=" * 80)

    scanner = SecurityScanner()

    # Test: Missing RLS detection
    print("\nTest: Missing PostgreSQL RLS Detection")
    print("-" * 80)
    findings = scanner.scan_codebase('tests', pattern_id='csec_33_missing_rls')

    print(f"Found {len(findings)} RLS issues")

    # Categorize findings
    model_findings = []
    middleware_findings = []
    database_findings = []
    migration_findings = []

    for finding in findings:
        desc = finding['description'].lower()
        if 'model' in desc or 'tenant_id' in desc or 'fk' in desc:
            model_findings.append(finding)
        elif 'middleware' in desc:
            middleware_findings.append(finding)
        elif 'database' in desc:
            database_findings.append(finding)
        elif 'migration' in desc:
            migration_findings.append(finding)

    print(f"\nBreakdown:")
    print(f"  Models with tenant FK: {len(model_findings)}")
    print(f"  Missing RLS middleware: {len(middleware_findings)}")
    print(f"  Database configuration: {len(database_findings)}")
    print(f"  Migration files: {len(migration_findings)}")

    # Display findings
    for i, finding in enumerate(findings[:10], 1):  # Show first 10
        print(f"\n{i}. {finding['pattern_name']}")
        print(f"   File: {finding['file']}:{finding['line']}")
        print(f"   Severity: {finding['severity'].upper()}")
        print(f"   Description: {finding['description']}")
        if len(finding['matched_code']) > 80:
            print(f"   Code: {finding['matched_code'][:80]}...")
        else:
            print(f"   Code: {finding['matched_code']}")

    # Summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    print(f"Total RLS Issues: {len(findings)}")
    print(f"Models needing RLS: {len(model_findings)}")
    print(f"Missing middleware: {len(middleware_findings)}")

    # Expected results
    print("\n" + "=" * 80)
    print("EXPECTED VS ACTUAL")
    print("=" * 80)
    print(f"Expected: 3+ issues (3 models + 1 middleware + 1 database)")
    print(f"Actual: {len(findings)} issues")
    print(f"Models detected: {len(model_findings)} (expected: 3)")
    print(f"Middleware issues: {len(middleware_findings)} (expected: 1)")

    # Validation
    success = True
    if len(model_findings) < 3:
        print("\n[ERROR] Expected at least 3 models with tenant FK")
        success = False
    if len(middleware_findings) < 1:
        print("\n[ERROR] Expected at least 1 middleware issue")
        success = False

    if success:
        print("\nMatch: YES [OK]")
    else:
        print("\nMatch: NO [ERROR]")

    # Save detailed findings
    with open('csec_33_test_results.json', 'w', encoding='utf-8') as f:
        json.dump({
            'findings': findings,
            'summary': {
                'total_count': len(findings),
                'model_findings': len(model_findings),
                'middleware_findings': len(middleware_findings),
                'database_findings': len(database_findings),
                'migration_findings': len(migration_findings)
            }
        }, f, indent=2)

    print("\nDetailed results saved to csec_33_test_results.json")
    print("=" * 80)

    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
