"""
Shield AI Backend CLI
"""
import sys
import argparse
import json
from pathlib import Path
from shield_ai.core.scanner import SecurityScanner
from shield_ai.core.fixer import SecurityFixer


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Shield AI Backend - Security Vulnerability Remediation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a codebase
  python -m shield_ai scan /path/to/codebase

  # Scan for specific pattern
  python -m shield_ai scan /path/to/codebase --pattern csec_18_hardcoded_secret

  # Preview fixes (dry run)
  python -m shield_ai fix /path/to/codebase --dry-run

  # Apply Phase 1 fixes (warnings)
  python -m shield_ai fix /path/to/codebase --phase warning

  # Apply Phase 2 fixes (enforcement)
  python -m shield_ai fix /path/to/codebase --phase enforcement

  # Generate report
  python -m shield_ai report /path/to/codebase --format json
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan codebase for vulnerabilities')
    scan_parser.add_argument('path', help='Path to codebase to scan')
    scan_parser.add_argument('--pattern', help='Specific pattern ID to scan for')
    scan_parser.add_argument('--output', help='Output file for findings (JSON)')

    # Fix command
    fix_parser = subparsers.add_parser('fix', help='Apply security fixes')
    fix_parser.add_argument('path', help='Path to codebase to fix')
    fix_parser.add_argument('--pattern', help='Specific pattern ID to fix')
    fix_parser.add_argument('--phase', choices=['warning', 'enforcement'],
                           default='warning', help='Fix phase to apply')
    fix_parser.add_argument('--deadline-days', type=int, default=30,
                           help='Days until enforcement (for warning phase)')
    fix_parser.add_argument('--dry-run', action='store_true',
                           help='Preview changes without applying them')
    fix_parser.add_argument('--framework', help='Framework hint (django, flask, etc.)')

    # Report command
    report_parser = subparsers.add_parser('report', help='Generate security report')
    report_parser.add_argument('path', help='Path to codebase to report on')
    report_parser.add_argument('--pattern', help='Specific pattern ID to report on')
    report_parser.add_argument('--format', choices=['text', 'json', 'markdown'],
                              default='text', help='Report format')
    report_parser.add_argument('--output', help='Output file for report')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Execute command
    try:
        if args.command == 'scan':
            return cmd_scan(args)
        elif args.command == 'fix':
            return cmd_fix(args)
        elif args.command == 'report':
            return cmd_report(args)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        return 1

    return 0


def cmd_scan(args):
    """Execute scan command"""
    print("=" * 80)
    print("🛡️  SHIELD AI BACKEND - SECURITY SCANNER")
    print("=" * 80)

    scanner = SecurityScanner()
    findings = scanner.scan_codebase(args.path, pattern_id=args.pattern)

    print(f"\n{'=' * 80}")
    print(f"📊 SCAN RESULTS")
    print(f"{'=' * 80}")
    print(f"Total findings: {len(findings)}")

    if findings:
        print(f"\nFindings by severity:")
        by_severity = {}
        for f in findings:
            sev = f['severity']
            by_severity[sev] = by_severity.get(sev, 0) + 1

        for sev, count in sorted(by_severity.items()):
            print(f"  {sev.upper()}: {count}")

        print(f"\nDetailed findings:")
        for i, finding in enumerate(findings, 1):
            print(f"\n{i}. {finding['pattern_name']} ({finding['pattern_id']})")
            print(f"   File: {finding['file']}:{finding['line']}")
            print(f"   Severity: {finding['severity'].upper()}")
            print(f"   Code: {finding['matched_code'][:80]}...")
            print(f"   Env Var: {finding['metadata']['env_var_name']}")

    # Save findings if output specified
    if args.output:
        output_path = Path(args.output)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(findings, f, indent=2)
        print(f"\n✓ Findings saved to {output_path}")

    return 0 if not findings else 1


def cmd_fix(args):
    """Execute fix command"""
    print("=" * 80)
    print("🛡️  SHIELD AI BACKEND - SECURITY FIXER")
    print("=" * 80)
    print(f"Mode: {'DRY RUN (Preview)' if args.dry_run else 'APPLY FIXES'}")
    print(f"Phase: {args.phase.upper()}")
    print("=" * 80)

    # First, scan for issues
    scanner = SecurityScanner()
    findings = scanner.scan_codebase(args.path, pattern_id=args.pattern)

    if not findings:
        print("\n✓ No security issues found!")
        return 0

    print(f"\nFound {len(findings)} issue(s) to fix\n")

    # Apply fixes
    fixer = SecurityFixer(dry_run=args.dry_run)
    results = []

    for finding in findings:
        result = fixer.apply_fix(
            finding,
            phase=args.phase,
            deadline_days=args.deadline_days,
            framework=args.framework
        )
        results.append(result)

    # Generate additional files
    if not args.dry_run:
        print("\n" + "=" * 80)
        print("📝 Generating documentation...")
        print("=" * 80)

        fixer.generate_env_example(findings)
        fixer.generate_documentation(findings, phase=args.phase,
                                    deadline_days=args.deadline_days)

    # Summary
    print("\n" + "=" * 80)
    print("📊 FIX SUMMARY")
    print("=" * 80)
    successful = sum(1 for r in results if r.get('success'))
    print(f"Total: {len(results)}")
    print(f"Successful: {successful}")
    print(f"Failed: {len(results) - successful}")

    if not args.dry_run:
        print("\n⚠️  IMPORTANT: Test your application after applying fixes!")
        print("   Backups created with .shield_ai_backup extension")

    return 0


def cmd_report(args):
    """Execute report command"""
    print("=" * 80)
    print("🛡️  SHIELD AI BACKEND - SECURITY REPORT")
    print("=" * 80)

    scanner = SecurityScanner()
    findings = scanner.scan_codebase(args.path, pattern_id=args.pattern)

    if args.format == 'json':
        report = generate_json_report(findings)
        output = json.dumps(report, indent=2)
    elif args.format == 'markdown':
        output = generate_markdown_report(findings)
    else:  # text
        output = generate_text_report(findings)

    if args.output:
        output_path = Path(args.output)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(output)
        print(f"\n✓ Report saved to {output_path}")
    else:
        print(output)

    return 0


def generate_json_report(findings):
    """Generate JSON report"""
    return {
        'total_findings': len(findings),
        'by_severity': get_by_severity(findings),
        'by_pattern': get_by_pattern(findings),
        'findings': findings
    }


def generate_markdown_report(findings):
    """Generate Markdown report"""
    report = "# Shield AI Security Report\n\n"
    report += f"**Total Findings:** {len(findings)}\n\n"

    if findings:
        report += "## Summary\n\n"
        report += "| Severity | Count |\n"
        report += "|----------|-------|\n"
        for sev, count in get_by_severity(findings).items():
            report += f"| {sev.upper()} | {count} |\n"

        report += "\n## Detailed Findings\n\n"
        for i, finding in enumerate(findings, 1):
            report += f"### {i}. {finding['pattern_name']}\n\n"
            report += f"- **File:** `{finding['file']}:{finding['line']}`\n"
            report += f"- **Severity:** {finding['severity'].upper()}\n"
            report += f"- **Pattern:** {finding['pattern_id']}\n"
            report += f"- **Environment Variable:** `{finding['metadata']['env_var_name']}`\n\n"
            report += f"```python\n{finding['matched_code']}\n```\n\n"

    return report


def generate_text_report(findings):
    """Generate text report"""
    report = "\n" + "=" * 80 + "\n"
    report += "SHIELD AI SECURITY REPORT\n"
    report += "=" * 80 + "\n\n"
    report += f"Total Findings: {len(findings)}\n\n"

    if findings:
        report += "By Severity:\n"
        for sev, count in get_by_severity(findings).items():
            report += f"  {sev.upper()}: {count}\n"

        report += "\nDetailed Findings:\n"
        report += "-" * 80 + "\n"
        for i, finding in enumerate(findings, 1):
            report += f"\n{i}. {finding['pattern_name']}\n"
            report += f"   File: {finding['file']}:{finding['line']}\n"
            report += f"   Severity: {finding['severity'].upper()}\n"
            report += f"   Code: {finding['matched_code'][:80]}\n"

    return report


def get_by_severity(findings):
    """Group findings by severity"""
    by_sev = {}
    for f in findings:
        sev = f['severity']
        by_sev[sev] = by_sev.get(sev, 0) + 1
    return by_sev


def get_by_pattern(findings):
    """Group findings by pattern"""
    by_pat = {}
    for f in findings:
        pat = f['pattern_id']
        by_pat[pat] = by_pat.get(pat, 0) + 1
    return by_pat


if __name__ == '__main__':
    sys.exit(main())
