"""
Shield AI Backend - Security Vulnerability Scanner
"""
import re
import os
from pathlib import Path
from typing import List, Dict, Any
import yaml


class SecurityScanner:
    """Scans codebases for security vulnerabilities based on patterns"""

    def __init__(self, patterns_dir: str = None):
        """
        Initialize the scanner

        Args:
            patterns_dir: Directory containing pattern YAML files
        """
        if patterns_dir is None:
            patterns_dir = Path(__file__).parent.parent / "patterns"

        self.patterns_dir = Path(patterns_dir)
        self.patterns = self.load_patterns()

    def load_patterns(self) -> List[Dict[str, Any]]:
        """Load all pattern definitions from YAML files"""
        patterns = []

        if not self.patterns_dir.exists():
            print(f"Warning: Patterns directory not found: {self.patterns_dir}")
            return patterns

        for yaml_file in self.patterns_dir.glob("*.yaml"):
            try:
                with open(yaml_file, 'r', encoding='utf-8') as f:
                    pattern = yaml.safe_load(f)
                    patterns.append(pattern)
                    print(f"✓ Loaded pattern: {pattern.get('pattern_id', yaml_file.name)}")
            except Exception as e:
                print(f"✗ Error loading {yaml_file}: {e}")

        return patterns

    def scan_codebase(self, repo_path: str, pattern_id: str = None) -> List[Dict[str, Any]]:
        """
        Scan a codebase for vulnerabilities

        Args:
            repo_path: Path to the codebase to scan
            pattern_id: Optional specific pattern to scan for

        Returns:
            List of findings
        """
        repo_path = Path(repo_path)
        findings = []

        if not repo_path.exists():
            raise FileNotFoundError(f"Repository path not found: {repo_path}")

        patterns_to_scan = self.patterns
        if pattern_id:
            patterns_to_scan = [p for p in self.patterns if p['pattern_id'] == pattern_id]
            if not patterns_to_scan:
                raise ValueError(f"Pattern not found: {pattern_id}")

        print(f"\n🔍 Scanning {repo_path}...")
        print(f"📋 Patterns to check: {len(patterns_to_scan)}\n")

        for pattern in patterns_to_scan:
            pattern_findings = self.scan_pattern(repo_path, pattern)
            findings.extend(pattern_findings)

            if pattern_findings:
                print(f"  ⚠️  Found {len(pattern_findings)} issues for {pattern['pattern_id']}")

        return findings

    def scan_pattern(self, repo_path: Path, pattern: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan for a specific pattern"""
        findings = []
        file_patterns = pattern.get('file_patterns', [])

        # Find matching files
        matching_files = self.find_matching_files(repo_path, file_patterns)

        for file_path in matching_files:
            file_findings = self.scan_file(file_path, pattern)
            findings.extend(file_findings)

        return findings

    def find_matching_files(self, repo_path: Path, file_patterns: List[str]) -> List[Path]:
        """Find files matching the given patterns"""
        matching_files = []

        for pattern in file_patterns:
            # Convert glob pattern to work with Path
            matches = list(repo_path.glob(pattern))
            matching_files.extend([m for m in matches if m.is_file()])

        return list(set(matching_files))  # Remove duplicates

    def scan_file(self, file_path: Path, pattern: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan a single file for pattern matches"""
        findings = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            print(f"  ⚠️  Could not read {file_path}: {e}")
            return findings

        # Detect language
        language = self.detect_language(file_path)

        # Get patterns for this language
        detection_patterns = pattern.get('detection', {}).get(language, [])

        for detect_pattern in detection_patterns:
            regex = detect_pattern['pattern']
            matches = re.finditer(regex, content, re.MULTILINE)

            for match in matches:
                finding = self.create_finding(
                    file_path=file_path,
                    pattern=pattern,
                    match=match,
                    content=content,
                    language=language,
                    detection_pattern=detect_pattern
                )
                findings.append(finding)

        return findings

    def detect_language(self, file_path: Path) -> str:
        """Detect programming language from file extension (Python only for CSEC-18)"""
        ext = file_path.suffix.lower()

        if ext == '.py':
            return 'python'

        return 'unknown'

    def create_finding(self, file_path: Path, pattern: Dict[str, Any],
                      match: re.Match, content: str, language: str,
                      detection_pattern: Dict[str, Any]) -> Dict[str, Any]:
        """Create a finding object from a pattern match"""
        line_number = content[:match.start()].count('\n') + 1

        # Extract metadata from match groups
        groups = match.groups()
        variable_name = groups[0] if len(groups) > 0 else "UNKNOWN"
        env_var_name = groups[1] if len(groups) > 1 else variable_name
        fallback_value = groups[2] if len(groups) > 2 else "'default'"

        return {
            'pattern_id': pattern['pattern_id'],
            'pattern_name': pattern['name'],
            'file': str(file_path),
            'line': line_number,
            'matched_code': match.group(0),
            'language': language,
            'severity': pattern['severity'],
            'category': pattern['category'],
            'description': detection_pattern['description'],
            'metadata': {
                'variable_name': variable_name,
                'env_var_name': env_var_name,
                'original_fallback': fallback_value
            },
            'jira_reference': pattern.get('jira_reference', {}),
            'fix_strategy': pattern.get('fix_strategy', {})
        }

    def get_line_context(self, content: str, line_number: int, context_lines: int = 3) -> str:
        """Get surrounding lines for context"""
        lines = content.split('\n')
        start = max(0, line_number - context_lines - 1)
        end = min(len(lines), line_number + context_lines)

        context = []
        for i in range(start, end):
            prefix = ">>> " if i == line_number - 1 else "    "
            context.append(f"{prefix}{i+1:4d} | {lines[i]}")

        return '\n'.join(context)
