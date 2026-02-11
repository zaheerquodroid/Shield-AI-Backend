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
                    print(f"[OK] Loaded pattern: {pattern.get('pattern_id', yaml_file.name)}")
            except Exception as e:
                print(f"[ERROR] Error loading {yaml_file}: {e}")

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

        print(f"\nScanning {repo_path}...")
        print(f"Patterns to check: {len(patterns_to_scan)}\n")

        for pattern in patterns_to_scan:
            pattern_findings = self.scan_pattern(repo_path, pattern)
            findings.extend(pattern_findings)

            if pattern_findings:
                print(f"  [!] Found {len(pattern_findings)} issues for {pattern['pattern_id']}")

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
            print(f"  [!] Could not read {file_path}: {e}")
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
        # For env_var_name, use groups[1] if it exists and is not None/empty, else use variable_name
        env_var_name = groups[1] if (len(groups) > 1 and groups[1]) else variable_name
        fallback_value = groups[2] if len(groups) > 2 else "'default'"

        # Context-aware analysis for bare except patterns (CSEC-23)
        context_analysis = {}
        if detection_pattern.get('context_aware', False):
            context_analysis = self.analyze_exception_context(content, match.start())

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
                'original_fallback': fallback_value,
                'context_analysis': context_analysis
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

    def analyze_exception_context(self, content: str, except_position: int) -> Dict[str, Any]:
        """
        Analyze the context around a bare except clause to suggest appropriate exception type.
        This is used for CSEC-23 bare except pattern detection.

        Args:
            content: Full file content
            except_position: Position of the except statement in content

        Returns:
            Dict with suggested_exception, confidence, and try_block_content
        """
        # Find the try block that this except belongs to
        try_block = self.extract_try_block(content, except_position)

        if not try_block:
            return {
                'suggested_exception': 'Exception',
                'confidence': 'low',
                'reason': 'Could not extract try block for analysis',
                'try_block_content': ''
            }

        # Context patterns to detect
        context_patterns = {
            'json_operations': {
                'patterns': [r'json\.loads', r'json\.load', r'json\.dumps', r'json\.dump'],
                'exception': 'json.JSONDecodeError',
                'confidence': 'high'
            },
            'file_operations': {
                'patterns': [r'open\(', r'\.read\(', r'\.write\(', r'Path\('],
                'exception': '(IOError, FileNotFoundError)',
                'confidence': 'high'
            },
            'database_operations': {
                'patterns': [r'\.execute\(', r'\.fetch', r'cursor\.', r'connection\.'],
                'exception': 'DatabaseError',
                'confidence': 'medium'
            },
            'http_requests': {
                'patterns': [r'requests\.', r'urllib\.', r'http\.'],
                'exception': 'requests.RequestException',
                'confidence': 'high'
            },
            'type_conversions': {
                'patterns': [r'\bint\(', r'\bfloat\(', r'\bstr\('],
                'exception': '(ValueError, TypeError)',
                'confidence': 'high'
            },
            'dict_access': {
                'patterns': [r'\[[\'\"]', r'\.get\('],
                'exception': 'KeyError',
                'confidence': 'medium'
            },
        }

        # Check which patterns match
        for context_name, context_info in context_patterns.items():
            for pattern in context_info['patterns']:
                if re.search(pattern, try_block):
                    return {
                        'suggested_exception': context_info['exception'],
                        'confidence': context_info['confidence'],
                        'reason': f'Detected {context_name} in try block',
                        'try_block_content': try_block,
                        'context_type': context_name
                    }

        # No specific pattern found
        return {
            'suggested_exception': 'Exception',
            'confidence': 'low',
            'reason': 'No specific operation pattern detected',
            'try_block_content': try_block,
            'context_type': 'generic'
        }

    def extract_try_block(self, content: str, except_position: int) -> str:
        """
        Extract the try block content before an except statement.

        Args:
            content: Full file content
            except_position: Position of the except statement

        Returns:
            str: Content of the try block, or empty string if not found
        """
        # Find the line of the except statement
        lines_before = content[:except_position].split('\n')
        except_line_num = len(lines_before) - 1

        # Work backwards to find the matching try statement
        lines = content.split('\n')
        try_line_num = -1

        # Simple indentation-based search (works for most Python code)
        except_indent = len(lines[except_line_num]) - len(lines[except_line_num].lstrip())

        for i in range(except_line_num - 1, max(0, except_line_num - 50), -1):
            line = lines[i]
            stripped = line.strip()

            if stripped.startswith('try:'):
                # Check if indentation matches
                try_indent = len(line) - len(line.lstrip())
                if try_indent == except_indent:
                    try_line_num = i
                    break

        if try_line_num == -1:
            return ""

        # Extract content between try and except
        try_block_lines = lines[try_line_num + 1:except_line_num]
        return '\n'.join(try_block_lines)
