"""
Shield AI Backend - Security Vulnerability Fixer
"""
import os
import re
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime, timedelta
import importlib.util


class SecurityFixer:
    """Applies security fixes to codebases"""

    def __init__(self, templates_dir: str = None, dry_run: bool = False):
        """
        Initialize the fixer

        Args:
            templates_dir: Directory containing fix templates
            dry_run: If True, only preview changes without applying them
        """
        if templates_dir is None:
            templates_dir = Path(__file__).parent.parent / "fix_templates"

        self.templates_dir = Path(templates_dir)
        self.dry_run = dry_run
        self.templates = {}

    def load_template(self, pattern_id: str, language: str):
        """Load fix template for a specific pattern and language"""
        template_file = self.templates_dir / f"{pattern_id}_{language}.py"

        if not template_file.exists():
            raise FileNotFoundError(f"Template not found: {template_file}")

        # Dynamically import the template module
        spec = importlib.util.spec_from_file_location(f"template_{pattern_id}", template_file)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        return module

    def apply_fix(self, finding: Dict[str, Any], phase: str = "warning",
                  deadline_days: int = 30, framework: str = None) -> Dict[str, Any]:
        """
        Apply fix for a finding

        Args:
            finding: Finding dictionary from scanner
            phase: 'warning' or 'enforcement'
            deadline_days: Days until enforcement (for warning phase)
            framework: Optional framework hint (e.g., 'django', 'flask')

        Returns:
            Dict with fix results
        """
        pattern_id = finding['pattern_id']
        language = finding['language']
        file_path = Path(finding['file'])

        print(f"\n{'[DRY RUN] ' if self.dry_run else ''}Fixing {file_path}:{finding['line']}")
        print(f"  Pattern: {pattern_id}")
        print(f"  Phase: {phase}")

        # Load template module
        try:
            template_module = self.load_template(pattern_id, language)
        except FileNotFoundError as e:
            print(f"  ✗ {e}")
            return {'success': False, 'error': str(e)}

        # Detect framework if not provided
        if framework is None:
            framework = self.detect_framework(file_path)

        # Get the appropriate template
        template = template_module.get_template(phase, framework)

        # Calculate deadline
        deadline = (datetime.now() + timedelta(days=deadline_days)).strftime("%Y-%m-%d")

        # Format template with metadata
        fix_code = self.format_template(
            template,
            finding['metadata'],
            deadline=deadline,
            phase=phase,
            phase_description=self.get_phase_description(phase)
        )

        # Read current file content
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                original_content = f.read()
        except Exception as e:
            print(f"  ✗ Could not read file: {e}")
            return {'success': False, 'error': str(e)}

        # Replace the vulnerable code
        new_content = self.replace_code(
            original_content,
            finding['matched_code'],
            fix_code
        )

        if new_content == original_content:
            print(f"  ⚠️  No changes made (code might already be fixed)")
            return {'success': False, 'error': 'No changes needed'}

        # Preview or apply the fix
        if self.dry_run:
            print(f"\n  Preview of changes:")
            print(f"  {'─' * 60}")
            print(f"  BEFORE:")
            print(f"  {finding['matched_code']}")
            print(f"  {'─' * 60}")
            print(f"  AFTER:")
            print(f"  {fix_code.strip()}")
            print(f"  {'─' * 60}")
            return {'success': True, 'dry_run': True, 'preview': fix_code}
        else:
            try:
                # Backup original file
                backup_path = file_path.with_suffix(file_path.suffix + '.shield_ai_backup')
                with open(backup_path, 'w', encoding='utf-8') as f:
                    f.write(original_content)

                # Write fixed content
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(new_content)

                print(f"  ✓ Fix applied successfully")
                print(f"  ✓ Backup created: {backup_path}")

                return {
                    'success': True,
                    'file': str(file_path),
                    'backup': str(backup_path),
                    'phase': phase
                }
            except Exception as e:
                print(f"  ✗ Error applying fix: {e}")
                return {'success': False, 'error': str(e)}

    def format_template(self, template: str, metadata: Dict[str, Any], **kwargs) -> str:
        """Format template with metadata"""
        format_vars = {**metadata, **kwargs}
        return template.format(**format_vars)

    def replace_code(self, content: str, old_code: str, new_code: str) -> str:
        """Replace old code with new code in content"""
        # Escape special regex characters in old_code
        old_code_escaped = re.escape(old_code)

        # Replace
        new_content = re.sub(old_code_escaped, new_code, content, count=1)

        return new_content

    def detect_framework(self, file_path: Path) -> str:
        """Detect framework based on file path and imports"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Check for Django
            if 'django' in content.lower() or 'settings.py' in str(file_path):
                return 'django'

            # Check for Flask
            if 'flask' in content.lower():
                return 'flask'

            # Check for FastAPI
            if 'fastapi' in content.lower():
                return 'fastapi'

        except Exception:
            pass

        return 'generic'

    def get_phase_description(self, phase: str) -> str:
        """Get human-readable description of phase"""
        descriptions = {
            'warning': 'Application will show warnings but continue to work with fallback value',
            'enforcement': 'Application will fail to start if environment variable is not set'
        }
        return descriptions.get(phase, 'Unknown phase')

    def generate_env_example(self, findings: List[Dict[str, Any]], output_path: Path = None) -> str:
        """Generate .env.example file from findings"""
        if output_path is None:
            output_path = Path('.env.example')

        env_vars = set()
        for finding in findings:
            env_vars.add(finding['metadata']['env_var_name'])

        # Load template
        template_module = self.load_template(findings[0]['pattern_id'], 'python')
        env_template = template_module.ENV_EXAMPLE_ENTRY

        content = "# Shield AI - Security Configuration\n"
        content += "# Auto-generated on " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n\n"

        for env_var in sorted(env_vars):
            content += env_template.format(env_var_name=env_var) + "\n"

        if not self.dry_run:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"\n✓ Generated {output_path}")
        else:
            print(f"\n[DRY RUN] Would generate {output_path}:")
            print(content)

        return content

    def generate_documentation(self, findings: List[Dict[str, Any]], phase: str = "warning",
                              deadline_days: int = 30, output_path: Path = None) -> str:
        """Generate documentation for security fixes"""
        if output_path is None:
            output_path = Path('SECURITY_UPDATES.md')

        deadline = (datetime.now() + timedelta(days=deadline_days)).strftime("%Y-%m-%d")

        # Load template
        template_module = self.load_template(findings[0]['pattern_id'], 'python')
        doc_template = template_module.DOCUMENTATION_TEMPLATE

        content = "# Shield AI Security Updates\n\n"
        content += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        content += f"## Summary\n\n"
        content += f"Shield AI has identified and fixed {len(findings)} security issue(s) in your codebase.\n\n"

        # Group by environment variable
        by_env_var = {}
        for finding in findings:
            env_var = finding['metadata']['env_var_name']
            if env_var not in by_env_var:
                by_env_var[env_var] = []
            by_env_var[env_var].append(finding)

        for env_var, env_findings in by_env_var.items():
            content += doc_template.format(
                env_var_name=env_var,
                phase=phase.upper(),
                deadline=deadline,
                phase_description=self.get_phase_description(phase)
            )
            content += "\n"

        if not self.dry_run:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"✓ Generated {output_path}")
        else:
            print(f"\n[DRY RUN] Would generate {output_path}")

        return content
