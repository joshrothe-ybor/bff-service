#!/usr/bin/env python3
"""
Template Variable Substitution Audit Script

This script scans the archetype template files for hardcoded references 
that should be replaced with template variables.

Usage:
    python scripts/validate_templates.py [--template-dir PATH] [--reference-dir PATH]
"""

import os
import re
import sys
import argparse
from pathlib import Path
from typing import List
from dataclasses import dataclass

@dataclass
class Issue:
    file_path: Path
    line_number: int
    issue_type: str
    line_content: str
    pattern: str
    suggested_fix: str = ""

class TemplateValidator:
    """Validates archetype templates for proper variable substitution."""
    
    def __init__(self, template_dir: Path, reference_dir: Path = None):
        self.template_dir = template_dir
        self.reference_dir = reference_dir
        self.issues: List[Issue] = []
        
        # Patterns to detect hardcoded references
        self.hardcoded_patterns = {
            # Service name patterns  
            r'python-rest01-service(?!-)': 'Service name should use bff-service',
            r'python-rest01-service-([a-z-]+)': 'Package name should use bff-service-$1',
            r'python_rest01_service': 'Python package should use bff_service',
            
            # Database patterns (excluding template variables and false positives)
            r'(?<!prefix_name }}_\{\{ suffix_name }})example_service(?!_core|_api|Service|Client|Impl)': 'Database name should use bff_service',
            
            # Import path patterns  
            r'from ybor\.playground\.python_rest01\.service': 'Import should use ybor.faq.bff.service',
            r'import ybor\.playground\.python_rest01\.service': 'Import should use ybor.faq.bff.service',
            r'-m ybor\.playground\.python_rest01\.service': 'Module path should use ybor.faq.bff.service',
            
            # Docker and container patterns
            r'python-rest01-service(?=:)': 'Container name should use bff-service',
            r'python-rest01-service-postgres': 'Container name should use bff-service-postgres',
            r'python-rest01-service-prometheus': 'Container name should use bff-service-prometheus',
            r'python-rest01-service-grafana': 'Container name should use bff-service-grafana',
            
            # GitHub Actions workflow patterns
            r'Python REST Service(?! Integration)': 'Workflow name should use bff-service REST Service',
            
            # Configuration and title patterns
            r'"Python REST Service"': 'Title should use "bff-service REST Service"',
            r"'Python REST Service'": 'Title should use "bff-service REST Service"',
        }
        
        # File patterns to check
        self.file_extensions = {'.py', '.yml', '.yaml', '.toml', '.sh', '.md', '.sql', '.json'}
        
        # Files to exclude from validation
        self.exclude_files = {
            'validate_templates.py',  # This script itself
            '__pycache__',
            '.git',
            'node_modules',
            '.venv',
            'dist',
            'build'
        }
    
    def should_check_file(self, file_path: Path) -> bool:
        """Determine if a file should be checked for template issues."""
        # Skip if file extension not in our list
        if file_path.suffix not in self.file_extensions:
            return False
            
        # Skip excluded files/directories
        for exclude in self.exclude_files:
            if exclude in str(file_path):
                return False
                
        return True
    
    def _is_likely_false_positive(self, line: str) -> bool:
        """Check if a line is likely to contain false positive matches."""
        line_stripped = line.strip()
        
        # Skip function definitions, class definitions, imports
        if (line_stripped.startswith(('def ', 'class ', 'async def ')) or
            line_stripped.startswith(('from ', 'import ')) or
            '@pytest.fixture' in line or
            line_stripped.startswith('def test_')):
            return True
            
        return False
    
    def scan_file(self, file_path: Path) -> List[Issue]:
        """Scan a single file for template issues."""
        issues = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            for line_num, line in enumerate(lines, 1):
                line_content = line.rstrip()
                
                # Skip lines that already use template variables correctly
                if ' in line_content and ' in line_content:
                    continue
                
                # Skip lines that are clearly false positives
                if self._is_likely_false_positive(line_content):
                    continue
                    
                # Check each hardcoded pattern
                for pattern, description in self.hardcoded_patterns.items():
                    matches = re.finditer(pattern, line_content)
                    for match in matches:
                        # Generate suggested fix
                        suggested_fix = self._generate_fix_suggestion(pattern, line_content, match)
                        
                        issue = Issue(
                            file_path=file_path,
                            line_number=line_num,
                            issue_type=description,
                            line_content=line_content,
                            pattern=pattern,
                            suggested_fix=suggested_fix
                        )
                        issues.append(issue)
                        
        except Exception as e:
            print(f"Warning: Could not read {file_path}: {e}")
            
        return issues
    
    def _generate_fix_suggestion(self, pattern: str, line: str, match: re.Match) -> str:
        """Generate a suggested fix for a matched pattern."""
        matched_text = match.group(0)
        
        # Generate fixes based on common patterns
        fixes = {
            'python-rest01-service': 'bff-service',
            'python_rest01_service': 'bff_service',
            'example_service': 'bff_service',
            'ybor.playground.python_rest01.service': 'ybor.faq.bff.service',
            'Python REST Service': 'bff-service REST Service',
        }
        
        for old_text, new_text in fixes.items():
            if old_text in matched_text:
                return line.replace(matched_text, new_text)
                
        return f"Replace '{matched_text}' with appropriate template variable"
    
    def scan_directory(self, directory: Path) -> None:
        """Recursively scan a directory for template issues."""
        for file_path in directory.rglob('*'):
            if file_path.is_file() and self.should_check_file(file_path):
                file_issues = self.scan_file(file_path)
                self.issues.extend(file_issues)
    
    def run_validation(self) -> bool:
        """Run the complete validation process."""
        print(f"Scanning template directory: {self.template_dir}")
        
        # Scan for hardcoded patterns
        self.scan_directory(self.template_dir)
        
        # Report results
        return self.report_results()
    
    def report_results(self) -> bool:
        """Report validation results."""
        if not self.issues:
            print("✅ No template validation issues found!")
            print("All hardcoded references appear to be properly templated.")
            return True
        
        print(f"❌ Found {len(self.issues)} template validation issues:")
        print("=" * 60)
        
        # Group issues by file
        issues_by_file = {}
        for issue in self.issues:
            file_path = str(issue.file_path)
            if file_path not in issues_by_file:
                issues_by_file[file_path] = []
            issues_by_file[file_path].append(issue)
        
        # Report issues by file
        for file_path, file_issues in sorted(issues_by_file.items()):
            print(f"\n📁 {file_path}")
            print("-" * 40)
            
            for issue in file_issues:
                print(f"  Line {issue.line_number}: {issue.issue_type}")
                print(f"    Current: {issue.line_content}")
                if issue.suggested_fix:
                    print(f"    Suggest: {issue.suggested_fix}")
                print()
        
        print("=" * 60)
        print(f"Total issues: {len(self.issues)}")
        print("\nPlease fix these issues before releasing the archetype.")
        
        return False


def main():
    """Main entry point for the validation script."""
    parser = argparse.ArgumentParser(description='Validate archetype template variables')
    parser.add_argument('--template-dir', 
                       type=Path, 
                       default=Path('.'),
                       help='Path to template directory (default: current directory)')
    parser.add_argument('--reference-dir', 
                       type=Path,
                       help='Path to reference implementation for comparison')
    parser.add_argument('--quiet', '-q',
                       action='store_true',
                       help='Only show errors, not progress messages')
    
    args = parser.parse_args()
    
    # Resolve template directory
    template_dir = args.template_dir
    if not template_dir.exists():
        print(f"Error: Template directory '{template_dir}' does not exist")
        sys.exit(1)
    
    # Create validator and run
    validator = TemplateValidator(template_dir, args.reference_dir)
    
    if not args.quiet:
        print("🔍 Archetype Template Validation Starting...")
        print(f"Template directory: {template_dir.absolute()}")
        print()
    
    success = validator.run_validation()
    
    if success:
        if not args.quiet:
            print("🎉 Validation completed successfully!")
        sys.exit(0)
    else:
        print("\n💥 Validation failed - template issues found")
        sys.exit(1)


if __name__ == "__main__":
    main() 