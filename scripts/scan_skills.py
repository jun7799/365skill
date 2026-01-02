#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
365skill - Skill Security Scanner
Scans installed skills for potential security risks
"""

import os
import re
import json
import argparse
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field
from enum import Enum


class ScanLevel(Enum):
    """Scan level"""
    BASIC = "basic"
    DEEP = "deep"
    FULL = "full"


class RiskLevel(Enum):
    """Risk level"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class RiskFinding:
    """Risk finding"""
    skill_name: str
    file_path: str
    line_number: int
    risk_level: RiskLevel
    category: str
    description: str
    code_snippet: str
    recommendation: str


@dataclass
class ScanResult:
    """Scan result"""
    skill_name: str
    is_safe: bool
    findings: List[RiskFinding] = field(default_factory=list)
    total_files: int = 0
    scanned_files: int = 0


class SkillSecurityScanner:
    """Skill security scanner"""

    def __init__(self, skills_dir: str, scan_level: ScanLevel = ScanLevel.DEEP, use_whitelist: bool = True):
        self.skills_dir = Path(skills_dir)
        self.scan_level = scan_level
        self.findings: List[RiskFinding] = []
        self.results: List[ScanResult] = []
        self.use_whitelist = use_whitelist
        self.whitelist = self._load_whitelist()
        self.skipped_whitelist = []
        self._init_patterns()

    def _load_whitelist(self) -> set:
        """Load whitelist from config file"""
        if not self.use_whitelist:
            return set()

        whitelist_path = self.skills_dir / "365skill" / "assets" / "whitelist.json"
        if not whitelist_path.exists():
            return set()

        try:
            with open(whitelist_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return set(item.get('name', '') for item in data.get('whitelisted_skills', []))
        except Exception as e:
            print(f"Warning: Failed to load whitelist: {e}")
            return set()

    def _init_patterns(self):
        """Initialize detection patterns"""

        # Basic detection patterns
        self.basic_patterns = {
            "sensitive_api_keys": [
                (r'(?:api[_-]?key|apikey|api_key)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
                 "Possible API Key hardcoded"),
                (r'(?:token|access_token|auth_token|bearer[_-]?token)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_.-]{20,})["\']',
                 "Possible auth token hardcoded"),
                (r'(?:password|passwd|pwd)["\']?\s*[:=]\s*["\']([^"\'\s]{8,})["\']',
                 "Possible password hardcoded"),
                (r'(?:secret|private[_-]?key|secret_key)["\']?\s*[:=]\s*["\']([a-zA-Z0-9/+=_-]{16,})["\']',
                 "Possible secret key hardcoded"),
            ],

            "dangerous_commands": [
                (r'\b(?:rm\s+-rf|rmdir\s+/s)\b',
                 "Dangerous file deletion command"),
                (r'\beval\s*\(',
                 "Dynamic code execution with eval"),
                (r'\bexec\s*\(',
                 "Dynamic code execution with exec"),
                (r'\bsubprocess\.(?:call|run|Popen)\s*\(\s*["\']?\s*\$',
                 "Possible command injection"),
                (r'\bos\.system\s*\(',
                 "Command execution with os.system"),
            ],

            "suspicious_network": [
                (r'(?:requests|urllib|fetch|axios)\.(?:get|post|put|delete|patch)\s*\(\s*["\']https?://(?:[^"\']*?)(?:key|token|password|secret|credential)',
                 "Network request with possible sensitive data"),
                (r'["\']https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0):\d+["\']',
                 "Localhost port connection"),
            ],
        }

        # Deep detection patterns (includes basic)
        self.deep_patterns = {
            **self.basic_patterns,

            "code_obfuscation": [
                (r'(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\[0-7]{3}){5,}',
                 "Possible code obfuscation (escape characters)"),
                (r'chr\s*\(\s*\d+\s*\)\s*\)',
                 "Possible character encoding obfuscation"),
                (r'\bbase64\.(?:b64decode|decodebytes|standard_b64decode)\s*\(',
                 "Base64 decode operation"),
                (r'(?:exec|eval)\s*\(\s*(?:base64\.decode|chr\(|__import__\()',
                 "Multi-layer obfuscated code execution"),
            ],

            "suspicious_file_ops": [
                (r'\bopen\s*\(\s*["\']~/(?:\.ssh|\.gnupg|\.aws)',
                 "Accessing sensitive config directory"),
                (r'\bshutil\.(?:copy|copytree|move|rmtree)\s*\(',
                 "Bulk file operations"),
                (r'\b(?:sendmail|smtplib\.SMTP)\s*\(',
                 "Email sending functionality"),
                (r'\bpathlib\.Path\s*\(\s*["\']~/\.?',
                 "Accessing user home directory"),
            ],

            "data_exfiltration": [
                (r'(?:requests|urllib)\.(?:get|post)\s*\(\s*["\']https?://.*?(?:exfil|log|track|telemetry|analytics|beacon)',
                 "Possible data exfiltration request"),
                (r'\bsocket\.(?:create_connection|connect)\s*\(',
                 "Raw socket connection"),
                (r'["\']https?://(?:[a-z0-9-]+\.)?(?:pastebin|gist\.github|discord|webhook|telegram)\.',
                 "Data possibly sent to external service"),
            ],

            "shell_injection": [
                (r'\bsubprocess\.(?:call|run|Popen)\s*\(\s*.*?\$',
                 "Possible shell variable injection"),
                (r'\bos\.popen\s*\(',
                 "Command execution with os.popen"),
                (r'\bcommands\.getoutput\s*\(',
                 "Command execution with commands.getoutput"),
            ],
        }

        # Full detection patterns (includes deep)
        self.full_patterns = {
            **self.deep_patterns,

            "behavior_analysis": [
                (r'(?:while\s+True|for\s+\w+\s+in\s+range\(\s*\d{6,}',
                 "Possible infinite loop or massive iteration"),
                (r'\btime\.sleep\s*\(\s*\d{3,}',
                 "Long sleep delay (possible delay attack)"),
                (r'\bthreading\.(?:Thread|Process)\s*\(',
                 "Multi-threading/process creation"),
                (r'\bmultiprocessing\.(?:Process|Pool)\s*\(',
                 "Multi-process creation"),
            ],

            "environment_fingerprinting": [
                (r'\b(?:os|platform)\.(?:uname|system|release|version|machine)\s*\(',
                 "System fingerprinting"),
                (r'\b(?:os\.getenv|sys\.version|platform\.platform)\s*\(',
                 "Environment info gathering"),
            ],

            "persistence_hooks": [
                (r'~/(?:\.bashrc|\.zshrc|\.profile|\.bash_profile)',
                 "Shell config file modification"),
                (r'(?:crontab|systemd|launchd|plist)',
                 "Cron job or service configuration"),
            ],
        }

    def get_risk_level(self, category: str) -> RiskLevel:
        """Get risk level by category"""
        critical_categories = {"dangerous_commands", "shell_injection", "persistence_hooks"}
        high_categories = {"sensitive_api_keys", "data_exfiltration", "code_obfuscation"}
        medium_categories = {"suspicious_file_ops", "suspicious_network", "behavior_analysis"}

        if category in critical_categories:
            return RiskLevel.CRITICAL
        elif category in high_categories:
            return RiskLevel.HIGH
        elif category in medium_categories:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW

    def get_recommendation(self, category: str) -> str:
        """Get fix recommendation"""
        recommendations = {
            "sensitive_api_keys": "Use environment variables or config files for sensitive info",
            "dangerous_commands": "Remove dangerous commands or add strict validation",
            "suspicious_network": "Review network requests for legitimacy",
            "code_obfuscation": "Code obfuscation may hide malicious behavior, manual review needed",
            "suspicious_file_ops": "Review necessity and permissions of file operations",
            "data_exfiltration": "Possible data exfiltration detected, review network communications",
            "shell_injection": "Use parameterized commands instead of string concatenation",
            "behavior_analysis": "Review reasonableness of anomalous behavior",
            "environment_fingerprinting": "Confirm necessity of environment probing",
            "persistence_hooks": "Persistence mechanism detected, review needed",
        }
        return recommendations.get(category, "Manual review recommended")

    def scan_file(self, file_path: Path, skill_name: str) -> List[RiskFinding]:
        """Scan single file"""
        findings = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            # Select detection mode
            if self.scan_level == ScanLevel.BASIC:
                patterns = self.basic_patterns
            elif self.scan_level == ScanLevel.DEEP:
                patterns = self.deep_patterns
            else:
                patterns = self.full_patterns

            for line_num, line in enumerate(lines, 1):
                for category, pattern_list in patterns.items():
                    for pattern, description in pattern_list:
                        matches = re.finditer(pattern, line, re.IGNORECASE)
                        for match in matches:
                            snippet = line.strip()
                            if len(snippet) > 100:
                                snippet = snippet[:100] + "..."

                            finding = RiskFinding(
                                skill_name=skill_name,
                                file_path=str(file_path.relative_to(self.skills_dir)),
                                line_number=line_num,
                                risk_level=self.get_risk_level(category),
                                category=category,
                                description=description,
                                code_snippet=snippet,
                                recommendation=self.get_recommendation(category)
                            )
                            findings.append(finding)

        except Exception as e:
            print(f"  Warning: Cannot read file {file_path}: {e}")

        return findings

    def scan_skill(self, skill_path: Path) -> ScanResult:
        """Scan single skill"""
        skill_name = skill_path.name
        print(f"\nScanning {skill_name}...")

        result = ScanResult(skill_name=skill_name, is_safe=True)

        # Skip 365skill itself
        if skill_name == "365skill":
            result.is_safe = True
            return result

        # Skip whitelisted skills
        if skill_name in self.whitelist:
            print(f"  [SKIP] Whitelisted")
            self.skipped_whitelist.append(skill_name)
            result.is_safe = True
            return result

        # Find all files to scan
        extensions = {'.py', '.js', '.ts', '.sh', '.bash', '.md', '.json', '.yml', '.yaml', '.txt'}
        files_to_scan = []

        for ext in extensions:
            files_to_scan.extend(skill_path.rglob(f'*{ext}'))

        result.total_files = len(files_to_scan)

        for file_path in files_to_scan:
            findings = self.scan_file(file_path, skill_name)
            result.findings.extend(findings)
            if findings:
                result.scanned_files += 1

        result.is_safe = len(result.findings) == 0
        return result

    def scan_all_skills(self, target_skill: Optional[str] = None) -> List[ScanResult]:
        """Scan all skills or specific skill"""
        results = []

        if target_skill:
            skill_paths = [self.skills_dir / target_skill]
            if not skill_paths[0].exists():
                print(f"Error: Skill not found: {target_skill}")
                return results
        else:
            skill_paths = [d for d in self.skills_dir.iterdir() if d.is_dir() and not d.name.startswith('.')]

        for skill_path in skill_paths:
            result = self.scan_skill(skill_path)
            results.append(result)
            self.results.extend([result])

        return results

    def print_results(self):
        """Print scan results"""
        if not self.results:
            print("\nNo skills found to scan")
            return

        # Show whitelisted skills that were skipped
        if self.skipped_whitelist:
            print(f"\n[WHITELIST] Skipped {len(self.skipped_whitelist)} skill(s):")
            for name in self.skipped_whitelist:
                print(f"   - {name}")

        # Classify by risk level
        critical_skills = []
        high_risk_skills = []
        medium_risk_skills = []
        low_risk_skills = []

        for result in self.results:
            if result.is_safe:
                continue

            # Find highest risk level
            highest_risk = RiskLevel.INFO
            for finding in result.findings:
                if finding.risk_level.value == "critical":
                    highest_risk = RiskLevel.CRITICAL
                    break
                elif finding.risk_level.value == "high" and highest_risk.value in ["info", "low", "medium"]:
                    highest_risk = RiskLevel.HIGH
                elif finding.risk_level.value == "medium" and highest_risk.value in ["info", "low"]:
                    highest_risk = RiskLevel.MEDIUM
                elif highest_risk.value == "info":
                    highest_risk = RiskLevel.LOW

            skill_info = (result.skill_name, result)
            if highest_risk == RiskLevel.CRITICAL:
                critical_skills.append(skill_info)
            elif highest_risk == RiskLevel.HIGH:
                high_risk_skills.append(skill_info)
            elif highest_risk == RiskLevel.MEDIUM:
                medium_risk_skills.append(skill_info)
            else:
                low_risk_skills.append(skill_info)

        # Print report
        print("\n" + "="*70)
        print("365skill Security Scan Report")
        print("="*70)

        total_risks = sum(len(r.findings) for r in self.results if not r.is_safe)
        print(f"\nScan Statistics:")
        print(f"   Total skills scanned: {len(self.results)}")
        print(f"   Safe skills: {sum(1 for r in self.results if r.is_safe)}")
        print(f"   Risky skills: {sum(1 for r in self.results if not r.is_safe)}")
        print(f"   Total risk findings: {total_risks}")

        if critical_skills:
            print(f"\n[CRITICAL] Critical Risk ({len(critical_skills)}):")
            for name, result in critical_skills:
                print(f"\n   ! {name}")
                for finding in result.findings:
                    print(f"      [{finding.risk_level.value.upper()}] {finding.description}")
                    print(f"         File: {finding.file_path}:{finding.line_number}")
                    print(f"         Fix: {finding.recommendation}")

        if high_risk_skills:
            print(f"\n[ HIGH ] High Risk ({len(high_risk_skills)}):")
            for name, result in high_risk_skills:
                print(f"\n   ! {name}")
                for finding in result.findings[:3]:
                    print(f"      [{finding.risk_level.value.upper()}] {finding.description}")
                    print(f"         File: {finding.file_path}:{finding.line_number}")
                if len(result.findings) > 3:
                    print(f"      ... and {len(result.findings) - 3} more findings")

        if medium_risk_skills:
            print(f"\n[MEDIUM] Medium Risk ({len(medium_risk_skills)}):")
            for name, _ in medium_risk_skills:
                print(f"   - {name}")

        if low_risk_skills:
            print(f"\n[ LOW  ] Low Risk ({len(low_risk_skills)}):")
            for name, _ in low_risk_skills:
                print(f"   - {name}")

        all_risky_skills = [name for name, _ in critical_skills + high_risk_skills + medium_risk_skills + low_risk_skills]

        if all_risky_skills:
            print(f"\n" + "="*70)
            print(f"Found {len(all_risky_skills)} skill(s) with risks")
            print("="*70)
        else:
            print(f"\n[OK] All skills are safe!")


def main():
    parser = argparse.ArgumentParser(description="365skill - Skill Security Scanner")
    parser.add_argument(
        "--level",
        choices=["basic", "deep", "full"],
        default="deep",
        help="Scan level: basic, deep, or full"
    )
    parser.add_argument(
        "--skill",
        help="Specific skill name to scan (scans all if not specified)"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format"
    )
    parser.add_argument(
        "--skills-dir",
        default=str(Path.home() / ".claude" / "skills"),
        help="Skills directory path"
    )
    parser.add_argument(
        "--no-whitelist",
        action="store_true",
        help="Disable whitelist and scan all skills"
    )
    parser.add_argument(
        "--whitelist-add",
        metavar="SKILL_NAME",
        help="Add a skill to the whitelist"
    )
    parser.add_argument(
        "--whitelist-remove",
        metavar="SKILL_NAME",
        help="Remove a skill from the whitelist"
    )
    parser.add_argument(
        "--whitelist-show",
        action="store_true",
        help="Show all whitelisted skills"
    )

    args = parser.parse_args()

    skills_dir = Path(args.skills_dir)

    # Handle whitelist management commands
    if args.whitelist_show:
        whitelist_path = skills_dir / "365skill" / "assets" / "whitelist.json"
        if not whitelist_path.exists():
            print("Whitelist is empty or doesn't exist")
            return

        with open(whitelist_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        print("\n[WHITELIST] Trusted skills:")
        for item in data.get('whitelisted_skills', []):
            print(f"  - {item.get('name', 'Unknown')}")
            if item.get('reason'):
                print(f"    Reason: {item.get('reason')}")
            print(f"    Added: {item.get('added_at', 'Unknown')}")
        return

    if args.whitelist_add:
        whitelist_path = skills_dir / "365skill" / "assets" / "whitelist.json"
        whitelist_path.parent.mkdir(parents=True, exist_ok=True)

        # Load existing whitelist
        if whitelist_path.exists():
            with open(whitelist_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        else:
            data = {"whitelisted_skills": [], "notes": "Skills in this list will be skipped during security scans"}

        # Check if already whitelisted
        for item in data.get('whitelisted_skills', []):
            if item.get('name') == args.whitelist_add:
                print(f"Skill '{args.whitelist_add}' is already whitelisted")
                return

        # Add to whitelist
        from datetime import datetime
        data['whitelisted_skills'].append({
            'name': args.whitelist_add,
            'reason': 'Manually added via CLI',
            'added_at': datetime.now().strftime('%Y-%m-%d')
        })

        with open(whitelist_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        print(f"Added '{args.whitelist_add}' to whitelist")
        return

    if args.whitelist_remove:
        whitelist_path = skills_dir / "365skill" / "assets" / "whitelist.json"
        if not whitelist_path.exists():
            print(f"Whitelist doesn't exist")
            return

        with open(whitelist_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Remove from whitelist
        original_count = len(data.get('whitelisted_skills', []))
        data['whitelisted_skills'] = [
            item for item in data.get('whitelisted_skills', [])
            if item.get('name') != args.whitelist_remove
        ]

        if len(data['whitelisted_skills']) == original_count:
            print(f"Skill '{args.whitelist_remove}' not found in whitelist")
            return

        with open(whitelist_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        print(f"Removed '{args.whitelist_remove}' from whitelist")
        return

    # Normal scan
    scan_level = ScanLevel(args.level)
    use_whitelist = not args.no_whitelist

    scanner = SkillSecurityScanner(args.skills_dir, scan_level, use_whitelist)
    scanner.scan_all_skills(args.skill)

    if args.json:
        # JSON output
        output = {
            "scan_level": args.level,
            "results": [
                {
                    "skill_name": r.skill_name,
                    "is_safe": r.is_safe,
                    "findings": [
                        {
                            "file_path": f.file_path,
                            "line_number": f.line_number,
                            "risk_level": f.risk_level.value,
                            "category": f.category,
                            "description": f.description,
                            "code_snippet": f.code_snippet,
                            "recommendation": f.recommendation,
                        }
                        for f in r.findings
                    ]
                }
                for r in scanner.results
            ]
        }
        print(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        scanner.print_results()


if __name__ == "__main__":
    main()
