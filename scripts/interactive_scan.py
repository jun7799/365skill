#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
365skill Interactive Scanner
Provides interactive interface to review risks and delete risky skills
"""

import os
import sys
import shutil
from pathlib import Path
from scan_skills import SkillSecurityScanner, ScanLevel, RiskLevel


class InteractiveScanner:
    """Interactive scanner"""

    def __init__(self, skills_dir: str, scan_level: ScanLevel = ScanLevel.DEEP):
        self.skills_dir = Path(skills_dir)
        self.scan_level = scan_level
        self.scanner = SkillSecurityScanner(skills_dir, scan_level)

    def print_finding_details(self, skill_name: str):
        """Print detailed risk findings"""
        for result in self.scanner.results:
            if result.skill_name == skill_name and not result.is_safe:
                print(f"\n{'='*70}")
                print(f"Details: {skill_name} - Risk Information")
                print(f"{'='*70}")

                # Group by risk level
                by_level = {
                    RiskLevel.CRITICAL: [],
                    RiskLevel.HIGH: [],
                    RiskLevel.MEDIUM: [],
                    RiskLevel.LOW: [],
                }

                for finding in result.findings:
                    by_level[finding.risk_level].append(finding)

                for level in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]:
                    findings = by_level[level]
                    if findings:
                        level_symbol = {
                            RiskLevel.CRITICAL: "[!]",
                            RiskLevel.HIGH: "[HIGH]",
                            RiskLevel.MEDIUM: "[MED]",
                            RiskLevel.LOW: "[LOW]",
                        }
                        print(f"\n{level_symbol[level]} {level.value.upper()} ({len(findings)} found):")
                        for finding in findings:
                            print(f"\n   ! {finding.description}")
                            print(f"      File: {finding.file_path}:{finding.line_number}")
                            print(f"      Code: {finding.code_snippet}")
                            print(f"      Fix: {finding.recommendation}")

    def confirm_deletion(self, skill_name: str) -> bool:
        """Confirm skill deletion"""
        print(f"\n{'='*70}")
        print(f"Confirm Action")
        print(f"{'='*70}")
        print(f"About to delete skill: {skill_name}")
        print(f"This action cannot be undone!")

        while True:
            response = input("\nDelete this skill? (y/n/v): ").strip().lower()
            if response == 'y':
                return True
            elif response == 'n':
                return False
            elif response == 'v':
                self.print_finding_details(skill_name)
            else:
                print("Enter y (yes), n (no), or v (view details)")

    def delete_skill(self, skill_name: str) -> bool:
        """Delete skill directory"""
        skill_path = self.skills_dir / skill_name
        try:
            shutil.rmtree(skill_path)
            print(f"[OK] Deleted skill: {skill_name}")
            return True
        except Exception as e:
            print(f"[ERROR] Delete failed: {e}")
            return False

    def run(self):
        """Run interactive scan"""
        print("\n" + "="*70)
        print("365skill Security Guard - Interactive Scan")
        print("="*70)
        print(f"\nScan level: {self.scan_level.value}")
        print(f"Skills dir: {self.skills_dir}")
        print("\nStarting scan...\n")

        # Scan all skills
        self.scanner.scan_all_skills()

        # Classify results
        risky_skills = []
        for result in self.scanner.results:
            if not result.is_safe and result.skill_name != "365skill":
                # Find highest risk level
                highest_risk = RiskLevel.INFO
                for finding in result.findings:
                    risk_priority = {
                        RiskLevel.CRITICAL: 4,
                        RiskLevel.HIGH: 3,
                        RiskLevel.MEDIUM: 2,
                        RiskLevel.LOW: 1,
                        RiskLevel.INFO: 0,
                    }
                    if risk_priority[finding.risk_level] > risk_priority[highest_risk]:
                        highest_risk = finding.risk_level

                risky_skills.append((result.skill_name, highest_risk, len(result.findings)))

        # Sort by risk level
        risk_priority = {RiskLevel.CRITICAL: 4, RiskLevel.HIGH: 3, RiskLevel.MEDIUM: 2, RiskLevel.LOW: 1}
        risky_skills.sort(key=lambda x: risk_priority[x[1]], reverse=True)

        if not risky_skills:
            print("\n" + "="*70)
            print("[OK] Scan Complete - All skills are safe!")
            print("="*70)
            return

        # Show summary
        print("\n" + "="*70)
        print(f"[!] Found {len(risky_skills)} skill(s) with risks")
        print("="*70)

        for i, (name, level, count) in enumerate(risky_skills, 1):
            level_symbol = {
                RiskLevel.CRITICAL: "[!]",
                RiskLevel.HIGH: "[HIGH]",
                RiskLevel.MEDIUM: "[MED]",
                RiskLevel.LOW: "[LOW]",
            }
            print(f"{i}. {level_symbol[level]} {name} ({count} risk(s))")

        # Interactive handling
        skills_to_delete = []
        for name, level, count in risky_skills:
            print(f"\n{'='*70}")
            print(f"Processing: {name}")
            print(f"{'='*70}")
            print(f"Risk level: {level.value}")
            print(f"Risk count: {count}")

            # Show first 3 risks
            for result in self.scanner.results:
                if result.skill_name == name:
                    for finding in result.findings[:3]:
                        print(f"  - [{finding.risk_level.value}] {finding.description}")
                    if len(result.findings) > 3:
                        print(f"  - ... and {len(result.findings) - 3} more risks")
                    break

            while True:
                print("\nOptions:")
                print("  [v] View detailed risks")
                print("  [d] Delete this skill")
                print("  [s] Skip, keep this skill")
                print("  [q] Quit")
                choice = input("Choose (v/d/s/q): ").strip().lower()

                if choice == 'v':
                    self.print_finding_details(name)
                elif choice == 'd':
                    if self.confirm_deletion(name):
                        if self.delete_skill(name):
                            skills_to_delete.append(name)
                    break
                elif choice == 's':
                    print(f"[SKIP] Kept {name}")
                    break
                elif choice == 'q':
                    print("\nExiting interactive scan...")
                    return
                else:
                    print("Invalid choice, try again")

        # Final report
        print("\n" + "="*70)
        print("Scan Complete")
        print("="*70)
        if skills_to_delete:
            print(f"\n[OK] Deleted {len(skills_to_delete)} skill(s):")
            for name in skills_to_delete:
                print(f"   - {name}")
        else:
            print("\nNo skills were deleted")

        remaining_risky = len(risky_skills) - len(skills_to_delete)
        if remaining_risky > 0:
            print(f"\n[!] {remaining_risky} risky skill(s) were kept")


def main():
    import argparse

    parser = argparse.ArgumentParser(description="365skill Interactive Security Scan")
    parser.add_argument(
        "--level",
        choices=["basic", "deep", "full"],
        default="deep",
        help="Scan level: basic, deep, or full"
    )
    parser.add_argument(
        "--skills-dir",
        default=str(Path.home() / ".claude" / "skills"),
        help="Skills directory path"
    )

    args = parser.parse_args()

    scan_level = ScanLevel(args.level)
    scanner = InteractiveScanner(args.skills_dir, scan_level)
    scanner.run()


if __name__ == "__main__":
    main()
