"""
Automated Dependency Updater
Checks and updates package versions automatically.

Features:
- Scan requirements.txt for outdated packages
- Check PyPI for latest versions
- Generate update reports
- Auto-update to latest/specific versions
- Safety check against breaking changes

Usage:
    python dependency_updater.py --check
    python dependency_updater.py --update
    python dependency_updater.py --report
"""

import subprocess
import json
import sys
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from datetime import datetime
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class PackageInfo:
    """Information about a package."""
    name: str
    current_version: str
    latest_version: str
    is_outdated: bool
    update_available: bool
    breaking_changes_risk: bool = False


class DependencyUpdater:
    """Automated dependency management."""

    def __init__(self, requirements_file: str = "requirements.txt"):
        self.requirements_file = Path(requirements_file)
        self.packages: Dict[str, PackageInfo] = {}

    def parse_requirements(self) -> Dict[str, str]:
        """Parse requirements.txt into package names and versions."""
        packages = {}

        if not self.requirements_file.exists():
            logger.warning(f"Requirements file not found: {self.requirements_file}")
            return packages

        with open(self.requirements_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                # Parse "package==1.2.3" format
                match = re.match(r'^([a-zA-Z0-9\-_.]+)\s*==\s*([0-9.]+.*)', line)
                if match:
                    name, version = match.groups()
                    packages[name] = version

        return packages

    def get_latest_version(self, package_name: str) -> Optional[str]:
        """Get latest version from PyPI."""
        try:
            result = subprocess.run(
                ['pip', 'index', 'versions', package_name],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                # Parse output: "Available versions: 1.2.3, 1.2.2, 1.2.1, ..."
                output = result.stdout
                versions = re.findall(r'(\d+\.\d+\.\d+[a-zA-Z0-9]*)', output)
                if versions:
                    return versions[0]  # First is latest

        except Exception as e:
            logger.debug(f"Error getting latest version for {package_name}: {e}")

        return None

    def check_updates(self) -> Dict[str, PackageInfo]:
        """Check for available updates."""
        packages = self.parse_requirements()
        self.packages = {}

        logger.info(f"Checking {len(packages)} packages for updates...")

        for package_name, current_version in packages.items():
            latest_version = self.get_latest_version(package_name)

            is_outdated = (
                latest_version and
                self._compare_versions(current_version, latest_version) < 0
            )

            self.packages[package_name] = PackageInfo(
                name=package_name,
                current_version=current_version,
                latest_version=latest_version or "unknown",
                is_outdated=is_outdated,
                update_available=latest_version is not None,
                breaking_changes_risk=self._check_breaking_changes(
                    package_name, current_version, latest_version
                )
            )

            if is_outdated:
                logger.info(
                    f"  {package_name}: {current_version} → {latest_version}"
                )

        return self.packages

    def update_requirements(self, safe_mode: bool = True) -> bool:
        """Update requirements.txt with latest versions."""
        if not self.packages:
            self.check_updates()

        lines = []
        updated_count = 0

        with open(self.requirements_file, 'r') as f:
            for line in f:
                stripped = line.strip()

                if not stripped or stripped.startswith('#'):
                    lines.append(line)
                    continue

                # Find matching package
                package_name = stripped.split('==')[0].split('[')[0]
                package_name = package_name.strip()

                if package_name in self.packages:
                    pkg = self.packages[package_name]

                    if pkg.is_outdated:
                        if safe_mode and pkg.breaking_changes_risk:
                            logger.warning(
                                f"Skipping {package_name} (breaking changes risk)"
                            )
                            lines.append(line)
                        else:
                            new_line = f"{package_name}=={pkg.latest_version}\n"
                            lines.append(new_line)
                            updated_count += 1
                            logger.info(f"Updated: {package_name}")
                    else:
                        lines.append(line)
                else:
                    lines.append(line)

        # Write updated requirements
        with open(self.requirements_file, 'w') as f:
            f.writelines(lines)

        logger.info(f"Updated {updated_count} packages")
        return updated_count > 0

    def generate_report(self) -> str:
        """Generate a report of package updates."""
        if not self.packages:
            self.check_updates()

        report = []
        report.append("=" * 80)
        report.append("DEPENDENCY UPDATE REPORT")
        report.append(f"Generated: {datetime.now().isoformat()}")
        report.append("=" * 80)
        report.append("")

        # Summary
        total = len(self.packages)
        outdated = sum(1 for p in self.packages.values() if p.is_outdated)
        at_risk = sum(
            1 for p in self.packages.values()
            if p.is_outdated and p.breaking_changes_risk
        )

        report.append(f"Total Packages: {total}")
        report.append(f"Outdated: {outdated}")
        report.append(f"Breaking Change Risk: {at_risk}")
        report.append("")

        # Details
        report.append("OUTDATED PACKAGES:")
        report.append("-" * 80)

        for name, pkg in sorted(self.packages.items()):
            if pkg.is_outdated:
                risk_flag = "⚠️  BREAKING RISK" if pkg.breaking_changes_risk else ""
                report.append(
                    f"  {name:30} {pkg.current_version:10} → {pkg.latest_version:10} {risk_flag}"
                )

        report.append("")
        report.append("UP-TO-DATE PACKAGES:")
        report.append("-" * 80)

        for name, pkg in sorted(self.packages.items()):
            if not pkg.is_outdated:
                report.append(f"  {name:30} {pkg.current_version:10} ✓")

        report.append("")
        report.append("=" * 80)

        return "\n".join(report)

    @staticmethod
    def _compare_versions(v1: str, v2: str) -> int:
        """Compare two version strings. Returns -1 if v1 < v2, 0 if equal, 1 if v1 > v2."""
        v1_parts = [int(x) for x in v1.split('.')[:3]]
        v2_parts = [int(x) for x in v2.split('.')[:3]]

        # Pad with zeros
        while len(v1_parts) < 3:
            v1_parts.append(0)
        while len(v2_parts) < 3:
            v2_parts.append(0)

        if v1_parts < v2_parts:
            return -1
        elif v1_parts > v2_parts:
            return 1
        else:
            return 0

    @staticmethod
    def _check_breaking_changes(
        package_name: str,
        current_version: str,
        latest_version: Optional[str]
    ) -> bool:
        """Check if update likely has breaking changes (major version bump)."""
        if not latest_version:
            return False

        try:
            curr_major = int(current_version.split('.')[0])
            latest_major = int(latest_version.split('.')[0])

            # Major version bump = breaking changes likely
            return latest_major > curr_major
        except (ValueError, IndexError):
            return False


def main():
    """CLI interface."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Automated dependency updater"
    )
    parser.add_argument(
        '--check',
        action='store_true',
        help='Check for outdated packages'
    )
    parser.add_argument(
        '--update',
        action='store_true',
        help='Update packages to latest versions'
    )
    parser.add_argument(
        '--report',
        action='store_true',
        help='Generate update report'
    )
    parser.add_argument(
        '--unsafe',
        action='store_true',
        help='Update even if breaking changes risk'
    )
    parser.add_argument(
        '--requirements',
        default='requirements.txt',
        help='Path to requirements.txt'
    )

    args = parser.parse_args()

    updater = DependencyUpdater(args.requirements)

    if args.check:
        packages = updater.check_updates()
        outdated = [p for p in packages.values() if p.is_outdated]
        print(f"\n{len(outdated)} packages are outdated\n")
        return 0 if not outdated else 1

    elif args.update:
        safe_mode = not args.unsafe
        updater.update_requirements(safe_mode=safe_mode)
        print("Dependencies updated!")
        return 0

    elif args.report:
        print(updater.generate_report())
        return 0

    else:
        # Default: check and report
        updater.check_updates()
        print(updater.generate_report())
        return 0


if __name__ == '__main__':
    sys.exit(main())
