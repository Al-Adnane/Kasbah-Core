#!/usr/bin/env python3
"""
Kasbah Core - Enterprise Security Detection and Analysis Framework

Setup script for kasbah-core package installation.

Author: Kasbah Guard Team
Date: March 11, 2026
License: MIT
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_path = Path(__file__).parent / "README.md"
long_description = ""
if readme_path.exists():
    long_description = readme_path.read_text(encoding="utf-8")

# Read requirements
requirements_path = Path(__file__).parent / "requirements.txt"
install_requires = []
if requirements_path.exists():
    install_requires = [
        line.strip() for line in requirements_path.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]

# Read dev requirements
dev_requirements_path = Path(__file__).parent / "requirements-dev.txt"
extras_require = {}
if dev_requirements_path.exists():
    extras_require["dev"] = [
        line.strip() for line in dev_requirements_path.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]

setup(
    name="kasbah-core",
    version="5.0.0",
    author="Kasbah Guard Team",
    author_email="support@bekasbah.com",
    description="Enterprise security detection and analysis framework with AI detection, deepfake detection, and agent authorization",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Al-Adnane/Kasbah-Core",
    project_urls={
        "Documentation": "https://bekasbah.com/docs",
        "Bug Tracker": "https://github.com/Al-Adnane/Kasbah-Core/issues",
        "Source": "https://github.com/Al-Adnane/Kasbah-Core",
    },
    packages=find_packages(
        include=["kasbah_core", "kasbah_core.*", "kasbah_python", "kasbah_python.*"],
        exclude=["tests", "tests.*", "archive", "archive.*"]
    ),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    keywords="security ai-detection deepfake voice-cloning secret-detection compliance",
    python_requires=">=3.9",
    install_requires=install_requires,
    extras_require=extras_require,
    include_package_data=True,
    package_data={
        "core": ["*.yaml", "*.json"],
        "core.ml": ["*.pkl", "*.json"],
        "crypto": ["*.pem"],
    },
    entry_points={
        "console_scripts": [
            "kasbah-core=kasbah_python.client:main",
        ],
    },
)
