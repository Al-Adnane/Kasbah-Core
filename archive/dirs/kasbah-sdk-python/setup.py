"""Setup configuration for Kasbah Guard Python SDK."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="kasbah-guard",
    version="1.0.0",
    author="Kasbah Guard",
    author_email="support@bekasbah.com",
    description="Kasbah Guard Python SDK - AI security and secret detection",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://bekasbah.com",
    packages=find_packages(include=["kasbah*"]),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.28.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ]
    },
    project_urls={
        "Homepage": "https://bekasbah.com",
        "Documentation": "https://docs.kasbah.ai",
        "Repository": "https://github.com/kasbah-guard/kasbah.git",
        "Issues": "https://github.com/kasbah-guard/kasbah/issues",
    },
)
