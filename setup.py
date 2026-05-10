"""
Setup configuration for SQL Injection Assessment Framework.
"""

from setuptools import setup, find_packages
from pathlib import Path

this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text() if (this_directory / "README.md").exists() else ""

setup(
    name="sqlprobe",
    version="2.0.0",
    author="Security Assessment Framework",
    author_email="security@example.com",
    description="Production-grade SQL Injection Assessment Framework for authorized security testing",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/example/sql-injection-framework",
    packages=[
        "sqlprobe",
        "sqlprobe.cli",
        "sqlprobe.engine",
        "sqlprobe.payloads",
        "sqlprobe.detection",
        "sqlprobe.crawler",
        "sqlprobe.analyzer",
        "sqlprobe.waf",
        "sqlprobe.reporting",
        "sqlprobe.plugins",
        "sqlprobe.utils",
    ],
    package_dir={"sqlprobe": "."},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.8",
    install_requires=[
        "httpx>=0.25.0",
        "beautifulsoup4>=4.12.0",
        "lxml>=4.9.0",
        "rich>=13.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "mypy>=1.0.0",
            "ruff>=0.1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "sql-inject-scan=sqlprobe.cli.interface:run_cli",
            "sqlprobe=sqlprobe.cli.interface:run_cli",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)