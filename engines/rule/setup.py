"""
Setup script for yaml-rule-builder
"""

from setuptools import setup, find_packages

setup(
    name="yaml-rule-builder",
    version="1.0.0",
    description="CLI tool for generating AWS compliance rule YAML files",
    packages=find_packages(),
    install_requires=[
        "pyyaml>=6.0",
    ],
    entry_points={
        "console_scripts": [
            "yaml-rule-builder=yaml_rule_builder.cli:main",
        ],
    },
    python_requires=">=3.7",
)

