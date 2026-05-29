"""
Chat engine entry point — delegates to the multi-agent orchestrator.

Kept for backward compatibility with api_server.py imports.
"""

from .orchestrator import run_agent

__all__ = ["run_agent"]
