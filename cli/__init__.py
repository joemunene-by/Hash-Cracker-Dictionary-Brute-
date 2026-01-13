"""
CLI Module

Professional command-line interface for the Hash Audit Tool
with safety controls and ethical usage enforcement.
"""

from .interface import main, HashAuditCLI

__all__ = [
    'main',
    'HashAuditCLI'
]
