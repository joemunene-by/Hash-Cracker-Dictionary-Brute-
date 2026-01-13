"""
Mask Handling Module

Provides mask pattern parsing, expansion, and generation for
brute-force and hybrid password cracking attacks.
"""

from .parser import MaskParser
from .expander import MaskExpander
from .generator import MaskGenerator

__all__ = [
    'MaskParser',
    'MaskExpander', 
    'MaskGenerator'
]
