"""
Attack Strategies Module

Contains implementations of various attack strategies for password cracking
including dictionary attacks, brute-force attacks, and hybrid approaches.
"""

from .base import AttackStrategy
from .dictionary import DictionaryAttack
from .brute_force import BruteForceAttack
from .hybrid import HybridAttack

__all__ = [
    'AttackStrategy',
    'DictionaryAttack',
    'BruteForceAttack',
    'HybridAttack'
]
