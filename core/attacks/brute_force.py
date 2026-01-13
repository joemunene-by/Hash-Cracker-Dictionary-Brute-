"""
Brute-Force Attack Implementation

Brute-force attacks systematically try all possible combinations of characters
within defined constraints. This implementation uses mask-based brute force
for efficient generation of candidate passwords.
"""

import itertools
from typing import Iterator, Dict, Any, List
from .base import AttackStrategy
from ..hashes.base import HashAlgorithm


class BruteForceAttack(AttackStrategy):
    """Brute-force attack strategy implementation using masks."""
    
    # Character sets for mask patterns
    CHARACTER_SETS = {
        '?l': 'abcdefghijklmnopqrstuvwxyz',  # lowercase
        '?u': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',  # uppercase
        '?d': '0123456789',                   # digits
        '?s': '!@#$%^&*()-_=+[]{}|;:,.<>?/~`',  # symbols
        '?a': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?/~`',  # all
        '?b': '01',                           # binary
        '?h': '0123456789abcdef',            # hex lowercase
        '?H': '0123456789ABCDEF',            # hex uppercase
    }
    
    def __init__(self, hash_algorithm: HashAlgorithm, mask: str, 
                 min_length: int = None, max_length: int = None):
        super().__init__("Brute-Force Attack", hash_algorithm)
        self.mask = mask
        self.min_length = min_length or self._extract_length_from_mask(mask)
        self.max_length = max_length or self._extract_length_from_mask(mask)
        self.character_set = self._expand_mask(mask)
        self.total_combinations = self._calculate_total_combinations()
    
    def _extract_length_from_mask(self, mask: str) -> int:
        """
        Extract password length from mask pattern.
        
        Args:
            mask: Mask pattern (e.g., '?l?l?l?d')
            
        Returns:
            Length of password implied by mask
        """
        # Count mask placeholders
        count = 0
        i = 0
        while i < len(mask):
            if i + 1 < len(mask) and mask[i] == '?' and mask[i+1] in self.CHARACTER_SETS:
                count += 1
                i += 2
            else:
                count += 1
                i += 1
        return count
    
    def _expand_mask(self, mask: str) -> str:
        """
        Expand mask pattern to character set.
        
        Args:
            mask: Mask pattern
            
        Returns:
            Expanded character set
        """
        if mask in self.CHARACTER_SETS:
            return self.CHARACTER_SETS[mask]
        
        # Handle complex masks like '?l?l?l?d'
        result = []
        i = 0
        while i < len(mask):
            if i + 1 < len(mask) and mask[i] == '?' and mask[i+1] in self.CHARACTER_SETS:
                result.append(self.CHARACTER_SETS[mask[i:i+2]])
                i += 2
            else:
                result.append(mask[i])
                i += 1
        
        return result
    
    def _calculate_total_combinations(self) -> int:
        """
        Calculate total number of possible combinations.
        
        Returns:
            Total combinations count
        """
        if isinstance(self.character_set, str):
            return len(self.character_set) ** self.min_length
        else:
            # Complex mask with different character sets
            total = 1
            for char_set in self.character_set:
                total *= len(char_set)
            return total
    
    def generate_candidates(self) -> Iterator[str]:
        """
        Generate password candidates using brute-force.
        
        Yields:
            Password candidate strings
        """
        if isinstance(self.character_set, str):
            # Simple character set
            for length in range(self.min_length, self.max_length + 1):
                for candidate in itertools.product(self.character_set, repeat=length):
                    yield ''.join(candidate)
        else:
            # Complex mask
            for candidate in itertools.product(*self.character_set):
                yield ''.join(candidate)
    
    def get_info(self) -> Dict[str, Any]:
        """
        Get brute-force attack information.
        
        Returns:
            Dictionary containing attack metadata
        """
        return {
            'name': self.name,
            'description': 'Mask-based brute-force password cracking attack',
            'mask': self.mask,
            'min_length': self.min_length,
            'max_length': self.max_length,
            'total_combinations': self.total_combinations,
            'character_set_size': len(self.character_set) if isinstance(self.character_set, str) else sum(len(s) for s in self.character_set),
            'estimated_time_hours': self._estimate_time(),
            'available_masks': list(self.CHARACTER_SETS.keys())
        }
    
    def _estimate_time(self) -> float:
        """
        Estimate time to complete attack (assuming 1M hashes/second).
        
        Returns:
            Estimated time in hours
        """
        hashes_per_second = 1000000  # Conservative estimate
        total_seconds = self.total_combinations / hashes_per_second
        return total_seconds / 3600
    
    @classmethod
    def get_available_masks(cls) -> Dict[str, str]:
        """
        Get available mask patterns and descriptions.
        
        Returns:
            Dictionary of mask patterns and descriptions
        """
        return {
            '?l': 'lowercase letters (a-z)',
            '?u': 'uppercase letters (A-Z)',
            '?d': 'digits (0-9)',
            '?s': 'special symbols',
            '?a': 'all characters',
            '?b': 'binary digits (0-1)',
            '?h': 'hexadecimal lowercase (0-9, a-f)',
            '?H': 'hexadecimal uppercase (0-9, A-F)'
        }
