"""
Dictionary Attack Implementation

Dictionary attacks use pre-compiled wordlists to attempt password cracking.
This implementation supports streaming processing for large wordlists,
rule-based mutations, and various optimization techniques.
"""

import os
from typing import Iterator, List, Dict, Any, Optional
from .base import AttackStrategy
from ..hashes.base import HashAlgorithm


class DictionaryAttack(AttackStrategy):
    """Dictionary attack strategy implementation."""

    # Pre-built translate table for leetspeak – avoids rebuilding per call
    _LEET_TABLE = str.maketrans({
        'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$',
        't': '7', 'l': '1', 'A': '@', 'E': '3', 'I': '1',
        'O': '0', 'S': '$', 'T': '7', 'L': '1',
    })

    def __init__(self, hash_algorithm: HashAlgorithm, wordlist_path: str,
                 apply_rules: bool = True):
        super().__init__("Dictionary Attack", hash_algorithm)
        self.wordlist_path = wordlist_path
        self.apply_rules = apply_rules
        self.wordlist_size = 0
        self._wordlist_stats = {}
    
    def generate_candidates(self) -> Iterator[str]:
        """
        Generate password candidates from wordlist.

        Yields unique candidates only – a lightweight set tracks what has
        already been yielded so duplicate base words and mutations that
        collide (e.g. "password".lower() == "password") are skipped.

        Yields:
            Password candidate strings with optional mutations
        """
        if not os.path.exists(self.wordlist_path):
            raise FileNotFoundError(f"Wordlist not found: {self.wordlist_path}")

        seen: set = set()

        try:
            with open(self.wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    candidate = line.strip()
                    if not candidate:
                        continue

                    if candidate not in seen:
                        seen.add(candidate)
                        yield candidate

                    if self.apply_rules:
                        for mutation in self._apply_mutations(candidate):
                            if mutation not in seen:
                                seen.add(mutation)
                                yield mutation

                    self.wordlist_size += 1

        except IOError as e:
            raise IOError(f"Error reading wordlist: {e}")
    
    def _apply_mutations(self, candidate: str) -> Iterator[str]:
        """
        Apply common password mutations to a candidate.
        
        Args:
            candidate: Original password candidate
            
        Yields:
            Mutated password candidates
        """
        # Case variations
        yield candidate.lower()
        yield candidate.upper()
        yield candidate.capitalize()
        
        # Common number suffixes
        for suffix in ['1', '12', '123', '1234', '2023', '2024', '2025']:
            yield candidate + suffix
        
        # Common number prefixes
        for prefix in ['1', '12', '123']:
            yield prefix + candidate
        
        # Leetspeak substitutions – single O(n) translate call
        leet_candidate = candidate.translate(self._LEET_TABLE)
        if leet_candidate != candidate:
            yield leet_candidate
        
        # Common symbols
        for symbol in ['!', '@', '#', '$', '%', '&', '*']:
            yield candidate + symbol
    
    def get_info(self) -> Dict[str, Any]:
        """
        Get dictionary attack information.
        
        Returns:
            Dictionary containing attack metadata
        """
        return {
            'name': self.name,
            'description': 'Dictionary-based password cracking attack',
            'wordlist_path': self.wordlist_path,
            'wordlist_size': self.wordlist_size,
            'mutations_enabled': self.apply_rules,
            'mutation_types': [
                'case_variations',
                'number_suffixes',
                'number_prefixes',
                'leetspeak',
                'symbol_suffixes'
            ],
            'memory_efficient': True,
            'streaming_capable': True
        }
    
    def get_wordlist_stats(self) -> Dict[str, Any]:
        """
        Get statistics about the wordlist.
        
        Returns:
            Dictionary containing wordlist statistics
        """
        if not self._wordlist_stats and os.path.exists(self.wordlist_path):
            try:
                total_lines = 0
                unique_lines = set()
                min_length = float('inf')
                max_length = 0
                
                with open(self.wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            total_lines += 1
                            unique_lines.add(line.lower())
                            min_length = min(min_length, len(line))
                            max_length = max(max_length, len(line))
                
                self._wordlist_stats = {
                    'total_lines': total_lines,
                    'unique_entries': len(unique_lines),
                    'duplicates': total_lines - len(unique_lines),
                    'min_length': min_length if min_length != float('inf') else 0,
                    'max_length': max_length,
                    'file_size_mb': os.path.getsize(self.wordlist_path) / (1024 * 1024)
                }
                
            except IOError:
                self._wordlist_stats = {'error': 'Unable to read wordlist'}
        
        return self._wordlist_stats
