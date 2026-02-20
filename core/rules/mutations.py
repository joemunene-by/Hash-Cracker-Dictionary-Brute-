"""
Password Mutation Rules

Defines common password mutations and transformations
used in password cracking attacks.
"""

import itertools
from typing import Iterator, List, Dict, Any


class MutationRules:
    """Applies various mutation rules to password candidates."""
    
    def __init__(self):
        # Common substitutions
        self.leet_substitutions = {
            'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7',
            'l': '1', 'g': '9', 'b': '8', 'z': '2', 'c': '(', 'd': ')'
        }

        # Pre-build a str.maketrans table for full leetspeak conversion –
        # this is O(n) per call instead of O(n * k) for k replace() calls.
        _leet_trans = {}
        for ch, sub in self.leet_substitutions.items():
            _leet_trans[ord(ch)] = sub
            _leet_trans[ord(ch.upper())] = sub
        self._leet_translate_table = _leet_trans

        # Common prefixes and suffixes
        self.prefixes = ['', 'x', 'xx', '1', '12', '123', 'admin', 'root']
        self.suffixes = ['', '1', '12', '123', '1234', '2023', '2024', '2025',
                        '!', '@', '#', '$', '%', '&', '*', '.', '_']

        # Case variations
        self.case_patterns = [
            lambda x: x.lower(),
            lambda x: x.upper(),
            lambda x: x.capitalize(),
            lambda x: x.title(),
            lambda x: self._alternating_case(x),
            lambda x: self._first_last_upper(x)
        ]
    
    def apply_mutations(self, word: str, max_mutations: int = 100) -> Iterator[str]:
        """
        Apply mutation rules to generate password variations.
        
        Args:
            word: Original word to mutate
            max_mutations: Maximum number of mutations to generate
            
        Yields:
            Mutated password candidates
        """
        mutation_count = 0
        
        # Original word
        yield word
        mutation_count += 1
        if mutation_count >= max_mutations:
            return
        
        # Case variations
        for case_func in self.case_patterns:
            mutated = case_func(word)
            if mutated != word:
                yield mutated
                mutation_count += 1
                if mutation_count >= max_mutations:
                    return
        
        # Leetspeak substitutions – iterate once, counting as we yield
        for leet_variant in self._apply_leetspeak(word, max_mutations - mutation_count):
            yield leet_variant
            mutation_count += 1
            if mutation_count >= max_mutations:
                return

        # Prefix and suffix combinations
        yield from self._apply_prefix_suffix(word, max_mutations - mutation_count)
    
    def _apply_leetspeak(self, word: str, max_mutations: int) -> Iterator[str]:
        """Apply leetspeak substitutions."""
        # Full substitution – single O(n) translate call
        leet_word = word.translate(self._leet_translate_table)

        if leet_word != word:
            yield leet_word

        # Partial substitutions (combinations) – deduplicate chars first
        if max_mutations > 1:
            seen_chars = set()
            chars_to_substitute = []
            for c in word.lower():
                if c in self.leet_substitutions and c not in seen_chars:
                    seen_chars.add(c)
                    chars_to_substitute.append(c)

            if len(chars_to_substitute) >= 2:
                for r in range(1, min(3, len(chars_to_substitute))):
                    for combo in itertools.combinations(chars_to_substitute, r):
                        variant = word
                        for char in combo:
                            variant = variant.replace(char, self.leet_substitutions[char])
                            variant = variant.replace(char.upper(), self.leet_substitutions[char])
                        if variant != word:
                            yield variant
    
    def _apply_prefix_suffix(self, word: str, max_mutations: int) -> Iterator[str]:
        """Apply prefix and suffix combinations."""
        count = 0
        
        # Prefixes only
        for prefix in self.prefixes:
            if prefix:  # Skip empty prefix (original word already yielded)
                yield prefix + word
                count += 1
                if count >= max_mutations:
                    return
        
        # Suffixes only
        for suffix in self.suffixes:
            if suffix:  # Skip empty suffix
                yield word + suffix
                count += 1
                if count >= max_mutations:
                    return
        
        # Prefix + suffix combinations (limited)
        if max_mutations > count:
            remaining = max_mutations - count
            for prefix in ['1', '123', 'admin']:
                for suffix in ['1', '123', '!']:
                    yield prefix + word + suffix
                    remaining -= 1
                    if remaining <= 0:
                        return
    
    def _alternating_case(self, word: str) -> str:
        """Convert word to alternating case."""
        result = []
        for i, char in enumerate(word):
            if i % 2 == 0:
                result.append(char.upper())
            else:
                result.append(char.lower())
        return ''.join(result)
    
    def _first_last_upper(self, word: str) -> str:
        """Make first and last characters uppercase."""
        if len(word) <= 1:
            return word.upper()
        return word[0].upper() + word[1:-1] + word[-1].upper()
    
    def get_mutation_info(self) -> Dict[str, Any]:
        """
        Get information about available mutations.
        
        Returns:
            Dictionary containing mutation information
        """
        return {
            'case_variations': len(self.case_patterns),
            'leet_substitutions': len(self.leet_substitutions),
            'prefixes': len(self.prefixes),
            'suffixes': len(self.suffixes),
            'total_possible_mutations': self._estimate_total_mutations(),
            'common_patterns': [
                'case_variations',
                'leetspeak',
                'prefix_suffix_combinations',
                'number_appending',
                'symbol_appending'
            ]
        }
    
    def _estimate_total_mutations(self) -> int:
        """Estimate total possible mutations for a typical word."""
        # This is a rough estimate
        return (
            len(self.case_patterns) +  # Case variations
            10 +  # Leetspeak variations
            len(self.prefixes) + len(self.suffixes) +  # Prefix/suffix
            20  # Combined variations
        )
