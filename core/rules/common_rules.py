"""
Common Password Rules

Pre-defined common password mutation rules based on
password analysis and cracking experience.
"""

from typing import Iterator, List, Dict, Any


class CommonPasswordRules:
    """Collection of common password mutation rules."""
    
    # Common number patterns
    COMMON_NUMBERS = [
        '1', '12', '123', '1234', '12345', '123456',
        '2023', '2024', '2025', '2022', '2021',
        '01', '02', '03', '04', '05', '06', '07', '08', '09', '10',
        '11', '22', '33', '44', '55', '66', '77', '88', '99', '00'
    ]
    
    # Common symbols
    COMMON_SYMBOLS = [
        '!', '@', '#', '$', '%', '&', '*', '(', ')',
        '-', '_', '+', '=', '[', ']', '{', '}', '|',
        ':', ';', '"', "'", '<', '>', ',', '.', '?', '/'
    ]
    
    # Common prefixes
    COMMON_PREFIXES = [
        'admin', 'root', 'user', 'test', 'demo', 'temp',
        'x', 'xx', 'xxx', '1', '12', '123'
    ]
    
    # Common suffixes
    COMMON_SUFFIXES = COMMON_NUMBERS + COMMON_SYMBOLS + [
        'admin', 'user', 'login', 'pass', 'pwd'
    ]
    
    # Leetspeak mappings
    LEET_MAP = {
        'a': ['@', '4'],
        'b': ['8', '6'],
        'c': ['(', '['],
        'e': ['3'],
        'g': ['9', '6'],
        'h': ['#'],
        'i': ['!', '1'],
        'l': ['1'],
        'o': ['0'],
        's': ['$', '5'],
        't': ['7'],
        'z': ['2'],
        'A': ['@', '4'],
        'E': ['3'],
        'I': ['!', '1'],
        'O': ['0'],
        'S': ['$', '5']
    }
    
    @classmethod
    def append_numbers(cls, word: str) -> Iterator[str]:
        """Append common numbers to word."""
        for number in cls.COMMON_NUMBERS:
            yield word + number
    
    @classmethod
    def prepend_numbers(cls, word: str) -> Iterator[str]:
        """Prepend common numbers to word."""
        for number in cls.COMMON_NUMBERS:
            yield number + word
    
    @classmethod
    def append_symbols(cls, word: str) -> Iterator[str]:
        """Append common symbols to word."""
        for symbol in cls.COMMON_SYMBOLS:
            yield word + symbol
    
    @classmethod
    def prepend_symbols(cls, word: str) -> Iterator[str]:
        """Prepend common symbols to word."""
        for symbol in cls.COMMON_SYMBOLS:
            yield symbol + word
    
    @classmethod
    def capitalize_variations(cls, word: str) -> Iterator[str]:
        """Generate capitalization variations."""
        if len(word) == 0:
            return
        
        # All lowercase
        yield word.lower()
        
        # All uppercase
        yield word.upper()
        
        # First letter uppercase
        yield word.capitalize()
        
        # Title case
        yield word.title()
        
        # Last letter uppercase
        if len(word) > 1:
            yield word[:-1] + word[-1].upper()
        
        # First and last letters uppercase
        if len(word) > 1:
            yield word[0].upper() + word[1:-1] + word[-1].upper()
    
    @classmethod
    def leetspeak_variations(cls, word: str) -> Iterator[str]:
        """Generate leetspeak variations."""
        # Full substitution
        leet_word = word
        for char, replacements in cls.LEET_MAP.items():
            for replacement in replacements:
                leet_word = leet_word.replace(char, replacement)
        
        if leet_word != word:
            yield leet_word
        
        # Partial substitutions (single character)
        for char, replacements in cls.LEET_MAP.items():
            if char in word:
                for replacement in replacements:
                    yield word.replace(char, replacement)
        
        # Case-insensitive substitutions
        lower_word = word.lower()
        for char, replacements in cls.LEET_MAP.items():
            if char in lower_word:
                for replacement in replacements:
                    yield word.replace(char, replacement)
                    yield word.replace(char.upper(), replacement)
    
    @classmethod
    def reverse_word(cls, word: str) -> Iterator[str]:
        """Generate reversed word."""
        reversed_word = word[::-1]
        if reversed_word != word:
            yield reversed_word
    
    @classmethod
    def duplicate_word(cls, word: str) -> Iterator[str]:
        """Generate duplicated word."""
        yield word + word
    
    @classmethod
    def toggle_case(cls, word: str) -> Iterator[str]:
        """Toggle case of each character."""
        toggled = ''.join(
            char.lower() if char.isupper() else char.upper()
            for char in word
        )
        if toggled != word:
            yield toggled
    
    @classmethod
    def remove_vowels(cls, word: str) -> Iterator[str]:
        """Remove vowels from word."""
        vowels = 'aeiouAEIOU'
        no_vowels = ''.join(char for char in word if char not in vowels)
        if no_vowels != word and len(no_vowels) > 1:
            yield no_vowels
    
    @classmethod
    def remove_consonants(cls, word: str) -> Iterator[str]:
        """Remove consonants from word."""
        vowels = 'aeiouAEIOU'
        no_consonants = ''.join(char for char in word if char in vowels)
        if no_consonants != word and len(no_consonants) > 1:
            yield no_consonants
    
    @classmethod
    def keyboard_patterns(cls, word: str) -> Iterator[str]:
        """Generate keyboard pattern combinations."""
        patterns = [
            'qwerty', 'asdf', 'zxcv', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
            '123456', '123456789', 'qwerty123', 'asdf123'
        ]
        
        for pattern in patterns:
            yield word + pattern
            yield pattern + word
    
    @classmethod
    def get_all_rule_functions(cls) -> Dict[str, callable]:
        """
        Get all available rule functions.
        
        Returns:
            Dictionary of rule names and functions
        """
        return {
            'append_numbers': cls.append_numbers,
            'prepend_numbers': cls.prepend_numbers,
            'append_symbols': cls.append_symbols,
            'prepend_symbols': cls.prepend_symbols,
            'capitalize_variations': cls.capitalize_variations,
            'leetspeak_variations': cls.leetspeak_variations,
            'reverse_word': cls.reverse_word,
            'duplicate_word': cls.duplicate_word,
            'toggle_case': cls.toggle_case,
            'remove_vowels': cls.remove_vowels,
            'remove_consonants': cls.remove_consonants,
            'keyboard_patterns': cls.keyboard_patterns
        }
    
    @classmethod
    def get_rule_descriptions(cls) -> Dict[str, str]:
        """
        Get descriptions of all rules.
        
        Returns:
            Dictionary of rule names and descriptions
        """
        return {
            'append_numbers': 'Append common numbers (123, 2024, etc.)',
            'prepend_numbers': 'Prepend common numbers',
            'append_symbols': 'Append common symbols (!, @, #, etc.)',
            'prepend_symbols': 'Prepend common symbols',
            'capitalize_variations': 'Generate capitalization variations',
            'leetspeak_variations': 'Generate leetspeak substitutions',
            'reverse_word': 'Reverse the word',
            'duplicate_word': 'Duplicate the word',
            'toggle_case': 'Toggle case of each character',
            'remove_vowels': 'Remove all vowels',
            'remove_consonants': 'Remove all consonants',
            'keyboard_patterns': 'Combine with keyboard patterns'
        }
    
    @classmethod
    def estimate_mutations(cls, word: str) -> Dict[str, int]:
        """
        Estimate number of mutations for a word.
        
        Args:
            word: Word to analyze
            
        Returns:
            Dictionary with mutation counts per rule
        """
        counts = {}
        
        # Count mutations for each rule
        counts['append_numbers'] = len(cls.COMMON_NUMBERS)
        counts['prepend_numbers'] = len(cls.COMMON_NUMBERS)
        counts['append_symbols'] = len(cls.COMMON_SYMBOLS)
        counts['prepend_symbols'] = len(cls.COMMON_SYMBOLS)
        counts['capitalize_variations'] = min(6, len(word))  # Max 6 variations
        counts['leetspeak_variations'] = len([c for c in word.lower() if c in cls.LEET_MAP]) * 2
        counts['reverse_word'] = 1 if len(word) > 1 else 0
        counts['duplicate_word'] = 1
        counts['toggle_case'] = 1 if any(c.isalpha() for c in word) else 0
        counts['remove_vowels'] = 1 if any(c in 'aeiouAEIOU' for c in word) and len(word) > 2 else 0
        counts['remove_consonants'] = 1 if any(c.isalpha() and c not in 'aeiouAEIOU' for c in word) and len(word) > 2 else 0
        counts['keyboard_patterns'] = 10  # Fixed number of patterns
        
        return counts
