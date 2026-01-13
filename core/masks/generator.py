"""
Mask Generator

Generates mask patterns based on common password structures
and analysis of cracked passwords.
"""

import re
from typing import List, Dict, Any, Set
from .parser import MaskParser


class MaskGenerator:
    """Generates mask patterns for password cracking."""
    
    def __init__(self):
        self.parser = MaskParser()
        self.common_patterns = [
            # Common password structures
            '?l?l?l?l?l?l?l?l',  # 8 lowercase
            '?l?l?l?l?l?l?l?l?l',  # 9 lowercase
            '?l?l?l?l?l?l?l?l?l?l',  # 10 lowercase
            '?u?l?l?l?l?l?l',  # Title case + lowercase
            '?l?l?l?l?d?d?d?d',  # Letters + 4 digits
            '?l?l?l?l?l?d?d',  # Letters + 2 digits
            '?d?d?d?d?d?d?d?d',  # 8 digits
            '?l?l?l?l?l?l?l?l?d?d',  # 8 letters + 2 digits
            '?l?l?l?l?l?l?d?d?d',  # 6 letters + 3 digits
            '?l?l?l?l?l?l?l?l?l?d',  # 9 letters + 1 digit
            '?u?l?l?l?l?l?l?d?d',  # Title case + lowercase + 2 digits
            '?l?l?l?l?l?l?s',  # Letters + symbol
            '?l?l?l?l?l?l?l?l?s',  # 8 letters + symbol
            '?l?l?l?l?l?d?d?s',  # 5 letters + 2 digits + symbol
        ]
    
    def generate_masks_from_passwords(self, passwords: List[str]) -> List[str]:
        """
        Generate mask patterns from a list of cracked passwords.
        
        Args:
            passwords: List of passwords to analyze
            
        Returns:
            List of generated mask patterns
        """
        mask_counts = {}
        
        for password in passwords:
            mask = self._password_to_mask(password)
            if mask:
                mask_counts[mask] = mask_counts.get(mask, 0) + 1
        
        # Sort by frequency and return unique masks
        sorted_masks = sorted(mask_counts.items(), key=lambda x: x[1], reverse=True)
        return [mask for mask, _ in sorted_masks]
    
    def _password_to_mask(self, password: str) -> str:
        """
        Convert a password to its mask representation.
        
        Args:
            password: Password to convert
            
        Returns:
            Mask representation
        """
        mask = ""
        
        for char in password:
            if char.islower():
                mask += "?l"
            elif char.isupper():
                mask += "?u"
            elif char.isdigit():
                mask += "?d"
            elif char in self.parser.CHARACTER_SETS.get('?s', ''):
                mask += "?s"
            else:
                mask += char  # Literal character
        
        return mask
    
    def generate_common_masks(self, min_length: int = 6, max_length: int = 12) -> List[str]:
        """
        Generate common mask patterns for password cracking.
        
        Args:
            min_length: Minimum password length
            max_length: Maximum password length
            
        Returns:
            List of common mask patterns
        """
        masks = []
        
        # Add predefined common patterns
        for pattern in self.common_patterns:
            parsed = self.parser.parse_mask(pattern)
            if min_length <= parsed['length'] <= max_length:
                masks.append(pattern)
        
        # Generate systematic patterns
        masks.extend(self._generate_systematic_masks(min_length, max_length))
        
        # Remove duplicates and return
        return list(set(masks))
    
    def _generate_systematic_masks(self, min_length: int, max_length: int) -> List[str]:
        """
        Generate systematic mask patterns.
        
        Args:
            min_length: Minimum password length
            max_length: Maximum password length
            
        Returns:
            List of systematic mask patterns
        """
        masks = []
        
        # Pure character type masks
        char_types = ['?l', '?u', '?d', '?s']
        
        for char_type in char_types:
            for length in range(min_length, max_length + 1):
                masks.append(char_type * length)
        
        # Mixed patterns (common combinations)
        mixed_patterns = [
            # Title case + lowercase
            ['?u'] + ['?l'] * (max_length - 1),
            # Lowercase + digits
            ['?l'] * (max_length - 2) + ['?d'] * 2,
            # Lowercase + symbols
            ['?l'] * (max_length - 1) + ['?s'],
            # Mixed case
            ['?u', '?l'] * (max_length // 2),
        ]
        
        for pattern in mixed_patterns:
            for length in range(min_length, max_length + 1):
                if len(pattern) >= length:
                    mask = ''.join(pattern[:length])
                    masks.append(mask)
        
        return masks
    
    def generate_targeted_masks(self, target_info: Dict[str, Any]) -> List[str]:
        """
        Generate masks based on target information.
        
        Args:
            target_info: Dictionary with target information
                - known_patterns: List of known patterns
                - common_words: List of common words
                - date_formats: List of date formats
                - name_variations: List of name variations
                
        Returns:
            List of targeted mask patterns
        """
        masks = []
        
        # Masks based on known patterns
        if 'known_patterns' in target_info:
            masks.extend(target_info['known_patterns'])
        
        # Masks based on common words
        if 'common_words' in target_info:
            for word in target_info['common_words']:
                word_mask = self._password_to_mask(word)
                if word_mask:
                    masks.append(word_mask)
        
        # Date-based masks
        if 'date_formats' in target_info:
            masks.extend(self._generate_date_masks(target_info['date_formats']))
        
        # Name-based masks
        if 'name_variations' in target_info:
            masks.extend(self._generate_name_masks(target_info['name_variations']))
        
        return list(set(masks))  # Remove duplicates
    
    def _generate_date_masks(self, date_formats: List[str]) -> List[str]:
        """Generate masks for common date formats."""
        date_masks = []
        
        # Common date patterns
        date_patterns = {
            'YYYY': '?d?d?d?d',
            'YY': '?d?d',
            'MM': '?d?d',
            'DD': '?d?d',
            'YYYYMMDD': '?d?d?d?d?d?d?d?d',
            'DDMMYYYY': '?d?d?d?d?d?d?d?d',
            'MMDDYYYY': '?d?d?d?d?d?d?d?d'
        }
        
        for fmt in date_formats:
            if fmt in date_patterns:
                date_masks.append(date_patterns[fmt])
        
        return date_masks
    
    def _generate_name_masks(self, name_variations: List[str]) -> List[str]:
        """Generate masks based on name variations."""
        name_masks = []
        
        for name in name_variations:
            # Name + common suffixes
            suffixes = ['', '1', '123', '2023', '2024', '2025', '!']
            
            for suffix in suffixes:
                full_name = name + suffix
                mask = self._password_to_mask(full_name)
                if mask:
                    name_masks.append(mask)
        
        return name_masks
    
    def rank_masks_by_effectiveness(self, masks: List[str], 
                                   cracked_passwords: List[str] = None) -> List[Dict[str, Any]]:
        """
        Rank masks by their potential effectiveness.
        
        Args:
            masks: List of mask patterns to rank
            cracked_passwords: Optional list of cracked passwords for analysis
            
        Returns:
            List of masks with effectiveness scores
        """
        ranked_masks = []
        
        for mask in masks:
            try:
                parsed = self.parser.parse_mask(mask)
                
                # Calculate base score
                score = 0
                
                # Length appropriateness (6-12 characters is common)
                length = parsed['length']
                if 6 <= length <= 12:
                    score += 20
                elif 13 <= length <= 16:
                    score += 10
                else:
                    score -= 10
                
                # Character diversity
                char_types = set()
                for component in parsed['components']:
                    if component['type'] == 'placeholder':
                        char_types.add(component['placeholder'])
                score += len(char_types) * 5
                
                # Complexity balance (not too simple, not too complex)
                combinations = parsed['total_combinations']
                if 10**6 <= combinations <= 10**10:
                    score += 15
                elif combinations < 10**6:
                    score -= 5
                elif combinations > 10**12:
                    score -= 10
                
                # Bonus for patterns matching cracked passwords
                if cracked_passwords:
                    matches = sum(1 for pwd in cracked_passwords 
                                if self._password_to_mask(pwd) == mask)
                    score += matches * 10
                
                ranked_masks.append({
                    'mask': mask,
                    'score': score,
                    'length': length,
                    'combinations': combinations,
                    'char_types': len(char_types),
                    'matches': matches if cracked_passwords else 0
                })
                
            except Exception:
                # Invalid mask gets lowest score
                ranked_masks.append({
                    'mask': mask,
                    'score': -100,
                    'length': 0,
                    'combinations': 0,
                    'char_types': 0,
                    'matches': 0
                })
        
        # Sort by score (highest first)
        ranked_masks.sort(key=lambda x: x['score'], reverse=True)
        
        return ranked_masks
