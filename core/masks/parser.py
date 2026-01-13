"""
Mask Parser

Parses mask patterns and validates mask syntax for brute-force attacks.
"""

import re
from typing import Dict, List, Any, Optional


class MaskParser:
    """Parses and validates mask patterns for password cracking."""
    
    # Standard mask placeholders
    MASK_PLACEHOLDERS = {
        '?l': 'lowercase letters (a-z)',
        '?u': 'uppercase letters (A-Z)', 
        '?d': 'digits (0-9)',
        '?s': 'special symbols (!@#$%^&*...)',
        '?a': 'all printable ASCII characters',
        '?b': 'binary digits (0-1)',
        '?h': 'hexadecimal lowercase (0-9, a-f)',
        '?H': 'hexadecimal uppercase (0-9, A-F)',
        '?p': 'printable characters (space + printable)',
        '?c': 'custom character set (defined separately)',
    }
    
    # Character sets for each placeholder
    CHARACTER_SETS = {
        '?l': 'abcdefghijklmnopqrstuvwxyz',
        '?u': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        '?d': '0123456789',
        '?s': '!@#$%^&*()-_=+[]{}|;:,.<>?/~`',
        '?a': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?/~`',
        '?b': '01',
        '?h': '0123456789abcdef',
        '?H': '0123456789ABCDEF',
        '?p': ' abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?/~`',
    }
    
    def __init__(self):
        self.custom_charsets: Dict[str, str] = {}
    
    def parse_mask(self, mask: str) -> Dict[str, Any]:
        """
        Parse a mask pattern into its components.
        
        Args:
            mask: Mask pattern string (e.g., '?l?l?l?d')
            
        Returns:
            Dictionary containing parsed mask information
        """
        if not mask:
            raise ValueError("Mask cannot be empty")
        
        components = []
        i = 0
        length = 0
        
        while i < len(mask):
            if i + 1 < len(mask) and mask[i] == '?' and mask[i+1] in self.CHARACTER_SETS:
                placeholder = mask[i:i+2]
                char_set = self.CHARACTER_SETS[placeholder]
                
                components.append({
                    'type': 'placeholder',
                    'placeholder': placeholder,
                    'character_set': char_set,
                    'size': len(char_set),
                    'description': self.MASK_PLACEHOLDERS[placeholder]
                })
                length += 1
                i += 2
            else:
                # Literal character
                char = mask[i]
                components.append({
                    'type': 'literal',
                    'character': char,
                    'character_set': char,
                    'size': 1
                })
                length += 1
                i += 1
        
        return {
            'original_mask': mask,
            'components': components,
            'length': length,
            'total_combinations': self._calculate_combinations(components),
            'is_valid': True
        }
    
    def _calculate_combinations(self, components: List[Dict[str, Any]]) -> int:
        """
        Calculate total number of combinations for parsed mask.
        
        Args:
            components: Parsed mask components
            
        Returns:
            Total number of combinations
        """
        total = 1
        for component in components:
            total *= component['size']
        return total
    
    def validate_mask(self, mask: str) -> Dict[str, Any]:
        """
        Validate mask syntax and structure.
        
        Args:
            mask: Mask pattern to validate
            
        Returns:
            Dictionary with validation results
        """
        result = {
            'is_valid': True,
            'errors': [],
            'warnings': [],
            'info': {}
        }
        
        if not mask:
            result['is_valid'] = False
            result['errors'].append("Mask cannot be empty")
            return result
        
        # Check for invalid placeholders
        i = 0
        while i < len(mask):
            if mask[i] == '?':
                if i + 1 >= len(mask):
                    result['is_valid'] = False
                    result['errors'].append(f"Incomplete placeholder at position {i}")
                    break
                
                placeholder = mask[i:i+2]
                if placeholder not in self.MASK_PLACEHOLDERS:
                    result['is_valid'] = False
                    result['errors'].append(f"Invalid placeholder '{placeholder}' at position {i}")
                
                i += 2
            else:
                i += 1
        
        # Calculate complexity and warnings
        try:
            parsed = self.parse_mask(mask)
            result['info'] = parsed
            
            # Warnings for very large search spaces
            if parsed['total_combinations'] > 10**12:
                result['warnings'].append("Very large search space may take excessive time")
            
            # Warnings for very short masks
            if parsed['length'] < 4:
                result['warnings'].append("Very short mask may have limited effectiveness")
            
        except Exception as e:
            result['is_valid'] = False
            result['errors'].append(f"Parse error: {str(e)}")
        
        return result
    
    def add_custom_charset(self, name: str, charset: str):
        """
        Add a custom character set.
        
        Args:
            name: Charset name (e.g., 'custom1')
            charset: String of characters in the set
        """
        self.custom_charsets[name] = charset
        self.CHARACTER_SETS[f'?{name}'] = charset
        self.MASK_PLACEHOLDERS[f'?{name}'] = f'custom set: {charset}'
    
    def get_available_placeholders(self) -> Dict[str, str]:
        """
        Get all available mask placeholders.
        
        Returns:
            Dictionary of placeholders and descriptions
        """
        return {**self.MASK_PLACEHOLDERS, **{f'?{k}': f'custom: {v}' for k, v in self.custom_charsets.items()}}
    
    def estimate_crack_time(self, mask: str, hashes_per_second: int = 1000000) -> Dict[str, Any]:
        """
        Estimate time required to crack a mask.
        
        Args:
            mask: Mask pattern
            hashes_per_second: Hashing performance estimate
            
        Returns:
            Dictionary with time estimates
        """
        try:
            parsed = self.parse_mask(mask)
            combinations = parsed['total_combinations']
            
            seconds = combinations / hashes_per_second
            minutes = seconds / 60
            hours = minutes / 60
            days = hours / 24
            years = days / 365
            
            return {
                'combinations': combinations,
                'seconds': seconds,
                'minutes': minutes,
                'hours': hours,
                'days': days,
                'years': years,
                'human_readable': self._format_time(seconds)
            }
            
        except Exception as e:
            return {'error': f'Estimation failed: {str(e)}'}
    
    def _format_time(self, seconds: float) -> str:
        """Format time in human-readable format."""
        if seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} hours"
        elif seconds < 31536000:
            return f"{seconds/86400:.1f} days"
        else:
            return f"{seconds/31536000:.1f} years"
