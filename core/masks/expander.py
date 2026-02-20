"""
Mask Expander

Expands mask patterns into actual character sets and generates
all possible combinations for brute-force attacks.
"""

import itertools
import math
from typing import Iterator, List, Dict, Any
from .parser import MaskParser


class MaskExpander:
    """Expands mask patterns into character combinations."""

    def __init__(self):
        self.parser = MaskParser()
        # Cache parsed mask results to avoid re-parsing the same mask
        self._parse_cache: Dict[str, Dict[str, Any]] = {}

    def _get_parsed(self, mask: str) -> Dict[str, Any]:
        """Return cached parse result for *mask*."""
        if mask not in self._parse_cache:
            self._parse_cache[mask] = self.parser.parse_mask(mask)
        return self._parse_cache[mask]

    def expand_mask(self, mask: str) -> List[str]:
        """
        Expand mask into list of character sets.

        Args:
            mask: Mask pattern to expand

        Returns:
            List of character sets for each position
        """
        parsed = self._get_parsed(mask)
        return [component['character_set'] for component in parsed['components']]
    
    def generate_combinations(self, mask: str, max_combinations: int = None) -> Iterator[str]:
        """
        Generate all combinations for a mask.
        
        Args:
            mask: Mask pattern
            max_combinations: Maximum combinations to generate (None for unlimited)
            
        Yields:
            Password combinations
        """
        char_sets = self.expand_mask(mask)
        
        count = 0
        for combination in itertools.product(*char_sets):
            if max_combinations and count >= max_combinations:
                break
            
            yield ''.join(combination)
            count += 1
    
    def get_combination_sample(self, mask: str, sample_size: int = 100) -> List[str]:
        """
        Get a sample of combinations from a mask.
        
        Args:
            mask: Mask pattern
            sample_size: Number of combinations to sample
            
        Returns:
            List of sample combinations
        """
        sample = []
        for i, combination in enumerate(self.generate_combinations(mask)):
            if i >= sample_size:
                break
            sample.append(combination)
        return sample
    
    def expand_mask_range(self, mask_template: str, min_length: int, 
                         max_length: int) -> Iterator[str]:
        """
        Expand mask for variable length ranges.
        
        Args:
            mask_template: Base mask template (e.g., '?l' for variable length)
            min_length: Minimum password length
            max_length: Maximum password length
            
        Yields:
            Password combinations for each length
        """
        for length in range(min_length, max_length + 1):
            # Create mask for this length
            if '?' in mask_template:
                # Repeat the placeholder pattern
                mask = mask_template * length
            else:
                # Use first character of template
                mask = mask_template[0] * length
            
            yield from self.generate_combinations(mask)
    
    def analyze_mask_complexity(self, mask: str) -> Dict[str, Any]:
        """
        Analyze the complexity of a mask pattern.
        
        Args:
            mask: Mask pattern to analyze
            
        Returns:
            Dictionary with complexity analysis
        """
        try:
            parsed = self._get_parsed(mask)
            char_sets = self.expand_mask(mask)

            # Calculate entropy
            total_entropy = sum(math.log2(len(cs)) for cs in char_sets)
            
            # Analyze character distribution
            char_type_counts = {
                'lowercase': 0,
                'uppercase': 0,
                'digits': 0,
                'symbols': 0,
                'literals': 0
            }
            
            for component in parsed['components']:
                if component['type'] == 'placeholder':
                    placeholder = component['placeholder']
                    if placeholder == '?l':
                        char_type_counts['lowercase'] += 1
                    elif placeholder == '?u':
                        char_type_counts['uppercase'] += 1
                    elif placeholder == '?d':
                        char_type_counts['digits'] += 1
                    elif placeholder == '?s':
                        char_type_counts['symbols'] += 1
                else:
                    char_type_counts['literals'] += 1
            
            return {
                'mask': mask,
                'length': parsed['length'],
                'total_combinations': parsed['total_combinations'],
                'entropy_bits': total_entropy,
                'character_distribution': char_type_counts,
                'complexity_score': self._calculate_complexity_score(parsed),
                'estimated_time': self.parser.estimate_crack_time(mask)
            }
            
        except Exception as e:
            return {'error': f'Analysis failed: {str(e)}'}
    
    def _calculate_complexity_score(self, parsed: Dict[str, Any]) -> float:
        """
        Calculate a complexity score for the mask.
        
        Args:
            parsed: Parsed mask information
            
        Returns:
            Complexity score (0-100)
        """
        score = 0.0

        # Base score from combinations (logarithmic scale)
        if parsed['total_combinations'] > 0:
            score += min(50, math.log10(parsed['total_combinations']))
        
        # Bonus for mixed character types
        char_types = set()
        for component in parsed['components']:
            if component['type'] == 'placeholder':
                char_types.add(component['placeholder'])
        
        score += len(char_types) * 5
        
        # Bonus for length
        score += min(20, parsed['length'] * 2)
        
        return min(100, score)
    
    def optimize_mask_order(self, masks: List[str]) -> List[str]:
        """
        Optimize the order of masks for efficient cracking.
        
        Args:
            masks: List of mask patterns
            
        Returns:
            Optimized list of masks (most likely first)
        """
        mask_scores = []
        
        for mask in masks:
            try:
                analysis = self.analyze_mask_complexity(mask)
                score = analysis.get('complexity_score', 0)
                
                # Prefer masks with moderate complexity (not too simple, not too complex)
                if 20 <= score <= 60:
                    score += 20  # Bonus for optimal complexity
                elif score > 80:
                    score -= 30  # Penalty for excessive complexity
                
                mask_scores.append((mask, score))
                
            except Exception:
                mask_scores.append((mask, 0))  # Lowest score for invalid masks
        
        # Sort by score (highest first)
        mask_scores.sort(key=lambda x: x[1], reverse=True)
        
        return [mask for mask, _ in mask_scores]
