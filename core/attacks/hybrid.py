"""
Hybrid Attack Implementation

Hybrid attacks combine dictionary attacks with brute-force techniques
to increase effectiveness. This implementation supports dictionary + mask
combinations and rule-based hybrid approaches.
"""

from typing import Iterator, Dict, Any, Optional
from .base import AttackStrategy
from .dictionary import DictionaryAttack
from .brute_force import BruteForceAttack
from ..hashes.base import HashAlgorithm


class HybridAttack(AttackStrategy):
    """Hybrid attack strategy implementation."""
    
    def __init__(self, hash_algorithm: HashAlgorithm, wordlist_path: str,
                 mask: str = None, hybrid_mode: str = 'dictionary_mask'):
        super().__init__("Hybrid Attack", hash_algorithm)
        self.wordlist_path = wordlist_path
        self.mask = mask
        self.hybrid_mode = hybrid_mode
        
        # Initialize sub-attacks
        self.dictionary_attack = DictionaryAttack(hash_algorithm, wordlist_path, apply_rules=False)
        
        if mask:
            self.brute_force_attack = BruteForceAttack(hash_algorithm, mask)
        else:
            self.brute_force_attack = None
    
    def generate_candidates(self) -> Iterator[str]:
        """
        Generate password candidates using hybrid approach.
        
        Yields:
            Password candidate strings
        """
        if self.hybrid_mode == 'dictionary_mask':
            yield from self._dictionary_mask_hybrid()
        elif self.hybrid_mode == 'mask_dictionary':
            yield from self._mask_dictionary_hybrid()
        elif self.hybrid_mode == 'rules_brute':
            yield from self._rules_brute_hybrid()
        else:
            raise ValueError(f"Unknown hybrid mode: {self.hybrid_mode}")
    
    def _dictionary_mask_hybrid(self) -> Iterator[str]:
        """
        Dictionary + mask hybrid: wordlist entries + mask combinations.
        
        Yields:
            Combined password candidates
        """
        if not self.brute_force_attack:
            raise ValueError("Mask required for dictionary-mask hybrid mode")
        
        # Generate all mask combinations
        mask_combinations = list(self.brute_force_attack.generate_candidates())
        
        # Combine with dictionary entries
        for word in self.dictionary_attack.generate_candidates():
            # Word + mask
            for mask_part in mask_combinations:
                yield word + mask_part
            
            # Mask + word
            for mask_part in mask_combinations:
                yield mask_part + word
    
    def _mask_dictionary_hybrid(self) -> Iterator[str]:
        """
        Mask + dictionary hybrid: mask combinations + wordlist entries.
        
        Yields:
            Combined password candidates
        """
        if not self.brute_force_attack:
            raise ValueError("Mask required for mask-dictionary hybrid mode")
        
        # Generate all mask combinations
        mask_combinations = list(self.brute_force_attack.generate_candidates())
        
        # Combine with dictionary entries
        for word in self.dictionary_attack.generate_candidates():
            # Insert word at different positions in mask
            for mask_part in mask_combinations:
                if len(mask_part) > 1:
                    # Insert word at beginning, middle, end
                    yield word + mask_part
                    yield mask_part + word
                    if len(mask_part) > 2:
                        mid = len(mask_part) // 2
                        yield mask_part[:mid] + word + mask_part[mid:]
    
    def _rules_brute_hybrid(self) -> Iterator[str]:
        """
        Rules + brute force hybrid: apply dictionary rules then brute force.
        
        Yields:
            Enhanced password candidates
        """
        # First, try dictionary with rules
        dict_attack_with_rules = DictionaryAttack(
            self.hash_algorithm, 
            self.wordlist_path, 
            apply_rules=True
        )
        
        yield from dict_attack_with_rules.generate_candidates()
        
        # Then try simple brute force if dictionary fails
        if self.brute_force_attack:
            yield from self.brute_force_attack.generate_candidates()
    
    def get_info(self) -> Dict[str, Any]:
        """
        Get hybrid attack information.
        
        Returns:
            Dictionary containing attack metadata
        """
        info = {
            'name': self.name,
            'description': 'Hybrid password cracking attack combining multiple strategies',
            'hybrid_mode': self.hybrid_mode,
            'wordlist_path': self.wordlist_path,
            'mask': self.mask
        }
        
        # Add sub-attack information
        info['dictionary_attack'] = self.dictionary_attack.get_info()
        
        if self.brute_force_attack:
            info['brute_force_attack'] = self.brute_force_attack.get_info()
        
        # Add mode-specific information
        if self.hybrid_mode == 'dictionary_mask':
            info['mode_description'] = 'Dictionary words combined with mask patterns'
        elif self.hybrid_mode == 'mask_dictionary':
            info['mode_description'] = 'Mask patterns combined with dictionary words'
        elif self.hybrid_mode == 'rules_brute':
            info['mode_description'] = 'Dictionary rules followed by brute force'
        
        return info
    
    @classmethod
    def get_available_modes(cls) -> Dict[str, str]:
        """
        Get available hybrid attack modes.
        
        Returns:
            Dictionary of hybrid modes and descriptions
        """
        return {
            'dictionary_mask': 'Dictionary words + mask combinations (word+mask, mask+word)',
            'mask_dictionary': 'Mask patterns + dictionary insertions',
            'rules_brute': 'Dictionary rules followed by brute force attack'
        }
