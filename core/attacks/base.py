"""
Base Attack Strategy Interface

Defines the abstract interface that all attack strategy implementations
must follow for consistency and reliability.
"""

from abc import ABC, abstractmethod
from typing import Iterator, Optional, Dict, Any
from ..hashes.base import HashAlgorithm


class AttackStrategy(ABC):
    """Abstract base class for attack strategy implementations."""
    
    def __init__(self, name: str, hash_algorithm: HashAlgorithm):
        self.name = name
        self.hash_algorithm = hash_algorithm
        self.target_hash = None
        self.attempts = 0
        self.start_time = None
    
    @abstractmethod
    def generate_candidates(self) -> Iterator[str]:
        """
        Generate password candidates for the attack.
        
        Yields:
            Password candidate strings
        """
        pass
    
    @abstractmethod
    def get_info(self) -> Dict[str, Any]:
        """
        Get attack strategy information and capabilities.
        
        Returns:
            Dictionary containing attack metadata
        """
        pass
    
    def set_target(self, target_hash: str):
        """
        Set the target hash to crack.
        
        Args:
            target_hash: The hash to attempt to crack
        """
        self.target_hash = self.hash_algorithm.normalize_hash(target_hash)
    
    def verify_candidate(self, candidate: str) -> bool:
        """
        Verify if a candidate matches the target hash.
        
        Args:
            candidate: Password candidate to verify
            
        Returns:
            True if candidate matches target hash, False otherwise
        """
        self.attempts += 1
        return self.hash_algorithm.verify(candidate, self.target_hash)
    
    def reset_stats(self):
        """Reset attack statistics."""
        self.attempts = 0
        self.start_time = None
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get current attack statistics.
        
        Returns:
            Dictionary containing attack statistics
        """
        return {
            'attempts': self.attempts,
            'strategy': self.name,
            'algorithm': self.hash_algorithm.name,
            'target_hash': self.target_hash
        }
