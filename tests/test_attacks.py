"""
Test Attack Strategies

Unit tests for attack strategy implementations to ensure
correctness and reliability.
"""

import unittest
import tempfile
import os
import sys

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.hashes import MD5Hash
from core.attacks import DictionaryAttack, BruteForceAttack, HybridAttack


class TestAttackStrategies(unittest.TestCase):
    """Test cases for attack strategy implementations."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.hash_algorithm = MD5Hash()
        self.target_hash = self.hash_algorithm.hash('password')
        
        # Create temporary wordlist
        self.wordlist_content = [
            'password',
            '123456',
            'admin',
            'test',
            'qwerty',
            'hello',
            'world',
            'login',
            'user',
            'pass'
        ]
        
        self.temp_wordlist = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        for word in self.wordlist_content:
            self.temp_wordlist.write(word + '\n')
        self.temp_wordlist.close()
    
    def tearDown(self):
        """Clean up test fixtures."""
        os.unlink(self.temp_wordlist.name)
    
    def test_dictionary_attack(self):
        """Test dictionary attack implementation."""
        attack = DictionaryAttack(self.hash_algorithm, self.temp_wordlist.name, apply_rules=False)
        
        # Test basic functionality
        attack.set_target(self.target_hash)
        self.assertEqual(attack.target_hash, self.target_hash)
        
        # Test candidate generation
        candidates = list(attack.generate_candidates())
        self.assertIn('password', candidates)
        self.assertEqual(len(candidates), len(self.wordlist_content))
        
        # Test verification
        self.assertTrue(attack.verify_candidate('password'))
        self.assertFalse(attack.verify_candidate('wrong'))
        
        # Test with rules enabled
        attack_with_rules = DictionaryAttack(self.hash_algorithm, self.temp_wordlist.name, apply_rules=True)
        candidates_with_rules = list(attack_with_rules.generate_candidates())
        self.assertGreater(len(candidates_with_rules), len(candidates))
        
        # Test info
        info = attack.get_info()
        self.assertEqual(info['name'], 'Dictionary Attack')
        self.assertTrue(info['mutations_enabled'])
        self.assertEqual(info['wordlist_path'], self.temp_wordlist.name)
    
    def test_brute_force_attack(self):
        """Test brute-force attack implementation."""
        mask = '?l?l?l?l'  # 4 lowercase letters
        attack = BruteForceAttack(self.hash_algorithm, mask)
        
        # Test basic functionality
        attack.set_target(self.target_hash)
        self.assertEqual(attack.target_hash, self.target_hash)
        
        # Test candidate generation (limited to avoid long test)
        candidates = []
        for i, candidate in enumerate(attack.generate_candidates()):
            candidates.append(candidate)
            if i >= 100:  # Limit for test
                break
        
        self.assertGreater(len(candidates), 0)
        self.assertTrue(all(len(c) == 4 and c.islower() for c in candidates))
        
        # Test verification
        self.assertTrue(attack.verify_candidate('password'))
        self.assertFalse(attack.verify_candidate('wrong'))
        
        # Test info
        info = attack.get_info()
        self.assertEqual(info['name'], 'Brute-Force Attack')
        self.assertEqual(info['mask'], mask)
        self.assertEqual(info['min_length'], 4)
        self.assertEqual(info['max_length'], 4)
        self.assertGreater(info['total_combinations'], 0)
        
        # Test available masks
        masks = BruteForceAttack.get_available_masks()
        self.assertIn('?l', masks)
        self.assertIn('?u', masks)
        self.assertIn('?d', masks)
    
    def test_hybrid_attack(self):
        """Test hybrid attack implementation."""
        mask = '?d?d'  # 2 digits
        attack = HybridAttack(self.hash_algorithm, self.temp_wordlist.name, mask, 'dictionary_mask')
        
        # Test basic functionality
        attack.set_target(self.target_hash)
        self.assertEqual(attack.target_hash, self.target_hash)
        
        # Test candidate generation (limited to avoid long test)
        candidates = []
        for i, candidate in enumerate(attack.generate_candidates()):
            candidates.append(candidate)
            if i >= 50:  # Limit for test
                break
        
        self.assertGreater(len(candidates), 0)
        
        # Test verification
        self.assertTrue(attack.verify_candidate('password'))
        self.assertFalse(attack.verify_candidate('wrong'))
        
        # Test info
        info = attack.get_info()
        self.assertEqual(info['name'], 'Hybrid Attack')
        self.assertEqual(info['hybrid_mode'], 'dictionary_mask')
        self.assertEqual(info['wordlist_path'], self.temp_wordlist.name)
        self.assertEqual(info['mask'], mask)
        
        # Test available modes
        modes = HybridAttack.get_available_modes()
        self.assertIn('dictionary_mask', modes)
        self.assertIn('mask_dictionary', modes)
        self.assertIn('rules_brute', modes)
    
    def test_attack_statistics(self):
        """Test attack statistics tracking."""
        attack = DictionaryAttack(self.hash_algorithm, self.temp_wordlist.name, apply_rules=False)
        
        # Test initial stats
        stats = attack.get_stats()
        self.assertEqual(stats['attempts'], 0)
        self.assertEqual(stats['strategy'], 'Dictionary Attack')
        self.assertEqual(stats['algorithm'], 'MD5')
        
        # Test stats after verification attempts
        attack.verify_candidate('wrong1')
        attack.verify_candidate('wrong2')
        stats = attack.get_stats()
        self.assertEqual(stats['attempts'], 2)
        
        # Test stats reset
        attack.reset_stats()
        stats = attack.get_stats()
        self.assertEqual(stats['attempts'], 0)
    
    def test_mask_validation(self):
        """Test mask validation in brute-force attack."""
        # Valid masks
        valid_masks = ['?l?l?l', '?u?d?d', '?s?l?u', '?a?a?a']
        
        for mask in valid_masks:
            attack = BruteForceAttack(self.hash_algorithm, mask)
            info = attack.get_info()
            self.assertGreater(info['total_combinations'], 0)
        
        # Test complex mask
        complex_mask = '?l?l?d?d?s'
        attack = BruteForceAttack(self.hash_algorithm, complex_mask)
        candidates = list(attack.generate_candidates())
        self.assertTrue(all(len(c) == 5 for c in candidates[:10]))
    
    def test_dictionary_wordlist_stats(self):
        """Test wordlist statistics functionality."""
        attack = DictionaryAttack(self.hash_algorithm, self.temp_wordlist.name, apply_rules=False)
        
        stats = attack.get_wordlist_stats()
        self.assertIn('total_lines', stats)
        self.assertIn('unique_entries', stats)
        self.assertIn('file_size_mb', stats)
        self.assertEqual(stats['total_lines'], len(self.wordlist_content))
    
    def test_attack_error_handling(self):
        """Test error handling in attacks."""
        # Test non-existent wordlist
        with self.assertRaises(FileNotFoundError):
            DictionaryAttack(self.hash_algorithm, 'nonexistent.txt')
        
        # Test invalid mask (should not raise error but handle gracefully)
        attack = BruteForceAttack(self.hash_algorithm, '?x')  # Invalid placeholder
        info = attack.get_info()
        # Should still work but with limited functionality
    
    def test_hybrid_mode_variations(self):
        """Test different hybrid attack modes."""
        modes = ['dictionary_mask', 'mask_dictionary', 'rules_brute']
        
        for mode in modes:
            attack = HybridAttack(self.hash_algorithm, self.temp_wordlist.name, '?d?d', mode)
            info = attack.get_info()
            self.assertEqual(info['hybrid_mode'], mode)
            
            # Test that it generates candidates
            candidates = list(attack.generate_candidates())
            self.assertGreater(len(candidates), 0)


if __name__ == '__main__':
    unittest.main()
