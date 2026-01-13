"""
Test Hash Algorithm Implementations

Unit tests for all hash algorithm implementations to ensure
correctness and reliability.
"""

import unittest
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.hashes import MD5Hash, SHA1Hash, SHA256Hash, SHA512Hash, NTLMHash, BcryptHash, PBKDF2Hash


class TestHashAlgorithms(unittest.TestCase):
    """Test cases for hash algorithm implementations."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_passwords = [
            'password',
            '123456',
            'admin',
            'test',
            'qwerty',
            'HelloWorld',
            'P@ssw0rd!',
            '',
            'a',
            'verylongpasswordwithspecialchars123!@#'
        ]
        
        self.algorithms = {
            'md5': MD5Hash(),
            'sha1': SHA1Hash(),
            'sha256': SHA256Hash(),
            'sha512': SHA512Hash(),
            'ntlm': NTLMHash(),
            'bcrypt': BcryptHash(),
            'pbkdf2': PBKDF2Hash()
        }
    
    def test_md5_hash(self):
        """Test MD5 hash implementation."""
        md5 = self.algorithms['md5']
        
        # Test known values
        self.assertEqual(md5.hash(''), 'd41d8cd98f00b204e9800998ecf8427e')
        self.assertEqual(md5.hash('password'), '5f4dcc3b5aa765d61d8327deb882cf99')
        self.assertEqual(md5.hash('123456'), 'e10adc3949ba59abbe56e057f20f883e')
        
        # Test verification
        self.assertTrue(md5.verify('password', '5f4dcc3b5aa765d61d8327deb882cf99'))
        self.assertFalse(md5.verify('wrong', '5f4dcc3b5aa765d61d8327deb882cf99'))
        
        # Test case insensitivity
        self.assertTrue(md5.verify('password', '5F4DCC3B5AA765D61D8327DEB882CF99'))
        
        # Test info
        info = md5.get_info()
        self.assertEqual(info['name'], 'MD5')
        self.assertEqual(info['output_length'], 128)
        self.assertFalse(info['recommended_for_new_systems'])
    
    def test_sha1_hash(self):
        """Test SHA-1 hash implementation."""
        sha1 = self.algorithms['sha1']
        
        # Test known values
        self.assertEqual(sha1.hash(''), 'da39a3ee5e6b4b0d3255bfef95601890afd80709')
        self.assertEqual(sha1.hash('password'), '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8')
        
        # Test verification
        self.assertTrue(sha1.verify('password', '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8'))
        self.assertFalse(sha1.verify('wrong', '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8'))
        
        # Test info
        info = sha1.get_info()
        self.assertEqual(info['name'], 'SHA-1')
        self.assertEqual(info['output_length'], 160)
        self.assertFalse(info['recommended_for_new_systems'])
    
    def test_sha256_hash(self):
        """Test SHA-256 hash implementation."""
        sha256 = self.algorithms['sha256']
        
        # Test known values
        self.assertEqual(sha256.hash(''), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
        self.assertEqual(sha256.hash('password'), 
                        '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8')
        
        # Test verification
        self.assertTrue(sha256.verify('password', 
                                     '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8'))
        self.assertFalse(sha256.verify('wrong', 
                                      '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8'))
        
        # Test info
        info = sha256.get_info()
        self.assertEqual(info['name'], 'SHA-256')
        self.assertEqual(info['output_length'], 256)
        self.assertTrue(info['recommended_for_new_systems'])
    
    def test_sha512_hash(self):
        """Test SHA-512 hash implementation."""
        sha512 = self.algorithms['sha512']
        
        # Test known values
        self.assertEqual(sha512.hash(''), 
                        'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce'
                        '47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e')
        
        # Test verification
        hash_value = sha512.hash('password')
        self.assertTrue(sha512.verify('password', hash_value))
        self.assertFalse(sha512.verify('wrong', hash_value))
        
        # Test info
        info = sha512.get_info()
        self.assertEqual(info['name'], 'SHA-512')
        self.assertEqual(info['output_length'], 512)
        self.assertTrue(info['recommended_for_new_systems'])
    
    def test_ntlm_hash(self):
        """Test NTLM hash implementation."""
        ntlm = self.algorithms['ntlm']
        
        # Test known values
        self.assertEqual(ntlm.hash(''), '31d6cfe0d16ae931b73c59d7e0c089c0')
        self.assertEqual(ntlm.hash('password'), '8846f7eaee8fb117ad06bdd830b7586f')
        
        # Test verification
        self.assertTrue(ntlm.verify('password', '8846f7eaee8fb117ad06bdd830b7586f'))
        self.assertFalse(ntlm.verify('wrong', '8846f7eaee8fb117ad06bdd830b7586f'))
        
        # Test info
        info = ntlm.get_info()
        self.assertEqual(info['name'], 'NTLM')
        self.assertEqual(info['base_algorithm'], 'MD4')
        self.assertFalse(info['recommended_for_new_systems'])
    
    def test_bcrypt_hash(self):
        """Test Bcrypt hash implementation."""
        bcrypt = self.algorithms['bcrypt']
        
        # Test that bcrypt is verification-only
        self.assertFalse(bcrypt.is_crackable())
        
        # Test hashing (generates new salt each time)
        hash1 = bcrypt.hash('password')
        hash2 = bcrypt.hash('password')
        self.assertNotEqual(hash1, hash2)  # Different salts
        self.assertTrue(hash1.startswith('$2b$'))
        
        # Test verification
        self.assertTrue(bcrypt.verify('password', hash1))
        self.assertFalse(bcrypt.verify('wrong', hash1))
        
        # Test invalid hash
        self.assertFalse(bcrypt.verify('password', 'invalid_hash'))
        
        # Test info
        info = bcrypt.get_info()
        self.assertEqual(info['name'], 'bcrypt')
        self.assertTrue(info['salted'])
        self.assertTrue(info['adaptive'])
        self.assertFalse(info['crackable'])
    
    def test_pbkdf2_hash(self):
        """Test PBKDF2 hash implementation."""
        pbkdf2 = self.algorithms['pbkdf2']
        
        # Test that PBKDF2 is verification-only
        self.assertFalse(pbkdf2.is_crackable())
        
        # Test hashing with custom parameters
        hash1 = pbkdf2.hash('password', salt='salt123', iterations=1000)
        hash2 = pbkdf2.hash('password', salt='different_salt', iterations=1000)
        self.assertNotEqual(hash1, hash2)
        self.assertTrue(hash1.startswith('pbkdf2:'))
        
        # Test verification
        self.assertTrue(pbkdf2.verify('password', hash1))
        self.assertFalse(pbkdf2.verify('wrong', hash1))
        
        # Test invalid hash
        self.assertFalse(pbkdf2.verify('password', 'invalid_hash'))
        
        # Test info
        info = pbkdf2.get_info()
        self.assertEqual(info['name'], 'PBKDF2')
        self.assertTrue(info['salted'])
        self.assertTrue(info['adaptive'])
        self.assertFalse(info['crackable'])
    
    def test_hash_consistency(self):
        """Test that all algorithms produce consistent results."""
        for password in self.test_passwords:
            for name, algorithm in self.algorithms.items():
                if algorithm.is_crackable():
                    # Test that hash and verify are consistent
                    hash_value = algorithm.hash(password)
                    self.assertTrue(algorithm.verify(password, hash_value),
                                  f"Verification failed for {name} with password '{password}'")
    
    def test_hash_info_structure(self):
        """Test that all algorithm info has required fields."""
        required_fields = ['name', 'output_length', 'security_status', 'recommended_for_new_systems']
        
        for name, algorithm in self.algorithms.items():
            info = algorithm.get_info()
            for field in required_fields:
                self.assertIn(field, info, f"Missing field '{field}' in {name} info")
    
    def test_hash_normalization(self):
        """Test hash normalization."""
        for name, algorithm in self.algorithms.items():
            if algorithm.is_crackable():
                hash_value = algorithm.hash('test')
                # Test with different cases and whitespace
                self.assertTrue(algorithm.verify('test', hash_value.upper()))
                self.assertTrue(algorithm.verify('test', f'  {hash_value}  '))
                self.assertTrue(algorithm.verify('test', hash_value.lower()))


if __name__ == '__main__':
    unittest.main()
