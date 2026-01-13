"""
Test Utility Functions

Unit tests for utility functions including formatters,
validators, and helpers.
"""

import unittest
import tempfile
import os
import sys

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.utils.formatters import format_bytes, format_time, format_number, format_rate
from core.utils.validators import validate_hash_format, validate_file_path, validate_mask_pattern
from core.utils.helpers import get_system_info, create_progress_bar, safe_filename


class TestFormatters(unittest.TestCase):
    """Test cases for formatting utilities."""
    
    def test_format_bytes(self):
        """Test byte formatting."""
        self.assertEqual(format_bytes(0), "0 B")
        self.assertEqual(format_bytes(1024), "1.0 KB")
        self.assertEqual(format_bytes(1048576), "1.0 MB")
        self.assertEqual(format_bytes(1073741824), "1.0 GB")
        self.assertEqual(format_bytes(500), "500 B")
        self.assertEqual(format_bytes(1536), "1.5 KB")
    
    def test_format_time(self):
        """Test time formatting."""
        self.assertEqual(format_time(0.5), "500ms")
        self.assertEqual(format_time(30), "30.0s")
        self.assertEqual(format_time(90), "1m 30s")
        self.assertEqual(format_time(3700), "1h 1m 40s")
        self.assertEqual(format_time(90000), "1d 1h")
    
    def test_format_number(self):
        """Test number formatting."""
        self.assertEqual(format_number(1000), "1,000")
        self.assertEqual(format_number(1000000), "1,000,000")
        self.assertEqual(format_number(1234.56), "1,234.56")
        self.assertEqual(format_number(0), "0")
    
    def test_format_rate(self):
        """Test rate formatting."""
        self.assertEqual(format_rate(500), "500 H/s")
        self.assertEqual(format_rate(1500), "1.5 K H/s")
        self.assertEqual(format_rate(1500000), "1.5 M H/s")
        self.assertEqual(format_rate(1500000000), "1.5 G H/s")


class TestValidators(unittest.TestCase):
    """Test cases for validation utilities."""
    
    def test_validate_hash_format(self):
        """Test hash format validation."""
        # Valid MD5
        result = validate_hash_format("5f4dcc3b5aa765d61d8327deb882cf99", "md5")
        self.assertTrue(result['is_valid'])
        self.assertEqual(len(result['errors']), 0)
        
        # Invalid MD5 (wrong length)
        result = validate_hash_format("5f4dcc3b5aa765d61d8327deb882cf9", "md5")
        self.assertFalse(result['is_valid'])
        self.assertGreater(len(result['errors']), 0)
        
        # Valid SHA256
        result = validate_hash_format(
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", 
            "sha256"
        )
        self.assertTrue(result['is_valid'])
        
        # Test normalization
        result = validate_hash_format(" 5F4DCC3B5AA765D61D8327DEB882CF99 ", "md5")
        self.assertTrue(result['is_valid'])
        self.assertEqual(result['normalized_hash'], "5f4dcc3b5aa765d61d8327deb882cf99")
        self.assertGreater(len(result['warnings']), 0)
    
    def test_validate_file_path(self):
        """Test file path validation."""
        # Create temporary file
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        temp_file.write(b"test content")
        temp_file.close()
        
        try:
            # Valid file
            result = validate_file_path(temp_file.name)
            self.assertTrue(result['is_valid'])
            self.assertIn('file_info', result)
            self.assertGreater(result['file_info']['size_bytes'], 0)
            
            # Non-existent file
            result = validate_file_path("nonexistent_file.txt")
            self.assertFalse(result['is_valid'])
            self.assertGreater(len(result['errors']), 0)
            
            # Empty path
            result = validate_file_path("")
            self.assertFalse(result['is_valid'])
            self.assertGreater(len(result['errors']), 0)
        
        finally:
            os.unlink(temp_file.name)
    
    def test_validate_mask_pattern(self):
        """Test mask pattern validation."""
        # Valid masks
        valid_masks = ['?l?l?l', '?u?d?d', '?s?l?u', '?a?a?a']
        
        for mask in valid_masks:
            result = validate_mask_pattern(mask)
            self.assertTrue(result['is_valid'], f"Mask {mask} should be valid")
            self.assertIn('mask_info', result)
            self.assertGreater(result['mask_info']['length'], 0)
        
        # Invalid masks
        invalid_masks = ['', '?x', '?', 'l?l?']
        
        for mask in invalid_masks:
            result = validate_mask_pattern(mask)
            self.assertFalse(result['is_valid'], f"Mask {mask} should be invalid")
            self.assertGreater(len(result['errors']), 0)
        
        # Test complexity estimation
        result = validate_mask_pattern('?l?l?l?l')
        self.assertEqual(result['mask_info']['estimated_combinations'], 26**4)
        self.assertEqual(result['mask_info']['complexity'], 'medium')


class TestHelpers(unittest.TestCase):
    """Test cases for helper utilities."""
    
    def test_get_system_info(self):
        """Test system information gathering."""
        info = get_system_info()
        
        # Check required fields
        required_fields = ['platform', 'system', 'cpu_count', 'python_version']
        for field in required_fields:
            self.assertIn(field, info)
        
        # Check data types
        self.assertIsInstance(info['cpu_count'], int)
        self.assertGreater(info['cpu_count'], 0)
        self.assertIsInstance(info['python_version'], str)
    
    def test_create_progress_bar(self):
        """Test progress bar creation."""
        # Test various progress levels
        bar = create_progress_bar(0, 100)
        self.assertIn('[', bar)
        self.assertIn(']', bar)
        self.assertIn('0.0%', bar)
        
        bar = create_progress_bar(50, 100)
        self.assertIn('50.0%', bar)
        
        bar = create_progress_bar(100, 100)
        self.assertIn('100.0%', bar)
        
        # Test different widths
        bar = create_progress_bar(25, 100, width=20)
        self.assertEqual(len(bar.split(']')[0]) + 1, 21)  # 20 chars + ]
    
    def test_safe_filename(self):
        """Test safe filename generation."""
        # Test invalid characters
        unsafe = "file<>name|with*invalid?chars"
        safe = safe_filename(unsafe)
        self.assertNotIn('<', safe)
        self.assertNotIn('>', safe)
        self.assertNotIn('|', safe)
        self.assertNotIn('*', safe)
        self.assertNotIn('?', safe)
        
        # Test empty filename
        safe = safe_filename("")
        self.assertEqual(safe, "unnamed")
        
        # Test long filename
        long_name = "a" * 300
        safe = safe_filename(long_name)
        self.assertLessEqual(len(safe), 255)
        
        # Test whitespace and dots
        safe = safe_filename("  .test.file.  ")
        self.assertEqual(safe, "test.file")


class TestIntegration(unittest.TestCase):
    """Integration tests for utility functions."""
    
    def test_validation_integration(self):
        """Test integration between validation functions."""
        # Test hash validation with different formats
        valid_hashes = {
            'md5': '5f4dcc3b5aa765d61d8327deb882cf99',
            'sha1': '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8',
            'sha256': '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8'
        }
        
        for algorithm, hash_value in valid_hashes.items():
            result = validate_hash_format(hash_value, algorithm)
            self.assertTrue(result['is_valid'], f"Hash should be valid for {algorithm}")
    
    def test_formatter_integration(self):
        """Test integration between formatting functions."""
        # Test formatting consistent data
        bytes_value = 1048576  # 1MB
        time_value = 3661     # 1h 1m 1s
        number_value = 1500000
        
        # All should return strings
        self.assertIsInstance(format_bytes(bytes_value), str)
        self.assertIsInstance(format_time(time_value), str)
        self.assertIsInstance(format_number(number_value), str)
        self.assertIsInstance(format_rate(number_value), str)


if __name__ == '__main__':
    unittest.main()
