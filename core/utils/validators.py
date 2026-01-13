"""
Validation Utilities

Provides functions for validating various inputs and formats
throughout the Hash Audit Tool.
"""

import re
import os
from typing import Optional, Dict, Any


def validate_hash_format(hash_value: str, algorithm: str) -> Dict[str, Any]:
    """
    Validate hash format against expected patterns.
    
    Args:
        hash_value: Hash string to validate
        algorithm: Hash algorithm type
        
    Returns:
        Dictionary with validation results
    """
    result = {
        'is_valid': True,
        'errors': [],
        'warnings': [],
        'normalized_hash': hash_value.strip().lower()
    }
    
    # Remove whitespace and normalize
    normalized = hash_value.strip().lower()
    
    # Algorithm-specific validation
    patterns = {
        'md5': r'^[a-f0-9]{32}$',
        'sha1': r'^[a-f0-9]{40}$',
        'sha256': r'^[a-f0-9]{64}$',
        'sha512': r'^[a-f0-9]{128}$',
        'ntlm': r'^[a-f0-9]{32}$',
        'bcrypt': r'^\$2[aby]\$\d+\$[./A-Za-z0-9]{53}$',
        'pbkdf2': r'^pbkdf2:[a-z0-9]+:\d+:[a-f0-9]+:[a-f0-9]+$'
    }
    
    if algorithm in patterns:
        if not re.match(patterns[algorithm], normalized):
            result['is_valid'] = False
            result['errors'].append(f"Invalid {algorithm.upper()} hash format")
    else:
        result['warnings'].append(f"No validation pattern for algorithm: {algorithm}")
    
    # General checks
    if not hash_value.strip():
        result['is_valid'] = False
        result['errors'].append("Hash cannot be empty")
    
    if len(normalized) != len(hash_value.strip()):
        result['warnings'].append("Hash contained whitespace or uppercase characters")
    
    return result


def validate_file_path(file_path: str, file_type: str = "file") -> Dict[str, Any]:
    """
    Validate file path and accessibility.
    
    Args:
        file_path: Path to validate
        file_type: Type of file (for error messages)
        
    Returns:
        Dictionary with validation results
    """
    result = {
        'is_valid': True,
        'errors': [],
        'warnings': [],
        'file_info': {}
    }
    
    if not file_path:
        result['is_valid'] = False
        result['errors'].append(f"{file_type} path cannot be empty")
        return result
    
    # Check if path exists
    if not os.path.exists(file_path):
        result['is_valid'] = False
        result['errors'].append(f"{file_type} not found: {file_path}")
        return result
    
    # Check if it's a file
    if not os.path.isfile(file_path):
        result['is_valid'] = False
        result['errors'].append(f"Path is not a file: {file_path}")
        return result
    
    # Check readability
    if not os.access(file_path, os.R_OK):
        result['is_valid'] = False
        result['errors'].append(f"{file_type} is not readable: {file_path}")
        return result
    
    # Get file info
    try:
        stat = os.stat(file_path)
        result['file_info'] = {
            'size_bytes': stat.st_size,
            'size_mb': stat.st_size / (1024 * 1024),
            'modified_time': stat.st_mtime,
            'is_empty': stat.st_size == 0
        }
        
        # Warnings for large files
        if stat.st_size > 100 * 1024 * 1024:  # 100MB
            result['warnings'].append(f"Large {file_type} detected ({stat.st_size / (1024*1024):.1f} MB)")
        
        # Warning for empty files
        if stat.st_size == 0:
            result['warnings'].append(f"{file_type} is empty")
    
    except OSError as e:
        result['warnings'].append(f"Could not get file info: {e}")
    
    return result


def validate_mask_pattern(mask: str) -> Dict[str, Any]:
    """
    Validate mask pattern syntax.
    
    Args:
        mask: Mask pattern to validate
        
    Returns:
        Dictionary with validation results
    """
    result = {
        'is_valid': True,
        'errors': [],
        'warnings': [],
        'mask_info': {}
    }
    
    if not mask:
        result['is_valid'] = False
        result['errors'].append("Mask pattern cannot be empty")
        return result
    
    # Valid placeholders
    valid_placeholders = ['?l', '?u', '?d', '?s', '?a', '?b', '?h', '?H', '?p', '?c']
    
    i = 0
    length = 0
    placeholders_used = set()
    
    while i < len(mask):
        if mask[i] == '?':
            if i + 1 >= len(mask):
                result['is_valid'] = False
                result['errors'].append(f"Incomplete placeholder at position {i}")
                break
            
            placeholder = mask[i:i+2]
            if placeholder not in valid_placeholders:
                result['is_valid'] = False
                result['errors'].append(f"Invalid placeholder '{placeholder}' at position {i}")
            else:
                placeholders_used.add(placeholder)
                length += 1
            
            i += 2
        else:
            # Literal character
            length += 1
            i += 1
    
    # Calculate combinations (rough estimate)
    char_set_sizes = {
        '?l': 26, '?u': 26, '?d': 10, '?s': 32,
        '?a': 95, '?b': 2, '?h': 16, '?H': 16, '?p': 96, '?c': 1
    }
    
    total_combinations = 1
    for placeholder in placeholders_used:
        total_combinations *= char_set_sizes.get(placeholder, 1)
    
    result['mask_info'] = {
        'length': length,
        'placeholders_used': list(placeholders_used),
        'estimated_combinations': total_combinations,
        'complexity': 'high' if total_combinations > 10**10 else 'medium' if total_combinations > 10**6 else 'low'
    }
    
    # Warnings
    if total_combinations > 10**12:
        result['warnings'].append("Very large search space may take excessive time")
    
    if length < 4:
        result['warnings'].append("Very short mask may have limited effectiveness")
    
    return result


def validate_attack_parameters(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate attack parameters comprehensively.
    
    Args:
        params: Dictionary of attack parameters
        
    Returns:
        Dictionary with validation results
    """
    result = {
        'is_valid': True,
        'errors': [],
        'warnings': [],
        'recommendations': []
    }
    
    # Validate algorithm
    if 'algorithm' not in params:
        result['is_valid'] = False
        result['errors'].append("Algorithm not specified")
    elif params['algorithm'] not in ['md5', 'sha1', 'sha256', 'sha512', 'ntlm', 'bcrypt', 'pbkdf2']:
        result['is_valid'] = False
        result['errors'].append(f"Unsupported algorithm: {params['algorithm']}")
    
    # Validate attack mode
    if 'mode' not in params:
        result['is_valid'] = False
        result['errors'].append("Attack mode not specified")
    elif params['mode'] not in ['dictionary', 'brute', 'hybrid']:
        result['is_valid'] = False
        result['errors'].append(f"Unsupported attack mode: {params['mode']}")
    
    # Mode-specific validation
    if params.get('mode') == 'dictionary':
        if 'wordlist' not in params or not params['wordlist']:
            result['is_valid'] = False
            result['errors'].append("Dictionary attack requires wordlist file")
        else:
            wordlist_validation = validate_file_path(params['wordlist'], "wordlist")
            result['errors'].extend(wordlist_validation['errors'])
            result['warnings'].extend(wordlist_validation['warnings'])
    
    elif params.get('mode') == 'brute':
        if 'mask' not in params or not params['mask']:
            result['is_valid'] = False
            result['errors'].append("Brute-force attack requires mask pattern")
        else:
            mask_validation = validate_mask_pattern(params['mask'])
            result['errors'].extend(mask_validation['errors'])
            result['warnings'].extend(mask_validation['warnings'])
    
    elif params.get('mode') == 'hybrid':
        if 'wordlist' not in params or not params['wordlist']:
            result['is_valid'] = False
            result['errors'].append("Hybrid attack requires wordlist file")
        
        if 'mask' in params and params['mask']:
            mask_validation = validate_mask_pattern(params['mask'])
            result['warnings'].extend(mask_validation['warnings'])
    
    # Performance validation
    if 'workers' in params and params['workers']:
        if params['workers'] <= 0:
            result['is_valid'] = False
            result['errors'].append("Number of workers must be positive")
        elif params['workers'] > 64:
            result['warnings'].append("High number of workers may degrade performance")
    
    if 'timeout' in params and params['timeout']:
        if params['timeout'] <= 0:
            result['is_valid'] = False
            result['errors'].append("Timeout must be positive")
        elif params['timeout'] < 60:
            result['warnings'].append("Very short timeout may be insufficient")
    
    # Recommendations
    if result['is_valid'] and not result['warnings']:
        result['recommendations'].append("Parameters look good for efficient cracking")
    
    return result
