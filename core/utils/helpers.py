"""
Helper Utilities

Provides general helper functions and system utilities
for the Hash Audit Tool.
"""

import os
import platform
import time
import multiprocessing
from typing import Dict, Any, List, Optional
from .formatters import format_bytes, format_time


def get_system_info() -> Dict[str, Any]:
    """
    Get comprehensive system information.
    
    Returns:
        Dictionary containing system information
    """
    info = {
        'platform': platform.platform(),
        'system': platform.system(),
        'release': platform.release(),
        'version': platform.version(),
        'machine': platform.machine(),
        'processor': platform.processor(),
        'python_version': platform.python_version(),
        'cpu_count': multiprocessing.cpu_count(),
        'memory_info': get_memory_info(),
        'disk_info': get_disk_info()
    }
    
    return info


def get_memory_info() -> Dict[str, Any]:
    """
    Get memory information.
    
    Returns:
        Dictionary containing memory information
    """
    try:
        import psutil
        
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        return {
            'total_bytes': memory.total,
            'total_formatted': format_bytes(memory.total),
            'available_bytes': memory.available,
            'available_formatted': format_bytes(memory.available),
            'used_bytes': memory.used,
            'used_formatted': format_bytes(memory.used),
            'usage_percent': memory.percent,
            'swap_total_bytes': swap.total,
            'swap_total_formatted': format_bytes(swap.total),
            'swap_used_bytes': swap.used,
            'swap_used_formatted': format_bytes(swap.used),
            'swap_percent': swap.percent
        }
        
    except ImportError:
        return {
            'error': 'psutil not available for memory information',
            'note': 'Install psutil for detailed memory monitoring'
        }


def get_disk_info(path: str = '.') -> Dict[str, Any]:
    """
    Get disk information for a specific path.
    
    Args:
        path: Path to check disk usage for
        
    Returns:
        Dictionary containing disk information
    """
    try:
        import psutil
        
        disk = psutil.disk_usage(path)
        
        return {
            'total_bytes': disk.total,
            'total_formatted': format_bytes(disk.total),
            'used_bytes': disk.used,
            'used_formatted': format_bytes(disk.used),
            'free_bytes': disk.free,
            'free_formatted': format_bytes(disk.free),
            'usage_percent': (disk.used / disk.total) * 100
        }
        
    except ImportError:
        return {
            'error': 'psutil not available for disk information',
            'note': 'Install psutil for detailed disk monitoring'
        }


def benchmark_performance(hash_algorithm, test_passwords: List[str] = None) -> Dict[str, Any]:
    """
    Benchmark hash algorithm performance.
    
    Args:
        hash_algorithm: Hash algorithm instance to benchmark
        test_passwords: List of test passwords (default: common passwords)
        
    Returns:
        Dictionary containing benchmark results
    """
    if test_passwords is None:
        test_passwords = [
            'password', '123456', 'qwerty', 'admin', 'letmein',
            'welcome', 'monkey', 'dragon', 'master', 'sunshine'
        ]
    
    # Warm up
    for password in test_passwords[:3]:
        hash_algorithm.hash(password)
    
    # Benchmark
    iterations = 10000
    start_time = time.time()
    
    for _ in range(iterations):
        for password in test_passwords:
            hash_algorithm.hash(password)
    
    end_time = time.time()
    total_time = end_time - start_time
    
    total_hashes = iterations * len(test_passwords)
    hashes_per_second = total_hashes / total_time
    
    return {
        'algorithm': hash_algorithm.name,
        'iterations': iterations,
        'passwords_tested': len(test_passwords),
        'total_hashes': total_hashes,
        'total_time': total_time,
        'hashes_per_second': hashes_per_second,
        'time_per_hash': total_time / total_hashes,
        'performance_rating': get_performance_rating(hashes_per_second)
    }


def get_performance_rating(hashes_per_second: float) -> str:
    """
    Get performance rating based on hash rate.
    
    Args:
        hashes_per_second: Hash rate per second
        
    Returns:
        Performance rating string
    """
    if hashes_per_second > 1000000:
        return "Excellent"
    elif hashes_per_second > 500000:
        return "Very Good"
    elif hashes_per_second > 100000:
        return "Good"
    elif hashes_per_second > 50000:
        return "Fair"
    else:
        return "Poor"


def estimate_crack_time(combinations: int, hashes_per_second: float) -> Dict[str, Any]:
    """
    Estimate time to crack based on combinations and hash rate.
    
    Args:
        combinations: Number of possible combinations
        hashes_per_second: Hashing performance
        
    Returns:
        Dictionary containing time estimates
    """
    if hashes_per_second == 0:
        return {'error': 'Hash rate cannot be zero'}
    
    seconds = combinations / hashes_per_second
    
    return {
        'combinations': combinations,
        'hashes_per_second': hashes_per_second,
        'seconds': seconds,
        'minutes': seconds / 60,
        'hours': seconds / 3600,
        'days': seconds / 86400,
        'weeks': seconds / 604800,
        'months': seconds / 2592000,
        'years': seconds / 31536000,
        'human_readable': format_time(seconds),
        'feasibility': get_feasibility_rating(seconds)
    }


def get_feasibility_rating(seconds: float) -> str:
    """
    Get feasibility rating based on time estimate.
    
    Args:
        seconds: Time in seconds
        
    Returns:
        Feasibility rating string
    """
    if seconds < 60:
        return "Immediate"
    elif seconds < 3600:
        return "Very Quick"
    elif seconds < 86400:
        return "Quick"
    elif seconds < 604800:
        return "Moderate"
    elif seconds < 2592000:
        return "Slow"
    elif seconds < 31536000:
        return "Very Slow"
    else:
        return "Impractical"


def create_progress_bar(current: int, total: int, width: int = 50) -> str:
    """
    Create a text progress bar.
    
    Args:
        current: Current progress
        total: Total items
        width: Progress bar width in characters
        
    Returns:
        Progress bar string
    """
    if total == 0:
        return "[" + "=" * width + "] 100.0%"
    
    percentage = current / total
    filled_width = int(width * percentage)
    
    bar = "[" + "=" * filled_width + "-" * (width - filled_width) + "]"
    percentage_str = f" {percentage * 100:.1f}%"
    
    return bar + percentage_str


def safe_filename(filename: str) -> str:
    """
    Create a safe filename by removing/replacing invalid characters.
    
    Args:
        filename: Original filename
        
    Returns:
        Safe filename
    """
    # Remove or replace invalid characters
    invalid_chars = '<>:"/\\|?*'
    safe_name = filename
    
    for char in invalid_chars:
        safe_name = safe_name.replace(char, '_')
    
    # Remove leading/trailing spaces and dots
    safe_name = safe_name.strip(' .')
    
    # Ensure it's not empty
    if not safe_name:
        safe_name = "unnamed"
    
    # Limit length
    if len(safe_name) > 255:
        safe_name = safe_name[:255]
    
    return safe_name


def detect_file_encoding(file_path: str, sample_size: int = 10000) -> str:
    """
    Detect file encoding.
    
    Args:
        file_path: Path to file
        sample_size: Number of bytes to sample for detection
        
    Returns:
        Detected encoding string
    """
    try:
        import chardet
        
        with open(file_path, 'rb') as f:
            raw_data = f.read(sample_size)
            result = chardet.detect(raw_data)
            return result.get('encoding', 'utf-8')
            
    except ImportError:
        return 'utf-8'  # Default if chardet not available
    except Exception:
        return 'unknown'


def get_optimal_chunk_size(total_items: int, num_workers: int) -> int:
    """
    Calculate optimal chunk size for parallel processing.
    
    Args:
        total_items: Total number of items to process
        num_workers: Number of worker processes
        
    Returns:
        Optimal chunk size
    """
    if num_workers <= 0:
        return total_items
    
    # Base chunk size
    base_chunk = max(1, total_items // num_workers)
    
    # Adjust for very small or large workloads
    if total_items < num_workers * 10:
        return max(1, total_items // (num_workers * 2))
    elif base_chunk > 10000:
        return 10000
    
    return base_chunk
