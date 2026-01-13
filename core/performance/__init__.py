"""
Performance Module

Contains performance optimization utilities, benchmarking tools,
and parallel processing enhancements for the Hash Audit Tool.
"""

from .optimizer import PerformanceOptimizer
from .benchmark import BenchmarkSuite
from .parallel import ParallelProcessor

__all__ = [
    'PerformanceOptimizer',
    'BenchmarkSuite',
    'ParallelProcessor'
]
