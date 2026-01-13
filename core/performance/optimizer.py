"""
Performance Optimizer

Optimizes hash cracking performance through various techniques
including algorithm selection, memory management, and processing strategies.
"""

import multiprocessing as mp
import time
from typing import Dict, Any, List, Optional, Tuple
from ..hashes.base import HashAlgorithm
from ..utils.helpers import get_system_info, benchmark_performance


class PerformanceOptimizer:
    """Optimizes performance for hash cracking operations."""
    
    def __init__(self):
        self.system_info = get_system_info()
        self.algorithm_benchmarks: Dict[str, Dict[str, Any]] = {}
        self.optimization_history: List[Dict[str, Any]] = []
    
    def optimize_worker_count(self, algorithm: HashAlgorithm, 
                            workload_size: int) -> Dict[str, Any]:
        """
        Optimize the number of worker processes for a given workload.
        
        Args:
            algorithm: Hash algorithm being used
            workload_size: Size of the workload (number of candidates)
            
        Returns:
            Dictionary with optimization recommendations
        """
        cpu_count = self.system_info['cpu_count']
        memory_info = self.system_info.get('memory_info', {})
        
        # Base recommendations
        recommendations = {
            'optimal_workers': cpu_count,
            'max_workers': cpu_count * 2,
            'min_workers': 1,
            'reasoning': [],
            'memory_considerations': []
        }
        
        # Adjust based on workload size
        if workload_size < 1000:
            recommendations['optimal_workers'] = min(2, cpu_count)
            recommendations['reasoning'].append('Small workload - fewer workers to reduce overhead')
        elif workload_size < 10000:
            recommendations['optimal_workers'] = min(4, cpu_count)
            recommendations['reasoning'].append('Medium workload - moderate worker count')
        else:
            recommendations['optimal_workers'] = cpu_count
            recommendations['reasoning'].append('Large workload - maximize parallelism')
        
        # Adjust based on algorithm characteristics
        if algorithm.name in ['bcrypt', 'pbkdf2']:
            # These are slow algorithms, so more workers may not help
            recommendations['optimal_workers'] = min(4, recommendations['optimal_workers'])
            recommendations['reasoning'].append('Slow algorithm - limit workers to avoid contention')
        
        # Memory considerations
        if 'available_bytes' in memory_info:
            available_mb = memory_info['available_bytes'] / (1024 * 1024)
            
            if available_mb < 1024:  # Less than 1GB available
                recommendations['optimal_workers'] = min(2, recommendations['optimal_workers'])
                recommendations['memory_considerations'].append('Low memory - reduce worker count')
            elif available_mb < 4096:  # Less than 4GB available
                recommendations['optimal_workers'] = min(cpu_count // 2, recommendations['optimal_workers'])
                recommendations['memory_considerations'].append('Moderate memory - moderate worker count')
        
        # CPU-specific optimizations
        if self.system_info['system'] == 'Windows':
            # Windows may have different optimal worker counts
            recommendations['optimal_workers'] = min(recommendations['optimal_workers'], cpu_count - 1)
            recommendations['reasoning'].append('Windows optimization - reserve one core')
        
        return recommendations
    
    def optimize_chunk_size(self, total_items: int, worker_count: int,
                           algorithm: HashAlgorithm) -> Dict[str, Any]:
        """
        Optimize chunk size for work distribution.
        
        Args:
            total_items: Total number of items to process
            worker_count: Number of worker processes
            algorithm: Hash algorithm being used
            
        Returns:
            Dictionary with chunk size recommendations
        """
        base_chunk_size = max(1, total_items // worker_count)
        
        recommendations = {
            'base_chunk_size': base_chunk_size,
            'optimized_chunk_size': base_chunk_size,
            'reasoning': []
        }
        
        # Algorithm-specific adjustments
        if algorithm.name in ['bcrypt', 'pbkdf2']:
            # Slow algorithms benefit from smaller chunks
            recommendations['optimized_chunk_size'] = min(1000, base_chunk_size)
            recommendations['reasoning'].append('Slow algorithm - use smaller chunks for better distribution')
        elif algorithm.name in ['md5', 'sha1']:
            # Fast algorithms benefit from larger chunks
            recommendations['optimized_chunk_size'] = max(10000, base_chunk_size)
            recommendations['reasoning'].append('Fast algorithm - use larger chunks to reduce overhead')
        
        # Workload size adjustments
        if total_items < worker_count * 100:
            recommendations['optimized_chunk_size'] = max(10, total_items // (worker_count * 2))
            recommendations['reasoning'].append('Small workload - use smaller chunks for better distribution')
        elif total_items > 1000000:
            recommendations['optimized_chunk_size'] = min(50000, recommendations['optimized_chunk_size'])
            recommendations['reasoning'].append('Large workload - limit chunk size to prevent memory issues')
        
        # Memory considerations
        memory_info = self.system_info.get('memory_info', {})
        if 'available_bytes' in memory_info:
            available_mb = memory_info['available_bytes'] / (1024 * 1024)
            
            # Estimate memory per chunk (rough approximation)
            estimated_memory_per_chunk = recommendations['optimized_chunk_size'] * 100  # 100 bytes per candidate
            
            if estimated_memory_per_chunk > available_mb * 0.1:  # Don't use more than 10% of available memory
                recommendations['optimized_chunk_size'] = int((available_mb * 0.1 * 1024 * 1024) / 100)
                recommendations['reasoning'].append('Memory constraint - reduce chunk size')
        
        return recommendations
    
    def benchmark_algorithms(self, test_passwords: List[str] = None) -> Dict[str, Any]:
        """
        Benchmark all available hash algorithms.
        
        Args:
            test_passwords: List of test passwords
            
        Returns:
            Dictionary with benchmark results
        """
        if test_passwords is None:
            test_passwords = ['password', '123456', 'admin', 'test', 'qwerty']
        
        from ..hashes import MD5Hash, SHA1Hash, SHA256Hash, SHA512Hash, NTLMHash, BcryptHash, PBKDF2Hash
        
        algorithms = [
            MD5Hash(), SHA1Hash(), SHA256Hash(), SHA512Hash(), NTLMHash(),
            BcryptHash(), PBKDF2Hash()
        ]
        
        results = {}
        
        for algorithm in algorithms:
            try:
                benchmark = benchmark_performance(algorithm, test_passwords)
                results[algorithm.name] = benchmark
                self.algorithm_benchmarks[algorithm.name] = benchmark
            except Exception as e:
                results[algorithm.name] = {'error': str(e)}
        
        # Sort by performance
        sorted_results = sorted(
            results.items(),
            key=lambda x: x[1].get('hashes_per_second', 0),
            reverse=True
        )
        
        return {
            'benchmarks': dict(sorted_results),
            'fastest_algorithm': sorted_results[0][0] if sorted_results else None,
            'slowest_algorithm': sorted_results[-1][0] if sorted_results else None,
            'performance_ratio': (
                sorted_results[0][1].get('hashes_per_second', 0) / 
                sorted_results[-1][1].get('hashes_per_second', 1)
            ) if len(sorted_results) > 1 else 1
        }
    
    def get_optimization_recommendations(self, algorithm: HashAlgorithm,
                                        workload_size: int) -> Dict[str, Any]:
        """
        Get comprehensive optimization recommendations.
        
        Args:
            algorithm: Hash algorithm being used
            workload_size: Size of the workload
            
        Returns:
            Dictionary with optimization recommendations
        """
        recommendations = {
            'algorithm': algorithm.name,
            'workload_size': workload_size,
            'system_info': self.system_info,
            'worker_optimization': self.optimize_worker_count(algorithm, workload_size),
            'chunk_optimization': self.optimize_chunk_size(workload_size, 
                                                         self.system_info['cpu_count'], 
                                                         algorithm),
            'general_recommendations': []
        }
        
        # Add general recommendations
        if algorithm.name in ['bcrypt', 'pbkdf2']:
            recommendations['general_recommendations'].append(
                'Consider using GPU acceleration for slow algorithms'
            )
        
        if workload_size > 10000000:
            recommendations['general_recommendations'].append(
                'Large workload detected - consider using resume functionality'
            )
        
        if self.system_info.get('memory_info', {}).get('usage_percent', 0) > 80:
            recommendations['general_recommendations'].append(
                'High memory usage detected - consider closing other applications'
            )
        
        # Store optimization in history
        self.optimization_history.append({
            'timestamp': time.time(),
            'algorithm': algorithm.name,
            'workload_size': workload_size,
            'recommendations': recommendations
        })
        
        return recommendations
    
    def analyze_performance_bottlenecks(self, recent_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze recent performance results to identify bottlenecks.
        
        Args:
            recent_results: List of recent cracking results
            
        Returns:
            Dictionary with bottleneck analysis
        """
        if not recent_results:
            return {'error': 'No performance data available'}
        
        analysis = {
            'total_operations': len(recent_results),
            'average_hashes_per_second': 0,
            'performance_trend': 'stable',
            'bottlenecks': [],
            'recommendations': []
        }
        
        # Calculate average performance
        total_hashes = sum(result.get('hashes_per_second', 0) for result in recent_results)
        analysis['average_hashes_per_second'] = total_hashes / len(recent_results)
        
        # Analyze performance trend
        if len(recent_results) >= 3:
            recent_hps = [result.get('hashes_per_second', 0) for result in recent_results[-3:]]
            if recent_hps[-1] < recent_hps[0] * 0.8:
                analysis['performance_trend'] = 'declining'
            elif recent_hps[-1] > recent_hps[0] * 1.2:
                analysis['performance_trend'] = 'improving'
        
        # Identify potential bottlenecks
        avg_hps = analysis['average_hashes_per_second']
        
        if avg_hps < 10000:
            analysis['bottlenecks'].append('Low hash rate - possible CPU bottleneck')
            analysis['recommendations'].append('Consider reducing worker count or using faster algorithms')
        
        if avg_hps > 1000000 and self.system_info['cpu_count'] < 8:
            analysis['bottlenecks'].append('High hash rate with few cores - possible memory bottleneck')
            analysis['recommendations'].append('Consider monitoring memory usage')
        
        # Check for algorithm-specific issues
        algorithm_performance = {}
        for result in recent_results:
            algo = result.get('algorithm', 'unknown')
            if algo not in algorithm_performance:
                algorithm_performance[algo] = []
            algorithm_performance[algo].append(result.get('hashes_per_second', 0))
        
        for algo, hps_list in algorithm_performance.items():
            avg_algo_hps = sum(hps_list) / len(hps_list)
            if avg_algo_hps < 1000 and algo in ['md5', 'sha1']:
                analysis['bottlenecks'].append(f'Poor performance for {algo.upper()} - possible implementation issue')
        
        return analysis
    
    def get_performance_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive performance report.
        
        Returns:
            Dictionary containing performance report
        """
        return {
            'system_info': self.system_info,
            'algorithm_benchmarks': self.algorithm_benchmarks,
            'optimization_history': self.optimization_history[-10:],  # Last 10 optimizations
            'performance_summary': {
                'total_optimizations': len(self.optimization_history),
                'algorithms_tested': len(self.algorithm_benchmarks),
                'system_score': self._calculate_system_score()
            }
        }
    
    def _calculate_system_score(self) -> float:
        """Calculate overall system performance score."""
        score = 0.0
        
        # CPU score
        cpu_count = self.system_info['cpu_count']
        score += min(cpu_count * 10, 80)  # Max 80 points for CPU
        
        # Memory score
        memory_info = self.system_info.get('memory_info', {})
        if 'total_bytes' in memory_info:
            total_gb = memory_info['total_bytes'] / (1024**3)
            score += min(total_gb * 5, 20)  # Max 20 points for memory
        
        return min(score, 100)
