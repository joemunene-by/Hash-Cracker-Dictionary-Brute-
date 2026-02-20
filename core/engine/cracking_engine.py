"""
Main Cracking Engine

Coordinates attack strategies, manages multiprocessing, and provides
progress tracking and result reporting for hash cracking operations.
"""

import time
import itertools
import multiprocessing as mp
from typing import Optional, Dict, Any, List, Callable, Iterator
from ..hashes.base import HashAlgorithm
from ..attacks.base import AttackStrategy
from .scheduler import TaskScheduler
from .worker import WorkerProcess


class CrackingResult:
    """Container for cracking results."""
    
    def __init__(self, success: bool, password: Optional[str] = None, 
                 attempts: int = 0, elapsed_time: float = 0.0,
                 strategy: str = None, algorithm: str = None):
        self.success = success
        self.password = password
        self.attempts = attempts
        self.elapsed_time = elapsed_time
        self.strategy = strategy
        self.algorithm = algorithm
        self.hashes_per_second = attempts / elapsed_time if elapsed_time > 0 else 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary format."""
        return {
            'success': self.success,
            'password': self.password,
            'attempts': self.attempts,
            'elapsed_time': self.elapsed_time,
            'hashes_per_second': self.hashes_per_second,
            'strategy': self.strategy,
            'algorithm': self.algorithm
        }


class CrackingEngine:
    """Main engine for coordinating hash cracking operations."""
    
    def __init__(self, max_workers: int = None, progress_callback: Callable = None):
        self.max_workers = max_workers or mp.cpu_count()
        self.progress_callback = progress_callback
        self.scheduler = TaskScheduler()
        self._stop_event = mp.Event()
        self._result_queue = mp.Queue()
        self._stats_queue = mp.Queue()
    
    def crack_hash(self, target_hash: str, hash_algorithm: HashAlgorithm,
                   attack_strategy: AttackStrategy, timeout: Optional[float] = None) -> CrackingResult:
        """
        Attempt to crack a hash using the specified strategy.
        
        Args:
            target_hash: The hash to crack
            hash_algorithm: The hash algorithm implementation
            attack_strategy: The attack strategy to use
            timeout: Maximum time to attempt (None for no limit)
            
        Returns:
            CrackingResult with outcome details
        """
        start_time = time.time()
        
        # Validate inputs
        if not hash_algorithm.is_crackable():
            return CrackingResult(
                success=False,
                strategy=attack_strategy.name,
                algorithm=hash_algorithm.name,
                elapsed_time=0.0
            )
        
        # Set up the attack
        attack_strategy.set_target(target_hash)
        attack_strategy.reset_stats()
        
        # Create work chunks for multiprocessing
        work_chunks = self._create_work_chunks(attack_strategy)
        
        # Start worker processes
        workers = []
        for i in range(min(self.max_workers, len(work_chunks))):
            worker = WorkerProcess(
                worker_id=i,
                work_chunk=work_chunks[i],
                hash_algorithm=hash_algorithm,
                target_hash=target_hash,
                result_queue=self._result_queue,
                stats_queue=self._stats_queue,
                stop_event=self._stop_event
            )
            workers.append(worker)
            worker.start()
        
        # Monitor progress and collect results
        total_attempts = 0
        last_progress_time = start_time
        
        try:
            while any(worker.is_alive() for worker in workers):
                # Drain result queue using blocking get with timeout instead
                # of busy-wait polling – avoids wasting CPU cycles on sleep.
                try:
                    result = self._result_queue.get(timeout=0.05)
                    if result['found']:
                        # Password found!
                        self._stop_event.set()
                        elapsed_time = time.time() - start_time

                        # Wait for workers to finish
                        for worker in workers:
                            worker.join(timeout=1.0)

                        return CrackingResult(
                            success=True,
                            password=result['password'],
                            attempts=result['attempts'] + total_attempts,
                            elapsed_time=elapsed_time,
                            strategy=attack_strategy.name,
                            algorithm=hash_algorithm.name
                        )
                except Exception:
                    pass  # Queue empty – continue to stats / timeout checks

                # Drain all pending stats in one batch to reduce queue overhead
                while not self._stats_queue.empty():
                    try:
                        stats = self._stats_queue.get_nowait()
                        total_attempts += stats.get('attempts', 0)
                    except Exception:
                        break

                # Call progress callback if provided
                now = time.time()
                if self.progress_callback and now - last_progress_time > 0.5:
                    self.progress_callback({
                        'attempts': total_attempts,
                        'elapsed_time': now - start_time,
                        'workers_active': sum(1 for w in workers if w.is_alive())
                    })
                    last_progress_time = now

                # Check timeout
                if timeout and (time.time() - start_time) > timeout:
                    self._stop_event.set()
                    break
        
        except KeyboardInterrupt:
            self._stop_event.set()
            # Wait for workers to finish
            for worker in workers:
                worker.join(timeout=1.0)
        
        # No password found
        elapsed_time = time.time() - start_time
        return CrackingResult(
            success=False,
            attempts=total_attempts,
            elapsed_time=elapsed_time,
            strategy=attack_strategy.name,
            algorithm=hash_algorithm.name
        )
    
    def _create_work_chunks(self, attack_strategy: AttackStrategy,
                            chunk_size: int = 50000) -> List[List[str]]:
        """
        Create work chunks for distribution to worker processes.

        Uses streaming chunking to avoid materializing all candidates into
        memory at once. Candidates are read from the generator in fixed-size
        chunks and distributed round-robin across workers.

        Args:
            attack_strategy: The attack strategy to chunk
            chunk_size: Maximum candidates per chunk (default 50 000)

        Returns:
            List of work chunks (each chunk is a list of candidates)
        """
        chunks: List[List[str]] = [[] for _ in range(self.max_workers)]
        worker_idx = 0

        candidate_iter = attack_strategy.generate_candidates()
        while True:
            batch = list(itertools.islice(candidate_iter, chunk_size))
            if not batch:
                break
            chunks[worker_idx].extend(batch)
            worker_idx = (worker_idx + 1) % self.max_workers

        # Remove empty chunks (when fewer candidates than workers)
        chunks = [c for c in chunks if c]
        return chunks if chunks else [[]]
    
    def get_engine_info(self) -> Dict[str, Any]:
        """
        Get engine information and capabilities.
        
        Returns:
            Dictionary containing engine metadata
        """
        return {
            'max_workers': self.max_workers,
            'cpu_count': mp.cpu_count(),
            'multiprocessing_enabled': True,
            'progress_tracking': self.progress_callback is not None,
            'supported_features': [
                'multiprocessing',
                'progress_tracking',
                'timeout_support',
                'graceful_interruption'
            ]
        }
