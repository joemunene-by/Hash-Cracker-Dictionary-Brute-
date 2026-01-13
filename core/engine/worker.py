"""
Worker Process Implementation

Implements the worker process that performs the actual hash cracking
in parallel across multiple CPU cores.
"""

import multiprocessing as mp
import time
from typing import List, Dict, Any, Optional
from ..hashes.base import HashAlgorithm


class WorkerProcess(mp.Process):
    """Worker process for parallel hash cracking."""
    
    def __init__(self, worker_id: int, work_chunk: List[str],
                 hash_algorithm: HashAlgorithm, target_hash: str,
                 result_queue: mp.Queue, stats_queue: mp.Queue,
                 stop_event: mp.Event):
        super().__init__()
        self.worker_id = worker_id
        self.work_chunk = work_chunk
        self.hash_algorithm = hash_algorithm
        self.target_hash = target_hash
        self.result_queue = result_queue
        self.stats_queue = stats_queue
        self.stop_event = stop_event
        self.attempts = 0
        self.start_time = None
    
    def run(self):
        """Main worker process execution."""
        self.start_time = time.time()
        normalized_target = self.hash_algorithm.normalize_hash(self.target_hash)
        
        try:
            for candidate in self.work_chunk:
                # Check if we should stop
                if self.stop_event.is_set():
                    break
                
                # Verify candidate
                if self.hash_algorithm.verify(candidate, normalized_target):
                    # Found the password!
                    self.result_queue.put({
                        'found': True,
                        'password': candidate,
                        'worker_id': self.worker_id,
                        'attempts': self.attempts
                    })
                    return
                
                self.attempts += 1
                
                # Report progress periodically
                if self.attempts % 1000 == 0:
                    self.stats_queue.put({
                        'worker_id': self.worker_id,
                        'attempts': 1000,
                        'elapsed_time': time.time() - self.start_time
                    })
            
            # Password not found in this chunk
            self.result_queue.put({
                'found': False,
                'worker_id': self.worker_id,
                'attempts': self.attempts
            })
            
        except Exception as e:
            # Report error
            self.result_queue.put({
                'found': False,
                'worker_id': self.worker_id,
                'attempts': self.attempts,
                'error': str(e)
            })
    
    def get_worker_info(self) -> Dict[str, Any]:
        """
        Get worker information.
        
        Returns:
            Dictionary containing worker metadata
        """
        return {
            'worker_id': self.worker_id,
            'work_chunk_size': len(self.work_chunk),
            'hash_algorithm': self.hash_algorithm.name,
            'attempts': self.attempts,
            'elapsed_time': time.time() - self.start_time if self.start_time else 0
        }
