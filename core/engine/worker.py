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

    # Adaptive reporting interval: report less often to reduce queue overhead.
    # For fast algorithms (MD5/SHA-1) at ~50M H/s, reporting every 1 000
    # attempts floods the stats queue with 50 000 messages/s.  100 000
    # strikes a good balance between responsiveness and overhead.
    _REPORT_INTERVAL = 100_000

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

        # Local references for hot-loop performance – avoids repeated
        # attribute lookups on every iteration.
        verify = self.hash_algorithm.verify
        stop_is_set = self.stop_event.is_set
        report_interval = self._REPORT_INTERVAL
        attempts_since_report = 0

        try:
            for candidate in self.work_chunk:
                if stop_is_set():
                    break

                if verify(candidate, normalized_target):
                    self.result_queue.put({
                        'found': True,
                        'password': candidate,
                        'worker_id': self.worker_id,
                        'attempts': self.attempts
                    })
                    return

                self.attempts += 1
                attempts_since_report += 1

                # Report progress at a reduced frequency
                if attempts_since_report >= report_interval:
                    self.stats_queue.put({
                        'worker_id': self.worker_id,
                        'attempts': attempts_since_report,
                        'elapsed_time': time.time() - self.start_time
                    })
                    attempts_since_report = 0

            # Flush remaining unreported attempts
            if attempts_since_report > 0:
                self.stats_queue.put({
                    'worker_id': self.worker_id,
                    'attempts': attempts_since_report,
                    'elapsed_time': time.time() - self.start_time
                })

            # Password not found in this chunk
            self.result_queue.put({
                'found': False,
                'worker_id': self.worker_id,
                'attempts': self.attempts
            })

        except Exception as e:
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
