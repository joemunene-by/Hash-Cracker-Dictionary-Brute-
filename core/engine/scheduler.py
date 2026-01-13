"""
Task Scheduler

Manages task distribution and scheduling for efficient resource utilization
across multiple worker processes in the cracking engine.
"""

import time
from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class Task:
    """Represents a cracking task."""
    task_id: str
    priority: int
    work_chunk: List[str]
    created_time: float
    assigned_worker: Optional[int] = None
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    status: str = 'pending'  # pending, assigned, completed, failed


class TaskScheduler:
    """Schedules and distributes tasks to worker processes."""
    
    def __init__(self):
        self.tasks: Dict[str, Task] = {}
        self.task_queue: List[str] = []
        self.worker_assignments: Dict[int, str] = {}
        self.completed_tasks: List[str] = []
        self.total_tasks_created = 0
    
    def create_task(self, work_chunk: List[str], priority: int = 0) -> str:
        """
        Create a new task.
        
        Args:
            work_chunk: List of password candidates for this task
            priority: Task priority (higher = more important)
            
        Returns:
            Task ID
        """
        task_id = f"task_{self.total_tasks_created}"
        self.total_tasks_created += 1
        
        task = Task(
            task_id=task_id,
            priority=priority,
            work_chunk=work_chunk,
            created_time=time.time()
        )
        
        self.tasks[task_id] = task
        self.task_queue.append(task_id)
        
        # Sort queue by priority (highest first)
        self.task_queue.sort(key=lambda tid: self.tasks[tid].priority, reverse=True)
        
        return task_id
    
    def assign_task(self, worker_id: int) -> Optional[str]:
        """
        Assign the next available task to a worker.
        
        Args:
            worker_id: ID of the worker requesting a task
            
        Returns:
            Task ID if available, None if no tasks remaining
        """
        if not self.task_queue:
            return None
        
        # Check if worker already has a task
        if worker_id in self.worker_assignments:
            return self.worker_assignments[worker_id]
        
        # Get next task
        task_id = self.task_queue.pop(0)
        task = self.tasks[task_id]
        
        # Assign to worker
        task.assigned_worker = worker_id
        task.start_time = time.time()
        task.status = 'assigned'
        
        self.worker_assignments[worker_id] = task_id
        
        return task_id
    
    def complete_task(self, task_id: str, success: bool = True):
        """
        Mark a task as completed.
        
        Args:
            task_id: ID of the completed task
            success: Whether the task completed successfully
        """
        if task_id not in self.tasks:
            return
        
        task = self.tasks[task_id]
        task.end_time = time.time()
        task.status = 'completed' if success else 'failed'
        
        # Remove from worker assignments
        if task.assigned_worker in self.worker_assignments:
            del self.worker_assignments[task.assigned_worker]
        
        self.completed_tasks.append(task_id)
    
    def get_task(self, task_id: str) -> Optional[Task]:
        """
        Get task by ID.
        
        Args:
            task_id: Task ID
            
        Returns:
            Task object or None if not found
        """
        return self.tasks.get(task_id)
    
    def get_worker_task(self, worker_id: int) -> Optional[Task]:
        """
        Get the current task assigned to a worker.
        
        Args:
            worker_id: Worker ID
            
        Returns:
            Task object or None if no task assigned
        """
        task_id = self.worker_assignments.get(worker_id)
        return self.tasks.get(task_id) if task_id else None
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get scheduler statistics.
        
        Returns:
            Dictionary containing scheduler statistics
        """
        current_time = time.time()
        
        # Calculate task statistics
        pending_tasks = len(self.task_queue)
        active_tasks = len(self.worker_assignments)
        completed_tasks = len(self.completed_tasks)
        
        # Calculate average task duration
        total_duration = 0
        completed_count = 0
        
        for task_id in self.completed_tasks:
            task = self.tasks[task_id]
            if task.start_time and task.end_time:
                total_duration += task.end_time - task.start_time
                completed_count += 1
        
        avg_duration = total_duration / completed_count if completed_count > 0 else 0
        
        return {
            'total_tasks_created': self.total_tasks_created,
            'pending_tasks': pending_tasks,
            'active_tasks': active_tasks,
            'completed_tasks': completed_tasks,
            'workers_assigned': len(self.worker_assignments),
            'average_task_duration': avg_duration,
            'tasks_per_second': completed_tasks / max(1, current_time - (self.tasks[min(self.completed_tasks, key=lambda tid: self.tasks[tid].created_time)].created_time if self.completed_tasks else current_time))
        }
    
    def reset(self):
        """Reset scheduler state."""
        self.tasks.clear()
        self.task_queue.clear()
        self.worker_assignments.clear()
        self.completed_tasks.clear()
        self.total_tasks_created = 0
