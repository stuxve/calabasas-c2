"""
Task creation, queuing, and timeout monitoring.
"""

import threading
import time
from datetime import datetime
from typing import Optional, Callable
from uuid import uuid4

from ..protocol.commands import TaskType, TaskStatus
from .session_manager import AgentSession, Task, TaskResult


class ChunkBuffer:
    """Collects chunks for a single chunked task result."""

    __slots__ = ("total", "chunks", "success")

    def __init__(self, total: int, success: bool):
        self.total = total
        self.chunks: dict[int, bytes] = {}
        self.success = success

    def add(self, seq: int, data: bytes, success: bool):
        self.chunks[seq] = data
        if not success:
            self.success = False

    @property
    def complete(self) -> bool:
        return len(self.chunks) == self.total

    def reassemble(self) -> bytes:
        return b"".join(self.chunks[i] for i in sorted(self.chunks))


class TaskManager:
    """
    Manages task lifecycle across all agent sessions.
    Runs a background thread to check for timed-out tasks.
    """

    def __init__(self, on_timeout: Optional[Callable[[AgentSession, Task], None]] = None):
        self._on_timeout = on_timeout
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._chunk_buffers: dict[str, ChunkBuffer] = {}  # task_id → ChunkBuffer

    def create_task(
        self,
        agent: AgentSession,
        task_type: TaskType,
        module_name: str,
        payload: bytes = b"",
        arguments: bytes = b"",
        timeout: int = 300,
    ) -> Task:
        """Create a task and append it to the agent's pending queue."""
        task = Task(
            task_id=str(uuid4()),
            task_type=task_type,
            module_name=module_name,
            payload=payload,
            arguments=arguments,
            created_at=datetime.utcnow(),
            timeout_seconds=timeout,
        )
        agent.pending_tasks.append(task)
        return task

    def mark_sent(self, agent: AgentSession, task: Task):
        """Move task from pending to active."""
        task.status = TaskStatus.SENT
        task.sent_at = datetime.utcnow()
        agent.active_tasks[task.task_id] = task

    def mark_complete(self, agent: AgentSession, task: Task, result_data: bytes,
                      success: bool = True):
        """Mark a task as completed and move to history."""
        task.status = TaskStatus.COMPLETE if success else TaskStatus.ERROR
        task.completed_at = datetime.utcnow()
        task.result = TaskResult(raw=result_data)
        agent.active_tasks.pop(task.task_id, None)
        agent.completed_tasks.append(task)

    def handle_chunk(
        self,
        agent: AgentSession,
        task: Task,
        result_data: bytes,
        success: bool,
        chunk_seq: int,
        chunk_total: int,
    ) -> bool:
        """
        Handle a chunked task result. Returns True when all chunks received
        and the task has been marked complete.
        """
        tid = task.task_id
        if tid not in self._chunk_buffers:
            self._chunk_buffers[tid] = ChunkBuffer(chunk_total, success)

        buf = self._chunk_buffers[tid]
        buf.add(chunk_seq, result_data, success)

        if buf.complete:
            full_data = buf.reassemble()
            del self._chunk_buffers[tid]
            self.mark_complete(agent, task, full_data, buf.success)
            return True

        return False

    def flush_pending(self, agent: AgentSession) -> list[Task]:
        """
        Dequeue all pending tasks for an agent (called on check-in).
        Returns the tasks and marks them as sent.
        """
        tasks = []
        while agent.pending_tasks:
            task = agent.pending_tasks.popleft()
            self.mark_sent(agent, task)
            tasks.append(task)
        return tasks

    def clear_pending(self, agent: AgentSession) -> int:
        """Clear all pending (unsent) tasks. Returns count cleared."""
        count = len(agent.pending_tasks)
        agent.pending_tasks.clear()
        return count

    # ─── Timeout monitoring ───

    def start_monitor(self, interval: float = 10.0):
        """Start background thread to check for timed-out tasks."""
        if self._monitor_thread and self._monitor_thread.is_alive():
            return

        self._stop_event.clear()
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(interval,),
            daemon=True,
            name="task-timeout-monitor",
        )
        self._monitor_thread.start()

    def stop_monitor(self):
        self._stop_event.set()
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)

    def _monitor_loop(self, interval: float):
        while not self._stop_event.is_set():
            self._stop_event.wait(interval)
            if self._stop_event.is_set():
                break
            # Check would require access to all sessions — caller should
            # integrate this with SessionManager. Placeholder for now.

    def check_timeouts(self, agent: AgentSession):
        """Check and mark timed-out tasks for a single agent."""
        now = datetime.utcnow()
        timed_out = []

        for task_id, task in list(agent.active_tasks.items()):
            if task.sent_at and task.timeout_seconds > 0:
                elapsed = (now - task.sent_at).total_seconds()
                if elapsed > task.timeout_seconds:
                    task.status = TaskStatus.TIMEOUT
                    task.completed_at = now
                    timed_out.append(task)

        for task in timed_out:
            agent.active_tasks.pop(task.task_id, None)
            agent.completed_tasks.append(task)
            if self._on_timeout:
                self._on_timeout(agent, task)
