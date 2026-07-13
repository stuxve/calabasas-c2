"""
Simple async event bus for decoupling listeners from the CLI.
"""

import asyncio
from typing import Any, Callable, Coroutine
from collections import defaultdict


class EventBus:
    """
    Async event bus. Listeners register callbacks for event types.
    Events are dispatched to all registered callbacks.
    """

    # Event types
    AGENT_CHECKIN = "agent_checkin"
    AGENT_LOST = "agent_lost"
    TASK_RESULT = "task_result"
    TASK_TIMEOUT = "task_timeout"
    LISTENER_STARTED = "listener_started"
    LISTENER_STOPPED = "listener_stopped"

    def __init__(self):
        self._handlers: dict[str, list[Callable]] = defaultdict(list)
        self._queue: asyncio.Queue = None

    def on(self, event_type: str, handler: Callable):
        """Register a handler for an event type."""
        self._handlers[event_type].append(handler)

    def off(self, event_type: str, handler: Callable):
        """Unregister a handler."""
        handlers = self._handlers.get(event_type, [])
        if handler in handlers:
            handlers.remove(handler)

    async def emit(self, event_type: str, **kwargs):
        """Emit an event to all registered handlers."""
        for handler in self._handlers.get(event_type, []):
            try:
                result = handler(**kwargs)
                if asyncio.iscoroutine(result):
                    await result
            except Exception as e:
                # Don't let a handler crash the emitter
                pass

    def init_queue(self):
        """Initialize the async queue (call from within an event loop)."""
        self._queue = asyncio.Queue()

    async def put(self, event_type: str, data: Any):
        """Put an event on the queue for async consumers."""
        if self._queue:
            await self._queue.put((event_type, data))

    async def get(self):
        """Get next event from queue."""
        if self._queue:
            return await self._queue.get()
        raise RuntimeError("Event queue not initialized")


# Global event bus instance
event_bus = EventBus()
