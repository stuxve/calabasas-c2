"""
Base listener abstract class.
"""

from abc import ABC, abstractmethod
from typing import Optional


class BaseListener(ABC):
    """Abstract base for all C2 listeners."""

    def __init__(self, listener_id: int, listener_type: str):
        self.listener_id = listener_id
        self.listener_type = listener_type
        self.running = False

    @abstractmethod
    async def start(self):
        """Start the listener."""
        pass

    @abstractmethod
    async def stop(self):
        """Stop the listener."""
        pass

    @abstractmethod
    def info(self) -> dict:
        """Return listener metadata for display."""
        pass
