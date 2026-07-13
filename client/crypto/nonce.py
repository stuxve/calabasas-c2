"""
Nonce counter management.

Server uses odd counters, agent uses even counters.
This prevents nonce reuse across both directions.
"""

import struct
import threading


class NonceManager:
    """Thread-safe nonce counter for a single session."""

    def __init__(self, agent_id_prefix: bytes, is_server: bool = True):
        """
        agent_id_prefix: first 4 bytes of agent UUID (for nonce construction)
        is_server: True → odd counters, False → even counters
        """
        if len(agent_id_prefix) != 4:
            raise ValueError(f"Agent ID prefix must be 4 bytes, got {len(agent_id_prefix)}")

        self._prefix = agent_id_prefix
        self._counter = 1 if is_server else 0  # Server=odd, Agent=even
        self._step = 2  # Increment by 2 to stay odd/even
        self._lock = threading.Lock()
        self._max_counter = 2**32  # Re-key after 2^32 messages

    def next_nonce(self) -> bytes:
        """Get the next nonce (12 bytes) and increment counter."""
        with self._lock:
            if self._counter >= self._max_counter:
                raise RuntimeError(
                    "Nonce counter exhausted — re-key required "
                    "(trigger new ECDH exchange)"
                )
            nonce = self._prefix + struct.pack("<Q", self._counter)
            self._counter += self._step
            return nonce

    @property
    def counter(self) -> int:
        with self._lock:
            return self._counter

    @property
    def needs_rekey(self) -> bool:
        with self._lock:
            return self._counter >= (self._max_counter - 1000)
