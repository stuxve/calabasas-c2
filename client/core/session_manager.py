"""
Agent session tracking.
Each connected agent gets an AgentSession with full metadata and task state.
"""

import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from uuid import UUID

from ..protocol.commands import TaskType, TaskStatus


@dataclass
class TokenInfo:
    token_handle: int
    username: str
    integrity: str
    impersonation_level: str
    timestamp: datetime


@dataclass
class TaskResult:
    raw: bytes
    parsed: Optional[object] = None


@dataclass
class Task:
    task_id: str
    task_type: TaskType
    module_name: str
    payload: bytes
    arguments: bytes
    created_at: datetime
    sent_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    status: TaskStatus = TaskStatus.PENDING
    result: Optional[TaskResult] = None
    timeout_seconds: int = 300


@dataclass
class AgentSession:
    agent_id: str
    hostname: str = ""
    username: str = ""
    pid: int = 0
    ppid: int = 0
    arch: str = "x64"
    os_version: str = ""
    dotnet_version: str = ""
    integrity: str = "MEDIUM"
    is_admin: bool = False
    process_name: str = ""
    c2_channel: str = "HTTPS"
    listener_id: int = 0
    sleep_interval: int = 60
    jitter_percent: int = 25
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    cwd: str = "C:\\"
    token_stack: list = field(default_factory=list)
    pending_tasks: deque = field(default_factory=deque)
    active_tasks: dict = field(default_factory=dict)
    completed_tasks: list = field(default_factory=list)
    encryption_key: bytes = b""
    peer_public_key: bytes = b""
    agent_version: str = "1.0.0"
    supported_exec_types: list = field(default_factory=lambda: ["bof", "assembly", "native"])
    loaded_modules_cache: dict = field(default_factory=dict)
    # Nonce manager set after key exchange
    nonce_manager: Optional[object] = None
    # Internal numeric ID for CLI display
    display_id: int = 0

    def update_last_seen(self):
        self.last_seen = datetime.utcnow()

    @property
    def integrity_short(self) -> str:
        return self.integrity.upper()

    @property
    def last_seen_ago(self) -> str:
        delta = (datetime.utcnow() - self.last_seen).total_seconds()
        if delta < 60:
            return f"{int(delta)}s"
        elif delta < 3600:
            return f"{int(delta / 60)}m"
        elif delta < 86400:
            return f"{int(delta / 3600)}h"
        else:
            return f"{int(delta / 86400)}d"


class SessionManager:
    """Thread-safe registry of active agent sessions."""

    def __init__(self):
        self._sessions: dict[str, AgentSession] = {}  # agent_id → session
        self._display_map: dict[int, str] = {}  # display_id → agent_id
        self._next_display_id = 1
        self._lock = threading.Lock()

    def register(self, session: AgentSession) -> int:
        """Register a new agent session. Returns display ID."""
        with self._lock:
            display_id = self._next_display_id
            self._next_display_id += 1
            session.display_id = display_id
            self._sessions[session.agent_id] = session
            self._display_map[display_id] = session.agent_id
            return display_id

    def get(self, agent_id: str) -> Optional[AgentSession]:
        with self._lock:
            return self._sessions.get(agent_id)

    def get_by_display_id(self, display_id: int) -> Optional[AgentSession]:
        with self._lock:
            agent_id = self._display_map.get(display_id)
            if agent_id:
                return self._sessions.get(agent_id)
            return None

    def remove(self, agent_id: str):
        with self._lock:
            session = self._sessions.pop(agent_id, None)
            if session:
                self._display_map.pop(session.display_id, None)

    def all_sessions(self) -> list[AgentSession]:
        with self._lock:
            return list(self._sessions.values())

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._sessions)

    def find_by_agent_id_prefix(self, prefix: str) -> Optional[AgentSession]:
        """Find a session by agent_id prefix (for CLI convenience)."""
        with self._lock:
            for aid, session in self._sessions.items():
                if aid.startswith(prefix):
                    return session
            return None
