"""
JSONL logging system.

Two log streams:
1. Operator log (operator_YYYY-MM-DD.jsonl): every command and response
2. Per-agent log (agent_{id}_{hostname}.jsonl): only that agent's traffic
"""

import json
import logging
from datetime import datetime, date
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


class OperatorLogger:

    def __init__(self, log_dir: Path):
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def _write(self, filename: str, entry: dict):
        path = self.log_dir / filename
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        except Exception as e:
            log.error(f"Failed to write log {path}: {e}")

    def log_command(self, agent_id: str, hostname: str, username: str,
                    command: str, arguments: dict):
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event": "COMMAND",
            "agent_id": agent_id,
            "hostname": hostname,
            "user": username,
            "command": command,
            "arguments": arguments,
        }
        self._write(f"agent_{agent_id[:8]}_{hostname}.jsonl", entry)
        self._write(f"operator_{date.today().isoformat()}.jsonl", entry)

    def log_result(self, agent_id: str, hostname: str, task_id: str,
                   module_name: str, status: str, duration_ms: Optional[float],
                   output_preview: str):
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event": "RESULT",
            "agent_id": agent_id,
            "task_id": task_id,
            "module": module_name,
            "status": status,
            "duration_ms": duration_ms,
            "output_preview": output_preview[:500],
        }
        self._write(f"agent_{agent_id[:8]}_{hostname}.jsonl", entry)
        self._write(f"operator_{date.today().isoformat()}.jsonl", entry)

    def log_raw_traffic(self, direction: str, agent_id: str,
                        encrypted_bytes: bytes, decrypted_size: int):
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event": "TRAFFIC",
            "direction": direction,
            "agent_id": agent_id,
            "encrypted_hex": encrypted_bytes[:64].hex() + ("..." if len(encrypted_bytes) > 64 else ""),
            "encrypted_size": len(encrypted_bytes),
            "decrypted_size": decrypted_size,
        }
        self._write(f"traffic_{date.today().isoformat()}.jsonl", entry)

    def log_event(self, event_type: str, **kwargs):
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event": event_type,
            **kwargs,
        }
        self._write(f"operator_{date.today().isoformat()}.jsonl", entry)
