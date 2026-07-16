"""
Context-aware tab completion for the operator shell.
"""

from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.document import Document

from ..core.module_registry import ModuleRegistry
from ..core.session_manager import SessionManager


# Built-in commands per context
MAIN_COMMANDS = {
    "agents": "List connected agents",
    "interact": "Interact with an agent (interact <id>)",
    "listeners": "Manage listeners (start/stop/list)",
    "modules": "List or search modules",
    "generate": "Generate an agent payload",
    "help": "Show help",
    "exit": "Exit the operator client",
}

AGENT_COMMANDS = {
    "help": "Show commands and modules",
    "info": "Agent metadata",
    "sleep": "Change beacon interval (sleep <sec> [jitter%])",
    "clear": "Clear pending task queue",
    "tasks": "Show pending/active/completed task queue",
    "back": "Return to main context",
    "exit": "Kill agent (asks confirmation)",
    "whoami": "Current user, privileges, groups (native)",
    "ps": "List running processes (native)",
    "cd": "Change working directory (native, cd <path>)",
    "ls": "Directory listing (native, ls [path])",
    "cat": "Read file contents (native, cat <path>)",
    "upload": "Upload file (upload <local> <remote>)",
    "download": "Download file (download <remote> [local])",
    "rev2self": "Revert to process token (drop impersonation)",
    "shell": "DANGER: spawns cmd.exe",
    "powershell": "DANGER: spawns powershell.exe",
    "bof": "Load and execute arbitrary BOF",
    "assembly": "Load and execute .NET assembly",
    "modules": "List or search modules",
}

LISTENER_SUBCOMMANDS = {
    "list": "List all listeners",
    "start": "Start a new listener",
    "stop": "Stop a listener",
    "kill": "Kill and remove a listener",
}

LISTENER_TYPES = {
    "https": "HTTPS listener",
    "http": "HTTP listener (no TLS)",
    "smb": "SMB named pipe listener",
    "dns": "DNS listener",
    "tcp": "Raw TCP listener",
}


class ShellCompleter(Completer):
    """Context-aware completer for the operator shell."""

    def __init__(self, module_registry: ModuleRegistry,
                 session_manager: SessionManager):
        self.module_registry = module_registry
        self.session_manager = session_manager
        self.context = "main"  # "main" or "agent"

    def get_completions(self, document: Document, complete_event):
        text = document.text_before_cursor
        words = text.split()
        word_count = len(words)

        # If cursor is right after a space, we're completing a new word
        if text.endswith(" "):
            word_count += 1
            current_prefix = ""
        else:
            current_prefix = words[-1] if words else ""

        if self.context == "main":
            yield from self._complete_main(words, word_count, current_prefix)
        elif self.context == "agent":
            yield from self._complete_agent(words, word_count, current_prefix)

    def _complete_main(self, words, word_count, prefix):
        if word_count <= 1:
            for cmd, desc in MAIN_COMMANDS.items():
                if cmd.startswith(prefix):
                    yield Completion(
                        cmd, start_position=-len(prefix),
                        display_meta=desc,
                    )

        elif words[0] == "interact" and word_count == 2:
            for session in self.session_manager.all_sessions():
                sid = str(session.display_id)
                if sid.startswith(prefix):
                    yield Completion(
                        sid, start_position=-len(prefix),
                        display_meta=f"{session.hostname} ({session.username})",
                    )

        elif words[0] == "listeners" and word_count == 2:
            for sub, desc in LISTENER_SUBCOMMANDS.items():
                if sub.startswith(prefix):
                    yield Completion(sub, start_position=-len(prefix),
                                    display_meta=desc)

        elif words[0] == "listeners" and len(words) >= 2 and words[1] == "start" and word_count == 3:
            for lt, desc in LISTENER_TYPES.items():
                if lt.startswith(prefix):
                    yield Completion(lt, start_position=-len(prefix),
                                    display_meta=desc)

    def _complete_agent(self, words, word_count, prefix):
        if word_count <= 1:
            # Complete built-in commands + module names
            for cmd, desc in AGENT_COMMANDS.items():
                if cmd.startswith(prefix):
                    yield Completion(cmd, start_position=-len(prefix),
                                    display_meta=desc)

            for mod in self.module_registry.modules.values():
                if mod.name.startswith(prefix):
                    yield Completion(
                        mod.name, start_position=-len(prefix),
                        display_meta=f"[{mod.category}] {mod.description[:40]}",
                    )

        elif word_count >= 2:
            # Complete module arguments
            cmd = words[0]
            mod = self.module_registry.get(cmd)
            if mod:
                used_args = {w.lstrip("-") for w in words[1:] if w.startswith("--")}
                for arg in mod.arguments:
                    if arg.name not in used_args:
                        flag = f"--{arg.name}"
                        if flag.startswith(f"--{prefix.lstrip('-')}") or not prefix:
                            meta = f"({arg.type}) {arg.description[:30]}"
                            if arg.required:
                                meta = "[REQ] " + meta
                            yield Completion(
                                flag, start_position=-len(prefix),
                                display_meta=meta,
                            )
