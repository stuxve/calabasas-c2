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
    "bof-import": "Register an external BOF (.o + optional .cna/.yaml)",
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
    "systeminfo": "System info: hostname, IP, OS, user, domain (native)",
    "whoami": "Current user, privileges, groups (native)",
    "ps": "List running processes (native)",
    "cd": "Change working directory (native, cd <path>)",
    "ls": "Directory listing (native, ls [path])",
    "dir": "Directory listing (alias for ls)",
    "cat": "Read file contents (native, cat <path>)",
    "keylogger": "Keystroke logger (keylogger start|stop|dump)",
    "jump": "Lateral movement (jump <method> <target> <listener>)",
    "link": "Link child agent via SMB pipe (link <target> <pipe>)",
    "unlink": "Unlink child agent (unlink [target])",
    "spawnto": "Set sacrificial process (spawnto <x64|x86> <path>)",
    "ak-settings": "Framework settings (ak-settings <setting> <value>)",
    "ppid": "Set parent PID for spawned processes (ppid <pid>)",
    "spawn": "Fork new beacon process (spawn <listener>)",
    "upload": "Upload file (upload <local> <remote>)",
    "download": "Download file (download <remote> [local])",
    "steal_token": "Steal token from PID (steal_token <pid>)",
    "rev2self": "Revert to process token (drop impersonation)",
    "shell": "DANGER: spawns cmd.exe",
    "powershell": "DANGER: spawns powershell.exe",
    "bof": "Load and execute arbitrary BOF",
    "assembly": "Load and execute .NET assembly",
    "modules": "List or search modules",
}

AGENT_SUBCOMMANDS = {
    "keylogger": {
        "start": "Begin capturing keystrokes",
        "stop": "Stop capturing and return keystrokes",
        "dump": "Return captured keystrokes (keeps running)",
    },
    "jump": {
        "psexec64": "PsExec x64 — service creation (drops to ADMIN$)",
        "psexec32": "PsExec x86 — service creation (drops to ADMIN$)",
        "wmiexec64": "WMI x64 — DCOM Win32_Process.Create",
        "wmiexec32": "WMI x86 — DCOM Win32_Process.Create",
        "scshell64": "SCShell x64 — service binPath hijack (most OPSEC)",
        "scshell32": "SCShell x86 — service binPath hijack (most OPSEC)",
    },
    "spawnto": {
        "x64": "Set x64 sacrificial process path",
        "x86": "Set x86 sacrificial process path",
    },
    "ak-settings": {
        "spawnto_x64": "Set x64 sacrificial process for post-ex/lateral movement",
        "spawnto_x86": "Set x86 sacrificial process for post-ex/lateral movement",
    },
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
        # Cached remote directory entries from last ls output
        # list of (name, is_dir) tuples
        self.remote_entries: list[tuple[str, bool]] = []
        # Reference to listeners dict (set by shell after init)
        self.listeners: dict = {}

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

        elif words[0] == "bof-import":
            # After the path, complete the flag names bof-import knows.
            # We don't try to complete filesystem paths here — the shell
            # doesn't wrap a filesystem completer for us — but flag
            # completion after the first arg keeps the UX consistent
            # with module argument completion in agent context.
            flags = {
                "--name": "Explicit module name (default: derived from filename)",
                "--args": "Pack spec, e.g. 'z:host,i:port' or bare 'zzi'",
                "--desc": "Human-readable description shown in modules list",
                "--category": "Category for `modules list` grouping",
            }
            if word_count >= 3:
                used = {w for w in words[1:] if w.startswith("--")}
                for f, desc in flags.items():
                    if f in used:
                        continue
                    if f.startswith(prefix) or not prefix:
                        yield Completion(f, start_position=-len(prefix),
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

        elif word_count == 2 and words[0] in AGENT_SUBCOMMANDS:
            # Complete subcommands (e.g. keylogger start|stop|dump)
            subs = AGENT_SUBCOMMANDS[words[0]]
            for sub, desc in subs.items():
                if sub.startswith(prefix):
                    yield Completion(sub, start_position=-len(prefix),
                                    display_meta=desc)

        elif word_count == 2 and words[0] == "spawn":
            # Complete listener names
            yield from self._complete_listeners(prefix)

        elif word_count == 4 and words[0] == "jump":
            # jump <method> <target> <listener>
            yield from self._complete_listeners(prefix)

        elif words[0] == "jump" and word_count >= 5:
            # After method/target/listener, offer --server-connection
            if "--server-connection".startswith(prefix) and "--server-connection" not in words:
                yield Completion("--server-connection", start_position=-len(prefix),
                                display_meta="Child connects directly to C2")

        elif word_count == 2 and words[0] in ("cd", "ls", "dir", "cat"):
            # Complete remote paths from cached ls entries
            for name, is_dir in self.remote_entries:
                if name.startswith(prefix):
                    meta = "dir" if is_dir else "file"
                    # For cd, only show directories
                    if words[0] == "cd" and not is_dir:
                        continue
                    yield Completion(name, start_position=-len(prefix),
                                    display_meta=meta)

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

    def _complete_listeners(self, prefix):
        """Yield completions for listener names/types/IDs."""
        seen = set()
        for lid, lst in self.listeners.items():
            info = lst.info()
            name = info.get("name", "")
            ltype = info.get("type", "")
            lid_str = str(info["id"])
            status = info.get("status", "")
            meta = f"{ltype} ({status})"
            for candidate in (name, ltype, lid_str):
                if candidate and candidate not in seen and candidate.lower().startswith(prefix.lower()):
                    seen.add(candidate)
                    yield Completion(candidate, start_position=-len(prefix),
                                    display_meta=meta)
