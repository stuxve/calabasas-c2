"""
Agent management commands: agents, interact, kill.
"""

from rich.console import Console
from rich.table import Table

from ...core.session_manager import SessionManager

console = Console(stderr=True)


def cmd_agents(session_manager: SessionManager):
    """List all connected agents."""
    sessions = session_manager.all_sessions()
    if not sessions:
        console.print("[dim]No agents connected.[/dim]")
        return

    table = Table(show_lines=False, title="Active Agents")
    table.add_column("ID", style="bold")
    table.add_column("Hostname", style="bold white")
    table.add_column("User", style="cyan")
    table.add_column("PID")
    table.add_column("Arch")
    table.add_column("Integrity")
    table.add_column("Channel")
    table.add_column("Last Seen")

    for s in sessions:
        integrity_style = "yellow"
        if s.integrity == "HIGH":
            integrity_style = "bold red"
        elif s.integrity == "SYSTEM":
            integrity_style = "bold magenta"

        table.add_row(
            str(s.display_id),
            s.hostname or "???",
            s.username or "???",
            str(s.pid),
            s.arch,
            f"[{integrity_style}]{s.integrity}[/{integrity_style}]",
            s.c2_channel,
            s.last_seen_ago,
        )

    console.print(table)
