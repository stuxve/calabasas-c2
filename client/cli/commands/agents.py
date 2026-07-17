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

    table = Table(
        show_lines=False,
        title="[bold bright_red]Sessions[/bold bright_red]",
        title_style="",
        border_style="bright_black",
        header_style="bold bright_red",
        pad_edge=True,
        padding=(0, 1),
    )
    table.add_column("ID", style="bold white", justify="right")
    table.add_column("Hostname", style="bold white")
    table.add_column("User", style="bright_yellow")
    table.add_column("PID", style="white", justify="right")
    table.add_column("Arch", style="white")
    table.add_column("Integrity", min_width=8)
    table.add_column("Channel", style="cyan")
    table.add_column("Last", style="bright_black", justify="right")

    for s in sessions:
        if s.integrity == "SYSTEM":
            int_str = "[bold bright_magenta]SYSTEM[/bold bright_magenta]"
        elif s.integrity == "HIGH":
            int_str = "[bold red]HIGH[/bold red]"
        elif s.integrity == "LOW":
            int_str = "[dim white]LOW[/dim white]"
        else:
            int_str = "[yellow]MEDIUM[/yellow]"

        table.add_row(
            str(s.display_id),
            s.hostname or "???",
            s.username or "???",
            str(s.pid),
            s.arch,
            int_str,
            s.c2_channel,
            s.last_seen_ago,
        )

    console.print(table)
