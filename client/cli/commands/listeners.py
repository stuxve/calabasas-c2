"""
Listener management commands.
"""

from rich.console import Console
from rich.table import Table

console = Console(stderr=True)


def cmd_listeners_list(listeners: dict):
    """List all listeners."""
    if not listeners:
        console.print("[dim]No listeners configured.[/dim]")
        return

    table = Table(
        show_lines=False,
        title="[bold bright_red]Jobs[/bold bright_red]",
        title_style="",
        border_style="bright_black",
        header_style="bold bright_red",
        pad_edge=True,
        padding=(0, 1),
    )
    table.add_column("ID", style="bold white", justify="right")
    table.add_column("Type", style="white")
    table.add_column("Interface", style="white")
    table.add_column("Port/Pipe", style="white")
    table.add_column("Profile", style="bright_black")
    table.add_column("Status", min_width=8)

    for lid, listener in listeners.items():
        info = listener.info()
        status = info["status"]
        if status == "RUNNING":
            status_str = "[bold green]RUNNING[/bold green]"
        else:
            status_str = "[bold red]STOPPED[/bold red]"

        table.add_row(
            str(info["id"]),
            info["type"],
            info.get("interface", "-"),
            str(info.get("port", "-")),
            info.get("profile", "-"),
            status_str,
        )

    console.print(table)
