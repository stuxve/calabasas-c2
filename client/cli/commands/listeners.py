"""
Listener management commands.
"""

from rich.console import Console
from rich.table import Table

console = Console(stderr=True, no_color=True)


def cmd_listeners_list(listeners: dict):
    """List all listeners."""
    if not listeners:
        console.print("[dim]No listeners configured.[/dim]")
        return

    table = Table(show_lines=False, title="Listeners")
    table.add_column("ID", style="bold")
    table.add_column("Type")
    table.add_column("Interface")
    table.add_column("Port/Pipe")
    table.add_column("Profile")
    table.add_column("Status")

    for lid, listener in listeners.items():
        info = listener.info()
        status_style = "green" if info["status"] == "RUNNING" else "red"
        table.add_row(
            str(info["id"]),
            info["type"],
            info.get("interface", "-"),
            str(info.get("port", "-")),
            info.get("profile", "-"),
            f"[{status_style}]{info['status']}[/{status_style}]",
        )

    console.print(table)
