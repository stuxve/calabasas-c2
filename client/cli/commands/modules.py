"""
Module browsing commands: modules list, modules search, help <module>.
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from ...core.module_registry import ModuleRegistry, ModuleDefinition

console = Console(stderr=True)


def cmd_modules_list(registry: ModuleRegistry):
    """List all modules grouped by category."""
    categories = registry.list_by_category()
    if not categories:
        console.print("[dim]No modules loaded.[/dim]")
        return

    for category, mods in sorted(categories.items()):
        table = Table(
            title=f"[bold bright_red]{category}[/bold bright_red]",
            title_style="",
            show_lines=False,
            border_style="bright_black",
            header_style="bold bright_red",
            pad_edge=True,
            padding=(0, 1),
        )
        table.add_column("Module", style="bold white")
        table.add_column("Type", style="bright_black")
        table.add_column("OPSEC", min_width=6)
        table.add_column("Description", style="white")

        for mod in sorted(mods, key=lambda m: m.name):
            if mod.opsec_level == "high":
                opsec_str = "[bold red]HIGH[/bold red]"
            elif mod.opsec_level == "medium":
                opsec_str = "[yellow]MED[/yellow]"
            else:
                opsec_str = "[green]LOW[/green]"
            table.add_row(
                mod.name,
                mod.execution_type,
                opsec_str,
                mod.description[:60],
            )
        console.print(table)
        console.print()


def cmd_modules_search(registry: ModuleRegistry, query: str):
    """Search modules by name, category, tag, or description."""
    results = registry.search(query)
    if not results:
        console.print(f"[dim]No modules matching '{query}'.[/dim]")
        return

    table = Table(
        title=f"[bold bright_red]Search: {query}[/bold bright_red]",
        title_style="",
        show_lines=False,
        border_style="bright_black",
        header_style="bold bright_red",
        pad_edge=True,
        padding=(0, 1),
    )
    table.add_column("Module", style="bold white")
    table.add_column("Category", style="bright_black")
    table.add_column("Type", style="bright_black")
    table.add_column("Description", style="white")

    for mod in results:
        table.add_row(mod.name, mod.category, mod.execution_type, mod.description[:60])
    console.print(table)


def cmd_module_help(mod: ModuleDefinition):
    """Show detailed help for a specific module."""
    lines = []
    lines.append(f"[bold bright_red]{mod.name}[/bold bright_red] [bright_black]v{mod.version}[/bright_black]")
    lines.append(f"[bright_black]{mod.category} | {mod.execution_type} | OPSEC: {mod.opsec_level}[/bright_black]")
    lines.append("")
    lines.append(f"[white]{mod.description.strip()}[/white]")

    if mod.arguments:
        lines.append("")
        lines.append("[bold bright_red]Arguments:[/bold bright_red]")
        for arg in mod.arguments:
            req = "[red]required[/red]" if arg.required else "[bright_black]optional[/bright_black]"
            default = f" [bright_black](default: {arg.default})[/bright_black]" if arg.default and not arg.required else ""
            lines.append(f"  [bold white]--{arg.name:<20}[/bold white] {arg.type:<10} {req}{default}")
            if arg.description:
                lines.append(f"    [white]{arg.description}[/white]")
            if arg.example:
                lines.append(f"    [bright_black]Example: {arg.example}[/bright_black]")

    if mod.opsec_notes:
        lines.append("")
        lines.append("[bold yellow]OPSEC Notes:[/bold yellow]")
        lines.append(f"  [white]{mod.opsec_notes.strip()}[/white]")

    if mod.mitre_attack_id:
        lines.append(f"\n[bright_black]MITRE ATT&CK: {mod.mitre_attack_id}[/bright_black]")

    if mod.references:
        lines.append("[bright_black]References:[/bright_black]")
        for ref in mod.references:
            lines.append(f"  [bright_black]{ref}[/bright_black]")

    console.print(Panel(
        "\n".join(lines),
        title=f"[bold bright_red]{mod.name}[/bold bright_red]",
        border_style="bright_red",
        padding=(1, 2),
    ))
