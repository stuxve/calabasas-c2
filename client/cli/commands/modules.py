"""
Module browsing commands: modules list, modules search, help <module>.
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from ...core.module_registry import ModuleRegistry, ModuleDefinition

console = Console()


def cmd_modules_list(registry: ModuleRegistry):
    """List all modules grouped by category."""
    categories = registry.list_by_category()
    if not categories:
        console.print("[dim]No modules loaded.[/dim]")
        return

    for category, mods in sorted(categories.items()):
        table = Table(title=f"[bold]{category}[/bold]", show_lines=False)
        table.add_column("Module", style="cyan bold")
        table.add_column("Type")
        table.add_column("OPSEC")
        table.add_column("Description")

        for mod in sorted(mods, key=lambda m: m.name):
            opsec_style = {"low": "green", "medium": "yellow", "high": "bold red"}.get(
                mod.opsec_level, "white"
            )
            table.add_row(
                mod.name,
                mod.execution_type,
                f"[{opsec_style}]{mod.opsec_level}[/{opsec_style}]",
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

    table = Table(title=f"Search: {query}", show_lines=False)
    table.add_column("Module", style="cyan bold")
    table.add_column("Category")
    table.add_column("Type")
    table.add_column("Description")

    for mod in results:
        table.add_row(mod.name, mod.category, mod.execution_type, mod.description[:60])
    console.print(table)


def cmd_module_help(mod: ModuleDefinition):
    """Show detailed help for a specific module."""
    lines = []
    lines.append(f"[bold cyan]{mod.name}[/bold cyan] v{mod.version}")
    lines.append(f"[dim]{mod.category} | {mod.execution_type} | OPSEC: {mod.opsec_level}[/dim]")
    lines.append("")
    lines.append(mod.description.strip())

    if mod.arguments:
        lines.append("")
        lines.append("[bold]Arguments:[/bold]")
        for arg in mod.arguments:
            req = "[red]required[/red]" if arg.required else "optional"
            default = f" (default: {arg.default})" if arg.default and not arg.required else ""
            lines.append(f"  --{arg.name:<20} {arg.type:<10} {req}{default}")
            if arg.description:
                lines.append(f"    {arg.description}")
            if arg.example:
                lines.append(f"    [dim]Example: {arg.example}[/dim]")

    if mod.opsec_notes:
        lines.append("")
        lines.append("[bold yellow]OPSEC Notes:[/bold yellow]")
        lines.append(f"  {mod.opsec_notes.strip()}")

    if mod.mitre_attack_id:
        lines.append(f"\n[dim]MITRE ATT&CK: {mod.mitre_attack_id}[/dim]")

    if mod.references:
        lines.append("[dim]References:[/dim]")
        for ref in mod.references:
            lines.append(f"  [dim]{ref}[/dim]")

    console.print(Panel("\n".join(lines), title=mod.name, border_style="cyan"))
