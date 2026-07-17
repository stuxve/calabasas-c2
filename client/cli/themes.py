"""
Color and style definitions for the Caraxes C2 CLI shell.
Inspired by Sliver C2's aesthetic — bold colors, stylized tables, dragon-fire theme.
"""

import random

from rich.theme import Theme

# ── Rich theme for console output ──
C2_THEME = Theme({
    "info": "bold cyan",
    "warning": "bold yellow",
    "error": "bold red",
    "success": "bold green",
    "agent.hostname": "bold white",
    "agent.user": "bold bright_red",
    "agent.integrity": "bold yellow",
    "agent.high": "bold red",
    "agent.system": "bold bright_magenta",
    "opsec.low": "green",
    "opsec.medium": "yellow",
    "opsec.high": "bold red",
    "module.name": "bold bright_red",
    "module.category": "dim white",
    "table.header": "bold bright_red",
    "table.border": "bright_black",
    "listener.running": "bold green",
    "listener.stopped": "bold red",
    "task.pending": "yellow",
    "task.complete": "green",
    "task.error": "bold red",
})

# ── Prompt styles for prompt_toolkit ──
PROMPT_STYLE_MAIN = [
    ("prompt", "fg:ansired bold"),
]

PROMPT_STYLE_AGENT = [
    ("agent-id", "fg:ansired bold"),
    ("hostname", "fg:ansiwhite bold"),
    ("username", "fg:ansibrightyellow"),
    ("integrity", "fg:ansired"),
    ("integrity-system", "fg:ansibrightmagenta bold"),
    ("arch", "fg:ansiwhite"),
    ("pid", "fg:ansibrightblack"),
    ("separator", "fg:ansibrightblack"),
    ("path", "fg:ansicyan"),
    ("prompt-end", "fg:ansired bold"),
    ("last-seen", "fg:ansibrightblack"),
]


# ── ASCII banners — randomized on each startup like Sliver ──

_BANNERS = [
    r"""
    [bright_red]
       ██████╗ █████╗ ██████╗  █████╗ ██╗  ██╗███████╗███████╗
      ██╔════╝██╔══██╗██╔══██╗██╔══██╗╚██╗██╔╝██╔════╝██╔════╝
      ██║     ███████║██████╔╝███████║ ╚███╔╝ █████╗  ███████╗
      ██║     ██╔══██║██╔══██╗██╔══██║ ██╔██╗ ██╔══╝  ╚════██║
      ╚██████╗██║  ██║██║  ██║██║  ██║██╔╝ ██╗███████╗███████║
       ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝
    [/bright_red]""",

    r"""
    [bright_red]
      ░█████╗░░█████╗░██████╗░░█████╗░██╗░░██╗███████╗░██████╗
      ██╔══██╗██╔══██╗██╔══██╗██╔══██╗╚██╗██╔╝██╔════╝██╔════╝
      ██║░░╚═╝███████║██████╔╝███████║░╚███╔╝░█████╗░░╚█████╗░
      ██║░░██╗██╔══██║██╔══██╗██╔══██║░██╔██╗░██╔══╝░░░╚═══██╗
      ╚█████╔╝██║░░██║██║░░██║██║░░██║██╔╝╚██╗███████╗██████╔╝
      ░╚════╝░╚═╝░░╚═╝╚═╝░░╚═╝╚═╝░░╚═╝╚═╝░░╚═╝╚══════╝╚═════╝
    [/bright_red]""",

    r"""
    [bright_red]
       ▄████▄   ▄▄▄       ██▀███   ▄▄▄       ▒██   ██▒▓█████   ██████
      ▒██▀ ▀█  ▒████▄    ▓██ ▒ ██▒▒████▄     ▒▒ █ █ ▒░▓█   ▀ ▒██    ▒
      ▒▓█    ▄ ▒██  ▀█▄  ▓██ ░▄█ ▒▒██  ▀█▄   ░░  █   ░▒███   ░ ▓██▄
      ▒▓▓▄ ▄██▒░██▄▄▄▄██ ▒██▀▀█▄  ░██▄▄▄▄██   ░ █ █ ▒ ▒▓█  ▄   ▒   ██▒
      ▒ ▓███▀ ░ ▓█   ▓██▒░██▓ ▒██▒ ▓█   ▓██▒ ▒██▒ ▒██▒░▒████▒▒██████▒▒
      ░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒▓ ░▒▓░ ▒▒   ▓▒█░ ▒▒ ░ ░▓ ░░ ▒░ ░▒ ▒▓▒ ▒ ░
    [/bright_red]""",

    r"""
    [bright_red]
       _____                               _____ ___
      / ____|                             / ____|__ \
     | |     __ _ _ __ __ ___  _____  ___| |       ) |
     | |    / _` | '__/ _` \ \/ / _ \/ __| |      / /
     | |___| (_| | | | (_| |>  <  __/\__ \ |____ / /_
      \_____\__,_|_|  \__,_/_/\_\___||___/\_____|____|
    [/bright_red]""",
]

_TAGLINES = [
    "[dim]The Blood Wyrm[/dim]",
    "[dim]Fire & Blood[/dim]",
    "[dim]Dracarys.[/dim]",
    "[dim]No process spawned. No command executed.[/dim]",
    "[dim]Pure API. Pure fire.[/dim]",
    "[dim]What feeds on process tokens?[/dim]",
    "[dim]Thread impersonation is not a crime... in Westeros.[/dim]",
]


def get_banner() -> str:
    """Return a random banner + tagline, Sliver-style."""
    banner = random.choice(_BANNERS)
    tagline = random.choice(_TAGLINES)
    version_line = "[bold bright_black]  v1.0.0 — AD Post-Exploitation Framework[/bold bright_black]"
    return f"{banner}\n{version_line}\n  {tagline}\n"


# Legacy export for backward compatibility
BANNER = get_banner()
