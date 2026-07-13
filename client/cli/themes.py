"""
Color and style definitions for the CLI shell.
"""

from rich.theme import Theme

C2_THEME = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "success": "bold green",
    "agent.hostname": "bold white",
    "agent.user": "bold cyan",
    "agent.integrity": "bold yellow",
    "agent.high": "bold red",
    "agent.system": "bold magenta",
    "opsec.low": "green",
    "opsec.medium": "yellow",
    "opsec.high": "bold red",
    "module.name": "bold cyan",
    "module.category": "dim white",
})

# Prompt styles for prompt_toolkit
PROMPT_STYLE_MAIN = [
    ("prompt", "fg:ansigreen bold"),
]

PROMPT_STYLE_AGENT = [
    ("agent-id", "fg:ansicyan"),
    ("hostname", "fg:ansiwhite bold"),
    ("username", "fg:ansicyan"),
    ("integrity", "fg:ansiyellow"),
    ("arch", "fg:ansiwhite"),
    ("pid", "fg:ansiwhite"),
    ("separator", "fg:ansiwhite"),
    ("path", "fg:ansiblue"),
    ("prompt-end", "fg:ansigreen bold"),
]

BANNER = r"""
   ______      __      __                             ________
  / ____/___ _/ /___ _/ /_  ____ ___________ ______  / ____/__ \
 / /   / __ `/ / __ `/ __ \/ __ `/ ___/ __ `/ ___/ / /    __/ /
/ /___/ /_/ / / /_/ / /_/ / /_/ (__  ) /_/ (__  ) / /___ / __/
\____/\__,_/_/\__,_/_.___/\__,_/____/\__,_/____/  \____//____/
                                          v1.0.0 | AD Post-Ex
"""
