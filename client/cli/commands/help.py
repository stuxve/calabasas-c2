"""
Help command rendering.
"""

from rich.console import Console
from rich.panel import Panel

console = Console()

MAIN_HELP = """[bold]Global Commands[/bold]
  agents                    List connected agents
  interact <id>             Select an agent to interact with
  listeners <sub>           Manage listeners (list|start|stop|kill)
  modules [list|search]     Browse module registry
  generate                  Generate agent payload
  help                      Show this help
  exit                      Exit operator client
"""

AGENT_HELP = """[bold]Agent Commands[/bold]
  help                      Show this help
  help <module>             Show module usage and OPSEC notes
  modules [list|search]     Browse/search module registry
  info                      Show agent metadata
  sleep <sec> [jitter%]     Change beacon interval
  clear                     Clear pending task queue
  back                      Return to main context
  exit                      Kill agent process (asks confirmation)

[bold]Execution[/bold]
  <module_name> [args]      Execute a module
  bof <path.o> [args]       Load and execute arbitrary BOF
  assembly <path.exe> [a]   Load and execute .NET assembly

[bold]File Operations[/bold]
  upload <local> <remote>   Upload file to target
  download <remote> [local] Download file from target

[bold yellow]Dangerous (spawns processes)[/bold yellow]
  shell <cmd>               Spawns cmd.exe
  powershell <cmd>          Spawns powershell.exe
"""


def cmd_help(context: str):
    if context == "main":
        console.print(Panel(MAIN_HELP, title="Help", border_style="cyan"))
    else:
        console.print(Panel(AGENT_HELP, title="Agent Help", border_style="cyan"))
