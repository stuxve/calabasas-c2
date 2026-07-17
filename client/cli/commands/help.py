"""
Help command rendering.
"""

from rich.console import Console
from rich.panel import Panel

console = Console(stderr=True)

MAIN_HELP = """[bold bright_red]Global Commands[/bold bright_red]
  [bold white]agents[/bold white]                    List connected sessions
  [bold white]interact[/bold white] <id>             Select a session to interact with
  [bold white]listeners[/bold white] <sub>           Manage listeners (list|start|stop|kill)
  [bold white]modules[/bold white] [list|search]     Browse module registry
  [bold white]generate[/bold white]                  Generate agent payload
  [bold white]help[/bold white]                      Show this help
  [bold white]exit[/bold white]                      Exit operator client
"""

AGENT_HELP = """[bold bright_red]Session Commands[/bold bright_red]
  [bold white]help[/bold white]                      Show this help
  [bold white]help[/bold white] <module>             Show module usage and OPSEC notes
  [bold white]modules[/bold white] [list|search]     Browse/search module registry
  [bold white]info[/bold white]                      Show agent metadata
  [bold white]sleep[/bold white] <sec> [jitter%]     Change beacon interval
  [bold white]clear[/bold white]                     Clear pending task queue
  [bold white]tasks[/bold white]                     Show pending/active/completed tasks
  [bold white]back[/bold white]                      Return to main context
  [bold white]exit[/bold white]                      Kill agent process (asks confirmation)

[bold bright_red]Native Modules[/bold bright_red] [bright_black](built into agent, no child process)[/bright_black]
  [bold white]whoami[/bold white]                    Current user, privileges, group membership
  [bold white]ps[/bold white]                        List running processes
  [bold white]cd[/bold white] [path]                 Change working directory
  [bold white]ls[/bold white] [path]                 Directory listing (default: CWD)
  [bold white]cat[/bold white] <path>                Read file contents

[bold bright_red]Execution[/bold bright_red]
  [bold white]<module_name>[/bold white] [args]      Execute a registered BOF/Assembly module
  [bold white]bof[/bold white] <path.o> [args]       Load and execute arbitrary BOF
  [bold white]assembly[/bold white] <path.exe> [a]   Load and execute .NET assembly

[bold bright_red]File Operations[/bold bright_red]
  [bold white]upload[/bold white] <local> <remote>   Upload file to target
  [bold white]download[/bold white] <remote> [local] Download file from target

[bold yellow]Dangerous[/bold yellow] [bright_black](spawns processes)[/bright_black]
  [bold white]shell[/bold white] <cmd>               Spawns cmd.exe
  [bold white]powershell[/bold white] <cmd>          Spawns powershell.exe
"""


def cmd_help(context: str):
    if context == "main":
        console.print(Panel(
            MAIN_HELP,
            title="[bold bright_red]Caraxes[/bold bright_red]",
            border_style="bright_red",
            padding=(1, 2),
        ))
    else:
        console.print(Panel(
            AGENT_HELP,
            title="[bold bright_red]Session Commands[/bold bright_red]",
            border_style="bright_red",
            padding=(1, 2),
        ))
