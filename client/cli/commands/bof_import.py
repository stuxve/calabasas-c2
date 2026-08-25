"""
bof-import — runtime command that ingests an external BOF (a .o file
compiled for CobaltStrike, TrustedSec CS-SA, Havoc, or any COFF-compatible
framework) into the module registry.

Once imported, the BOF is indistinguishable from a native module: it
appears in `modules list`, in agent-context tab completion, and gets a
`help <name>` panel auto-rendered from its ArgumentDef list. The
completer and help subsystems both read from ModuleRegistry.modules,
so registration is the ONLY step needed to make the command "loaded in
the tool" — there is no separate completer wire-up per BOF.

Usage:

  bof-import <path_to.o>
      Auto-detect a sibling module.yaml / manifest.json / .cna next to
      the .o. Best for BOFs that ship with framework metadata.

  bof-import <path_to.o> --name mimikatz --args z:command --desc "text"
      Explicit — use when the BOF has no metadata files or when you want
      to override what auto-detection would infer.

  bof-import <dir>
      Ingest a whole prepared directory (already in the layout that
      startup discovery uses). Copies it under modules/external/.

The command persists what it imports under modules/external/<name>/ so
subsequent startups pick it up automatically without another import.
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console

from ...core.external_bof import build_module_from_ofile, build_module_from_directory
from ...core.module_registry import ModuleRegistry, ManifestError

console = Console(stderr=True)


def cmd_bof_import(registry: ModuleRegistry, args: list[str],
                   project_root: Path) -> None:
    """
    Dispatch bof-import. `args` is the token list after the command word.
    """
    if not args:
        _usage()
        return

    parsed = _parse_flags(args)
    if not parsed["path"]:
        console.print("[red]bof-import: missing <path>[/red]")
        _usage()
        return

    src = Path(parsed["path"]).expanduser().resolve()
    if not src.exists():
        console.print(f"[red]bof-import: no such file or directory:[/red] {src}")
        return

    external_root = _external_root(registry, project_root)
    external_root.mkdir(parents=True, exist_ok=True)

    try:
        if src.is_dir():
            # Directory form: copy into external_root, then discover it.
            dest = external_root / (parsed["name"] or src.name)
            if dest.exists() and dest.resolve() != src.resolve():
                console.print(
                    f"[yellow]bof-import: {dest.name} already exists — "
                    f"replacing.[/yellow]"
                )
            _copy_tree(src, dest)
            mod = build_module_from_directory(dest)
        else:
            # Single-file form.
            mod, persisted = build_module_from_ofile(
                src,
                name=parsed["name"],
                args_spec=parsed["args"],
                description=parsed["desc"],
                category=parsed["category"],
                external_root=external_root,
            )
            console.print(f"[dim]  persisted → {persisted}[/dim]")

        registry.register(mod)
    except ManifestError as e:
        console.print(f"[red]bof-import: {e}[/red]")
        return
    except Exception as e:
        console.print(f"[red]bof-import: unexpected error: {e}[/red]")
        return

    # Confirmation — since the completer reads registry.modules directly,
    # the BOF is now tab-completable at the agent prompt with no further
    # action.
    arg_names = ", ".join(a.name for a in mod.arguments) or "(none)"
    console.print(
        f"[bright_green][+][/bright_green] Registered [bold]{mod.name}[/bold] "
        f"[bright_black]({mod.execution_type}, {mod.bof_arch})[/bright_black]\n"
        f"[dim]    args: {arg_names}[/dim]\n"
        f"[dim]    try: modules list | help {mod.name} | "
        f"<in an agent> {mod.name} --...[/dim]"
    )


# ---------------------------------------------------------------------------

def _parse_flags(args: list[str]) -> dict:
    """
    Tiny hand-rolled flag parser — no argparse, since the shell already
    tokenizes and we want short, forgiving behavior. Recognizes:

      --name  NAME
      --args  SPEC       (e.g. "z:host,i:port" or bare "zzi")
      --desc  "TEXT"
      --category CAT     (defaults to "external")

    First non-flag token is treated as the <path>.
    """
    out = {"path": None, "name": None, "args": None,
           "desc": "", "category": "external"}
    i = 0
    while i < len(args):
        tok = args[i]
        if tok in ("--name", "-n") and i + 1 < len(args):
            out["name"] = args[i + 1]; i += 2; continue
        if tok in ("--args", "-a") and i + 1 < len(args):
            out["args"] = args[i + 1]; i += 2; continue
        if tok in ("--desc", "-d") and i + 1 < len(args):
            out["desc"] = args[i + 1]; i += 2; continue
        if tok == "--category" and i + 1 < len(args):
            out["category"] = args[i + 1]; i += 2; continue
        if tok.startswith("--"):
            # Unknown flag — skip its value if any.
            i += 2 if i + 1 < len(args) and not args[i + 1].startswith("--") else 1
            continue
        if out["path"] is None:
            out["path"] = tok
        i += 1
    return out


def _external_root(registry: ModuleRegistry, project_root: Path) -> Path:
    """
    Prefer registry.modules_dir/external so imports live next to the
    modules the registry already knows about. Fall back to
    <project_root>/modules/external.
    """
    if registry.modules_dir:
        return registry.modules_dir / "external"
    return project_root / "modules" / "external"


def _copy_tree(src: Path, dest: Path) -> None:
    import shutil
    if src.resolve() == dest.resolve():
        return
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(src, dest)


def _usage() -> None:
    console.print(
        "[bold]Usage:[/bold]\n"
        "  bof-import <path.o> [--name NAME] [--args SPEC] [--desc TEXT] [--category CAT]\n"
        "  bof-import <directory>\n"
        "\n"
        "[bold]--args[/bold] examples:\n"
        "  --args 'z:host,i:port,Z:command'   explicit name per arg\n"
        "  --args zzi                          CobaltStrike bare format\n"
        "\n"
        "Pack chars: b=bytes  i=int32  s=int16  z=char*  Z=wchar_t*\n"
        "Uppercase Z marks an optional wide-string argument.\n"
    )
